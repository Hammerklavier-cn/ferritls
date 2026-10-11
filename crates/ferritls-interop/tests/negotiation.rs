//! 套件协商顺序互操作：服务端偏好序（provider 声明序）对客户端 offer
//! 集的裁决，与批准模式（fips provider）的协商面拒绝。
//!
//! 此前的握手全部钉扎单套件——「多套件 offer 时服务端按自身偏好
//! 选择」与「无公共套件时协商失败」从未被执行过。

mod common;

use std::sync::Arc;

use common::handshake_ping_pong;
use rustls::crypto::CryptoProvider;
use rustls::{AlertDescription, CipherSuite, ClientConnection, ServerConnection};

const AES128: CipherSuite = CipherSuite::TLS13_AES_128_GCM_SHA256;
const AES256: CipherSuite = CipherSuite::TLS13_AES_256_GCM_SHA384;
const CHACHA: CipherSuite = CipherSuite::TLS13_CHACHA20_POLY1305_SHA256;

/// 默认 provider，但套件面收窄为给定子集（保持声明序的相对顺序）。
fn provider_with_suites(suites: &[CipherSuite]) -> CryptoProvider {
    let base = ferritls_rustls::default_provider();
    let cipher_suites: Vec<_> = suites
        .iter()
        .map(|want| {
            base.cipher_suites
                .iter()
                .find(|s| s.suite() == *want)
                .copied()
                .unwrap_or_else(|| panic!("suite {want:?} not in default provider"))
        })
        .collect();
    CryptoProvider {
        cipher_suites,
        kx_groups: base.kx_groups,
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    }
}

/// 客户端全开 vs 服务端默认：服务端按声明序选首选（AES128-GCM）。
#[test]
fn server_preference_picks_top_suite_from_wide_offer() {
    let provider = ferritls_rustls::default_provider();
    handshake_ping_pong(
        common::server_config(provider.clone()).expect("server config"),
        common::client_config(provider),
        AES128,
    )
    .expect("wide-offer handshake");
}

/// rustls 服务端默认尊重客户端 offer 顺序（`ignore_client_order =
/// false`）：客户端只开 {ChaCha, AES256} 且 ChaCha 在前 → 协商 ChaCha。
#[test]
fn client_offer_order_honored_by_default() {
    let client = provider_with_suites(&[CHACHA, AES256]);
    handshake_ping_pong(
        common::server_config(ferritls_rustls::default_provider()).expect("server config"),
        common::client_config(client),
        CHACHA,
    )
    .expect("client-order handshake");
}

/// 服务端偏好（`ignore_client_order = true`）：同样只开 {ChaCha,
/// AES256} 的客户端，服务端按自身声明序选 AES256-GCM。
#[test]
fn server_preference_wins_when_client_order_ignored() {
    let client = provider_with_suites(&[CHACHA, AES256]);
    let mut server_cfg =
        common::server_config(ferritls_rustls::default_provider()).expect("server config");
    server_cfg.ignore_client_order = true;
    handshake_ping_pong(server_cfg, common::client_config(client), AES256)
        .expect("server-preference handshake");
}

/// 客户端只开 ChaCha：服务端在其偏好序中找不到更靠前者，回退到
/// ChaCha（多套件 offer 的回退路径）。
#[test]
fn chacha_only_offer_falls_through_to_chacha() {
    let client = provider_with_suites(&[CHACHA]);
    handshake_ping_pong(
        common::server_config(ferritls_rustls::default_provider()).expect("server config"),
        common::client_config(client),
        CHACHA,
    )
    .expect("chacha-only handshake");
}

/// 批准模式正向对照：fips 服务端与 AES256-only 客户端按批准套件协商。
#[test]
fn fips_provider_negotiates_approved_suite() {
    let client = provider_with_suites(&[AES256]);
    handshake_ping_pong(
        common::server_config(ferritls_rustls::fips_mode_provider()).expect("server config"),
        common::client_config(client),
        AES256,
    )
    .expect("fips approved handshake");
}

/// 批准模式协商面拒绝：fips 服务端 vs ChaCha-only 客户端——无公共
/// 套件，服务端必须立刻以 handshake_failure alert 拒绝 ClientHello
/// （非批准套件不能在协商层混入 fips provider）。
#[test]
fn fips_provider_rejects_non_approved_suite() {
    let server_cfg =
        common::server_config(ferritls_rustls::fips_mode_provider()).expect("server config");
    let client_cfg = common::client_config(provider_with_suites(&[CHACHA]));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");

    let server = std::thread::spawn(move || -> Result<(), rustls::Error> {
        let mut conn = ServerConnection::new(Arc::new(server_cfg))?;
        let mut io = server_io;
        while conn.is_handshaking() {
            common::drive_server(&mut conn, &mut io)?;
        }
        Err(rustls::Error::General(
            "server handshake completed — fips negotiation surface was breached".into(),
        ))
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_cfg),
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("name"),
    )
    .expect("client conn");
    let mut io = client_io;
    let client_err = loop {
        match common::drive_client(&mut conn, &mut io) {
            Err(e) => break e,
            Ok(()) => assert!(
                conn.is_handshaking(),
                "client handshake completed — fips negotiation surface was breached"
            ),
        }
    };
    assert_eq!(
        client_err,
        rustls::Error::AlertReceived(AlertDescription::HandshakeFailure),
        "fips server must reject with handshake_failure"
    );

    match server.join() {
        Ok(Ok(())) => panic!("server handshake completed — fips negotiation surface was breached"),
        Ok(Err(_)) => {}
        Err(panic) => std::panic::panic_any(panic),
    }
}
