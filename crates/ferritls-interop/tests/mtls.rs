//! mTLS（客户端认证）互操作测试。
//!
//! 覆盖适配层此前从未在握手层执行过的路径：服务端 CertificateRequest →
//! 客户端证书链上报（`ResolvesClientCert`）→ 客户端 CertificateVerify
//! 签名（`SigningKey::choose_scheme` → `sign`，ferritls KeyProvider 从
//! PKCS#8 加载）→ 服务端 webpki 客户端验证器校验（信任
//! tests/certs/client_root.pem）。
//!
//! 证书（tests/certs/，profile 与再生成命令见该目录 README.md）：
//! - client_root/client_leaf：P-256 客户端链，EKU clientAuth；
//! - 「不可信客户端证书」负例复用 Ed25519 服务器链（对 client_root
//!   而言 issuer 未知，无新证书）。
//!
//! 正例钉扎 TLS13_AES_128_GCM_SHA256 + X25519（客户端认证与套件/组
//! 选择正交，不需要矩阵）。

mod common;

use std::io::{Read, Write};
use std::sync::Arc;

use common::{
    cert_from_certs_dir, client_config, client_config_with_certs, ferritls_pinned,
    key_from_certs_dir, server_config_with_client_auth,
};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{CipherSuite, ClientConnection, ServerConnection};

/// ferritls provider 钉扎到 TLS13_AES_128_GCM_SHA256 + X25519。
fn pinned() -> rustls::crypto::CryptoProvider {
    let base = ferritls_rustls::default_provider();
    let suite = base
        .cipher_suites
        .iter()
        .find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .copied()
        .expect("TLS13_AES_128_GCM_SHA256");
    let group = base
        .kx_groups
        .iter()
        .find(|g| g.name() == rustls::NamedGroup::X25519)
        .copied()
        .expect("X25519");
    ferritls_pinned(suite, group)
}

/// 服务端 webpki 客户端验证器（ferritls 验证算法面 + 指定信任根）。
fn client_cert_verifier(
    provider: rustls::crypto::CryptoProvider,
    trust_root: CertificateDer<'static>,
) -> Arc<dyn rustls::server::danger::ClientCertVerifier> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trust_root).expect("add root");
    rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(provider.clone()),
    )
    .build()
    .expect("verifier")
}

fn client_leaf_chain() -> (
    Vec<CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    (
        vec![cert_from_certs_dir("client_leaf.pem")],
        key_from_certs_dir("client_leaf.key.der"),
    )
}

/// 正例：客户端证书被服务端接受，服务端能看到对端证书链，
/// 数据面 ping/pong 正常（客户端 CertificateVerify 由 ferritls 签发）。
#[test]
fn mtls_client_cert_accepted_and_visible_to_server() {
    let provider = pinned();
    let (chain, key) = client_leaf_chain();
    let server_cfg = server_config_with_client_auth(
        provider.clone(),
        client_cert_verifier(provider.clone(), cert_from_certs_dir("client_root.pem")),
    )
    .expect("server config");
    let client_cfg = client_config_with_certs(provider, chain, key);

    common::handshake_ping_pong_with(
        server_cfg,
        client_cfg,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        |conn| {
            let certs = conn
                .peer_certificates()
                .unwrap_or_else(|| panic!("server must observe client certificate"));
            assert!(!certs.is_empty(), "client cert chain empty");
        },
    )
    .unwrap_or_else(|e| panic!("mtls handshake failed: {e}"));
}

/// 负例：客户端不带证书 → 服务端要求客户端认证，握手必须失败
/// （客户端收到 alert；服务端停在验证错误上）。
#[test]
fn mtls_client_without_cert_rejected() {
    expect_rejected(|provider| {
        let server_cfg = server_config_with_client_auth(
            provider.clone(),
            client_cert_verifier(provider.clone(), cert_from_certs_dir("client_root.pem")),
        )
        .expect("server config");
        (server_cfg, client_config(provider))
    });
}

/// 负例：客户端证书的 issuer 不在服务端信任锚内（Ed25519 服务器链 vs
/// client_root 信任锚）→ 握手必须失败。
#[test]
fn mtls_untrusted_client_cert_rejected() {
    expect_rejected(|provider| {
        let server_cfg = server_config_with_client_auth(
            provider.clone(),
            client_cert_verifier(provider.clone(), cert_from_certs_dir("client_root.pem")),
        )
        .expect("server config");
        let chain = vec![
            cert_from_certs_dir("ed25519_leaf.pem"),
            cert_from_certs_dir("ed25519_int.pem"),
        ];
        let client_cfg =
            client_config_with_certs(provider, chain, key_from_certs_dir("ed25519_leaf.key.der"));
        (server_cfg, client_cfg)
    });
}

/// 驱动一次注定失败的握手：两端都必须以错误终止——
/// 客户端必须收到 alert（TLS 层拒绝，而非传输层挂断），
/// 服务端停在客户端证书验证错误上。
///
/// 注意 TLS 1.3 的时序：客户端在收到服务端首次飞行（含 Finished）后
/// 即单侧完成握手，服务端对客户端证书的裁决发生在其后——所以客户端
/// 侧的断言是「握手完成后继续驱动，alert 必须显式浮出」，不能断言
/// 握手阶段本身报错。
fn expect_rejected(
    build: impl FnOnce(rustls::crypto::CryptoProvider) -> (rustls::ServerConfig, rustls::ClientConfig),
) {
    let (server_cfg, client_cfg) = build(pinned());

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
            server_drive(&mut conn, &mut io)?;
        }
        Err(rustls::Error::General(
            "server handshake completed — client auth was not enforced".into(),
        ))
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("localhost".to_string()).expect("name"),
    )
    .expect("client conn");
    let mut io = client_io;
    let mut rounds = 0;
    let client_err = loop {
        rounds += 1;
        assert!(rounds < 50, "client never observed the rejection");
        match client_drive(&mut conn, &mut io) {
            Err(e) => break e,
            Ok(()) if conn.is_handshaking() => {}
            Ok(()) => {
                // 客户端单侧完成：只继续读（服务端 alert 已在途）。
                // 不能写应用数据——它会滞留在已退出的服务端接收缓冲，
                // 触发 RST 把在途 alert 一起毁掉（实测）。
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    };
    assert!(
        matches!(client_err, rustls::Error::AlertReceived(_)),
        "client must fail with a TLS alert, got: {client_err:?}"
    );

    match server.join() {
        Ok(Ok(())) => panic!("server handshake completed — client auth was not enforced"),
        Ok(Err(_)) => {} // 服务端停在验证错误上：预期
        Err(panic) => std::panic::panic_any(panic),
    }
}

/// 推进客户端一次 complete_io。complete_io 把 TLS 层错误包成
/// InvalidData 的 io::Error——源错误经 downcast 还原，alert 语义
/// （AlertReceived）才能被上层断言识别。
fn client_drive(
    conn: &mut ClientConnection,
    io: &mut (impl Read + Write),
) -> Result<(), rustls::Error> {
    conn.complete_io(io).map(|_| ()).map_err(unpack_tls_error)
}

fn server_drive(
    conn: &mut ServerConnection,
    io: &mut (impl Read + Write),
) -> Result<(), rustls::Error> {
    conn.complete_io(io).map(|_| ()).map_err(unpack_tls_error)
}

fn unpack_tls_error(e: std::io::Error) -> rustls::Error {
    if let Some(tls) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return tls.clone();
    }
    rustls::Error::General(format!("io: {e}"))
}
