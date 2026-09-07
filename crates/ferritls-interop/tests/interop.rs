//! 互操作测试（M6/M7）。
//!
//! 两类矩阵：
//! 1. ferritls ↔ ferritls：全部套件 × 全部密钥交换组 + fips 批准模式矩阵；
//! 2. ferritls ↔ ring（M7）：以 rustls-ring 为独立参照实现做双向交叉
//!    （3 个共有套件 × 双方向），打破「自握手双方同错也对得上」的盲区——
//!    transcript 编码、记录层组帧、密钥分享解析任何一侧偏差都会被
//!    独立实现对端拒绝。ring 无 CCM，故 CCM 仅出现在矩阵 1。
//!
//! 证书链校验以 accept-all 验证器代替（rustls provider 测试惯例）；
//! webpki 真实全链校验见 webpki.rs。服务器证书：本地 openssl 生成的
//! 自签 P-256 证书（CN=localhost），密钥为 PKCS#8 EC。

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{CipherSuite, ClientConfig, ClientConnection, ServerConfig, ServerConnection};

const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmvMELbMpk80AriRp
9ziET+oQW/VEDoUDU0vOtNRL/nihRANCAAR5VqwUQcBLC/nJ3d0leiS05y0hOe0p
mw/TJE1qoN/vWDObPnA6i0KK4Px+D3bD/EyHiujuMZu9SPpjIu2iOIMZ
-----END PRIVATE KEY-----";
const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBpDCCAUmgAwIBAgIUIMpnrSkCuY/asPTMYZ0M3jATn9owCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwNzExMzc0NFoXDTQ2MDkwMjEx
Mzc0NFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEeVasFEHASwv5yd3dJXoktOctITntKZsP0yRNaqDf71gzmz5wOotCiuD8
fg92w/xMh4ro7jGbvUj6YyLtojiDGaN5MHcwHQYDVR0OBBYEFPMUyJHCqRFUWP8l
YiqYB5WYDxwJMB8GA1UdIwQYMBaAFPMUyJHCqRFUWP8lYiqYB5WYDxwJMA8GA1Ud
EwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMBQGA1UdEQQNMAuCCWxvY2FsaG9z
dDAKBggqhkjOPQQDAgNJADBGAiEAxMTCFdG5zEdRC7SiR6BsD1syeb1HqOWu5L4G
PYooUoQCIQDGzgE0BjOm/J0tYRP/VOq6Ci+thSSUMBBXu3pakHhj+A==
-----END CERTIFICATE-----";

#[derive(Debug)]
struct AcceptAll;

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

/// ferritls provider，钉扎到单个 (套件, 组)。
fn ferritls_pinned(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) -> CryptoProvider {
    let base = ferritls_rustls::default_provider();
    CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: vec![group],
        ..base
    }
}

/// ring provider，钉扎到单个套件（组用 ring 全集）。
fn ring_pinned(suite: rustls::SupportedCipherSuite) -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    CryptoProvider {
        cipher_suites: vec![suite],
        ..base
    }
}

fn server_config(provider: CryptoProvider) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certs: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes())?];
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes())?;
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}").into())
}

fn client_config(provider: CryptoProvider) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth()
}

/// 跑一次完整握手 + ping/pong；断言协商出的套件。
fn handshake_ping_pong(
    server_cfg: ServerConfig,
    client_cfg: ClientConfig,
    expect: CipherSuite,
) -> Result<String, Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");

    let server = std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send>> {
        let mut conn = ServerConnection::new(Arc::new(server_cfg))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        let mut server_io = server_io;
        let io_err = |e| Box::new(e) as Box<dyn std::error::Error + Send>;
        while conn.is_handshaking() {
            conn.complete_io(&mut server_io).map_err(io_err)?;
        }
        // 先读 ping 再回 pong（避免服务端先退出导致 RST 竞态）
        let mut got = 0;
        let mut buf = [0u8; 4];
        while got < 4 {
            match conn.reader().read(&mut buf[got..]) {
                Ok(0) => {
                    return Err(io_err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "eof",
                    )));
                }
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    conn.complete_io(&mut server_io).map_err(io_err)?;
                }
                Err(e) => {
                    eprintln!("SERVER ERR: {e:?}");
                    return Err(io_err(e));
                }
            }
        }
        assert_eq!(&buf, b"ping");
        retry_would_block(|| conn.writer().write_all(b"pong")).map_err(io_err)?;
        while conn.wants_write() {
            match conn.complete_io(&mut server_io) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => {
                    eprintln!("SERVER FLUSH ERR: {e:?}");
                    return Err(io_err(e));
                }
            }
        }
        Ok(())
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .map_err(|e| format!("client conn: {e}"))?;
    let mut client_io = client_io;
    while conn.is_handshaking() {
        match conn.complete_io(&mut client_io) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let negotiated = conn.negotiated_cipher_suite().expect("negotiated");
    assert_eq!(negotiated.suite(), expect, "negotiated suite");

    retry_would_block(|| conn.writer().write_all(b"ping"))?;
    while conn.wants_write() {
        match conn.complete_io(&mut client_io) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    // reader() 不驱动连接：以 complete_io 拉取新记录
    let mut got = 0;
    let mut buf = [0u8; 4];
    while got < 4 {
        match conn.reader().read(&mut buf[got..]) {
            Ok(0) => return Err("eof".into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.complete_io(&mut client_io)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    // 服务器线程的 Err 必须传播（此前被静默丢弃掩盖了真实失败）
    match server.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("server thread: {e}").into()),
        Err(e) => return Err(format!("server thread panicked: {e:?}").into()),
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// 以限定 (套件, 组) 的 ferritls provider 跑完整握手。
fn run_handshake(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) -> Result<String, Box<dyn std::error::Error>> {
    let mk = || ferritls_pinned(suite, group);
    handshake_ping_pong(server_config(mk())?, client_config(mk()), suite.suite())
}

/// rustls 在等待对端数据/套接字就绪时会合法返回 WouldBlock；
/// 对阻塞套接字以 1ms 退避重试（上限 30s 防止测试挂死）。
fn retry_would_block<T, F: FnMut() -> std::io::Result<T>>(mut f: F) -> std::io::Result<T> {
    let mut waited = 0u32;
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(waited < 30_000, "timeout waiting for peer");
                std::thread::sleep(std::time::Duration::from_millis(1));
                waited += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

fn assert_handshake(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) {
    run_handshake(suite, group).unwrap_or_else(|e| panic!("handshake failed: {e}"));
}

// ---------- 矩阵 1：ferritls ↔ ferritls ----------

#[test]
fn ping_pong_aes128gcm_x25519() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ping_pong_aes256gcm_x25519() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ping_pong_chacha_x25519() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ping_pong_ccm_x25519() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_ccm_sha256(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ping_pong_aes128gcm_p256() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::SECP256R1_GROUP,
    );
}

#[test]
fn ping_pong_aes128gcm_p384() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::SECP384R1_GROUP,
    );
}

/// fips_mode_provider 矩阵（批准套件 × 批准组）。
#[test]
fn fips_mode_matrix() {
    for suite in ferritls_rustls::cipher::fips_tls13_suites() {
        for group in ferritls_rustls::kx::FIPS_KX_GROUPS {
            assert_handshake(suite, *group);
        }
    }
}

// ---------- 矩阵 2：ferritls ↔ ring（M7） ----------

/// 双向交叉：一个 provider 作客户端、另一个作服务端，双方钉扎同一套件。
fn cross_handshake(client: CryptoProvider, server: CryptoProvider, expect: CipherSuite) {
    handshake_ping_pong(
        server_config(server).unwrap_or_else(|e| panic!("server config: {e}")),
        client_config(client),
        expect,
    )
    .unwrap_or_else(|e| panic!("handshake failed: {e}"));
}

#[test]
fn ring_client_ferritls_server_aes128gcm() {
    let s = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    cross_handshake(
        ring_pinned(s),
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        s.suite(),
    );
}

#[test]
fn ring_client_ferritls_server_aes256gcm() {
    let s = ferritls_rustls::cipher::tls13_aes_256_gcm_sha384();
    cross_handshake(
        ring_pinned(s),
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        s.suite(),
    );
}

#[test]
fn ring_client_ferritls_server_chacha() {
    let s = ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256();
    cross_handshake(
        ring_pinned(s),
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        s.suite(),
    );
}

#[test]
fn ferritls_client_ring_server_aes128gcm() {
    let s = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    cross_handshake(
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        ring_pinned(s),
        s.suite(),
    );
}

#[test]
fn ferritls_client_ring_server_aes256gcm() {
    let s = ferritls_rustls::cipher::tls13_aes_256_gcm_sha384();
    cross_handshake(
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        ring_pinned(s),
        s.suite(),
    );
}

#[test]
fn ferritls_client_ring_server_chacha() {
    let s = ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256();
    cross_handshake(
        ferritls_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        ring_pinned(s),
        s.suite(),
    );
}
