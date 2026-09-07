//! 互操作测试（M6）：ferritls ↔ ferritls 完整 TLS 1.3 握手。
//!
//! 覆盖：全部套件 × 全部密钥交换组的内存内（duplex）双向握手与数据
//! 交换。证书链校验以 accept-all 验证器代替（rustls provider 测试的
//! 惯例；签名验证路径由 verify.rs 的核心向量测试覆盖），webpki 全链
//! 校验在 M7 以 dev-dep 形式补足。
//!
//! 服务器证书：本地 openssl 生成的自签 P-256 证书（CN=localhost），
//! 密钥为 PKCS#8 EC——同时覆盖 KeyLoader 的 EC 路径。

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::SupportedCipherSuite;
use rustls::{ClientConnection, ServerConnection};

const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgB42pC/S7GyVC6ZOV
bxaAA+nc1YGUaOx1E7Jle2rXRVWhRANCAAQjTtSngN4klreQ3bP8uXi+ZFCWzyFr
4SdGAUsoWsLbO7ekhaji0vyiADzUWFl2bVoxUMFaPHTosnMEdG50nnI4
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUGWpypHr9AX0JNLaOXaV0pykcUjgwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwNzA4MzUwOFoXDTM2MDkwNDA4
MzUwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEI07Up4DeJJa3kN2z/Ll4vmRQls8ha+EnRgFLKFrC2zu3pIWo4tL8ogA8
1FhZdm1aMVDBWjx06LJzBHRudJ5yOKNTMFEwHQYDVR0OBBYEFKaX9GcSMd7UNhuM
+ofsBQoJPRcAMB8GA1UdIwQYMBaAFKaX9GcSMd7UNhuM+ofsBQoJPRcAMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIPTkcBy9qtsH8G8JEXRiiWk
ZcpO58+Q5FghEQZX9cERAiAB0PEVvG5b92e6PTtA1QkHtGKTOU48oLZ2qgmy+Eix
yw==
-----END CERTIFICATE-----";
const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBfTCCASOgAwIBAgIUGWpypHr9AX0JNLaOXaV0pykcUjgwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDkwNzA4MzUwOFoXDTM2MDkwNDA4
MzUwOFowFDESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEI07Up4DeJJa3kN2z/Ll4vmRQls8ha+EnRgFLKFrC2zu3pIWo4tL8ogA8
1FhZdm1aMVDBWjx06LJzBHRudJ5yOKNTMFEwHQYDVR0OBBYEFKaX9GcSMd7UNhuM
+ofsBQoJPRcAMB8GA1UdIwQYMBaAFKaX9GcSMd7UNhuM+ofsBQoJPRcAMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAIPTkcBy9qtsH8G8JEXRiiWk
ZcpO58+Q5FghEQZX9cERAiAB0PEVvG5b92e6PTtA1QkHtGKTOU48oLZ2qgmy+Eix
yw==
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

/// 以限定 (套件, 组) 的 provider 跑一次完整握手 + ping/pong。
fn run_handshake(
    suite: SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) -> Result<String, Box<dyn std::error::Error>> {
    let base = ferritls_rustls::default_provider();
    let mk = || CryptoProvider {
        cipher_suites: vec![suite],
        kx_groups: vec![group],
        signature_verification_algorithms: base.signature_verification_algorithms,
        secure_random: base.secure_random,
        key_provider: base.key_provider,
    };

    let certs: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes())?];
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes())?;

    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(mk()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}"))?;

    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(mk()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth();

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
                    )))
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
    assert_eq!(negotiated.suite(), suite.suite(), "negotiated suite");

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
    server.join().map_err(|e| format!("server thread: {e:?}"))?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
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
    suite: SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) {
    run_handshake(suite, group).unwrap_or_else(|e| panic!("handshake failed: {e}"));
}

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
