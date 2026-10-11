//! 互操作测试共享助手（每个集成测试通过 `mod common;` 引入）。
//!
//! 仅测试基础设施：证书、AcceptAll 验证器、provider 钉扎、TCP 握手
//! 驱动、QUIC 内存回环。真正的密码学实现绝不出现在 tests/ 下。

#![allow(dead_code)]

pub mod quic;

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
pub fn ferritls_pinned(
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
pub fn ring_pinned(suite: rustls::SupportedCipherSuite) -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    CryptoProvider {
        cipher_suites: vec![suite],
        ..base
    }
}

pub fn server_config(provider: CryptoProvider) -> Result<ServerConfig, Box<dyn std::error::Error>> {
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

/// 带客户端认证的服务端配置：客户端证书由调用方提供的验证器校验
/// （`WebPkiClientVerifier::builder_with_provider(roots, provider)`，
/// 验证算法面取自 ferritls provider）。
pub fn server_config_with_client_auth(
    provider: CryptoProvider,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certs: Vec<CertificateDer<'static>> =
        vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes())?];
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes())?;
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("server config: {e}").into())
}

/// tests/certs/ 下的证书文件（PemObject 解析）。
pub fn cert_from_certs_dir(name: &str) -> CertificateDer<'static> {
    let path = format!("{}/tests/certs/{name}", env!("CARGO_MANIFEST_DIR"));
    CertificateDer::from_pem_file(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// tests/certs/ 下的私钥文件（PKCS#8 DER）。
pub fn key_from_certs_dir(name: &str) -> PrivateKeyDer<'static> {
    let path = format!("{}/tests/certs/{name}", env!("CARGO_MANIFEST_DIR"));
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    PrivateKeyDer::Pkcs8(der.into())
}

/// 携带客户端证书的客户端配置（密钥经 provider 的 KeyProvider 加载）。
pub fn client_config_with_certs(
    provider: CryptoProvider,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_client_auth_cert(chain, key)
        .expect("client auth cert")
}

pub fn client_config(provider: CryptoProvider) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth()
}

/// 跑一次完整握手 + ping/pong；断言协商出的套件。
pub fn handshake_ping_pong(
    server_cfg: ServerConfig,
    client_cfg: ClientConfig,
    expect: CipherSuite,
) -> Result<String, Box<dyn std::error::Error>> {
    handshake_ping_pong_with(server_cfg, client_cfg, expect, |_| {}, |_| {})
}

/// 同上，但两侧握手完成后先分别执行回调（用于断言 `peer_certificates`、
/// `handshake_kind` 等观察点），再进入 ping/pong。
pub fn handshake_ping_pong_with(
    server_cfg: ServerConfig,
    client_cfg: ClientConfig,
    expect: CipherSuite,
    on_server_handshake_done: impl FnOnce(&mut ServerConnection) + Send + 'static,
    on_client_handshake_done: impl FnOnce(&mut ClientConnection),
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
        on_server_handshake_done(&mut conn);
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

    on_client_handshake_done(&mut conn);

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
pub fn run_handshake(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) -> Result<String, Box<dyn std::error::Error>> {
    let mk = || ferritls_pinned(suite, group);
    handshake_ping_pong(server_config(mk())?, client_config(mk()), suite.suite())
}

/// rustls 在等待对端数据/套接字就绪时会合法返回 WouldBlock；
/// 对阻塞套接字以 1ms 退避重试（上限 30s 防止测试挂死）。
pub fn retry_would_block<T, F: FnMut() -> std::io::Result<T>>(mut f: F) -> std::io::Result<T> {
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

/// 推进客户端一次 complete_io。complete_io 把 TLS 层错误包成
/// InvalidData 的 io::Error——源错误经 downcast 还原，alert 语义
/// （如 `Error::AlertReceived`）才能被负例断言识别。
pub fn drive_client(
    conn: &mut ClientConnection,
    io: &mut (impl std::io::Read + std::io::Write),
) -> Result<(), rustls::Error> {
    conn.complete_io(io).map(|_| ()).map_err(unpack_tls_error)
}

/// 同 [`drive_client`]，服务端侧。
pub fn drive_server(
    conn: &mut ServerConnection,
    io: &mut (impl std::io::Read + std::io::Write),
) -> Result<(), rustls::Error> {
    conn.complete_io(io).map(|_| ()).map_err(unpack_tls_error)
}

/// 还原 complete_io 包装的 rustls 错误（非 TLS 错误归一为 General）。
pub fn unpack_tls_error(e: std::io::Error) -> rustls::Error {
    if let Some(tls) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        return tls.clone();
    }
    rustls::Error::General(format!("io: {e}"))
}

/// 从 rustls reader 读满 `buf`（解密后的流没有消息边界；
/// WouldBlock 时以 complete_io 拉取新记录）。
fn read_exact_tls(
    conn: &mut ServerConnection,
    io: &mut std::net::TcpStream,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error + Send>> {
    let io_err = |e| Box::new(e) as Box<dyn std::error::Error + Send>;
    let mut got = 0;
    while got < buf.len() {
        match conn.reader().read(&mut buf[got..]) {
            Ok(0) => {
                return Err(io_err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "eof",
                )));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.complete_io(io).map_err(io_err)?;
            }
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(())
}

/// 完整握手后传输任意长度负载：客户端发 `payload`，服务端读全并回显，
/// 客户端读回比对。超过单条记录容量（16384 B）时由 rustls 分片——
/// 用于 16 KiB 满记录与 `max_fragment_size` 强制多片传输。
pub fn transfer_roundtrip(
    server_cfg: ServerConfig,
    client_cfg: ClientConfig,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");

    let expected = payload.to_vec();
    let server = std::thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send>> {
        let mut conn = ServerConnection::new(Arc::new(server_cfg))
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send>)?;
        let mut server_io = server_io;
        let io_err = |e| Box::new(e) as Box<dyn std::error::Error + Send>;
        while conn.is_handshaking() {
            conn.complete_io(&mut server_io).map_err(io_err)?;
        }
        let mut received = vec![0u8; expected.len()];
        read_exact_tls(&mut conn, &mut server_io, &mut received)?;
        assert_eq!(received, expected, "server received altered payload");
        retry_would_block(|| conn.writer().write_all(&expected)).map_err(io_err)?;
        while conn.wants_write() {
            match conn.complete_io(&mut server_io) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => return Err(io_err(e)),
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
    retry_would_block(|| conn.writer().write_all(payload))?;
    while conn.wants_write() {
        match conn.complete_io(&mut client_io) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let mut echoed = vec![0u8; payload.len()];
    {
        let mut got = 0;
        while got < echoed.len() {
            match conn.reader().read(&mut echoed[got..]) {
                Ok(0) => return Err("eof".into()),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    conn.complete_io(&mut client_io)?;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
    assert_eq!(echoed, payload, "echo roundtrip mismatch");
    match server.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(format!("server thread: {e}").into()),
        Err(e) => Err(format!("server thread panicked: {e:?}").into()),
    }
}

pub fn assert_handshake(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) {
    run_handshake(suite, group).unwrap_or_else(|e| panic!("handshake failed: {e}"));
}

/// 双向交叉：一个 provider 作客户端、另一个作服务端，双方钉扎同一套件。
pub fn cross_handshake(client: CryptoProvider, server: CryptoProvider, expect: CipherSuite) {
    handshake_ping_pong(
        server_config(server).unwrap_or_else(|e| panic!("server config: {e}")),
        client_config(client),
        expect,
    )
    .unwrap_or_else(|e| panic!("handshake failed: {e}"));
}
