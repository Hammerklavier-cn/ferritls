//! 握手基准共享助手（`mod support;` 引入）。
//!
//! 进程内 duplex 管道、AcceptAll 验证器、自签测试证书与 provider 钉扎。
//! 证书见 `tests/interop.rs` 说明（本地 openssl 生成，仅测试用）。

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, NamedGroup, ServerConfig, ServerConnection,
};

pub const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmvMELbMpk80AriRp
9ziET+oQW/VEDoUDU0vOtNRL/nihRANCAAR5VqwUQcBLC/nJ3d0leiS05y0hOe0p
mw/TJE1qoN/vWDObPnA6i0KK4Px+D3bD/EyHiujuMZu9SPpjIu2iOIMZ
-----END PRIVATE KEY-----";
pub const SERVER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
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
pub struct AcceptAll;

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
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// duplex 管道的一端：`rx` 为对端写入的缓冲，`tx` 写入对端可读的缓冲。
pub struct PipeEnd {
    rx: Arc<Mutex<Vec<u8>>>,
    tx: Arc<Mutex<Vec<u8>>>,
}

impl Read for PipeEnd {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut rx = self.rx.lock().unwrap();
        if rx.is_empty() {
            return Err(std::io::Error::new(ErrorKind::WouldBlock, "pipe empty"));
        }
        let n = out.len().min(rx.len());
        out[..n].copy_from_slice(&rx[..n]);
        rx.drain(..n);
        Ok(n)
    }
}

impl Write for PipeEnd {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.tx.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 建一对连通的管道端点。
pub fn pipe_pair() -> (PipeEnd, PipeEnd) {
    let a = Arc::new(Mutex::new(Vec::new()));
    let b = Arc::new(Mutex::new(Vec::new()));
    (
        PipeEnd {
            rx: Arc::clone(&b),
            tx: Arc::clone(&a),
        },
        PipeEnd { rx: a, tx: b },
    )
}

/// 从 provider 的套件/组列表里按标识取一个（基准钉扎用）。
pub fn pinned_provider(mut base: CryptoProvider, group: NamedGroup) -> CryptoProvider {
    base.cipher_suites
        .retain(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
    base.kx_groups.retain(|g| g.name() == group);
    assert_eq!(base.cipher_suites.len(), 1, "suite pinning");
    assert_eq!(base.kx_groups.len(), 1, "group pinning");
    base
}

pub fn server_config(provider: CryptoProvider) -> ServerConfig {
    let certs = vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes()).expect("cert")];
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes()).expect("key");
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert")
}

pub fn client_config(provider: CryptoProvider) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth()
}

/// 驱动一次完整握手至双方均退出 handshaking。
pub fn full_handshake(
    client_cfg: &Arc<ClientConfig>,
    server_cfg: &Arc<ServerConfig>,
    name: &ServerName<'static>,
) {
    let mut client =
        ClientConnection::new(Arc::clone(client_cfg), name.clone()).expect("client conn");
    let mut server = ServerConnection::new(Arc::clone(server_cfg)).expect("server conn");
    let (mut c_io, mut s_io) = pipe_pair();

    while client.is_handshaking() || server.is_handshaking() {
        let mut progress = false;
        if client.is_handshaking() {
            match client.complete_io(&mut c_io) {
                Ok(_) => progress = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("client io: {e}"),
            }
        }
        if server.is_handshaking() {
            match server.complete_io(&mut s_io) {
                Ok(_) => progress = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("server io: {e}"),
            }
        }
        assert!(
            progress || (!client.is_handshaking() && !server.is_handshaking()),
            "handshake stalled"
        );
    }
}
