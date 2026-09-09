//! TLS 1.3 内存全握手基准：ferritls ↔ ferritls（X25519 / P-256，
//! AES-128-GCM）与 ring ↔ ring 同套件基线对照。
//!
//! 用进程内 duplex 管道替代 TCP 回环（排除调度/线程噪声），单线程交替
//! 驱动 client/server 的 `complete_io`；每次迭代 = 一次完整握手（双方
//! 全部密码学计算 + 记录层组帧）。AcceptAll 验证器与自签测试证书沿用
//! `tests/interop.rs` 的惯例（证书见该文件说明）。
//!
//! 运行：`cargo bench -p ferritls-interop --bench handshake`。

use std::io::{ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{
    CipherSuite, ClientConfig, ClientConnection, NamedGroup, ServerConfig, ServerConnection,
};

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
        vec![rustls::SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// duplex 管道的一端：`rx` 为对端写入的缓冲，`tx` 写入对端可读的缓冲。
struct PipeEnd {
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
fn pipe_pair() -> (PipeEnd, PipeEnd) {
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
fn pinned_provider(mut base: CryptoProvider, group: NamedGroup) -> CryptoProvider {
    base.cipher_suites
        .retain(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256);
    base.kx_groups.retain(|g| g.name() == group);
    assert_eq!(base.cipher_suites.len(), 1, "suite pinning");
    assert_eq!(base.kx_groups.len(), 1, "group pinning");
    base
}

fn server_config(provider: CryptoProvider) -> ServerConfig {
    let certs = vec![CertificateDer::from_pem_slice(SERVER_CERT_PEM.as_bytes()).expect("cert")];
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes()).expect("key");
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert")
}

fn client_config(provider: CryptoProvider) -> ClientConfig {
    ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll))
        .with_no_client_auth()
}

/// 驱动一次完整握手至双方均退出 handshaking。
fn full_handshake(
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

/// 基准用例：(名称, 基础 provider 构造器, 钉扎的密钥交换组)。
type Case = (&'static str, fn() -> CryptoProvider, NamedGroup);

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.throughput(Throughput::Elements(1));

    let name = ServerName::try_from("localhost".to_string()).expect("server name");

    let cases: &[Case] = &[
        (
            "ferritls-x25519",
            ferritls_rustls::default_provider,
            NamedGroup::X25519,
        ),
        (
            "ferritls-p256",
            ferritls_rustls::default_provider,
            NamedGroup::secp256r1,
        ),
        (
            "ring-baseline-x25519",
            rustls::crypto::ring::default_provider,
            NamedGroup::X25519,
        ),
    ];

    for (case_name, provider_fn, kx) in cases {
        let provider = pinned_provider(provider_fn(), *kx);
        let server_cfg = Arc::new(server_config(provider.clone()));
        let client_cfg = Arc::new(client_config(provider));
        full_handshake(&client_cfg, &server_cfg, &name);
        group.bench_function(*case_name, |b| {
            b.iter(|| full_handshake(&client_cfg, &server_cfg, &name))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
