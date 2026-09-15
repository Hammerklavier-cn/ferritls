//! QUIC 包保护端到端（M8.5）。
//!
//! 内存回环 QUIC 传输（common::quic）驱动 rustls `quic::Connection`
//! 的完整 TLS 1.3 握手：ferritls↔ferritls 三套件（每个握手覆盖
//! Initial/Handshake/1-RTT 三级密钥切换、ALPN、transport parameters、
//! export_keying_material、1-RTT 数据往返、篡改拒绝、密钥更新），
//! 以及 rustls-ring 交叉互操作（两个独立 provider 的 QUIC 包保护
//! 必须逐字节兼容——打破「自握手双方同错也对得上」的盲区）。
//!
//! CCM 套件不参与 QUIC（RFC 9001 §5.1 以 AES-GCM 为强制基准），
//! 仅含 CCM 的 provider 必须被 rustls 拒绝建立 QUIC 连接。

mod common;

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::ServerName;
use rustls::quic::{ClientConnection, Version};
use rustls::{CipherSuite, ClientConfig};

use common::client_config;
use common::quic::quic_handshake;
use common::{ferritls_pinned, ring_pinned};

/// 钉扎套件 + 保留 AES-128-GCM 作 Initial 包保护（RFC 9001 §5.2）。
fn pinned_with_initial(
    suite: rustls::SupportedCipherSuite,
    provider: CryptoProvider,
) -> CryptoProvider {
    let aes128 = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    let mut suites = vec![suite];
    if suite.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256 {
        suites.push(aes128);
    }
    CryptoProvider {
        cipher_suites: suites,
        ..provider
    }
}

fn ring_with_initial(suite: rustls::SupportedCipherSuite) -> CryptoProvider {
    let base = ring::default_provider();
    let aes128 = base
        .cipher_suites
        .iter()
        .find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)
        .copied()
        .expect("ring has aes128gcm");
    let mut suites = vec![suite];
    if suite.suite() != CipherSuite::TLS13_AES_128_GCM_SHA256 {
        suites.push(aes128);
    }
    CryptoProvider {
        cipher_suites: suites,
        ..base
    }
}

/// ferritls ↔ ferritls：三套件全握手矩阵。
#[test]
fn quic_handshake_ferritls_self_all_suites() {
    for suite in [
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(),
        ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(),
    ] {
        let mk = || pinned_with_initial(suite, ferritls_rustls::default_provider());
        quic_handshake(mk(), mk(), suite.suite());
    }
}

/// 交叉：ring 客户端 ↔ ferritls 服务端（AES-128-GCM）。
#[test]
fn quic_cross_ring_client_ferritls_server() {
    let suite = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    quic_handshake(
        ring_pinned(suite),
        pinned_with_initial(suite, ferritls_rustls::default_provider()),
        suite.suite(),
    );
}

/// 交叉：ferritls 客户端（ChaCha）↔ ring 服务端。
#[test]
fn quic_cross_ferritls_client_ring_server_chacha() {
    let suite = ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256();
    quic_handshake(
        pinned_with_initial(suite, ferritls_rustls::default_provider()),
        ring_with_initial(suite),
        suite.suite(),
    );
}

/// 仅含 CCM（无 QUIC 能力套件）的 provider 必须被拒绝建立 QUIC 连接。
#[test]
fn quic_rejects_quic_incapable_config() {
    let p = ferritls_pinned(
        ferritls_rustls::cipher::tls13_aes_128_ccm_sha256(),
        ferritls_rustls::kx::X25519_GROUP,
    );
    let cfg: ClientConfig = client_config(p);
    let r = ClientConnection::new(
        Arc::new(cfg),
        Version::V1,
        ServerName::try_from("localhost".to_string()).expect("name"),
        b"params".to_vec(),
    );
    assert!(r.is_err(), "CCM-only provider must not support QUIC");
}
