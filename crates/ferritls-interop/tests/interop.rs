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

mod common;

use common::{assert_handshake, cross_handshake, ferritls_pinned, ring_pinned};

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
