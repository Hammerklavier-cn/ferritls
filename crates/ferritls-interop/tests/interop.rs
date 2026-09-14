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

/// X25519MLKEM768 混合组（M8.3）：自互操作（client=解封装方、
/// server=封装方，同 provider）；ring 无 ML-KEM，交叉矩阵不适用。
#[test]
fn ping_pong_aes128gcm_x25519_mlkem768() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::X25519MLKEM768_GROUP,
    );
}

#[test]
fn ping_pong_aes256gcm_x25519_mlkem768() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(),
        ferritls_rustls::kx::X25519MLKEM768_GROUP,
    );
}

/// 纯 ML-KEM 组（M8.4，0x0200–0x0202）：自互操作（client=解封装方、
/// server=封装方，同 provider）；ring 无纯 ML-KEM，交叉矩阵不适用。
#[test]
fn ping_pong_aes128gcm_mlkem512() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::MLKEM512_GROUP,
    );
}

#[test]
fn ping_pong_aes128gcm_mlkem768() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::MLKEM768_GROUP,
    );
}

#[test]
fn ping_pong_aes128gcm_mlkem1024() {
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::MLKEM1024_GROUP,
    );
}

/// fips_mode_provider 矩阵（批准套件 × 批准组，M8.3 起含混合组，
/// M8.4 起含纯 ML-KEM 三组：3 套件 × 6 组）。
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
