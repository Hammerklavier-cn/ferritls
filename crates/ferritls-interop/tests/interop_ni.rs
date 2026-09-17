//! AES-NI 后端安装后的三方互操作矩阵（M8.1）。
//!
//! **独立测试二进制**：`install()` 是进程级且不可撤销的——本文件与
//! `interop.rs` 分离，保证后者的矩阵始终运行在软件默认路径上。安装后
//! ferritls 侧的 AES-GCM 执行核心为 AES-NI/CLMUL，交叉对象不变：
//!
//! 1. ferritls(Ni) ↔ ferritls(Ni)：批准套件 × X25519/P-256；
//! 2. ring ↔ ferritls(Ni) 与 ferritls(Ni) ↔ ring：打破自握手盲区的
//!    交叉矩阵在硬件路径上重复（记录层密文由 Ni 产出、ring 验证，
//!    反之亦然——等价于对 Ni 密码学正确性的独立实现裁决）。
//!
//! CPU 不支持时 `install()` 失败，测试打印后跳过；CCM/ChaCha 不经
//! AES 路径，不在本矩阵重复（软件路径已由 interop.rs 覆盖）。

#![cfg(target_arch = "x86_64")]

mod common;

use common::{assert_handshake, cross_handshake, ferritls_pinned, ring_pinned};
use rustls::crypto::CryptoProvider;

fn setup() -> bool {
    match ferritls_backend_x86_64::install() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("aesni backend unavailable ({e:?}); skipping Ni interop matrix");
            false
        }
    }
}

// ---------- ferritls(Ni) ↔ ferritls(Ni) ----------

#[test]
fn ni_ping_pong_aes128gcm_x25519() {
    if !setup() {
        return;
    }
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ni_ping_pong_aes128gcm_p256() {
    if !setup() {
        return;
    }
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        ferritls_rustls::kx::SECP256R1_GROUP,
    );
}

#[test]
fn ni_ping_pong_aes256gcm_x25519() {
    if !setup() {
        return;
    }
    assert_handshake(
        ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(),
        ferritls_rustls::kx::X25519_GROUP,
    );
}

#[test]
fn ni_fips_mode_matrix() {
    if !setup() {
        return;
    }
    for suite in ferritls_rustls::cipher::fips_tls13_suites() {
        for group in ferritls_rustls::kx::FIPS_KX_GROUPS {
            assert_handshake(suite, *group);
        }
    }
}

// ---------- ring ↔ ferritls(Ni) 双向交叉 ----------

fn ferritls_ni_pinned(
    suite: rustls::SupportedCipherSuite,
    group: &'static dyn rustls::crypto::SupportedKxGroup,
) -> CryptoProvider {
    // install 已由 setup() 完成；此处 provider 构造经 core 公开 API
    // 取到 Ni 执行核心。
    ferritls_pinned(suite, group)
}

#[test]
fn ni_ring_client_ferritls_server_aes128gcm() {
    if !setup() {
        return;
    }
    let s = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    cross_handshake(
        ring_pinned(s),
        ferritls_ni_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        s.suite(),
    );
}

#[test]
fn ni_ring_client_ferritls_server_aes256gcm() {
    if !setup() {
        return;
    }
    let s = ferritls_rustls::cipher::tls13_aes_256_gcm_sha384();
    cross_handshake(
        ring_pinned(s),
        ferritls_ni_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        s.suite(),
    );
}

#[test]
fn ni_ferritls_client_ring_server_aes128gcm() {
    if !setup() {
        return;
    }
    let s = ferritls_rustls::cipher::tls13_aes_128_gcm_sha256();
    cross_handshake(
        ferritls_ni_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        ring_pinned(s),
        s.suite(),
    );
}

#[test]
fn ni_ferritls_client_ring_server_aes256gcm() {
    if !setup() {
        return;
    }
    let s = ferritls_rustls::cipher::tls13_aes_256_gcm_sha384();
    cross_handshake(
        ferritls_ni_pinned(s, ferritls_rustls::kx::X25519_GROUP),
        ring_pinned(s),
        s.suite(),
    );
}
