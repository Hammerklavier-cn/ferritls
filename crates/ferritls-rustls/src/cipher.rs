//! TLS 1.3 密码套件装配（M2/M6）。
//!
//! `Tls13CipherSuite` 的静态表在 M6 用真实的
//! `hash_provider`/`hkdf_provider`/`aead_alg` 实现填充（HKDF 复用
//! rustls 内建 `HkdfUsingHmac` + 我们包装的 Hmac；见 ARCHITECTURE.md）。
//! 骨架期以函数形态锁定套件清单。
//!
//! 注意：`quic` 字段为 `None` = 本套件不参与 QUIC 握手（QUIC packet
//! protection 是 M8+ 项）。

use rustls::SupportedCipherSuite;

/// 套件清单（顺序即偏好）。同时被 `tests/api.rs` 断言，防止清单与
/// 文档漂移。
pub const TLS13_SUITE_NAMES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
];

/// `TLS_AES_128_GCM_SHA256`（批准）。
pub fn tls13_aes_128_gcm_sha256() -> SupportedCipherSuite {
    todo!("M2/M6")
}

/// `TLS_AES_256_GCM_SHA384`（批准）。
pub fn tls13_aes_256_gcm_sha384() -> SupportedCipherSuite {
    todo!("M2/M6")
}

/// `TLS_CHACHA20_POLY1305_SHA256`（非批准，仅默认模式）。
pub fn tls13_chacha20_poly1305_sha256() -> SupportedCipherSuite {
    todo!("M2/M6")
}

/// `TLS_AES_128_CCM_SHA256`（批准，SP 800-52r2 面向受限环境）。
pub fn tls13_aes_128_ccm_sha256() -> SupportedCipherSuite {
    todo!("M2/M6")
}

/// 默认模式全部套件（偏好序）。
pub fn all_tls13_suites() -> Vec<SupportedCipherSuite> {
    todo!("M6")
}

/// 批准模式套件（无 ChaCha20-Poly1305）。
pub fn fips_tls13_suites() -> Vec<SupportedCipherSuite> {
    todo!("M7")
}
