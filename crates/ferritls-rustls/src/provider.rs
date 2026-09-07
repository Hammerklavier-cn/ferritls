//! `CryptoProvider` 装配（M6）。
//!
//! rustls 0.23.43 的 `CryptoProvider` 共 **5 个字段**：
//! `cipher_suites` / `kx_groups` / `signature_verification_algorithms` /
//! `secure_random` / `key_provider`。本模块从 [`cipher`]、[`kx`]、
//! [`verify`]、[`random`]、[`sign`] 的静态表组装两个出厂配置。

use rustls::crypto::CryptoProvider;

/// 默认 provider（非批准模式）：全部 TLS 1.3 套件、三组密钥交换、
/// 全部验证算法、OS 熵直读。
///
/// `fips()` 返回 `false`（见 lib.rs“fips() 语义”）。
pub fn default_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: crate::cipher::all_tls13_suites(),
        kx_groups: crate::kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: crate::verify::SUPPORTED_ALGORITHMS,
        secure_random: crate::random::SYSTEM_RANDOM,
        key_provider: crate::sign::KEY_LOADER,
    }
}

/// 批准模式 provider：仅 FIPS 批准套件/组/算法（AES-GCM/CCM、P-256/384、
/// RSA、ECDSA）+ CTR-DRBG 随机源 + 上电自检路径。
///
/// `fips()` 仍返回 `false`——它描述的是“按 FIPS 批准模式运行的配置”，
/// 不是 CMVP 认证声明。
pub fn fips_mode_provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: crate::cipher::fips_tls13_suites(),
        kx_groups: crate::kx::FIPS_KX_GROUPS.to_vec(),
        signature_verification_algorithms: crate::verify::FIPS_SUPPORTED_ALGORITHMS,
        secure_random: crate::random::FIPS_RANDOM,
        key_provider: crate::sign::KEY_LOADER,
    }
}
