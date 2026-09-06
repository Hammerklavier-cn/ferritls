//! HKDF（RFC 5869），基于 [`crate::hmac`]。
//!
//! FIPS 批准（模块内按 SP 800-56C/108 相关注册，见 docs/FIPS.md）。
//! TLS 1.3 的密钥调度（extract/expand/derive-secret）由 rustls 内建的
//! `HkdfUsingHmac` 辅助器驱动，适配层把 [`HmacSha256`]/[`HmacSha384`]
//! 包装成 `rustls::crypto::hmac::Hmac` 即可，无需在边界内重复实现调度逻辑。
//!
//! 里程碑：M1。向量：RFC 5869 Test Case 1–3（`tests/hkdf.rs` 已预置）。

/// HKDF-Extract（SHA-256）：IKM + salt → PRK（32 字节）。
///
/// `salt` 可为空（按 RFC 5869 以 `HashLen` 个零字节处理）。
pub fn extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let _ = (salt, ikm);
    todo!("M1")
}

/// HKDF-Expand（SHA-256）：PRK + info → OKM（长度 = `okm.len()`，≤ 255×32）。
pub fn expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let _ = (prk, info, okm);
    todo!("M1")
}

/// HKDF-Extract（SHA-384）：IKM + salt → PRK（48 字节）。
pub fn extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let _ = (salt, ikm);
    todo!("M1")
}

/// HKDF-Expand（SHA-384）：PRK + info → OKM（长度 = `okm.len()`，≤ 255×48）。
pub fn expand_sha384(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let _ = (prk, info, okm);
    todo!("M1")
}
