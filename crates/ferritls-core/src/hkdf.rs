//! HKDF（RFC 5869），基于 [`crate::hmac`]。
//!
//! FIPS 批准（模块内按 SP 800-56C/108 相关注册，见 docs/FIPS.md）。
//! TLS 1.3 的密钥调度由 rustls 内建的 `HkdfUsingHmac` 辅助器驱动，
//! 适配层把 [`HmacSha256`]/[`HmacSha384`] 包装成 `rustls::crypto::hmac::Hmac`
//! 即可，无需在边界内重复实现调度逻辑。
//!
//! 向量：RFC 5869 Test Case 1–3（`tests/hkdf.rs`）。

use crate::hmac::{HmacSha256, HmacSha384};

/// HKDF-Extract（SHA-256）：IKM + salt → PRK（32 字节）。
///
/// `salt` 为空时按 RFC 5869 以 `HashLen` 个零字节处理。
pub fn extract_sha256(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let s: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    HmacSha256::one_shot(s, ikm)
}

/// HKDF-Expand（SHA-256）：PRK + info → OKM（写入 `okm`，长度 ≤ 255×32）。
pub fn expand_sha256(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut t = [0u8; 32];
    expand_generic::<32, _>(HmacSha256::one_shot, prk, info, &mut t, okm);
}

/// HKDF-Extract（SHA-384）：IKM + salt → PRK（48 字节）。
pub fn extract_sha384(salt: &[u8], ikm: &[u8]) -> [u8; 48] {
    let s: &[u8] = if salt.is_empty() { &[0u8; 48] } else { salt };
    HmacSha384::one_shot(s, ikm)
}

/// HKDF-Expand（SHA-384）：PRK + info → OKM（写入 `okm`，长度 ≤ 255×48）。
pub fn expand_sha384(prk: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut t = [0u8; 48];
    expand_generic::<48, _>(HmacSha384::one_shot, prk, info, &mut t, okm);
}

fn expand_generic<const L: usize, F>(
    hmac: F,
    prk: &[u8],
    info: &[u8],
    t: &mut [u8; L],
    okm: &mut [u8],
) where
    F: Fn(&[u8], &[u8]) -> [u8; L],
{
    let mut t_len = 0usize;
    let mut counter = 1u8;
    let mut done = 0usize;
    while done < okm.len() {
        let mut input = Vec::with_capacity(t_len + info.len() + 1);
        input.extend_from_slice(&t[..t_len]);
        input.extend_from_slice(info);
        input.push(counter);
        *t = hmac(prk, &input);
        t_len = L;
        let n = (okm.len() - done).min(L);
        okm[done..done + n].copy_from_slice(&t[..n]);
        done += n;
        counter = counter.wrapping_add(1);
    }
    t.fill(0);
}
