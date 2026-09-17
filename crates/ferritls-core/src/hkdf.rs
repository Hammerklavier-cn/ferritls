//! HKDF（RFC 5869），基于 [`crate::hmac`]。
//!
//! FIPS 批准（模块内按 SP 800-56C/108 相关注册，见 docs/FIPS.md）。
//! TLS 1.3 的密钥调度由 rustls 内建的 `HkdfUsingHmac` 辅助器驱动，
//! 适配层把 [`HmacSha256`]/[`HmacSha384`] 包装成 `rustls::crypto::hmac::Hmac`
//! 即可，无需在边界内重复实现调度逻辑。
//!
//! 公开 API 按 hash 家族化：Extract/Expand 各三个函数
//! （SHA-256/384/512）。SHA-512 无 TLS 消费者（TLS 1.3 套件只用
//! SHA-256/384），属边界内公开 API 的家族补全；RFC 5869 的全部逻辑
//! （零盐、255 块上限、T 链）由内部 `expand_generic` 统一承载，
//! 实例只注入 hash 类型与 HashLen。
//!
//! 向量：RFC 5869 Test Case 1–3（SHA-256，`tests/hkdf.rs`）；
//! SHA-384/512 期望值由双参照链生成互验（纯 python RFC 5869 参照 +
//! python-cryptography/OpenSSL 后端，2026-09-17）。

use crate::hmac::{HmacSha256, HmacSha384, HmacSha512};

/// 生成一对 HKDF Extract/Expand 公开函数。
macro_rules! hkdf_impl {
    ($extract:ident, $expand:ident, $hmac:ident, $len:expr, $name:expr) => {
        #[doc = concat!(
            "HKDF-Extract（", $name, "）：IKM + salt → PRK（`[u8; ", stringify!($len), "]`）。",
            "\n\n`salt` 为空时按 RFC 5869 以 `HashLen` 个零字节处理。"
        )]
        pub fn $extract(salt: &[u8], ikm: &[u8]) -> [u8; $len] {
            let s: &[u8] = if salt.is_empty() { &[0u8; $len] } else { salt };
            $hmac::one_shot(s, ikm)
        }

        #[doc = concat!(
            "HKDF-Expand（", $name, "）：PRK + info → OKM（写入 `okm`）。",
            "\n\nRFC 5869 §2.3：OKM 长度不得超过 255×", stringify!($len),
            " 字节，超限返回 [`Error::InvalidInput`](crate::Error)——",
            "Expand 计数器只有 8 位，绝不能回绕后产出错误密钥材料。"
        )]
        pub fn $expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), crate::Error> {
            if okm.len() > 255 * $len {
                return Err(crate::Error::InvalidInput);
            }
            let mut t = [0u8; $len];
            expand_generic::<$len, _>($hmac::one_shot, prk, info, &mut t, okm);
            Ok(())
        }
    };
}

hkdf_impl!(extract_sha256, expand_sha256, HmacSha256, 32, "SHA-256");
hkdf_impl!(extract_sha384, expand_sha384, HmacSha384, 48, "SHA-384");
hkdf_impl!(extract_sha512, expand_sha512, HmacSha512, 64, "SHA-512");

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
