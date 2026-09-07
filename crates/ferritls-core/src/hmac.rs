//! HMAC（RFC 2104 / FIPS 198-1），基于 [`crate::sha2`]。
//!
//! FIPS 批准；上电自检覆盖（M5）。TLS 1.3 密钥调度（经 rustls 的
//! `HkdfUsingHmac` 辅助器）与 HKDF、TLS 1.2 PRF（M8）都建立在它之上。
//!
//! 向量：RFC 4231（`tests/hmac.rs`，Test Case 1–3 + 验证/篡改路径）。

use crate::sha2::{Sha256, Sha384, Sha512};

macro_rules! hmac_impl {
    ($name:ident, $hash:ident, $out:expr, $block:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            ipad: [u8; $block],
            opad: [u8; $block],
            inner: $hash,
        }

        impl $name {
            /// 标签输出字节数。
            pub const OUTPUT_LEN: usize = $out;
            /// 内部哈希块字节数。
            pub const BLOCK_LEN: usize = $block;

            /// 以任意长度密钥初始化（短于块长补零、长于块长先哈希）。
            pub fn new(key: &[u8]) -> Self {
                let mut k = [0u8; $block];
                if key.len() > $block {
                    k[..$out].copy_from_slice(&$hash::one_shot(key));
                } else {
                    k[..key.len()].copy_from_slice(key);
                }
                let mut ipad = [0x36u8; $block];
                let mut opad = [0x5cu8; $block];
                for i in 0..$block {
                    ipad[i] ^= k[i];
                    opad[i] ^= k[i];
                }
                let mut inner = $hash::new();
                inner.update(&ipad);
                Self { ipad, opad, inner }
            }

            /// 吸入数据。
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// 结束并输出标签。消耗 `self` 以清零内部密钥状态。
            pub fn finalize(mut self) -> [u8; $out] {
                let inner = std::mem::replace(&mut self.inner, $hash::default());
                let it = inner.finalize();
                let mut outer = $hash::new();
                outer.update(&self.opad);
                outer.update(&it);
                let tag = outer.finalize();
                self.ipad.fill(0);
                self.opad.fill(0);
                tag
            }

            /// 流式计算结束后常数时间验证给定标签。
            pub fn verify(mut self, tag: &[u8]) -> Result<(), crate::Error> {
                let computed = self.finalize();
                crate::ct::verify_tag(&computed, tag)
            }

            /// 一次性标签计算。
            pub fn one_shot(key: &[u8], data: &[u8]) -> [u8; $out] {
                let mut m = Self::new(key);
                m.update(data);
                m.finalize()
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.ipad.fill(0);
                self.opad.fill(0);
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

hmac_impl!(HmacSha256, Sha256, 32, 64, "HMAC-SHA-256 流式计算器。");
hmac_impl!(HmacSha384, Sha384, 48, 128, "HMAC-SHA-384 流式计算器。");
hmac_impl!(HmacSha512, Sha512, 64, 128, "HMAC-SHA-512 流式计算器。");
