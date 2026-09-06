//! HMAC（RFC 2104 / FIPS 198-1），基于 [`crate::sha2`]。
//!
//! FIPS 批准；上电自检覆盖（M5）。TLS 1.3 密钥调度（经 rustls 的
//! `HkdfUsingHmac` 辅助器）与 HKDF、TLS 1.2 PRF（M8）都建立在它之上。
//!
//! 里程碑：M1。向量：RFC 4231（`tests/hmac.rs` 已预置 Test Case 1–3）。

macro_rules! hmac_impl {
    ($name:ident, $hash:ident, $out:expr, $block:expr, $milestone:expr) => {
        /// HMAC-SHA-2 流式计算器。
        ///
        /// 用法：`new(key)` → [`update`](Self::update)* →
        /// [`finalize`](Self::finalize) / [`verify`](Self::verify)。
        #[derive(Clone, Debug)]
        pub struct $name;

        impl $name {
            /// 标签输出字节数。
            pub const OUTPUT_LEN: usize = $out;
            /// 内部哈希块字节数。
            pub const BLOCK_LEN: usize = $block;

            /// 以任意长度密钥初始化（短于块长补零、长于块长先哈希）。
            /// 密钥材料在 `finalize`/drop 时零化。
            pub fn new(key: &[u8]) -> Self {
                let _ = key;
                todo!($milestone)
            }

            /// 吸入数据。
            pub fn update(&mut self, data: &[u8]) {
                let _ = data;
                todo!($milestone)
            }

            /// 结束并输出标签。消耗 `self` 以零化内部密钥状态。
            pub fn finalize(self) -> [u8; $out] {
                todo!($milestone)
            }

            /// 流式计算结束后常数时间验证给定标签
            /// （使用 [`crate::ct::verify_tag`]）。
            pub fn verify(self, tag: &[u8]) -> Result<(), crate::Error> {
                let _ = tag;
                todo!($milestone)
            }

            /// 一次性标签计算。
            pub fn one_shot(key: &[u8], data: &[u8]) -> [u8; $out] {
                let mut m = Self::new(key);
                m.update(data);
                m.finalize()
            }
        }
    };
}

hmac_impl!(HmacSha256, Sha256, 32, 64, "M1");
hmac_impl!(HmacSha384, Sha384, 48, 128, "M1");
hmac_impl!(HmacSha512, Sha512, 64, 128, "M1");
