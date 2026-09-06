//! SHA-2 家族：SHA-256 / SHA-384 / SHA-512（FIPS 180-4）。
//!
//! FIPS 批准；上电自检覆盖（M5）。软实现为唯一后端；SHA 扩展 intrinsics
//! 后端在 M8+ 经 [`crate::ops`] 入口挂接。
//!
//! 里程碑：M1。向量：NIST CAVP SHAVS（`tests/sha2.rs` 已预置样例）。

macro_rules! sha2_impl {
    ($name:ident, $out:expr, $block:expr, $milestone:expr) => {
        /// SHA-2 摘要器（流式）。
        ///
        /// 用法：`Sha##::new()` → [`update`](Self::update)* → [`finalize`](Self::finalize)。
        #[derive(Clone, Debug)]
        pub struct $name;

        impl $name {
            /// 摘要输出字节数。
            pub const OUTPUT_LEN: usize = $out;
            /// 压缩函数块字节数。
            pub const BLOCK_LEN: usize = $block;

            /// 创建新的摘要器。
            pub fn new() -> Self {
                todo!($milestone)
            }

            /// 吸入数据。可多次调用。
            pub fn update(&mut self, data: &[u8]) {
                let _ = data;
                todo!($milestone)
            }

            /// 结束并输出摘要。消耗 `self` 以便内部状态被零化。
            pub fn finalize(self) -> [u8; $out] {
                todo!($milestone)
            }

            /// 一次性摘要便捷函数。
            pub fn one_shot(data: &[u8]) -> [u8; $out] {
                let mut h = Self::new();
                h.update(data);
                h.finalize()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

sha2_impl!(Sha256, 32, 64, "M1");
sha2_impl!(Sha384, 48, 128, "M1");
sha2_impl!(Sha512, 64, 128, "M1");
