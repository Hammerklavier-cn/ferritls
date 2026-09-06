//! AES 块密码（FIPS 197），128/192/256 位密钥的软件实现。
//!
//! FIPS 批准；作为 GCM/CCM 与 CTR-DRBG 的底层部件，上电自检覆盖（M5）。
//! AES-NI 后端在 M8+ 经 [`crate::ops`] 入口挂接，不影响本模块公开 API。
//!
//! 里程碑：M2。向量：NIST CAVP ECB/AESVS（实现时随 `tests/aes.rs` 引入；
//! GHASH/GCM 的向量在 [`crate::gcm`]）。
//!
//! 安全注意：`new` 展开后的轮密钥在 `Drop` 时零化；块操作不得依赖明文
//! 内容产生分支（T 表实现禁止——查表索引依赖密钥即构成缓存侧信道，
//! 只允许按位实现的 S-box）。

macro_rules! aes_impl {
    ($name:ident, $keylen:expr, $milestone:expr) => {
        /// AES 块密码实例（内部持有已展开的轮密钥，Drop 时零化）。
        #[derive(Clone, Debug)]
        pub struct $name;

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $keylen;

            /// 展开密钥。
            pub fn new(key: &[u8; $keylen]) -> Self {
                let _ = key;
                todo!($milestone)
            }

            /// 就地加密一个块。
            pub fn encrypt_block(&self, block: &mut [u8; 16]) {
                let _ = block;
                todo!($milestone)
            }

            /// 就地解密一个块（等价逆变换；DRBG 与 GCM 只需加密方向）。
            pub fn decrypt_block(&self, block: &mut [u8; 16]) {
                let _ = block;
                todo!($milestone)
            }
        }
    };
}

aes_impl!(Aes128, 16, "M2");
aes_impl!(Aes192, 24, "M2");
aes_impl!(Aes256, 32, "M2");
