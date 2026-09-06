//! AES-GCM（NIST SP 800-38D），认证加密。
//!
//! FIPS 批准；TLS 1.3 批准套件 `TLS_AES_128_GCM_SHA256` /
//! `TLS_AES_256_GCM_SHA384` 的记录层 AEAD。上电自检覆盖（M5）。
//!
//! 里程碑：M2。向量：NIST CAVP GCMVS + McGrew-Viega 测试样例
//! （`tests/aes_gcm.rs` 已预置 TC5/TC16）。
//!
//! 安全注意：
//! - GHASH 的 GF(2^128) 乘法必须常数时间（逐位移位-约减，不查表）；
//! - `open` 的标签比较必须常数时间（经 [`crate::ct`]）；
//! - nonce 由 rustls 记录层按 TLS 1.3 规则派生（右四字节计数器），
//!   本层不负责唯一性；
//! - 密钥材料 Drop 时零化。

macro_rules! gcm_impl {
    ($name:ident, $keylen:literal, $aes:ident, $milestone:expr) => {
        /// AES-GCM AEAD 实例（密钥 Drop 时零化）。
        #[derive(Clone, Debug)]
        pub struct $name;

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $keylen;
            /// 标准 96 位 nonce（TLS 1.3 固定长度）。
            pub const NONCE_LEN: usize = 12;
            /// 标签字节数（TLS 1.3 只用 128 位标签）。
            pub const TAG_LEN: usize = 16;

            /// 展开密钥（内部同时预计算 GHASH 的 H）。
            pub fn new(key: &[u8; $keylen]) -> Self {
                let _ = key;
                todo!($milestone)
            }

            /// 加密：返回 `密文 || 标签`（新分配缓冲，长度 = `pt.len() + 16`）。
            pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
                let _ = (nonce, aad, plaintext);
                todo!($milestone)
            }

            /// 解密并验证：输入为 `密文 || 标签`；失败返回
            /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)，
            /// 不区分“标签错”与“长度错”等具体原因。
            pub fn open(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                ct_and_tag: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                let _ = (nonce, aad, ct_and_tag);
                todo!($milestone)
            }
        }
    };
}

gcm_impl!(Aes128Gcm, 16, Aes128, "M2");
gcm_impl!(Aes256Gcm, 32, Aes256, "M2");
