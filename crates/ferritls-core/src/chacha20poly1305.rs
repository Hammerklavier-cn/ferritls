//! ChaCha20-Poly1305（RFC 8439），认证加密。
//!
//! **FIPS 非批准**：仅在默认（非批准模式）provider 中提供，不进入
//! `fips_mode_provider()` 的套件清单，上电自检不覆盖。
//!
//! 里程碑：M2。向量：RFC 8439 §2.8.2（`tests/chacha20poly1305.rs` 已预置）。
//!
//! 安全注意：Poly1305 的 5→4 字组约减与标签比较必须常数时间；密钥与
//! one-time Poly1305 key Drop 时零化。

/// ChaCha20-Poly1305 AEAD 实例（IETF 参数：256 位密钥、96 位 nonce）。
#[derive(Clone, Debug)]
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// 密钥字节数。
    pub const KEY_LEN: usize = 32;
    /// nonce 字节数。
    pub const NONCE_LEN: usize = 12;
    /// 标签字节数。
    pub const TAG_LEN: usize = 16;

    /// 本算法在 FIPS 140-3 下的批准状态。
    pub const APPROVAL: crate::Approval = crate::Approval::NonApproved;

    /// 展开密钥。
    pub fn new(key: &[u8; 32]) -> Self {
        let _ = key;
        todo!("M2")
    }

    /// 加密：返回 `密文 || 标签`。
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let _ = (nonce, aad, plaintext);
        todo!("M2")
    }

    /// 解密并验证；失败仅返回
    /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
    pub fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        let _ = (nonce, aad, ct_and_tag);
        todo!("M2")
    }
}
