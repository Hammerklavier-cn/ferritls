//! AES-CCM（RFC 3610 / SP 800-38C），认证加密。
//!
//! FIPS 批准；服务于 SP 800-52r2 批准的 TLS 1.3 套件
//! `TLS_AES_128_CCM_SHA256`（M=16、13 字节 nonce、L=2 的参数集）。
//! 上电自检覆盖（M5）。
//!
//! 里程碑：M2（优先级低于 GCM/ChaCha20：仅 FIPS 部署需要）。
//! 向量：NIST CAVP CCMVS + RFC 3610 附录测试向量（实现时引入）。

/// AES-128-CCM AEAD 实例（TLS 1.3 参数集：M=16，nonce=13，L=2）。
///
/// 注意与 GCM 的 nonce 长度不同（13 字节）。
#[derive(Clone, Debug)]
pub struct Aes128Ccm;

impl Aes128Ccm {
    /// 密钥字节数。
    pub const KEY_LEN: usize = 16;
    /// TLS 1.3 CCM nonce 长度（13 字节，L=2）。
    pub const NONCE_LEN: usize = 13;
    /// 标签字节数（M=16）。
    pub const TAG_LEN: usize = 16;

    /// 展开密钥。
    pub fn new(key: &[u8; 16]) -> Self {
        let _ = key;
        todo!("M2")
    }

    /// 加密：返回 `密文 || 标签`。
    pub fn seal(&self, nonce: &[u8; 13], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let _ = (nonce, aad, plaintext);
        todo!("M2")
    }

    /// 解密并验证；失败仅返回
    /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
    pub fn open(
        &self,
        nonce: &[u8; 13],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        let _ = (nonce, aad, ct_and_tag);
        todo!("M2")
    }
}
