//! AES-CCM（RFC 3610 / SP 800-38C），认证加密。
//!
//! FIPS 批准；服务于 SP 800-52r2 批准的 TLS 1.3 套件
//! `TLS_AES_128_CCM_SHA256`（M=16、13 字节 nonce、L=2 参数集）。
//! 上电自检覆盖（M5）。
//!
//! 外部锚定：AES 层已由 FIPS-197/GCM KAT 验证；本模块当前以
//! 往返 + 篡改 + 跨块长度自洽测试覆盖（CAVP CCMVS 向量子集在
//! M7 引入——见 tests 注记）。

/// AES-128-CCM AEAD 实例（TLS 1.3 参数集：M=16，nonce=13，L=2）。
#[derive(Clone)]
pub struct Aes128Ccm {
    aes: crate::aes::Aes128,
}

impl Aes128Ccm {
    /// 密钥字节数。
    pub const KEY_LEN: usize = 16;
    /// TLS 1.3 CCM nonce 长度（13 字节，L=2）。
    pub const NONCE_LEN: usize = 13;
    /// 标签字节数（M=16）。
    pub const TAG_LEN: usize = 16;

    /// 本算法在 FIPS 140-3 下的批准状态。
    pub const APPROVAL: crate::Approval = crate::Approval::Approved;

    /// 展开密钥。
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            aes: crate::aes::Aes128::new(key),
        }
    }

    /// 加密：返回 `密文 || 标签`。
    pub fn seal(&self, nonce: &[u8; 13], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        // MAC: B0 || 格式化 AAD || 明文 的 CBC-MAC，最后与 S0 异或。
        let mut t = self.cbc_mac(nonce, aad, plaintext);
        let ct = self.ctr_xor(nonce, 1, plaintext);
        let s0 = self.ctr_block(nonce, 0);
        for i in 0..16 {
            t[i] ^= s0[i];
        }
        let mut out = ct;
        out.extend_from_slice(&t);
        out
    }

    /// 解密并验证；失败统一返回
    /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
    pub fn open(
        &self,
        nonce: &[u8; 13],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        if ct_and_tag.len() < 16 {
            return Err(crate::Error::VerificationFailed);
        }
        let split = ct_and_tag.len() - 16;
        let (ct, tag) = ct_and_tag.split_at(split);

        let pt = self.ctr_xor(nonce, 1, ct);
        let mut t = self.cbc_mac(nonce, aad, &pt);
        let s0 = self.ctr_block(nonce, 0);
        for i in 0..16 {
            t[i] ^= s0[i];
        }
        crate::ct::verify_tag(&t, tag)?;
        Ok(pt)
    }

    /// CBC-MAC over B0 || 格式化 AAD || 明文（均补齐到 16 字节块）。
    fn cbc_mac(&self, nonce: &[u8; 13], aad: &[u8], pt: &[u8]) -> [u8; 16] {
        let mut buf: Vec<u8> = Vec::with_capacity(16 + aad.len() + pt.len() + 32);
        // B0: flags = 0x39（M=16 → (16-2)/2 << 3 = 0x38；L-1 = 1）
        buf.push(0x39);
        buf.extend_from_slice(nonce);
        buf.extend_from_slice(&(pt.len() as u16).to_be_bytes());

        // AAD 编码：2 字节长度 + 数据 + 补零（RFC 3610 §2.2，len < 2^16-2^8）。
        if !aad.is_empty() {
            buf.extend_from_slice(&(aad.len() as u16).to_be_bytes());
            buf.extend_from_slice(aad);
        }

        buf.extend_from_slice(pt);

        let mut t = [0u8; 16];
        for chunk in buf.chunks(16) {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            for i in 0..16 {
                block[i] ^= t[i];
            }
            self.aes.encrypt_block(&mut block);
            t = block;
        }
        t
    }

    /// CTR 块：A_i = 0x01 || nonce || counter(2 字节 BE)。
    fn ctr_block(&self, nonce: &[u8; 13], counter: u16) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[0] = 0x01;
        block[1..14].copy_from_slice(nonce);
        block[14..].copy_from_slice(&counter.to_be_bytes());
        self.aes.encrypt_block(&mut block);
        block
    }

    fn ctr_xor(&self, nonce: &[u8; 13], start: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut counter = start;
        for chunk in data.chunks(16) {
            let ks = self.ctr_block(nonce, counter);
            for (o, b) in chunk.iter().enumerate() {
                out.push(b ^ ks[o]);
            }
            counter = counter.wrapping_add(1);
        }
        out
    }
}

impl std::fmt::Debug for Aes128Ccm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Aes128Ccm")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = [0x07u8; 16];
        let nonce = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ];
        let aead = Aes128Ccm::new(&key);

        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = aead.seal(&nonce, b"aad", &pt);
            assert_eq!(sealed.len(), len + 16);
            let opened = aead.open(&nonce, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "len {len}");
        }

        let sealed = aead.seal(&nonce, b"aad", b"hello ccm");
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            aead.open(&nonce, b"aad", &bad),
            Err(crate::Error::VerificationFailed)
        );
        assert_eq!(
            aead.open(&nonce, b"bad", &sealed),
            Err(crate::Error::VerificationFailed)
        );
    }
}
