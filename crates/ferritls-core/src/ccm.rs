//! AES-CCM（RFC 3610 / SP 800-38C），认证加密。
//!
//! FIPS 批准；服务于 SP 800-52r2 批准的 TLS 1.3 套件
//! `TLS_AES_128_CCM_SHA256`。两个参数集：
//! - [`Aes128Ccm`]：M=16、13 字节 nonce、L=2；
//! - [`Aes128CcmTls`]：M=16、12 字节 nonce、L=3（RFC 8446 §B.5 的
//!   AEAD_AES_128_CCM，TLS 1.3 记录层使用）。
//!
//! 外部锚定：AES 层已由 FIPS-197/GCM KAT 验证；本模块的 M=16 参数集
//! 官方向量由经 RFC 3610 §8 官方分组向量（M=8/L=2 与 M=10/L=3，含 AAD
//! 路径）逐字节校验过的独立参照实现生成（python-cryptography，
//! OpenSSL 后端）——见 `tests/ccm.rs` 与 `docs/VECTOR-PROVENANCE.md`。
//! 上电自检覆盖（M5）。

/// 生成一个固定 nonce 长度的 CCM 实例类型。
///
/// flags 推导（RFC 3610 §2.2）：MAC B0 首字节 = ((M-2)/2)<<3 | (L-1)，
/// CTR 块首字节 = L-1；长度字段占 L 字节。
macro_rules! ccm_impl {
    ($name:ident, $nonce_len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            aes: crate::aes::Aes128,
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = 16;
            /// nonce 长度（L = 16 − nonce_len）。
            pub const NONCE_LEN: usize = $nonce_len;
            /// 标签字节数（M=16）。
            pub const TAG_LEN: usize = 16;

            /// 长度字段字节数：L = 15 − nonce_len（1 + nonce + L = 16）。
            const LEN_BYTES: usize = 15 - $nonce_len;
            /// MAC B0 首字节：((16-2)/2)<<3 | (L-1)。
            const B0_FLAGS: u8 = 0x38 | ((14 - $nonce_len) as u8);
            /// CTR 块首字节：L-1。
            const CTR_FLAGS: u8 = (14 - $nonce_len) as u8;

            /// 本算法在 FIPS 140-3 下的批准状态。
            pub const APPROVAL: crate::Approval = crate::Approval::Approved;

            /// 展开密钥。
            pub fn new(key: &[u8; 16]) -> Self {
                Self {
                    aes: crate::aes::Aes128::new(key),
                }
            }

            /// 加密：返回 `密文 || 标签`。
            ///
            /// 长度域限制（RFC 3610 §2.2）：明文长度必须 < 2^(8L)、AAD
            /// 长度必须 < 2^16 − 2^8（两字节长度编码上限），超限返回
            /// [`Error::InvalidInput`](crate::Error)（规范要求的显式拒绝，
            /// 不得按位截断后继续）。
            pub fn seal(
                &self,
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                if plaintext.len() >= 1 << (8 * Self::LEN_BYTES) {
                    return Err(crate::Error::InvalidInput);
                }
                if aad.len() >= 0xff00 {
                    return Err(crate::Error::InvalidInput);
                }
                let mut t = self.cbc_mac(nonce, aad, plaintext);
                let ct = self.ctr_xor(nonce, 1, plaintext);
                let s0 = self.ctr_block(nonce, 0);
                for i in 0..16 {
                    t[i] ^= s0[i];
                }
                let mut out = ct;
                out.extend_from_slice(&t);
                Ok(out)
            }

            /// 解密并验证；失败统一返回
            /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
            pub fn open(
                &self,
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                ct_and_tag: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                if ct_and_tag.len() < 16 {
                    return Err(crate::Error::VerificationFailed);
                }
                // 密文长度受同一长度域约束（超出必非本模块产物）
                if ct_and_tag.len() - 16 >= 1 << (8 * Self::LEN_BYTES) {
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
            fn cbc_mac(&self, nonce: &[u8; $nonce_len], aad: &[u8], pt: &[u8]) -> [u8; 16] {
                let mut buf: Vec<u8> = Vec::with_capacity(16 + aad.len() + pt.len() + 32);
                // B0: flags || nonce || 明文长度（L 字节 BE）；Flags 第 6 位
                // 为 Adata（RFC 3610 §2.2：64·Adata + 8·M' + L'）——带 AAD
                // 时必须置位，否则与规范实现不互操作。
                buf.push(Self::B0_FLAGS | (u8::from(!aad.is_empty()) << 6));
                buf.extend_from_slice(nonce);
                // 明文长度用 L 字节 BE；seal/open 已拒绝超长度域的输入
                let plen = pt.len();
                for i in (0..Self::LEN_BYTES).rev() {
                    buf.push((plen >> (8 * i)) as u8);
                }

                // AAD 编码：2 字节长度 + 数据 + 补零（RFC 3610 §2.2，
                // len < 2^16-2^8）。**AAD 段在此独立补齐到 16 字节边界**
                //（add-auth-data 与 payload 各自补齐）——若与 payload 连续
                // 排列仅在末尾补一次，MAC 与规范实现（OpenSSL 等）不一致。
                if !aad.is_empty() {
                    buf.extend_from_slice(&(aad.len() as u16).to_be_bytes());
                    buf.extend_from_slice(aad);
                    let rem = buf.len() % 16;
                    if rem != 0 {
                        buf.resize(buf.len() + 16 - rem, 0);
                    }
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

            /// CTR 块：A_i = (L-1) || nonce || counter(L 字节 BE)。
            fn ctr_block(&self, nonce: &[u8; $nonce_len], counter: u32) -> [u8; 16] {
                let mut block = [0u8; 16];
                block[0] = Self::CTR_FLAGS;
                block[1..1 + $nonce_len].copy_from_slice(nonce);
                // 计数器占 L 字节（全宽写入）。L=3 时最大块号
                // ceil(2^24/16) < 2^20，u32 足够且不可能回绕（L=2 时
                // 长度域限制明文 < 2^16 → 块号 < 2^12）。
                for i in 0..Self::LEN_BYTES {
                    block[16 - Self::LEN_BYTES + i] =
                        (counter >> (8 * (Self::LEN_BYTES - 1 - i))) as u8;
                }
                self.aes.encrypt_block(&mut block);
                block
            }

            fn ctr_xor(&self, nonce: &[u8; $nonce_len], start: u32, data: &[u8]) -> Vec<u8> {
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

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

ccm_impl!(
    Aes128Ccm,
    13,
    "AES-128-CCM 实例（M=16，13 字节 nonce，L=2）。"
);
ccm_impl!(
    Aes128CcmTls,
    12,
    "AES-128-CCM 实例（M=16，12 字节 nonce，L=3）——RFC 8446 §B.5 TLS 1.3 参数集。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = [0x07u8; 16];
        let nonce13 = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ];
        let aead = Aes128Ccm::new(&key);

        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = aead.seal(&nonce13, b"aad", &pt).unwrap();
            assert_eq!(sealed.len(), len + 16);
            let opened = aead.open(&nonce13, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "len {len}");
        }

        let sealed = aead.seal(&nonce13, b"aad", b"hello ccm").unwrap();
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            aead.open(&nonce13, b"aad", &bad),
            Err(crate::Error::VerificationFailed)
        );
        assert_eq!(
            aead.open(&nonce13, b"bad", &sealed),
            Err(crate::Error::VerificationFailed)
        );

        // TLS 参数集（nonce 12 / L=3）：同往返回归
        let nonce12 = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let tls = Aes128CcmTls::new(&key);
        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = tls.seal(&nonce12, b"aad", &pt).unwrap();
            assert_eq!(sealed.len(), len + 16);
            let opened = tls.open(&nonce12, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "tls len {len}");
        }
        // 两参数集对同一 (key, 数据) 输出必须不同（nonce/L 均不同）
        assert_ne!(
            aead.seal(&nonce13, b"aad", b"x").unwrap(),
            tls.seal(&nonce12, b"aad", b"x").unwrap()
        );

        // 长度域拒绝（RFC 3610 §2.2）：L=2 明文上限 65535 字节；
        // AAD 两字节编码上限 0xff00。L=3 上限为 2^24 字节，端到端构造
        // 过慢，经由 open 的长度域检查覆盖（校验先于任何 AES 运算）。
        let big = vec![0u8; 1 << 16];
        assert_eq!(
            aead.seal(&nonce13, b"", &big),
            Err(crate::Error::InvalidInput)
        );
        assert_eq!(
            aead.seal(&nonce13, &[0u8; 0xff00], &[0u8; 16]),
            Err(crate::Error::InvalidInput)
        );
        assert_eq!(
            tls.open(&nonce12, b"", &vec![0u8; 16 + (1 << 24)]),
            Err(crate::Error::VerificationFailed)
        );
    }
}
