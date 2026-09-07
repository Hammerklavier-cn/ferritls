//! AES-GCM（NIST SP 800-38D），认证加密。
//!
//! FIPS 批准；TLS 1.3 批准套件 `TLS_AES_128_GCM_SHA256` /
//! `TLS_AES_256_GCM_SHA384` 的记录层 AEAD。上电自检覆盖（M5）。
//!
//! 常数时间策略：GHASH 的 GF(2^128) 乘法为逐位掩码实现（不查表）；
//! 标签验证在返回任何明文前完成（open 路径失败统一同一错误码）。
//! nonce 唯一性由 rustls 记录层保证。密钥材料 Drop 时零化。
//!
//! 向量：McGrew–Viega TC5/TC16（`tests/aes_gcm.rs`）+ FIPS-197 AES KAT。

use crate::aes::{Aes128, Aes256};

macro_rules! gcm_impl {
    ($name:ident, $aes:ident, $keylen:literal, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            aes: $aes,
            /// GHASH 乘数 H = CIPH_K(0^128)，大端 u128 视图。
            h: u128,
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $keylen;
            /// 标准 96 位 nonce（TLS 1.3 固定长度）。
            pub const NONCE_LEN: usize = 12;
            /// 标签字节数（TLS 1.3 只用 128 位标签）。
            pub const TAG_LEN: usize = 16;

            /// 本算法在 FIPS 140-3 下的批准状态。
            pub const APPROVAL: crate::Approval = crate::Approval::Approved;

            /// 展开密钥（内部同时预计算 GHASH 的 H）。
            pub fn new(key: &[u8; $keylen]) -> Self {
                let aes = $aes::new(key);
                let mut h_block = [0u8; 16];
                aes.encrypt_block(&mut h_block);
                let h = u128::from_be_bytes(h_block);
                Self { aes, h }
            }

            /// 加密：返回 `密文 || 标签`（长度 = `plaintext.len() + 16`）。
            pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
                let j0 = block_j0(nonce);
                let tag_base = {
                    let mut b = j0.to_be_bytes();
                    self.aes.encrypt_block(&mut b);
                    u128::from_be_bytes(b)
                };

                let mut ct = vec![0u8; plaintext.len() + Self::TAG_LEN];
                let (body, tail) = ct.split_at_mut(plaintext.len());
                let mut ctr = inc32(j0);
                for (pt_chunk, ct_chunk) in plaintext.chunks(16).zip(body.chunks_mut(16)) {
                    let ks = self.keystream(ctr);
                    // 固定 ≤16 字节的 zip 异或：LLVM 按目标向量宽度自动向量化
                    //（P1 性能轮；无秘密条件分支/访存）。
                    for (c, (p, k)) in ct_chunk.iter_mut().zip(pt_chunk.iter().zip(ks)) {
                        *c = p ^ k;
                    }
                    ctr = inc32(ctr);
                }

                let s = self.ghash(aad, body);
                tail.copy_from_slice(&(tag_base ^ s).to_be_bytes());
                ct
            }

            /// 解密并验证；任何失败（含输入过短）统一返回
            /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
            pub fn open(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                ct_and_tag: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                if ct_and_tag.len() < 16 {
                    return Err(crate::Error::VerificationFailed);
                }
                let split = ct_and_tag.len() - 16;
                let (ct, tag_bytes) = ct_and_tag.split_at(split);

                let j0 = block_j0(nonce);
                let tag_base = {
                    let mut b = j0.to_be_bytes();
                    self.aes.encrypt_block(&mut b);
                    u128::from_be_bytes(b)
                };
                let s = self.ghash(aad, ct);
                // 常数时间标签比较（与 ccm.rs/chacha20poly1305.rs 对齐，
                // §5.1）：分支不得依赖秘密；先验后出的顺序不变。
                crate::ct::verify_tag(&(tag_base ^ s).to_be_bytes(), tag_bytes)?;

                let mut pt = vec![0u8; ct.len()];
                let mut ctr = inc32(j0);
                for (ct_chunk, pt_chunk) in ct.chunks(16).zip(pt.chunks_mut(16)) {
                    let ks = self.keystream(ctr);
                    for (p, (c, k)) in pt_chunk.iter_mut().zip(ct_chunk.iter().zip(ks)) {
                        *p = c ^ k;
                    }
                    ctr = inc32(ctr);
                }
                Ok(pt)
            }

            fn keystream(&self, ctr: u128) -> [u8; 16] {
                let mut b = ctr.to_be_bytes();
                self.aes.encrypt_block(&mut b);
                b
            }

            /// GHASH：Aad(pad) || C(pad) || [len(aad)]64 || [len(ct)]64。
            fn ghash(&self, aad: &[u8], ct: &[u8]) -> u128 {
                let mut y: u128 = 0;
                for chunk in aad.chunks(16) {
                    let mut block = [0u8; 16];
                    block[..chunk.len()].copy_from_slice(chunk);
                    let x = u128::from_be_bytes(block);
                    y = gf128_mul(y ^ x, self.h);
                }
                for chunk in ct.chunks(16) {
                    let mut block = [0u8; 16];
                    block[..chunk.len()].copy_from_slice(chunk);
                    let x = u128::from_be_bytes(block);
                    y = gf128_mul(y ^ x, self.h);
                }
                let mut len_block = [0u8; 16];
                len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
                len_block[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
                let x = u128::from_be_bytes(len_block);
                gf128_mul(y ^ x, self.h)
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self {
                    aes: self.aes.clone(),
                    h: self.h,
                }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

/// 96 位 nonce → J0 = nonce || 0x00000001。
fn block_j0(nonce: &[u8; 12]) -> u128 {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[15] = 1;
    u128::from_be_bytes(b)
}

/// 递增计数器块的最低 32 位（RFC 5116 inc32）。
fn inc32(block: u128) -> u128 {
    let ctr = (block as u32).wrapping_add(1);
    (block & !0xFFFF_FFFF) | (ctr as u128)
}

/// GF(2^128) 乘法，SP 800-38D 算法 1 的分支无关实现。
/// 块以大端 u128 表示，约减多项式 R = 0xE1 << 120。
fn gf128_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1u128 << 120;
    let mut z: u128 = 0;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & bit.wrapping_neg();
        let lsb = v & 1;
        v >>= 1;
        v ^= R.wrapping_mul(lsb);
    }
    z
}

gcm_impl!(
    Aes128Gcm,
    Aes128,
    16,
    "AES-128-GCM AEAD 实例（密钥 Drop 时零化）。"
);
gcm_impl!(
    Aes256Gcm,
    Aes256,
    32,
    "AES-256-GCM AEAD 实例（密钥 Drop 时零化）。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf128_properties() {
        let a = u128::from_be_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        // GF(2^128) 单位元（x^0）在本表示（左位=低位次）下为最高位。
        let one = 1u128 << 127;
        assert_eq!(gf128_mul(a, one), a, "X·1 = X");
        assert_eq!(gf128_mul(one, a), a, "1·Y = Y");
        assert_eq!(gf128_mul(0, a), 0);
        // 交换律。
        let b = 0xdeadbeefcafef00d1234567890abcdefu128;
        assert_eq!(gf128_mul(a, b), gf128_mul(b, a));
    }
}
