//! ChaCha20-Poly1305（RFC 8439），认证加密。
//!
//! **FIPS 非批准**：仅在默认（非批准模式）provider 中提供，不进入
//! `fips_mode_provider()` 的套件清单，上电自检不覆盖。
//!
//! 向量：RFC 8439 §2.8.2（`tests/chacha20poly1305.rs`）。
//! Poly1305 为 26 位字组常数时间实现（poly1305-donna 形态）。

/// ChaCha20-Poly1305 AEAD 实例（IETF 参数：256 位密钥、96 位 nonce）。
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

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
        Self { key: *key }
    }

    /// 加密：返回 `密文 || 标签`。
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let poly_key = chacha20_block(&self.key, 0, nonce);
        let mut ct = vec![0u8; plaintext.len() + Self::TAG_LEN];
        let (body, tail) = ct.split_at_mut(plaintext.len());
        let mut counter = 1u32;
        for (pt_chunk, ct_chunk) in plaintext.chunks(64).zip(body.chunks_mut(64)) {
            let ks = chacha20_block(&self.key, counter, nonce);
            // 固定 ≤64 字节的 zip 异或：LLVM 自动向量化
            //（P1 性能轮；无秘密条件分支/访存）。
            for (c, (p, k)) in ct_chunk.iter_mut().zip(pt_chunk.iter().zip(ks)) {
                *c = p ^ k;
            }
            counter = counter.wrapping_add(1);
        }
        let tag = poly1305_tag(&poly_key, aad, body);
        tail.copy_from_slice(&tag);
        ct
    }

    /// 解密并验证；失败统一返回
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
        let (ct, tag) = ct_and_tag.split_at(split);

        let poly_key = chacha20_block(&self.key, 0, nonce);
        let computed = poly1305_tag(&poly_key, aad, ct);
        crate::ct::verify_tag(&computed, tag)?;

        let mut pt = vec![0u8; ct.len()];
        let mut counter = 1u32;
        for (ct_chunk, pt_chunk) in ct.chunks(64).zip(pt.chunks_mut(64)) {
            let ks = chacha20_block(&self.key, counter, nonce);
            for (p, (c, k)) in pt_chunk.iter_mut().zip(ct_chunk.iter().zip(ks)) {
                *p = c ^ k;
            }
            counter = counter.wrapping_add(1);
        }
        Ok(pt)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl std::fmt::Debug for ChaCha20Poly1305 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChaCha20Poly1305")
    }
}

/// ChaCha20 单块（RFC 8439 §2.3）：64 字节密钥流。
pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut w = s;
    for _ in 0..10 {
        // 列轮
        qr(&mut w, 0, 4, 8, 12);
        qr(&mut w, 1, 5, 9, 13);
        qr(&mut w, 2, 6, 10, 14);
        qr(&mut w, 3, 7, 11, 15);
        // 对角轮
        qr(&mut w, 0, 5, 10, 15);
        qr(&mut w, 1, 6, 11, 12);
        qr(&mut w, 2, 7, 8, 13);
        qr(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&w[i].wrapping_add(s[i]).to_le_bytes());
    }
    out
}

fn qr(w: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    w[a] = w[a].wrapping_add(w[b]);
    w[d] ^= w[a];
    w[d] = w[d].rotate_left(16);
    w[c] = w[c].wrapping_add(w[d]);
    w[b] ^= w[c];
    w[b] = w[b].rotate_left(12);
    w[a] = w[a].wrapping_add(w[b]);
    w[d] ^= w[a];
    w[d] = w[d].rotate_left(8);
    w[c] = w[c].wrapping_add(w[d]);
    w[b] ^= w[c];
    w[b] = w[b].rotate_left(7);
}

/// Poly1305 一次性密钥 → 16 字节 MAC。
/// MAC 输入（RFC 8439 §2.8）为一个整体字节串：
/// AAD || pad16(AAD) || CT || pad16(CT) || len(AAD)_LE64 || len(CT)_LE64。
/// pad16 后的 AAD/CT 是完整块；只有整串的**最末**不足 16 字节部分
/// 才用 0x01 充当 2^128 位标记。
fn poly1305_tag(poly_key: &[u8; 64], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&poly_key[..32]);
    let mut st = Poly1305::new(&k);
    k.fill(0);

    let mut data = Vec::with_capacity(aad.len() + ct.len() + 48);
    data.extend_from_slice(aad);
    data.resize(data.len().next_multiple_of(16), 0);
    let ct_start = data.len();
    data.extend_from_slice(ct);
    data.resize(data.len().next_multiple_of(16), 0);
    data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    data.extend_from_slice(&(ct.len() as u64).to_le_bytes());
    let _ = ct_start;
    st.absorb_segment(&data);
    st.finish()
}

/// Poly1305（26 位字组形态，branch-free）。
struct Poly1305 {
    r: [u64; 5],
    h: [u64; 5],
    pad: [u64; 2],
}

impl Poly1305 {
    fn new(key: &[u8; 32]) -> Self {
        let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
        let r = [
            u64::from(le32(&key[0..4])) & 0x3ffffff,
            u64::from((le32(&key[3..7])) >> 2) & 0x3ffff03,
            u64::from((le32(&key[6..10])) >> 4) & 0x3ffc0ff,
            u64::from((le32(&key[9..13])) >> 6) & 0x3f03fff,
            u64::from((le32(&key[12..16])) >> 8) & 0x00fffff,
        ];
        let pad = [
            u64::from(le32(&key[16..20])) | (u64::from(le32(&key[20..24])) << 32),
            u64::from(le32(&key[24..28])) | (u64::from(le32(&key[28..32])) << 32),
        ];
        Self { r, h: [0; 5], pad }
    }

    /// 吸收一段数据：完整块带 hibit，末尾不足 16 字节的块在数据后
    /// 追加 0x01 再补零（hibit 位置由 0x01 字节承担）。
    fn absorb_segment(&mut self, mut data: &[u8]) {
        while data.len() >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb_full(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            let mut block = [0u8; 16];
            block[..data.len()].copy_from_slice(data);
            block[data.len()] = 1;
            self.absorb_partial(&block);
        }
    }

    /// 完整 16 字节块（hibit = 2^128 位）。
    fn absorb_full(&mut self, block: &[u8; 16]) {
        let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
        self.h[0] += u64::from(le32(&block[0..4])) & 0x3ffffff;
        self.h[1] += (u64::from(le32(&block[3..7])) >> 2) & 0x3ffffff;
        self.h[2] += (u64::from(le32(&block[6..10])) >> 4) & 0x3ffffff;
        self.h[3] += (u64::from(le32(&block[9..13])) >> 6) & 0x3ffffff;
        self.h[4] += ((u64::from(le32(&block[12..16])) >> 8) | (1 << 24)) & 0x3ffffff;
        self.mul_r();
    }

    /// 末尾部分块（数据后已有 0x01，无额外 hibit）。
    fn absorb_partial(&mut self, block: &[u8; 16]) {
        let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
        self.h[0] += u64::from(le32(&block[0..4])) & 0x3ffffff;
        self.h[1] += (u64::from(le32(&block[3..7])) >> 2) & 0x3ffffff;
        self.h[2] += (u64::from(le32(&block[6..10])) >> 4) & 0x3ffffff;
        self.h[3] += (u64::from(le32(&block[9..13])) >> 6) & 0x3ffffff;
        // (le32 >> 8) 天然 ≤ 2^24 < 2^26，无需掩码。
        self.h[4] += u64::from(le32(&block[12..16])) >> 8;
        self.mul_r();
    }

    fn mul_r(&mut self) {
        let s = [self.r[1] * 5, self.r[2] * 5, self.r[3] * 5, self.r[4] * 5];
        let (r, h) = (&self.r, &self.h);
        let d0 = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
        let d1 = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
        let d2 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
        let d3 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
        let d4 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

        let mut c: u64;
        let mut h0 = d0 & 0x3ffffff;
        c = d0 >> 26;
        let mut h1 = (d1 + c) & 0x3ffffff;
        c = (d1 + c) >> 26;
        let h2 = (d2 + c) & 0x3ffffff;
        c = (d2 + c) >> 26;
        let h3 = (d3 + c) & 0x3ffffff;
        c = (d3 + c) >> 26;
        let h4 = (d4 + c) & 0x3ffffff;
        c = (d4 + c) >> 26;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ffffff;
        h1 += c;

        // h 与 h - p 的常数时间选择。
        let g0 = h0.wrapping_add(5);
        let g1 = h1.wrapping_add(g0 >> 26);
        let g2 = h2.wrapping_add(g1 >> 26);
        let g3 = h3.wrapping_add(g2 >> 26);
        let g4 = h4.wrapping_add(g3 >> 26).wrapping_sub(1 << 26);
        // g4 的 bit63 为 1 ⇔ 发生借位（h < p，保留 h）。
        let keep_h = ((g4 >> 63) & 1).wrapping_neg();
        let take_g = !keep_h;
        let m26 = 0x3ffffffu64;
        self.h[0] = (h0 & keep_h) | (g0 & m26 & take_g);
        self.h[1] = (h1 & keep_h) | (g1 & m26 & take_g);
        self.h[2] = (h2 & keep_h) | (g2 & m26 & take_g);
        self.h[3] = (h3 & keep_h) | (g3 & m26 & take_g);
        self.h[4] = (h4 & keep_h) | (g4 & m26 & take_g);
    }

    /// 结束：t = (h + pad) mod 2^128。u128 加法合成，天然处理字组间进位
    /// （h ≥ 2^128 的高位按模 2^128 语义丢弃）。
    fn finish(self) -> [u8; 16] {
        let h = (u128::from(self.h[0]))
            + (u128::from(self.h[1]) << 26)
            + (u128::from(self.h[2]) << 52)
            + (u128::from(self.h[3]) << 78)
            + (u128::from(self.h[4]) << 104);
        let s = u128::from(self.pad[0]) | (u128::from(self.pad[1]) << 64);
        let t = h.wrapping_add(s);

        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&(t as u64).to_le_bytes());
        tag[8..].copy_from_slice(&((t >> 64) as u64).to_le_bytes());
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.h.fill(0);
        self.r.fill(0);
        self.pad.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poly1305_rfc8439_2_5_2() {
        // RFC 8439 §2.5.2 Poly1305 单独向量。
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        // 纯 Poly1305（无 AEAD 长度块）：直接吸收消息后 finish。
        let mut st = Poly1305::new(&key);
        st.absorb_segment(msg);
        assert_eq!(
            st.finish(),
            [
                0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
                0x27, 0xa9
            ]
        );
    }

    #[test]
    fn chacha_block_rfc8439_2_3_2() {
        // RFC 8439 §2.3.2: block function test vector.
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let ks = chacha20_block(&key, 1, &nonce);
        let expect: [u8; 64] = [
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
            0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
            0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
            0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        ];
        assert_eq!(ks, expect);
    }
}
