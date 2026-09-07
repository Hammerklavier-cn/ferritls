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
        keystream_xor(&self.key, nonce, plaintext, body);
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
        keystream_xor(&self.key, nonce, ct, &mut pt);
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

/// 密钥流异或（P1 性能轮）：按 256 字节步进用四块批量
/// [`chacha20_blocks4`]（转置布局，ARX 跨 4 通道自动向量化），尾段
/// （<256 字节）回退逐块标量 [`chacha20_block`]。无秘密条件分支/访存
/// （counter 与长度均为公开值）。
fn keystream_xor(key: &[u8; 32], nonce: &[u8; 12], input: &[u8], out: &mut [u8]) {
    debug_assert_eq!(input.len(), out.len());
    let mut counter = 1u32;
    let mut ks = [0u8; 256];
    for (in_chunk, out_chunk) in input.chunks(256).zip(out.chunks_mut(256)) {
        if in_chunk.len() == 256 {
            chacha20_blocks4(key, counter, nonce, &mut ks);
            for (o, (i, k)) in out_chunk.iter_mut().zip(in_chunk.iter().zip(ks)) {
                *o = i ^ k;
            }
            counter = counter.wrapping_add(4);
        } else {
            for (ic, oc) in in_chunk.chunks(64).zip(out_chunk.chunks_mut(64)) {
                let ksb = chacha20_block(key, counter, nonce);
                for (o, (i, k)) in oc.iter_mut().zip(ic.iter().zip(ksb)) {
                    *o = i ^ k;
                }
                counter = counter.wrapping_add(1);
            }
        }
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

/// ChaCha20 四块批量（P1 性能轮）：一次计算 counter..counter+3 的
/// 256 字节密钥流。状态为转置布局 `[u32; 4]`——每个状态字持有 4 个
/// 块的对应字，ARX 运算跨通道执行，LLVM 按目标向量宽度自动向量化
///（SSE2/AVX2，编译期决定，无 target_feature 探测）。计数器回绕按
/// wrapping 语义与标量路径一致。
fn chacha20_blocks4(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 256]) {
    let mut w = [[0u32; 4]; 16];
    w[0] = [0x6170_7865; 4];
    w[1] = [0x3320_646e; 4];
    w[2] = [0x7962_2d32; 4];
    w[3] = [0x6b20_6574; 4];
    for i in 0..8 {
        let k = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        w[4 + i] = [k; 4];
    }
    w[12] = [
        counter,
        counter.wrapping_add(1),
        counter.wrapping_add(2),
        counter.wrapping_add(3),
    ];
    for i in 0..3 {
        let n = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
        w[13 + i] = [n; 4];
    }
    let init = w;

    for _ in 0..10 {
        // 列轮
        qr4(&mut w, 0, 4, 8, 12);
        qr4(&mut w, 1, 5, 9, 13);
        qr4(&mut w, 2, 6, 10, 14);
        qr4(&mut w, 3, 7, 11, 15);
        // 对角轮
        qr4(&mut w, 0, 5, 10, 15);
        qr4(&mut w, 1, 6, 11, 12);
        qr4(&mut w, 2, 7, 8, 13);
        qr4(&mut w, 3, 4, 9, 14);
    }
    for blk in 0..4 {
        for i in 0..16 {
            let word = w[i][blk].wrapping_add(init[i][blk]);
            out[blk * 64 + i * 4..blk * 64 + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
}

/// 四通道四分之一轮。显式定长下标同步推进 4 个通道数组——这是
/// LLVM 自动向量化所依赖的形状，改写为迭代器形式会 obscures 该意图。
#[allow(clippy::needless_range_loop)]
fn qr4(w: &mut [[u32; 4]; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut wa, mut wb, mut wc, mut wd) = (w[a], w[b], w[c], w[d]);
    for l in 0..4 {
        wa[l] = wa[l].wrapping_add(wb[l]);
        wd[l] ^= wa[l];
        wd[l] = wd[l].rotate_left(16);
        wc[l] = wc[l].wrapping_add(wd[l]);
        wb[l] ^= wc[l];
        wb[l] = wb[l].rotate_left(12);
        wa[l] = wa[l].wrapping_add(wb[l]);
        wd[l] ^= wa[l];
        wd[l] = wd[l].rotate_left(8);
        wc[l] = wc[l].wrapping_add(wd[l]);
        wb[l] ^= wc[l];
        wb[l] = wb[l].rotate_left(7);
    }
    w[a] = wa;
    w[b] = wb;
    w[c] = wc;
    w[d] = wd;
}

/// Poly1305 一次性密钥 → 16 字节 MAC。
/// MAC 输入（RFC 8439 §2.8）为一个整体字节串：
/// AAD || pad16(AAD) || CT || pad16(CT) || len(AAD)_LE64 || len(CT)_LE64。
/// pad16 为零填充（整串恰在块边界结束，无 0x01 部分块标记）。
/// P1：流式吸收 AAD/CT，不再物化整体拷贝（原实现每条记录多一次
/// 全长 Vec 分配+拷贝）。
fn poly1305_tag(poly_key: &[u8; 64], aad: &[u8], ct: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 32];
    k.copy_from_slice(&poly_key[..32]);
    let mut st = Poly1305::new(&k);
    k.fill(0);

    st.absorb_zeropadded(aad);
    st.absorb_zeropadded(ct);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(ct.len() as u64).to_le_bytes());
    st.absorb_full(&len_block);
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
    ///（独立消息语义；AEAD 路径用 [`Self::absorb_zeropadded`]，
    /// 保留给 RFC 8439 §2.5.2 单测使用。）
    #[cfg(test)]
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

    /// 吸收一段零填充到 16 字节边界的数据（AEAD MAC 输入的 AAD/CT 段
    /// 语义：末块补零、hibit 置位；空段不贡献任何块）。
    fn absorb_zeropadded(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        while data.len() > 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&data[..16]);
            self.absorb_full(&block);
            data = &data[16..];
        }
        let mut block = [0u8; 16];
        block[..data.len()].copy_from_slice(data);
        self.absorb_full(&block);
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
    #[cfg(test)]
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

    #[test]
    fn blocks4_matches_scalar_and_rfc_anchor() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        // 批量路径 = 标量路径按 counter 拼接（含计数器回绕点）。
        for start in [0u32, 1, 42, 0x7fff_fffd, 0xffff_fffe] {
            let mut batched = [0u8; 256];
            chacha20_blocks4(&key, start, &nonce, &mut batched);
            let mut expect = [0u8; 256];
            for i in 0..4u32 {
                let b = chacha20_block(&key, start.wrapping_add(i), &nonce);
                expect[i as usize * 64..(i as usize + 1) * 64].copy_from_slice(&b);
            }
            assert_eq!(batched, expect, "counter={start}");
        }
        // RFC 8439 §2.4.2 密钥流的第 1 块 = §2.3.2 单块向量（同
        // key/nonce/counter=1）：批量的首块锚定官方字节，其余块由上面的
        // 标量等价覆盖（标量路径已由 §2.3.2 向量锚定）。
        let mut out = [0u8; 256];
        chacha20_blocks4(&key, 1, &nonce, &mut out);
        assert_eq!(
            &out[..64],
            &[
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
            ][..]
        );
    }

    #[test]
    fn keystream_xor_matches_scalar_all_shapes() {
        let mut seed = 0x9E37_79B9u32;
        let mut key = [0u8; 32];
        for b in key.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let nonce = [3u8; 12];
        let mut data = vec![0u8; 1024];
        for b in data.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        // 覆盖批量/标量边界：0、<64、=64、255/256/257、511/512/513、1024。
        for len in [0usize, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1024] {
            let input = &data[..len];
            let mut fast = vec![0u8; len];
            keystream_xor(&key, &nonce, input, &mut fast);
            // 参考实现：counter 从 1 起（与 keystream_xor 一致）
            let mut expect = vec![0u8; len];
            let mut counter = 1u32;
            for (ic, oc) in input.chunks(64).zip(expect.chunks_mut(64)) {
                let ks = chacha20_block(&key, counter, &nonce);
                for (o, (i, k)) in oc.iter_mut().zip(ic.iter().zip(ks)) {
                    *o = i ^ k;
                }
                counter = counter.wrapping_add(1);
            }
            assert_eq!(fast, expect, "len={len}");
        }
    }
}
