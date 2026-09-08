//! ChaCha20-Poly1305（RFC 8439），认证加密。
//!
//! **FIPS 非批准**：仅在默认（非批准模式）provider 中提供，不进入
//! `fips_mode_provider()` 的套件清单，上电自检不覆盖。
//!
//! 向量：RFC 8439 §2.8.2（`tests/chacha20poly1305.rs`）。
//! Poly1305 为 26 位字组常数时间实现（poly1305-donna 形态）。
//!
//! P2（`simd` feature，默认启用）：批处理密钥流的转置通道为显式
//! `Simd<u32, C>`，通道数按编译期目标特性三档（AVX-512 16 块 /
//! AVX2 8 块 / 基线 4 块，见 [`CHACHA_BLOCKS`]）——同一份源码在用户
//! 以 RUSTFLAGS 开启 target-feature 时自动加宽，无运行时分发；
//! 标量逐块路径（[`chacha20_block`]）与数组版四块批处理
//! （`chacha20_blocks4`，no-default-features 回退）原样保留为 oracle
//! 与降级路径。

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

#[cfg(feature = "simd")]
use std::simd::Simd;

/// 密钥流异或：分发到 simd 批处理路径（默认）或标量回退路径
///（no-default-features；P1 的四块自动向量化形态，原样冻结）。
fn keystream_xor(key: &[u8; 32], nonce: &[u8; 12], input: &[u8], out: &mut [u8]) {
    debug_assert_eq!(input.len(), out.len());
    #[cfg(feature = "simd")]
    keystream_xor_simd(key, nonce, input, out);
    #[cfg(not(feature = "simd"))]
    keystream_xor_scalar(key, nonce, input, out);
}

/// 密钥流异或（P2）：整批与"剩余 ≥ 1/4 批"的尾段都走
/// [`chacha20_blocks`]（不足整批时浪费 < 3/4 批——批处理每块成本
/// 约为标量 1/4，阈值取等价点）；更小的尾段回退逐块标量
/// [`chacha20_block`]。counter 按实际消耗的块数推进（公开长度决定
/// 全部分支，无秘密条件分支/访存）。
#[cfg(feature = "simd")]
fn keystream_xor_simd(key: &[u8; 32], nonce: &[u8; 12], input: &[u8], out: &mut [u8]) {
    const STEP: usize = CHACHA_BLOCKS * 64;
    let mut ks = [0u8; CHACHA_BLOCKS * 64];
    let mut counter = 1u32;
    let mut pos = 0usize;
    while pos < input.len() {
        let rem = input.len() - pos;
        if rem >= STEP / 4 {
            let take = rem.min(STEP);
            chacha20_blocks::<CHACHA_BLOCKS>(key, counter, nonce, &mut ks);
            let (ic, oc) = (&input[pos..pos + take], &mut out[pos..pos + take]);
            for (o, (i, k)) in oc.iter_mut().zip(ic.iter().zip(&ks[..take])) {
                *o = i ^ k;
            }
            counter = counter.wrapping_add(take.div_ceil(64) as u32);
            pos += take;
        } else {
            let take = rem.min(64);
            let ksb = chacha20_block(key, counter, nonce);
            let (ic, oc) = (&input[pos..pos + take], &mut out[pos..pos + take]);
            for (o, (i, k)) in oc.iter_mut().zip(ic.iter().zip(&ksb[..take])) {
                *o = i ^ k;
            }
            counter = counter.wrapping_add(1);
            pos += take;
        }
    }
}

/// 密钥流异或（P1 标量回退，原样冻结）：按 256 字节步进用四块批量
/// `chacha20_blocks4`（转置布局，ARX 跨 4 通道自动向量化），尾段
/// （<256 字节）回退逐块标量 [`chacha20_block`]。无秘密条件分支/访存
///（counter 与长度均为公开值）。
#[cfg(not(feature = "simd"))]
fn keystream_xor_scalar(key: &[u8; 32], nonce: &[u8; 12], input: &[u8], out: &mut [u8]) {
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

/// ChaCha20 批量块数（通道数）：按编译期目标特性三档（P2）。
/// AVX-512 → 16 块（16 个 ZMM 状态恰入寄存器）、AVX2 → 8 块
/// （16×YMM）、其余（x86-64 基线 SSE2 / aarch64 NEON）→ 4 块
/// （16×128-bit）。同一份源码：用户以 RUSTFLAGS 开启 target-feature
/// 即自动升级通道宽度；不做运行时分发（需 unsafe 调
/// `#[target_feature]` 函数，被 `#![forbid(unsafe_code)]` 禁止）。
#[cfg(feature = "simd")]
#[cfg(target_feature = "avx512f")]
const CHACHA_BLOCKS: usize = 16;
#[cfg(feature = "simd")]
#[cfg(all(not(target_feature = "avx512f"), target_feature = "avx2"))]
const CHACHA_BLOCKS: usize = 8;
#[cfg(feature = "simd")]
#[cfg(not(any(target_feature = "avx512f", target_feature = "avx2")))]
const CHACHA_BLOCKS: usize = 4;

/// C 通道四分之一轮（P2）：ARX 全部逐通道并行；旋转经 [`rotl`]
///（本版 portable_simd 的 SimdUint 未提供 rotate_left）。
#[cfg(feature = "simd")]
fn qr_simd<const C: usize>(w: &mut [Simd<u32, C>; 16], a: usize, b: usize, c: usize, d: usize) {
    let (mut wa, mut wb, mut wc, mut wd) = (w[a], w[b], w[c], w[d]);
    wa += wb;
    wd ^= wa;
    wd = rotl(wd, 16);
    wc += wd;
    wb ^= wc;
    wb = rotl(wb, 12);
    wa += wb;
    wd ^= wa;
    wd = rotl(wd, 8);
    wc += wd;
    wb ^= wc;
    wb = rotl(wb, 7);
    w[a] = wa;
    w[b] = wb;
    w[c] = wc;
    w[d] = wd;
}

/// 逐通道循环左移：`(v << r) | (v >> (32 − r))`——右移量必须是
/// `32 − r` 而非 `r`（后者仅在 r = 16 自对偶时凑巧正确；曾因此产出
/// 错误密钥流，由标量 oracle 立即拦截）。
#[cfg(feature = "simd")]
#[inline]
fn rotl<const C: usize>(v: Simd<u32, C>, r: u32) -> Simd<u32, C> {
    (v << Simd::splat(r)) | (v >> Simd::splat(32 - r))
}

/// ChaCha20 C 块批量（P2）：一次计算 counter..counter+C-1 的密钥流，
/// C*64 字节写入 `out`（调用方保证长度）。转置布局 `Simd<u32, C>`——
/// 每个状态字的 C 个通道承载 C 个块的对应字，显式向量类型保证宽 ISA
/// 下的通道利用率（P2 基线实测：P1 自动向量化在 +avx2 下不加宽）。
/// 计数器回绕按 wrapping 语义与标量路径一致。
#[cfg(feature = "simd")]
fn chacha20_blocks<const C: usize>(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]) {
    debug_assert!(out.len() >= C * 64);
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let mut w: [Simd<u32, C>; 16] = [
        Simd::splat(0x6170_7865),
        Simd::splat(0x3320_646e),
        Simd::splat(0x7962_2d32),
        Simd::splat(0x6b20_6574),
        Simd::splat(le32(&key[0..4])),
        Simd::splat(le32(&key[4..8])),
        Simd::splat(le32(&key[8..12])),
        Simd::splat(le32(&key[12..16])),
        Simd::splat(le32(&key[16..20])),
        Simd::splat(le32(&key[20..24])),
        Simd::splat(le32(&key[24..28])),
        Simd::splat(le32(&key[28..32])),
        Simd::from_array(core::array::from_fn(|i| counter.wrapping_add(i as u32))),
        Simd::splat(le32(&nonce[0..4])),
        Simd::splat(le32(&nonce[4..8])),
        Simd::splat(le32(&nonce[8..12])),
    ];
    let init = w;

    for _ in 0..10 {
        // 列轮
        qr_simd(&mut w, 0, 4, 8, 12);
        qr_simd(&mut w, 1, 5, 9, 13);
        qr_simd(&mut w, 2, 6, 10, 14);
        qr_simd(&mut w, 3, 7, 11, 15);
        // 对角轮
        qr_simd(&mut w, 0, 5, 10, 15);
        qr_simd(&mut w, 1, 6, 11, 12);
        qr_simd(&mut w, 2, 7, 8, 13);
        qr_simd(&mut w, 3, 4, 9, 14);
    }
    let fin = w.map(|v| v.to_array());
    let ini = init.map(|v| v.to_array());
    for blk in 0..C {
        for i in 0..16 {
            let word = fin[i][blk].wrapping_add(ini[i][blk]);
            out[blk * 64 + i * 4..blk * 64 + i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
    }
}

/// ChaCha20 四块批量（P1 标量回退，原样冻结；no-default-features 路径）：
/// 一次计算 counter..counter+3 的 256 字节密钥流。状态为转置布局
/// `[u32; 4]`——每个状态字持有 4 个块的对应字，ARX 运算跨通道执行，
/// LLVM 按目标向量宽度自动向量化（SSE2/AVX2，编译期决定，无
/// target_feature 探测）。计数器回绕按 wrapping 语义与标量路径一致。
#[cfg(not(feature = "simd"))]
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

/// 四通道四分之一轮（标量回退路径）。显式定长下标同步推进 4 个通道
/// 数组——这是 LLVM 自动向量化所依赖的形状，改写为迭代器形式会
/// obscures 该意图。
#[cfg(not(feature = "simd"))]
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
///
/// P1 余留优化：4 块分组吸收（[`Poly1305::absorb_zeropadded`]）。
/// 串行 Horner（每块 h←(h+m)·r）的乘法依赖链是吞吐瓶颈；按 4 块
/// 展开为 h←(h+m₁)·r⁴ + m₂·r³ + m₃·r² + m₄·r 后四个卷积乘法相互
/// 独立，指令级并行 4 路。r 的幂字组（r²/r³/r⁴，模 2^130−5 规整）
/// 在 [`Poly1305::new`] 预计算一次。字组界：h 输入每字 ≤ 2^26−1
/// （+最高字 ≤ 26 的进位 slack），卷积乘积 ≤ 5·2^54 << 2^64；组内
/// 四个乘积经"进位链 + c·5 回卷"松弛规整（每字 ≤ 2^26 + slack）
/// 后求和、再一次完整条件减 p，slack 不跨组累积。
struct Poly1305 {
    r: [u64; 5],
    r2: [u64; 5],
    r3: [u64; 5],
    r4: [u64; 5],
    h: [u64; 5],
    pad: [u64; 2],
}

/// 完整 16 字节块 → 26 位字组（最高字含 hibit 2^128）。
fn block_words(block: &[u8; 16]) -> [u64; 5] {
    let le32 = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    [
        u64::from(le32(&block[0..4])) & 0x3ffffff,
        u64::from(le32(&block[3..7]) >> 2) & 0x3ffffff,
        u64::from(le32(&block[6..10]) >> 4) & 0x3ffffff,
        u64::from(le32(&block[9..13]) >> 6) & 0x3ffffff,
        (u64::from(le32(&block[12..16]) >> 8) | (1 << 24)) & 0x3ffffff,
    ]
}

/// 26 位字组卷积乘积（未规整）：d_i = Σ_{j+k=i} a_j·b_k，b 的高次
/// 字以 ×5（2^130 ≡ 5）折叠进低次项。输入每字 ≤ 2^27 量级时
/// d_i ≤ 5·2^54，u64 内无溢出。
fn mul_conv(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    let s = [b[1] * 5, b[2] * 5, b[3] * 5, b[4] * 5];
    [
        a[0] * b[0] + a[1] * s[3] + a[2] * s[2] + a[3] * s[1] + a[4] * s[0],
        a[0] * b[1] + a[1] * b[0] + a[2] * s[3] + a[3] * s[2] + a[4] * s[1],
        a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * s[3] + a[4] * s[2],
        a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * s[3],
        a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
    ]
}

/// 进位链 + c·5 回卷：值模 2^130−5 缩小到 < 2^130，每字收紧到
/// ≤ 2^26−1（仅 h1 可带 ≤ ~26 的进位 slack）。
fn carry_fold(d: [u64; 5]) -> [u64; 5] {
    let mut c;
    let mut h0 = d[0] & 0x3ffffff;
    c = d[0] >> 26;
    let mut h1 = (d[1] + c) & 0x3ffffff;
    c = (d[1] + c) >> 26;
    let h2 = (d[2] + c) & 0x3ffffff;
    c = (d[2] + c) >> 26;
    let h3 = (d[3] + c) & 0x3ffffff;
    c = (d[3] + c) >> 26;
    let h4 = (d[4] + c) & 0x3ffffff;
    c = (d[4] + c) >> 26;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;
    [h0, h1, h2, h3, h4]
}

/// 常数时间条件减 p（h ≥ p 时取 h−p+5 折叠表示）：g 链逐字进位，
/// 掩码选择时被丢弃的高位均已传播到下一字，字组值精确保持；
/// g4 的 bit63 为 1 ⇔ 借位（h < p，保留 h）。
fn fold_mod_p(h: [u64; 5]) -> [u64; 5] {
    let g0 = h[0].wrapping_add(5);
    let g1 = h[1].wrapping_add(g0 >> 26);
    let g2 = h[2].wrapping_add(g1 >> 26);
    let g3 = h[3].wrapping_add(g2 >> 26);
    let g4 = h[4].wrapping_add(g3 >> 26).wrapping_sub(1 << 26);
    let keep_h = ((g4 >> 63) & 1).wrapping_neg();
    let take_g = !keep_h;
    let m26 = 0x3ffffffu64;
    [
        (h[0] & keep_h) | (g0 & m26 & take_g),
        (h[1] & keep_h) | (g1 & m26 & take_g),
        (h[2] & keep_h) | (g2 & m26 & take_g),
        (h[3] & keep_h) | (g3 & m26 & take_g),
        (h[4] & keep_h) | (g4 & m26 & take_g),
    ]
}

/// 完整规整乘法：卷积 + 进位回卷 + 条件减 p（输出 < p）。
fn mul_words(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
    fold_mod_p(carry_fold(mul_conv(a, b)))
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
        let r2 = mul_words(&r, &r);
        let r3 = mul_words(&r2, &r);
        let r4 = mul_words(&r2, &r2);
        Self {
            r,
            r2,
            r3,
            r4,
            h: [0; 5],
            pad,
        }
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
    /// ≥64 字节走 4 块分组并行路径，尾段（<64 字节）逐块。
    fn absorb_zeropadded(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        while data.len() >= 64 {
            let mut blocks = [[0u64; 5]; 4];
            for (i, blk) in blocks.iter_mut().enumerate() {
                *blk = block_words(data[i * 16..i * 16 + 16].try_into().unwrap());
            }
            self.absorb_blocks4(&blocks);
            data = &data[64..];
        }
        if data.is_empty() {
            return;
        }
        while data.len() > 16 {
            self.absorb_full(data[..16].try_into().unwrap());
            data = &data[16..];
        }
        let mut block = [0u8; 16];
        block[..data.len()].copy_from_slice(data);
        self.absorb_full(&block);
    }

    /// 4 块分组吸收：h ← (h+m₁)·r⁴ + m₂·r³ + m₃·r² + m₄·r，四个
    /// 卷积乘法独立（无依赖链）。乘积各自松弛规整后求和，一次完整
    /// 进位 + 条件减 p 收紧。
    fn absorb_blocks4(&mut self, blocks: &[[u64; 5]; 4]) {
        let mut t1 = self.h;
        for (t, &m) in t1.iter_mut().zip(blocks[0].iter()) {
            *t += m;
        }
        let t1 = carry_fold(mul_conv(&t1, &self.r4));
        let t2 = carry_fold(mul_conv(&blocks[1], &self.r3));
        let t3 = carry_fold(mul_conv(&blocks[2], &self.r2));
        let t4 = carry_fold(mul_conv(&blocks[3], &self.r));
        let mut d = [0u64; 5];
        for (((d, &a), &b), (&c, &e)) in d
            .iter_mut()
            .zip(t1.iter())
            .zip(t2.iter())
            .zip(t3.iter().zip(t4.iter()))
        {
            *d = a + b + c + e;
        }
        self.h = fold_mod_p(carry_fold(d));
    }

    /// 完整 16 字节块（hibit = 2^128 位）。
    fn absorb_full(&mut self, block: &[u8; 16]) {
        let m = block_words(block);
        for (h, &m) in self.h.iter_mut().zip(m.iter()) {
            *h += m;
        }
        self.h = mul_words(&self.h, &self.r);
    }

    /// 末尾部分块（数据后已有 0x01，无额外 hibit）。
    #[cfg(test)]
    fn absorb_partial(&mut self, block: &[u8; 16]) {
        let mut m = block_words(block);
        // block_words 置了 hibit，0x01 部分块语义要求清除。
        m[4] &= !(1u64 << 24);
        for (h, &m) in self.h.iter_mut().zip(m.iter()) {
            *h += m;
        }
        self.h = mul_words(&self.h, &self.r);
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
        self.r2.fill(0);
        self.r3.fill(0);
        self.r4.fill(0);
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
    fn poly1305_batched_matches_per_block() {
        // 4 块分组路径 vs 逐块 Horner 参考（同一实现的独立入口，
        // absorb_full 由 RFC 8439 §2.5.2/§2.8.2 向量锚定）。
        // 长度覆盖分组/尾段边界：63/64/65、127/128/129、255/256/257。
        let mut seed = 0x85E3_1A4Fu32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let key: [u8; 32] = core::array::from_fn(|_| next() as u8);
        let mut data = vec![0u8; 300];
        for b in data.iter_mut() {
            *b = next() as u8;
        }
        for len in [
            1usize, 15, 16, 17, 48, 63, 64, 65, 80, 127, 128, 129, 192, 255, 256, 257, 299, 300,
        ] {
            let msg = &data[..len];
            let mut fast = Poly1305::new(&key);
            fast.absorb_zeropadded(msg);
            let mut reference = Poly1305::new(&key);
            // 逐块参考：完整块 + 末块零填充（与批量路径的段语义一致）。
            let mut rest = msg;
            while rest.len() > 16 {
                reference.absorb_full(rest[..16].try_into().unwrap());
                rest = &rest[16..];
            }
            let mut block = [0u8; 16];
            block[..rest.len()].copy_from_slice(rest);
            reference.absorb_full(&block);
            assert_eq!(fast.finish(), reference.finish(), "len={len}");
        }
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
        // 批量入口按配置选择（P2：Simd 通道三档；回退：数组版四块）。
        #[cfg(feature = "simd")]
        let batch = |key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]| {
            chacha20_blocks::<CHACHA_BLOCKS>(key, counter, nonce, out)
        };
        #[cfg(not(feature = "simd"))]
        let batch = |key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8]| {
            let mut buf = [0u8; 256];
            chacha20_blocks4(key, counter, nonce, &mut buf);
            out[..256].copy_from_slice(&buf);
        };
        #[cfg(feature = "simd")]
        const T_BLOCKS: usize = CHACHA_BLOCKS;
        #[cfg(not(feature = "simd"))]
        const T_BLOCKS: usize = 4;

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
            let mut batched = vec![0u8; T_BLOCKS * 64];
            batch(&key, start, &nonce, &mut batched);
            let mut expect = vec![0u8; T_BLOCKS * 64];
            for i in 0..T_BLOCKS as u32 {
                let b = chacha20_block(&key, start.wrapping_add(i), &nonce);
                expect[i as usize * 64..(i as usize + 1) * 64].copy_from_slice(&b);
            }
            assert_eq!(batched, expect, "counter={start}");
        }
        // RFC 8439 §2.4.2 密钥流的第 1 块 = §2.3.2 单块向量（同
        // key/nonce/counter=1）：批量的首块锚定官方字节，其余块由上面的
        // 标量等价覆盖（标量路径已由 §2.3.2 向量锚定）。
        let mut out = vec![0u8; T_BLOCKS * 64];
        batch(&key, 1, &nonce, &mut out);
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
        let mut data = vec![0u8; 2048];
        for b in data.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        // 覆盖批量/尾段边界：0、<64、=64、255/256/257、511/512/513、
        // 1024/1025、1500（典型 MTU）、2048——P2 通道档（4/8/16 块）下
        // 的整批、填充批（剩余 ≥ 1/4 批）与小尾段三种路径全部命中。
        for len in [
            0usize, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1024, 1025, 1500, 1601, 2048,
        ] {
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
