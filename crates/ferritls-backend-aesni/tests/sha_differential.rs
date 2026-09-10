//! SHA-256 软件 vs SHA-NI 差分测试（**不安装**后端）。
//!
//! Ni 侧经 token 直接取得压缩函数指针，由测试基础设施驱动完整的
//! 缓冲/填充（约 30 行，FIPS 180-4 直写）；软件侧为 core 公开 API
//! （未安装 → 软件默认路径）。两者在数千组确定性伪随机输入上逐字节
//! 一致，并以 FIPS 180-4 / RFC 6234 的著名向量绝对锚定。

mod common;

use ferritls_backend_aesni::ShaNi;
use ferritls_core::ops::Sha256Compress;
use ferritls_core::sha2::Sha256;

/// SHA-256 初始散列值（FIPS 180-4 §5.3.3）。
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 测试基础设施：以给定压缩函数完整计算一次 SHA-256（含缓冲/填充）。
fn hash_with(f: Sha256Compress, data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    let (chunks, rem) = data.as_chunks::<64>();
    for c in chunks {
        f(&mut h, c);
    }
    let bit_len = (data.len() as u64).wrapping_mul(8);
    // 0x80 + 长度(8) 需要的空间决定单块或双块收尾。
    let tail = if rem.len() + 9 <= 64 { 64 } else { 128 };
    let mut last = [0u8; 128];
    last[..rem.len()].copy_from_slice(rem);
    last[rem.len()] = 0x80;
    last[tail - 8..tail].copy_from_slice(&bit_len.to_be_bytes());
    f(&mut h, &last[..64].try_into().expect("64 bytes"));
    if tail == 128 {
        f(&mut h, &last[64..128].try_into().expect("64 bytes"));
    }
    let mut out = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

/// xorshift64*，确定性。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// 著名向量绝对锚定（FIPS 180-4 / RFC 6234 口径）。
#[test]
fn known_answers() {
    let Some(tok) = ShaNi::detect() else {
        eprintln!("SHA-NI unavailable; skipping");
        return;
    };
    let f = tok.sha256_compress();

    common::assert_hex(
        &hash_with(f, b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256(\"\")",
    );
    common::assert_hex(
        &hash_with(f, b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256(abc)",
    );
    common::assert_hex(
        &hash_with(f, b"The quick brown fox jumps over the lazy dog"),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
        "sha256(fox)",
    );
    // 55/56/64 字节边界（单块收尾 / 双块收尾 / 整块 + 填充块）。
    for len in [55usize, 56, 63, 64, 65, 119, 120, 127, 128] {
        let data: Vec<u8> = (0..len as u8).cycle().take(len).collect();
        assert_eq!(
            hash_with(f, &data),
            Sha256::one_shot(&data),
            "boundary length {len}"
        );
    }
}

/// 软件 vs Ni：1000 组随机长度（0..300，覆盖全部填充形状）逐字节一致。
#[test]
fn differential_random_lengths() {
    let Some(tok) = ShaNi::detect() else {
        eprintln!("SHA-NI unavailable; skipping");
        return;
    };
    let f = tok.sha256_compress();
    let mut rng = Rng(0x243F_6A88_85A3_08D3_u64 ^ 0x5256);
    for round in 0..1000u32 {
        let len = (rng.next() % 300) as usize;
        let mut data = vec![0u8; len];
        rng.fill(&mut data);
        assert_eq!(
            hash_with(f, &data),
            Sha256::one_shot(&data),
            "sha256 differential round {round} (len {len})"
        );
    }
}

/// 大缓冲（16 KiB，31 个完整块 + 尾块）与流式分块一致性。
#[test]
fn differential_large_and_streaming() {
    let Some(tok) = ShaNi::detect() else {
        eprintln!("SHA-NI unavailable; skipping");
        return;
    };
    let f = tok.sha256_compress();
    let mut rng = Rng(0xDEADBEEF_CAFEF00D);

    let mut big = vec![0u8; 16384];
    rng.fill(&mut big);
    assert_eq!(
        hash_with(f, &big),
        Sha256::one_shot(&big),
        "16 KiB differential"
    );

    // 随机分块流式（软件路径）必须与一次性摘要一致——覆盖 core 的
    // 缓冲/填充逻辑在任意分块下的行为。
    for round in 0..100u32 {
        let len = (rng.next() % 500) as usize;
        let mut data = vec![0u8; len];
        rng.fill(&mut data);
        let mut h = Sha256::new();
        let mut off = 0usize;
        while off < len {
            let step = 1 + (rng.next() as usize % (len - off).max(1)).min(len - off);
            h.update(&data[off..off + step]);
            off += step;
        }
        assert_eq!(
            h.finalize(),
            Sha256::one_shot(&data),
            "streaming round {round}"
        );
    }
}
