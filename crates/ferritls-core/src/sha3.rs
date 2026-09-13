//! FIPS 202：Keccak 海绵族——SHA3-256/512 与 SHAKE-128/256（M8.3）。
//!
//! 纯软件标量实现（Keccak-f[1600]，24 轮 θ/ρ/π/χ/ι），全部运算为
//! 数据无关固定延迟，无侧信道敏感面（无以秘密为条件的分支或访存；
//! 状态零化不适用——海绵状态承载公开数据）。SHA3 与 SHAKE 共用同一
//! 海绵，仅域分隔填充字节不同（0x06 / 0x1F），由类型系统分开。
//!
//! ML-KEM（FIPS 203，[`crate::mlkem`]）按标准使用四个映射：
//! `H` = SHA3-256、`G` = SHA3-512、`J`/`PRF` = SHAKE-256、
//! `XOF` = SHAKE-128；本模块同时作为 FIPS 202 的公开边界内 API。
//!
//! 向量：FIPS 202 官方示例 + FIPS 203 附录 A 示例值，
//! 见 `tests/sha3.rs` 与 docs/VECTOR-PROVENANCE.md。

/// Keccak-f[1600] 置换的 24 个轮常量。
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// ρ 旋转偏移，按 `a[x + 5y]` 平铺（标准 5×5 矩阵的行主序平铺）。
const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// Keccak-f[1600]：对 25×64 位状态原地执行 24 轮置换。
fn keccak_f1600(a: &mut [u64; 25]) {
    for &rc in &RC {
        // θ：列奇偶 → 与相邻列异或
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for a in a.iter_mut().skip(x).step_by(5) {
                *a ^= d;
            }
        }
        // ρ + π：旋转并按 (x, y) → (y, 2x+3y) 重排
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(RHO[x + 5 * y]);
            }
        }
        // χ：行内非线性组合
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // ι：轮常量注入
        a[0] ^= rc;
    }
}

/// Keccak 海绵核：`rate` 为字节率（SHA3-256/SHAKE128 = 136，
/// SHA3-512 = 72，SHAKE256 = 64），全部 ≤ 200 = 25 lane × 8 B。
#[derive(Clone, Debug)]
struct Keccak {
    state: [u64; 25],
    /// 当前块内已吸收字节数（挤出阶段为已挤出字节数），恒 < rate。
    pos: usize,
    rate: usize,
}

impl Keccak {
    fn new(rate: usize) -> Self {
        debug_assert!(rate <= 200 && rate.is_multiple_of(8));
        Keccak {
            state: [0; 25],
            pos: 0,
            rate,
        }
    }

    fn xor_into(state: &mut [u64; 25], start: usize, data: &[u8]) {
        for (j, &b) in data.iter().enumerate() {
            let i = start + j;
            state[i / 8] ^= (b as u64) << (8 * (i % 8));
        }
    }

    fn absorb(&mut self, mut data: &[u8]) {
        if self.pos > 0 {
            let take = core::cmp::min(self.rate - self.pos, data.len());
            Self::xor_into(&mut self.state, self.pos, &data[..take]);
            self.pos += take;
            data = &data[take..];
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
        while data.len() >= self.rate {
            Self::xor_into(&mut self.state, 0, &data[..self.rate]);
            keccak_f1600(&mut self.state);
            data = &data[self.rate..];
        }
        if !data.is_empty() {
            Self::xor_into(&mut self.state, 0, data);
            self.pos = data.len();
        }
    }

    /// 追加域分隔填充（`dom` 的两高位恒 0，`0x80` 置于块末字节；
    /// 两者落点重合时按位异或叠加）并执行一次置换，进入挤出阶段。
    fn pad(&mut self, dom: u8) {
        debug_assert!(self.pos < self.rate);
        Self::xor_into(&mut self.state, self.pos, &[dom]);
        Self::xor_into(&mut self.state, self.rate - 1, &[0x80]);
        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        let mut out = out;
        while !out.is_empty() {
            let take = core::cmp::min(self.rate - self.pos, out.len());
            for (j, b) in out[..take].iter_mut().enumerate() {
                let i = self.pos + j;
                *b = (self.state[i / 8] >> (8 * (i % 8))) as u8;
            }
            self.pos += take;
            out = &mut out[take..];
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }
}

macro_rules! xof_type {
    ($name:ident, $xof:ident, $rate:expr, $dom:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            k: Keccak,
        }

        impl $name {
            /// 新建吸收态实例。
            pub fn new() -> Self {
                $name {
                    k: Keccak::new($rate),
                }
            }

            /// 吸收一段输入（可多次调用，顺序敏感）。
            pub fn update(&mut self, data: &[u8]) {
                self.k.absorb(data);
            }

            /// 结束吸收（追加域分隔填充），返回可无限挤出的 XOF 读取端。
            pub fn finalize_xof(self) -> $xof {
                let mut k = self.k;
                k.pad($dom);
                $xof(k)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        #[doc = concat!("`", stringify!($name), "` 的挤出读取端（可重复调用 [`", stringify!($xof), "::fill`]）。")]
        #[derive(Debug, Clone)]
        pub struct $xof(Keccak);

        impl $xof {
            /// 挤出任意长度输出；可连续调用，输出流与一次性大缓冲一致。
            pub fn fill(&mut self, out: &mut [u8]) {
                self.0.squeeze(out);
            }
        }
    };
}

xof_type!(
    Shake128,
    Shake128Xof,
    168,
    0x1f,
    "SHAKE-128 可扩展输出函数（FIPS 202）：rate = 168 字节（c = 256）。"
);
xof_type!(
    Shake256,
    Shake256Xof,
    136,
    0x1f,
    "SHAKE-256 可扩展输出函数（FIPS 202）：rate = 136 字节（c = 512）。"
);

/// SHA3-256 一次性摘要（FIPS 202）。
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::new(136);
    k.absorb(data);
    k.pad(0x06);
    let mut out = [0u8; 32];
    k.squeeze(&mut out);
    out
}

/// SHA3-512 一次性摘要（FIPS 202）。
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut k = Keccak::new(72);
    k.absorb(data);
    k.pad(0x06);
    let mut out = [0u8; 64];
    k.squeeze(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 分块吸收 + 分块挤出必须与一次性等价（海绵边界回归）。
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..700u32).map(|i| i as u8).collect();

        for split in [0usize, 1, 63, 64, 65, 135, 136, 137, 699, 700] {
            let (a, b) = data.split_at(split);
            let mut s = Shake256::new();
            s.update(a);
            s.update(b);
            let mut x = s.finalize_xof();
            let mut chunked = [0u8; 100];
            x.fill(&mut chunked[..37]);
            x.fill(&mut chunked[37..]);
            let mut once = Shake256::new();
            once.update(&data);
            let mut direct = once.finalize_xof();
            let mut whole = [0u8; 100];
            direct.fill(&mut whole);
            assert_eq!(chunked, whole, "Shake256 split at {split}");
        }

        for split in [0usize, 1, 71, 72, 73, 135, 136, 137, 699] {
            let (a, b) = data.split_at(split);
            let mut s = Shake128::new();
            s.update(a);
            s.update(b);
            let mut x = s.finalize_xof();
            let mut chunked = [0u8; 500];
            x.fill(&mut chunked[..300]);
            x.fill(&mut chunked[300..]);
            let mut once = Shake128::new();
            once.update(&data);
            let mut direct = once.finalize_xof();
            let mut whole = [0u8; 500];
            direct.fill(&mut whole);
            assert_eq!(chunked, whole, "Shake128 split at {split}");
        }
    }

    /// FIPS 203 附录 A 的 ML-KEM 域分隔示例值（官方锚，
    /// 另经 python hashlib 与 RustCrypto ml-kem 测试常量交叉核对）。
    #[test]
    fn fips203_appendix_a_anchors() {
        let mut s = Shake128::new();
        s.update(b"Input rho, to an XOF invocation!");
        s.update(b"i");
        s.update(b"j");
        let mut x = s.finalize_xof();
        let mut out = [0u8; 32];
        x.fill(&mut out);
        assert_eq!(
            out.as_slice(),
            hex32("0d2c3e65f754d074cb366cf1b099ae105cc40f018342509f15f1ba8a1a4144cb")
        );

        let mut s = Shake256::new();
        s.update(b"Input s to an invocation of PRF2");
        s.update(b"b");
        let mut x = s.finalize_xof();
        let mut prf = [0u8; 128];
        x.fill(&mut prf);
        assert_eq!(&prf[..16], &hex32("54c002415c2219b564d5c17b0df0c82f")[..]);

        let mut s = Shake256::new();
        s.update(b"Input to an invocation of J");
        let mut x = s.finalize_xof();
        let mut j = [0u8; 32];
        x.fill(&mut j);
        assert_eq!(
            j.as_slice(),
            hex32("a5292293d70c8eca049cbb475c48fabd625ed2b20785a18248504d3741196b52")
        );
    }

    fn hex32(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
}
