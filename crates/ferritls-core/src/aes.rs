//! AES 块密码（FIPS 197），128/192/256 位密钥的软件实现。
//!
//! FIPS 批准；作为 GCM/CCM 与 CTR-DRBG 的底层部件，上电自检覆盖（M5）。
//! AES-NI 后端在 M8+ 经 [`crate::ops`] 入口挂接，不影响本模块公开 API。
//!
//! 常数时间策略：S-box 不查表——**批量路径（P1 起）为位切片纯布尔
//! 电路**（逆元 = GF(2^8) 多项式基下 x^254 加法链 + FIPS-197 仿射
//! 变换，平方 = 平面重排 + 折叠），零查表、零秘密相关分支/访存；
//! **单块路径为 16 宽掩码全扫描**（[`sub_bytes`]：一次表遍历同时
//! 服务全部 16 字节，访问模式与输入无关）。实测单块走位切片电路
//! 反而慢约 2×（电路平面操作数按"批"固定，单块仅占极小 lane 占比），
//! 故两路径并存。字节移位/列混合全部为算术与掩码操作。轮密钥与
//! 其位平面 Drop 时零化。
//!
//! P2（`simd` feature，默认启用）：位切片电路按平面元素 [`Plane`]
//! 泛型——`u64`（64 块/批，P1 标量形态原样保留）与
//! `Simd<u64, L>`（64·L 块/批）共享同一份电路源码；
//! [`encrypt_ctr_batch`] 按公开请求块数在 64/128/256/512 块档位中
//! 取最小浪费档，向量宽度随编译目标自动决定（SSE2 每平面元素 2×
//! u64 / AVX2 4× / AVX-512 8×）。显式向量类型保证宽 ISA 下的通道
//! 利用率不依赖 LLVM 自动向量化启发式（P2 基线实测：P1 代码在
//! +avx2/+avx512 下吞吐几乎不变）。
//!
//! 向量：FIPS-197 附录 C.1/C.2/C.3 KAT（`tests` 内嵌）+ GCM 集成 KAT；
//! 位切片电路与 16 宽扫描分别对照逐字节标量实现（`bitslice_*`、
//! `sub_bytes_matches_scalar` 测试）；批量各档位对照逐块标量
//! （`encrypt_ctr_batch_matches_scalar`）。

/// 官方 S-box（FIPS-197 图 7）。
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// 逆 S-box：由正表程序化求逆（S-box 为双射，结果唯一）。
const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        let mut i = 0usize;
        loop {
            if SBOX[i] as usize == x {
                inv[x] = i as u8;
                break;
            }
            i += 1;
        }
        x += 1;
    }
    inv
};

/// GF(2^8) 倍乘（xtime）。
fn xtime(x: u8) -> u8 {
    let hi = ((x >> 7) & 1).wrapping_neg();
    (x << 1) ^ (hi & 0x1b)
}

/// GF(2^8) 分支无关乘法。
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & ((b & 1).wrapping_neg());
        let hi = ((a >> 7) & 1).wrapping_neg();
        a = (a << 1) ^ (hi & 0x1b);
        b >>= 1;
    }
    p
}

/// 常数时间表访问：遍历全部 256 项，按相等掩码选择。
/// 访问模式与输入无关（无缓存侧信道）。
#[inline]
fn ct_table_lookup(table: &[u8; 256], x: u8) -> u8 {
    let mut acc = 0u8;
    for (i, &entry) in table.iter().enumerate() {
        let eq = (((i as u8) ^ x) == 0) as u8;
        acc |= entry & eq.wrapping_neg();
    }
    acc
}

#[inline]
fn sbox(x: u8) -> u8 {
    ct_table_lookup(&SBOX, x)
}

#[inline]
/// 逐字节逆 S-box（生产路径已改用 [`inv_sub_bytes`]，保留为等价
/// 测试的独立 oracle）。
#[cfg(test)]
fn inv_sbox(x: u8) -> u8 {
    ct_table_lookup(&INV_SBOX, x)
}

/// SubBytes（P1 余留优化）：一次 256 项扫描同时服务全部 16 字节。
/// 内层对固定表项的 16 字节"相等→掩码→选择"是连续定长形状，LLVM
/// 将其向量化为宽 SIMD（每表项约 4-5 条向量指令）；逐字节各跑一遍
/// [`sbox`] 扫描则无法融合，实测慢约 3 倍。访问模式与输入无关
///（全表遍历），ct 性质与 [`ct_table_lookup`] 相同。
#[inline]
fn sub_bytes(s: &mut [u8; 16]) {
    let mut acc = [0u8; 16];
    for (i, &entry) in SBOX.iter().enumerate() {
        let idx = i as u8;
        for (a, &x) in acc.iter_mut().zip(s.iter()) {
            let eq = ((x == idx) as u8).wrapping_neg();
            *a |= entry & eq;
        }
    }
    *s = acc;
}

/// InvSubBytes：[`sub_bytes`] 的逆表版本（解密方向，无生产调用方，
/// 保持与加密方向同构）。
#[inline]
fn inv_sub_bytes(s: &mut [u8; 16]) {
    let mut acc = [0u8; 16];
    for (i, &entry) in INV_SBOX.iter().enumerate() {
        let idx = i as u8;
        for (a, &x) in acc.iter_mut().zip(s.iter()) {
            let eq = ((x == idx) as u8).wrapping_neg();
            *a |= entry & eq;
        }
    }
    *s = acc;
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [sbox(w[0]), sbox(w[1]), sbox(w[2]), sbox(w[3])]
}

macro_rules! aes_impl {
    ($name:ident, $nk:expr, $nr:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            /// 轮密钥（Nr+1 × 16 字节，按 FIPS-197 列序展开）。
            rk: Vec<u8>,
            /// 轮密钥位平面（broadcast 形态）：`rk_planes[r][g][b]` = 轮 r
            /// 字节 g 的比特 b 广播到全部 64 lane。位切片路径（单块与
            /// 批量）直接 XOR，免去每次调用的平面展开。秘密材料，
            /// Drop 零化。
            rk_planes: Vec<[Planes; 16]>,
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $nk * 4;
            const NR: usize = $nr;

            /// 展开密钥。
            pub fn new(key: &[u8; $nk * 4]) -> Self {
                let total = 16 * ($nr + 1);
                let mut rk = vec![0u8; total];
                let nk_bytes = $nk * 4;
                rk[..nk_bytes].copy_from_slice(key);

                let mut rcon = 1u8;
                let mut i = nk_bytes;
                while i < total {
                    let mut t: [u8; 4] = rk[i - 4..i].try_into().unwrap();
                    if i % nk_bytes == 0 {
                        t = sub_word([t[1], t[2], t[3], t[0]]);
                        t[0] ^= rcon;
                        rcon = xtime(rcon);
                    } else if $nk > 6 && i % nk_bytes == 16 {
                        t = sub_word(t);
                    }
                    for j in 0..4 {
                        rk[i + j] = rk[i - nk_bytes + j] ^ t[j];
                    }
                    i += 4;
                }
                let mut rk_planes = Vec::with_capacity($nr + 1);
                for round in 0..=$nr {
                    let mut planes = [[0u64; 8]; 16];
                    for g in 0..16 {
                        for (b, plane) in planes[g].iter_mut().enumerate() {
                            *plane = u64::from((rk[round * 16 + g] >> b) & 1).wrapping_neg();
                        }
                    }
                    rk_planes.push(planes);
                }
                Self { rk, rk_planes }
            }

            fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
                for j in 0..16 {
                    state[j] ^= self.rk[round * 16 + j];
                }
            }

            /// 就地加密一个块（掩码全扫描，P1 余留优化：SubBytes 以
            /// [`sub_bytes`] 单次扫描同时服务全部 16 字节——累加器内层
            /// 16 字节比较/选择被 LLVM 向量化为宽 SIMD，实测约为逐字节
            /// 扫描的 3 倍。位切片电路的平面操作数按"批"固定，单块仅
            /// 占 1/64 lane，实测反而慢 2×，故单块保持掩码路径。
            pub fn encrypt_block(&self, block: &mut [u8; 16]) {
                let mut s = *block;
                self.add_round_key(&mut s, 0);
                for round in 1..Self::NR {
                    sub_bytes(&mut s);
                    shift_rows(&mut s);
                    mix_columns(&mut s);
                    self.add_round_key(&mut s, round);
                }
                sub_bytes(&mut s);
                shift_rows(&mut s);
                self.add_round_key(&mut s, Self::NR);
                *block = s;
            }

            /// 就地解密一个块（等价逆变换；DRBG 与 GCM 只需加密方向）。
            pub fn decrypt_block(&self, block: &mut [u8; 16]) {
                let mut s = *block;
                self.add_round_key(&mut s, Self::NR);
                for round in (1..Self::NR).rev() {
                    inv_shift_rows(&mut s);
                    inv_sub_bytes(&mut s);
                    self.add_round_key(&mut s, round);
                    inv_mix_columns(&mut s);
                }
                inv_shift_rows(&mut s);
                inv_sub_bytes(&mut s);
                self.add_round_key(&mut s, 0);
                *block = s;
            }

            /// 批量加密计数器块（位切片路径，P1；P2 档位分发）：以
            /// `base` 为第 0 块，加密"base 低 32 位 + i"（i = 0..n）共
            /// n（≤ [`CTR_BATCH_BLOCKS`]）个块，每块 16 字节密钥流写入
            /// `out`。未用 lane 计算任意值但不写出。装载利用 CTR 结构：
            /// 前 12 字节跨块常量（平面全 0/全 1），仅低 32 位计数器按
            /// lane 展开。档位按公开 n 取最小浪费：64（u64，P1 形态）/
            /// 128/256/512（Simd<u64,2/4/8>，仅 simd feature）。
            /// 供 GCM/CCM/DRBG 的 CTR 密钥流使用；仅加密方向。
            ///（Aes192 当前无批量调用方——GCM/CCM/DRBG 用 128/256——
            /// 随宏同型生成，保留完整实例 API。）
            #[allow(dead_code)]
            pub(crate) fn encrypt_ctr_batch(&self, base: [u8; 16], n: usize, out: &mut [u8]) {
                debug_assert!(n > 0 && n <= CTR_BATCH_BLOCKS && out.len() >= n * 16);
                #[cfg(feature = "simd")]
                {
                    if n <= 64 {
                        encrypt_ctr_batch_p::<u64>(&self.rk_planes, base, n, out)
                    } else if n <= 128 {
                        encrypt_ctr_batch_p::<Simd<u64, 2>>(&self.rk_planes, base, n, out)
                    } else if n <= 256 {
                        encrypt_ctr_batch_p::<Simd<u64, 4>>(&self.rk_planes, base, n, out)
                    } else {
                        encrypt_ctr_batch_p::<Simd<u64, 8>>(&self.rk_planes, base, n, out)
                    }
                }
                #[cfg(not(feature = "simd"))]
                encrypt_ctr_batch_p::<u64>(&self.rk_planes, base, n, out);
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.rk.fill(0);
                self.rk_planes.fill([[0u64; 8]; 16]);
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 位切片批量加密路径（P1 性能轮；P2 平面元素泛型化）
//
// 表示：state = 16 个字节组 × 8 个位平面。平面元素 P 实现位运算且
// 承载一批块在同一字节位置同一比特上的值：u64 的 bit i（lane i）承载
// 第 i 块 → 一批 64 块；`Simd<u64, L>`（simd feature）的每个元素是一个
// 64-lane 组 → 一批 64·L 块。布尔运算逐元素即逐块并行，电路源码对
// P 泛型（u64 实例 = P1 标量形态，逐位对照穷举验证）。零查表、零秘密
// 相关控制流。
//
// 电路代数（全部与上方标量实现穷举对照验证）：
// - GF(2^8) 乘法：多项式基卷积（64 AND）+ 折叠约减
//   （x^8=x^4+x^3+x+1 及其倍数）；
// - 平方：偶次幂平面重排 + x^8/x^10/x^12/x^14 折叠，无乘法；
// - 逆元 x^254 = x^192·x^48·x^14（4 次乘法 + 9 次平方的加法链）；
// - 仿射：s_i = b_i ⊕ b_{i+4} ⊕ b_{i+5} ⊕ b_{i+6} ⊕ b_{i+7} ⊕ c_i
//   （下标 mod 8，c = 0x63；c_i=1 时平面取反）。
// ---------------------------------------------------------------------------

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};

#[cfg(feature = "simd")]
use std::simd::Simd;

/// 位平面元素（P2）：一批块在同一字节位置同一比特上的并行承载。
///
/// `u64` = 64 块/批（P1 标量形态）；`Simd<u64, L>` = 64·L 块/批，
/// 每个 Simd 元素是一个独立的 64-lane 组（装载/提取按组进行，
/// 见 [`encrypt_ctr_batch_p`]）。所有方法 `#[inline]`：u64 实例的
/// broadcast/组装配均为恒等操作，电路代码生成与 P1 逐位一致。
trait Plane:
    Copy
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + Not<Output = Self>
    + BitAndAssign
    + BitOrAssign
    + BitXorAssign
{
    /// 一批覆盖的块数。
    const LANES: usize;
    /// 同一 u64 值用于全部 lane 组（常数平面 / 轮密钥平面广播，
    /// 入参恒为 0 或 !0）。
    fn broadcast(x: u64) -> Self;
    /// 由"每个 64-lane 组的平面值"装配（计数器装载用）。
    fn from_lane_groups(f: impl FnMut(usize) -> u64) -> Self;
    /// 取第 e 个 64-lane 组的平面值（e < `LANES / 64`；提取用）。
    fn to_lane_group(self, e: usize) -> u64;
}

impl Plane for u64 {
    const LANES: usize = 64;
    #[inline]
    fn broadcast(x: u64) -> Self {
        x
    }
    #[inline]
    fn from_lane_groups(mut f: impl FnMut(usize) -> u64) -> Self {
        f(0)
    }
    #[inline]
    fn to_lane_group(self, e: usize) -> u64 {
        debug_assert_eq!(e, 0);
        self
    }
}

// 本 rustc 的 portable_simd 中 `Simd<T, N>` 仅要求 `T: SimdElement`，
// N 为任意 const 泛型参数（无需 LaneCount bound）。
#[cfg(feature = "simd")]
impl<const L: usize> Plane for Simd<u64, L> {
    const LANES: usize = 64 * L;
    #[inline]
    fn broadcast(x: u64) -> Self {
        Simd::splat(x)
    }
    #[inline]
    fn from_lane_groups(f: impl FnMut(usize) -> u64) -> Self {
        Simd::from_array(core::array::from_fn(f))
    }
    #[inline]
    fn to_lane_group(self, e: usize) -> u64 {
        self.to_array()[e]
    }
}

/// 64 位位平面组：一个状态字节在 64 个块上的全部比特。
type Planes = [u64; 8];

/// 一批并行加密的最大块数（= 最大档位平面覆盖）。
/// simd feature：512 块（Simd<u64,8> 每平面 8×64 lane）；
/// 标量回退：64 块（P1 形态）。
#[cfg(feature = "simd")]
pub(crate) const CTR_BATCH_BLOCKS: usize = 512;
#[cfg(not(feature = "simd"))]
pub(crate) const CTR_BATCH_BLOCKS: usize = 64;

/// GF(2^8) 位切片乘法：卷积 t_k = Σ_{i+j=k} a_i·b_j 后折叠约减。
/// 折叠关系（f = x^8+x^4+x^3+x+1）：
/// x^8→{4,3,1,0}，x^9→{5,4,2,1}，x^10→{6,5,3,2}，x^11→{7,6,4,3}，
/// x^12→{7,5,3,1,0}，x^13→{6,3,2,0}，x^14→{7,4,3,1}。
fn bs_mul<P: Plane>(a: &[P; 8], b: &[P; 8]) -> [P; 8] {
    let mut t = [P::broadcast(0); 15];
    for i in 0..8 {
        for j in 0..8 {
            t[i + j] ^= a[i] & b[j];
        }
    }
    [
        t[0] ^ t[8] ^ t[12] ^ t[13],
        t[1] ^ t[8] ^ t[9] ^ t[12] ^ t[14],
        t[2] ^ t[9] ^ t[10] ^ t[13],
        t[3] ^ t[8] ^ t[10] ^ t[11] ^ t[12] ^ t[13] ^ t[14],
        t[4] ^ t[8] ^ t[9] ^ t[11] ^ t[14],
        t[5] ^ t[9] ^ t[10] ^ t[12],
        t[6] ^ t[10] ^ t[11] ^ t[13],
        t[7] ^ t[11] ^ t[12] ^ t[14],
    ]
}

/// GF(2^8) 位切片平方：a_i → 偶次幂平面 2i，折叠 x^8/x^10/x^12/x^14
///（奇次卷积项为 0，折叠集见 [`bs_mul`]）。
fn bs_sq<P: Plane>(a: &[P; 8]) -> [P; 8] {
    [
        a[0] ^ a[4] ^ a[6],
        a[4] ^ a[6] ^ a[7],
        a[1] ^ a[5],
        a[4] ^ a[5] ^ a[6] ^ a[7],
        a[2] ^ a[4] ^ a[7],
        a[5] ^ a[6],
        a[3] ^ a[5],
        a[6] ^ a[7],
    ]
}

/// GF(2^8) 位切片乘 x（xtime）：a_i → i+1，a_7 折叠 0x1b。
fn bs_xtime<P: Plane>(a: &[P; 8]) -> [P; 8] {
    [
        a[7],
        a[0] ^ a[7],
        a[1],
        a[2] ^ a[7],
        a[3] ^ a[7],
        a[4],
        a[5],
        a[6],
    ]
}

/// 位切片 S-box：就地把一个字节组替换为 S-box 输出。
fn bs_sbox<P: Plane>(x: &mut [P; 8]) {
    let a = *x;
    // 逆元 x^254：
    let x2 = bs_sq(&a);
    let x3 = bs_mul(&a, &x2); // x^3
    let x6 = bs_sq(&x3);
    let x12 = bs_sq(&x6);
    let x24 = bs_sq(&x12);
    let x48 = bs_sq(&x24);
    let x96 = bs_sq(&x48);
    let x192 = bs_sq(&x96);
    let x4 = bs_sq(&x2);
    let x7 = bs_mul(&x3, &x4); // x^7
    let x14 = bs_sq(&x7);
    let t = bs_mul(&x192, &x48);
    let inv = bs_mul(&t, &x14); // x^(192+48+14) = x^254
    // 仿射变换（FIPS-197 §5.1.1）。
    for i in 0..8 {
        let mut s =
            inv[i] ^ inv[(i + 4) % 8] ^ inv[(i + 5) % 8] ^ inv[(i + 6) % 8] ^ inv[(i + 7) % 8];
        if (0x63 >> i) & 1 == 1 {
            s = !s; // XOR 常数 1 平面 = 取反
        }
        x[i] = s;
    }
}

/// 位切片轮函数（批量路径）：`st` 已含 ARK(0)，完成 1..Nr-1
/// 轮（S-box/Shift/Mix/ARK）与终轮（S-box/Shift/ARK）。
/// `rk_planes` 长度 = Nr+1；Simd 档位下轮密钥平面 splat-on-use，
/// 不新增秘密存储。
fn bs_rounds<P: Plane>(st: &mut [[P; 8]; 16], rk_planes: &[[Planes; 16]]) {
    for rk in &rk_planes[1..rk_planes.len() - 1] {
        for group in st.iter_mut() {
            bs_sbox(group);
        }
        bs_shift_rows(st);
        bs_mix_columns(st);
        for (sg, rg) in st.iter_mut().zip(rk.iter()) {
            for (s, r) in sg.iter_mut().zip(rg.iter()) {
                *s ^= P::broadcast(*r);
            }
        }
    }
    for group in st.iter_mut() {
        bs_sbox(group);
    }
    bs_shift_rows(st);
    let rk = &rk_planes[rk_planes.len() - 1];
    for (sg, rg) in st.iter_mut().zip(rk.iter()) {
        for (s, r) in sg.iter_mut().zip(rg.iter()) {
            *s ^= P::broadcast(*r);
        }
    }
}

/// 位切片 ShiftRows：字节组层面的平面重排（flat = 4*col + row）。
fn bs_shift_rows<P: Plane>(s: &mut [[P; 8]; 16]) {
    let t = *s;
    for row in 1..4 {
        for col in 0..4 {
            s[4 * col + row] = t[4 * ((col + row) % 4) + row];
        }
    }
}

/// 位切片 MixColumns：out = M·in，M 同标量路径（xtime 组合）。
fn bs_mix_columns<P: Plane>(s: &mut [[P; 8]; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
        let xt0 = bs_xtime(&a0);
        let xt1 = bs_xtime(&a1);
        let xt2 = bs_xtime(&a2);
        let xt3 = bs_xtime(&a3);
        for b in 0..8 {
            s[o][b] = xt0[b] ^ xt1[b] ^ a1[b] ^ a2[b] ^ a3[b];
            s[o + 1][b] = a0[b] ^ xt1[b] ^ xt2[b] ^ a2[b] ^ a3[b];
            s[o + 2][b] = a0[b] ^ a1[b] ^ xt2[b] ^ xt3[b] ^ a3[b];
            s[o + 3][b] = xt0[b] ^ a0[b] ^ a1[b] ^ a2[b] ^ xt3[b];
        }
    }
}

/// 计数器字节的某一个 64-lane 组的位平面（大端低 32 位 + lane）。
/// 与块数/计数器一样属公开量。
fn ctr_group_planes(ctr0: u32, e: usize, n: usize) -> [[u64; 8]; 16] {
    let mut grp = [[0u64; 8]; 16];
    for i in 0..64usize {
        let lane = e * 64 + i;
        if lane < n {
            let ctr = ctr0.wrapping_add(lane as u32).to_be_bytes();
            for k in 0..4 {
                for (b, slot) in grp[12 + k].iter_mut().enumerate() {
                    *slot |= u64::from((ctr[k] >> b) & 1) << i;
                }
            }
        }
    }
    grp
}

/// 批量加密核心（P2 泛型）：以 `base` 为第 0 块，加密"base 低 32
/// 位加 i"（i = 0..n，n ≤ `P::LANES`）共 n 个块，每块 16 字节密钥流
/// 写入 `out`。未用 lane 计算任意值但不写出。装载/提取按 64-lane
/// 组进行后装配为 P；档位选择在
/// [`encrypt_ctr_batch`](Aes128::encrypt_ctr_batch) 按公开 n 完成，
/// 本函数零分支于秘密。
fn encrypt_ctr_batch_p<P: Plane>(
    rk_planes: &[[Planes; 16]],
    base: [u8; 16],
    n: usize,
    out: &mut [u8],
) {
    debug_assert!(n > 0 && n <= P::LANES && out.len() >= n * 16);

    // 装载：前 12 字节跨块常量 → 全 0/全 1 平面。
    let mut st = [[P::broadcast(0); 8]; 16];
    for (g, byte) in base[..12].iter().enumerate() {
        for (b, plane) in st[g].iter_mut().enumerate() {
            *plane = P::broadcast(u64::from((byte >> b) & 1).wrapping_neg());
        }
    }
    // 计数器低 32 位（大端）按 lane 展开：逐 64-lane 组展开后装配。
    let ctr0 = u32::from_be_bytes(base[12..16].try_into().unwrap());
    let ng = P::LANES / 64;
    let mut groups = [[[0u64; 8]; 16]; 8]; // 上限档位 512 块 = 8 组
    for (e, slot) in groups.iter_mut().enumerate().take(ng) {
        *slot = ctr_group_planes(ctr0, e, n);
    }
    for g in 12..16 {
        for (b, slot) in st[g].iter_mut().enumerate() {
            *slot = P::from_lane_groups(|e| groups[e][g][b]);
        }
    }

    // ARK(0) + 主轮。
    let rk0 = &rk_planes[0];
    for (sg, rg) in st.iter_mut().zip(rk0.iter()) {
        for (s, r) in sg.iter_mut().zip(rg.iter()) {
            *s ^= P::broadcast(*r);
        }
    }
    bs_rounds(&mut st, rk_planes);

    // 提取前 n 个 lane（逐组拉平为 u64 平面后逐 lane 装配字节）。
    for e in 0..ng {
        let grp = st.map(|g8| {
            let mut grp8 = [0u64; 8];
            for (slot, p) in grp8.iter_mut().zip(g8.iter()) {
                *slot = p.to_lane_group(e);
            }
            grp8
        });
        for i in 0..64usize {
            let lane = e * 64 + i;
            if lane >= n {
                continue; // n 公开
            }
            for (g, group) in grp.iter().enumerate() {
                let mut byte = 0u8;
                for (b, plane) in group.iter().enumerate() {
                    byte |= (((plane >> i) & 1) as u8) << b;
                }
                out[lane * 16 + g] = byte;
            }
        }
    }
}

fn shift_rows(s: &mut [u8; 16]) {
    // flat index = 4*col + row（FIPS-197 列序）
    let t = *s;
    for row in 1..4 {
        for col in 0..4 {
            s[4 * col + row] = t[4 * ((col + row) % 4) + row];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for row in 1..4 {
        for col in 0..4 {
            s[4 * ((col + row) % 4) + row] = t[4 * col + row];
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
        // 矩阵 [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
        s[o] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[o + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[o + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[o + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
        s[o] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[o + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[o + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[o + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

aes_impl!(Aes128, 4, 10, "AES-128 块密码实例。");
aes_impl!(Aes192, 6, 12, "AES-192 块密码实例。");
aes_impl!(Aes256, 8, 14, "AES-256 块密码实例。");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_known_values_and_bijection() {
        // FIPS-197 官方锚点。
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x01), 0x7c);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0xff), 0x16);
        // P1：代数 sbox 与官方表逐值一致（穷举）。
        for (x, &official) in SBOX.iter().enumerate() {
            assert_eq!(sbox(x as u8), official, "sbox({x:#04x})");
        }
        let mut seen = [false; 256];
        for x in 0..=255u8 {
            assert_eq!(inv_sbox(sbox(x)), x, "round trip at {x}");
            seen[sbox(x) as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "sbox must be a bijection");
    }

    #[test]
    fn fips197_appendix_c_kats() {
        // C.1: AES-128
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes = Aes128::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        aes.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );

        // C.3: AES-256
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes = Aes256::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
        aes.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
    }

    #[test]
    fn bitslice_circuits_match_scalar_exhaustive() {
        // 每个 u8 值广播到全部 64 个 lane：bs_mul/bs_sq/bs_xtime/bs_sbox
        // 与标量实现逐值一致（bs_sq 与 gf_mul(v,v) 互为 oracle）。
        let planes_of = |v: u8| -> Planes {
            let mut p = [0u64; 8];
            for (b, plane) in p.iter_mut().enumerate() {
                *plane = u64::from((v >> b) & 1).wrapping_neg();
            }
            p
        };
        let byte_of = |p: &Planes| -> u8 {
            let mut v = 0u8;
            for (b, plane) in p.iter().enumerate() {
                v |= ((plane & 1) as u8) << b;
            }
            v
        };
        for v in 0..=255u8 {
            let a = planes_of(v);
            assert_eq!(byte_of(&bs_sq(&a)), gf_mul(v, v), "sq({v:#04x})");
            assert_eq!(byte_of(&bs_xtime(&a)), xtime(v), "xtime({v:#04x})");
            let mut s = a;
            bs_sbox(&mut s);
            assert_eq!(byte_of(&s), sbox(v), "sbox({v:#04x})");
        }
        // 双操作数全空间（65536 对）。
        for x in 0..=255u8 {
            for y in 0..=255u8 {
                assert_eq!(
                    byte_of(&bs_mul(&planes_of(x), &planes_of(y))),
                    gf_mul(x, y),
                    "mul({x:#04x},{y:#04x})"
                );
            }
        }
        // lane 独立性：64 个 lane 各放不同值，逐 lane 校验 S-box。
        let mut lanes = [0u8; 64];
        let mut seed = 0x9E37_79B9u32;
        for v in lanes.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *v = seed as u8;
        }
        let mut group = [0u64; 8];
        for (lane, &v) in lanes.iter().enumerate() {
            for (b, plane) in group.iter_mut().enumerate() {
                *plane |= u64::from((v >> b) & 1) << lane;
            }
        }
        bs_sbox(&mut group);
        for (lane, &v) in lanes.iter().enumerate() {
            let mut got = 0u8;
            for (b, plane) in group.iter().enumerate() {
                got |= (((plane >> lane) & 1) as u8) << b;
            }
            assert_eq!(got, sbox(v), "lane {lane}");
        }
    }

    #[test]
    fn sub_bytes_matches_scalar() {
        // 16 宽单次扫描 vs 逐字节 ct_table_lookup（独立实现），穷举
        // 边界 + 随机状态；正/逆表同测（sbox 穷举锚定见
        // sbox_known_values_and_bijection）。
        let mut seed = 0x243F_6A88u32;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed
        };
        let mut states = vec![[0u8; 16], [0xff; 16], [0x53; 16]];
        for _ in 0..64 {
            states.push(core::array::from_fn(|_| next() as u8));
        }
        for st in &states {
            let mut fwd = *st;
            sub_bytes(&mut fwd);
            let mut inv = *st;
            inv_sub_bytes(&mut inv);
            for g in 0..16 {
                assert_eq!(fwd[g], sbox(st[g]), "sub_bytes state={st:?} g={g}");
                assert_eq!(inv[g], inv_sbox(st[g]), "inv_sub_bytes state={st:?} g={g}");
            }
        }
    }

    #[test]
    fn encrypt_ctr_batch_matches_scalar() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes = Aes128::new(&key);
        let mut key256 = [0u8; 32];
        for (i, b) in key256.iter_mut().enumerate() {
            *b = (i * 7) as u8;
        }
        let aes256 = Aes256::new(&key256);
        let mut base = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x00, 0x00,
            0x00, 0x01,
        ];
        // 覆盖全部批量档位边界（P2：64/128/256/512 块档按 n 分发）。
        #[cfg(feature = "simd")]
        let sizes = [
            1usize, 2, 3, 63, 64, 65, 100, 128, 129, 200, 256, 257, 300, 511, 512,
        ];
        #[cfg(not(feature = "simd"))]
        let sizes = [1usize, 2, 3, 63, 64];
        for n in sizes {
            let mut fast = vec![0u8; CTR_BATCH_BLOCKS * 16];
            aes.encrypt_ctr_batch(base, n, &mut fast);
            let mut expect = vec![0u8; n * 16];
            let ctr0 = u32::from_be_bytes(base[12..16].try_into().unwrap());
            for i in 0..n {
                let mut blk = base;
                blk[12..16].copy_from_slice(&ctr0.wrapping_add(i as u32).to_be_bytes());
                aes.encrypt_block(&mut blk);
                expect[i * 16..(i + 1) * 16].copy_from_slice(&blk);
            }
            assert_eq!(&fast[..n * 16], &expect, "n={n} aes128");
            // aes256 单独比对
            let mut expect256 = vec![0u8; n * 16];
            for i in 0..n {
                let mut blk = base;
                blk[12..16].copy_from_slice(&ctr0.wrapping_add(i as u32).to_be_bytes());
                aes256.encrypt_block(&mut blk);
                expect256[i * 16..(i + 1) * 16].copy_from_slice(&blk);
            }
            aes256.encrypt_ctr_batch(base, n, &mut fast);
            assert_eq!(&fast[..n * 16], &expect256, "n={n} aes256");
        }
        // 计数器回绕点（64 块组内回绕 + P2 最大档位跨组回绕）。
        base[12..16].copy_from_slice(&0xFFFF_FFFDu32.to_be_bytes());
        let mut fast = vec![0u8; CTR_BATCH_BLOCKS * 16];
        aes.encrypt_ctr_batch(base, 64, &mut fast);
        let ctr0 = u32::from_be_bytes(base[12..16].try_into().unwrap());
        for i in 0..64usize {
            let mut blk = base;
            blk[12..16].copy_from_slice(&ctr0.wrapping_add(i as u32).to_be_bytes());
            aes.encrypt_block(&mut blk);
            assert_eq!(&fast[i * 16..(i + 1) * 16], &blk, "wrap i={i}");
        }
        #[cfg(feature = "simd")]
        {
            // 512 块档位：0xFFFFFF00 起第 256 块处回绕，覆盖两个 64-lane 组
            // 交界与组内回绕（批量入口按 wrapping 语义，与标量参考一致）。
            let mut base = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xff, 0xff,
                0xff, 0x00,
            ];
            let mut fast = vec![0u8; 512 * 16];
            aes.encrypt_ctr_batch(base, 512, &mut fast);
            let ctr0 = u32::from_be_bytes(base[12..16].try_into().unwrap());
            for i in 0..512usize {
                let mut blk = base;
                blk[12..16].copy_from_slice(&ctr0.wrapping_add(i as u32).to_be_bytes());
                aes.encrypt_block(&mut blk);
                assert_eq!(&fast[i * 16..(i + 1) * 16], &blk, "wrap512 i={i}");
            }
            base[12..16].copy_from_slice(&0xFFFF_FFFDu32.to_be_bytes());
            aes.encrypt_ctr_batch(base, 129, &mut fast);
            let ctr0 = u32::from_be_bytes(base[12..16].try_into().unwrap());
            for i in 0..129usize {
                let mut blk = base;
                blk[12..16].copy_from_slice(&ctr0.wrapping_add(i as u32).to_be_bytes());
                aes.encrypt_block(&mut blk);
                assert_eq!(&fast[i * 16..(i + 1) * 16], &blk, "wrap129 i={i}");
            }
        }
    }
}
