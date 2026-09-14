//! FIPS 203：ML-KEM 模格 KEM——全部三个参数集（M8.3 起 768，
//! M8.4 泛化为 512/768/1024）。
//!
//! 算法逐条对应 FIPS 203 的 K-PKE（算法 12–14）与 ML-KEM（算法
//! 15–17）：KeyGen 以 `(d, z)` 种子展开，Encaps 前做 §7.2 封装密钥
//! 检查（长度 + 解码系数全部落在 [0, q) 的模校验，由
//! [`MlkemEncapsKey::from_bytes`] 承载），Decaps 为 FO 变换 +
//! **隐式拒绝**——重加密密文比较经 `subtle` 常数时间完成后以
//! `conditional_select` 选择（K′ / K̃ = J(z‖c)），无分支实现。
//!
//! 参数化形态：du = 10、dv = 4、η₂ = 2 三集共享，差异在 k 与 η₁
//! （512 ↔ k = 2, **η₁ = 3**；768 ↔ k = 3, η₁ = 2；1024 ↔ k = 4,
//! η₁ = 2）。引擎以**运行时 k 与 η₁** 工作（k 上限 [`K_MAX`]，中间
//! 缓冲按最大档定容，零堆分配；两者都是公开的参数集信息，不构成
//! 侧信道面）；公开类型以**裸 const 长度参数**
//! （EK/DK/CT 字节数）参数化，per-set 入口在子模块
//! [`k512`]/[`k768`]/[`k1024`]——stable 工具链约束下的选择，不依赖
//! `generic_const_exprs`（长度表达式中不允许出现 const 参数）。
//! ML-KEM-768 的 M8.3 公共 API（`Mlkem768*` 别名 + 顶层函数）原样
//! 保留。
//!
//! 与 Kyber Round-3 **不兼容**（矩阵采样 `Â[i][j] = SampleNTT(XOF(ρ‖j‖i))`
//! 的输入顺序等差异）；一致性以 NIST ACVP 向量为最终仲裁
//! （`tests/mlkem_acvp.rs`，三参数集，溯源见
//! docs/VECTOR-PROVENANCE.md）。
//!
//! 常数时间：NTT zeta/γ 表索引为公开循环计数（表内容为公开常数）；
//! SampleNTT 拒绝循环与 CBD 位运算只依赖公开 XOF/PRF 输出（变量时间
//! 可接受）；模约减为纯算术掩码修正，无秘密分支。秘密（dk、ss、
//! K′/K̃、ŝ、种子）`Drop` 时零化。
//!
//! 本模块使用 [`crate::sha3`] 的 FIPS 202 原语：`G` = SHA3-512、
//! `H` = SHA3-256、`J`/`PRF` = SHAKE-256、`XOF` = SHAKE-128。

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::Error;
use crate::sha3::{Shake128, Shake256, sha3_256, sha3_512};

/// k 上限 = 4（ML-KEM-1024）；引擎中间缓冲按此定容。
const K_MAX: usize = 4;
/// ek 最大长度（ML-KEM-1024：384·4 + 32 = 1568 字节）。
const EK_MAX: usize = 384 * K_MAX + 32;
/// dk_PKE 最大长度（1536 字节）。
const DK_PKE_MAX: usize = 384 * K_MAX;
/// dk 最大长度（ML-KEM-1024：dk_PKE‖ek‖H(ek)‖z = 3168 字节）。
const DK_MAX: usize = DK_PKE_MAX + EK_MAX + 64;
/// 密文最大长度（ML-KEM-1024：32·(10·4 + 4) = 1408 字节）。
const CT_MAX: usize = 32 * (11 * K_MAX + 5);

const Q: i32 = 3329;
/// η₂ 三集共享（= 2）；η₁/du/dv 按参数集取值，见 [`fips203_params`]
/// ——FIPS 203 §8 参数表是该函数的唯一出处，勿在别处硬编码。
const ETA2: usize = 2;
const PRF_LEN_MAX: usize = 192;

/// FIPS 203 §8 参数表（全部三个参数集的差异都在这里），返回
/// (η₁, du, dv)：
///
/// | 参数集      | k | η₁ | du | dv |   ek |   dk |   ct |
/// | ML-KEM-512  | 2 | 3  | 10 | 4  |  800 | 1632 |  768 |
/// | ML-KEM-768  | 3 | 2  | 10 | 4  | 1184 | 2400 | 1088 |
/// | ML-KEM-1024 | 4 | 2  | 11 | 5  | 1568 | 3168 | 1568 |
///
/// 注意 512 与 1024 各藏一个"例外参数"（512 的 η₁ = 3；1024 的
/// (du, dv) = (11, 5)）——从 768 泛化时最容易漏掉的两处，ACVP 向量
/// 均已逐字节拦截。
const fn fips203_params(k: usize) -> (usize, usize, usize) {
    match k {
        2 => (3, 10, 4),
        3 => (2, 10, 4),
        4 => (2, 11, 5),
        _ => (0, 0, 0),
    }
}

/// GF(3329) 上的多项式（256 系数）。
type Poly = [i16; 256];

// ---------------------------------------------------------------------------
// 模算术（Barrett，纯算术无分支）
// ---------------------------------------------------------------------------

/// 带符号 Barrett 约减到 [0, q)，输入 |a| ≤ 2.2·10⁷（本模块全部调用
/// 点的乘积上界 2·3328²）。
///
/// `V = ⌊2²⁶/q⌋ + 1`：舍入项 a·(V/2²⁶ − 1/q) ≤ 0.381，故
/// t = round(a·V/2²⁶) ∈ {⌊a/q⌋, ⌈a/q⌉}，r = a − t·q ∈ [−q, q)，经
/// 两次符号/进位掩码修正落入 [0, q)。全程数据无关固定指令序列
/// （无除法指令、无分支）。
#[inline]
fn barrett(a: i32) -> i16 {
    const V: i64 = ((1i64 << 26) / (Q as i64)) + 1;
    let t = ((i64::from(a) * V + (1 << 25)) >> 26) as i32;
    let mut r = a - t * Q;
    let neg = (r >> 31) & 1;
    r += Q * neg; // r ∈ [0, q+1)
    let over = ((Q - 1 - r) >> 31) & 1;
    r -= Q * over; // r ∈ [0, q)
    r as i16
}

/// NTT 域逐点基例乘（FIPS 203 算法 12）：γᵢ = ζ^(2·BitRev₇(i)+1)。
#[inline]
fn base_mul(a0: i16, a1: i16, b0: i16, b1: i16, gamma: i16) -> (i16, i16) {
    let (a0, a1, b0, b1, g) = (
        i32::from(a0),
        i32::from(a1),
        i32::from(b0),
        i32::from(b1),
        i32::from(gamma),
    );
    let b1g = i32::from(barrett(b1 * g));
    (barrett(a0 * b0 + a1 * b1g), barrett(a0 * b1 + a1 * b0))
}

// ---------------------------------------------------------------------------
// zeta / gamma 表（编译期生成；公开常数，索引 = 公开循环计数）
// ---------------------------------------------------------------------------

const fn bitrev7(x: usize) -> usize {
    (x & 1) << 6
        | (x >> 1 & 1) << 5
        | (x >> 2 & 1) << 4
        | (x >> 3 & 1) << 3
        | (x >> 4 & 1) << 2
        | (x >> 5 & 1) << 1
        | x >> 6 & 1
}

const fn zeta_pows() -> [i16; 128] {
    let mut pow = [0i16; 128];
    let mut cur: i64 = 1;
    let mut i = 0;
    while i < 128 {
        pow[i] = cur as i16;
        cur = cur * 17 % (Q as i64);
        i += 1;
    }
    pow
}

/// `ZETA_POW_BITREV[i] = ζ^BitRev₇(i)`（ζ = 17；与 FIPS 203 附录 A 一致）。
const ZETA_POW_BITREV: [i16; 128] = {
    let pow = zeta_pows();
    let mut out = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        out[i] = pow[bitrev7(i)];
        i += 1;
    }
    out
};

/// `GAMMA[i] = ζ^(2·BitRev₇(i)+1)`（FIPS 203 算法 12 用）。
const GAMMA: [i16; 128] = {
    let mut out = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        let z = ZETA_POW_BITREV[i] as i64;
        out[i] = (z * z * 17 % (Q as i64)) as i16;
        i += 1;
    }
    out
};

// ---------------------------------------------------------------------------
// NTT（FIPS 203 算法 9/10）
// ---------------------------------------------------------------------------

/// 正向 NTT：7 层蝶形，zeta 索引 1..=127 递增。
fn ntt(f: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = i32::from(ZETA_POW_BITREV[k]);
            k += 1;
            for j in start..start + len {
                let t = barrett(zeta * i32::from(f[j + len]));
                let a = i32::from(f[j]);
                f[j + len] = barrett(a - i32::from(t));
                f[j] = barrett(a + i32::from(t));
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// 逆向 NTT（FIPS 203 算法 10，含末尾 ×3303 的规范缩放——该常数为
/// 标准原文所载，等价于层因子约定下的 n⁻¹ 修正）。
fn ntt_inverse(f: &mut Poly) {
    const SCALE: i32 = 3303;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < 256 {
            let zeta = i32::from(ZETA_POW_BITREV[k]);
            k -= 1;
            for j in start..start + len {
                let t = i32::from(f[j]);
                let b = i32::from(f[j + len]);
                f[j] = barrett(t + b);
                f[j + len] = barrett(zeta * (b - t));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = barrett(SCALE * i32::from(*c));
    }
}

/// NTT 域多项式逐点乘（成对基例乘，FIPS 203 算法 11）。
fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let mut out = [0i16; 256];
    for i in 0..128 {
        let (c0, c1) = base_mul(a[2 * i], a[2 * i + 1], b[2 * i], b[2 * i + 1], GAMMA[i]);
        out[2 * i] = c0;
        out[2 * i + 1] = c1;
    }
    out
}

fn poly_add(dst: &mut Poly, addend: &Poly) {
    for (x, y) in dst.iter_mut().zip(addend.iter()) {
        *x = barrett(i32::from(*x) + i32::from(*y));
    }
}

// ---------------------------------------------------------------------------
// 采样（SampleNTT / SamplePolyCBD；输入均为公开 XOF/PRF 输出）
// ---------------------------------------------------------------------------

/// FIPS 203 算法 7：从 XOF 流拒绝采样一致分布系数。96 字节缓冲
/// （64 系数/轮）滚动挤出；拒绝仅依赖公开输出。
fn sample_ntt(xof: &mut crate::sha3::Shake128Xof) -> Poly {
    let mut out = [0i16; 256];
    let mut buf = [0u8; 96];
    let mut pos = buf.len(); // 触发首次挤出
    let mut oi = 0usize;
    while oi < 256 {
        if pos + 3 > buf.len() {
            xof.fill(&mut buf);
            pos = 0;
        }
        let b0 = u32::from(buf[pos]);
        let b1 = u32::from(buf[pos + 1]);
        let b2 = u32::from(buf[pos + 2]);
        pos += 3;
        let d1 = b0 + ((b1 & 0x0f) << 8);
        let d2 = (b1 >> 4) + (b2 << 4);
        if d1 < Q as u32 && oi < 256 {
            out[oi] = d1 as i16;
            oi += 1;
        }
        if d2 < Q as u32 && oi < 256 {
            out[oi] = d2 as i16;
            oi += 1;
        }
    }
    out
}

/// FIPS 203 算法 8：SamplePolyCBD_η（PRF 输出 64η 字节 → 256 系数，
/// 每系数消费 2η 位：前 η 位为 x、后 η 位为 y）。位序 LSB 先进；位
/// 运算只依赖公开 PRF 输出，数据无关指令序列；输出 ∈ [−η, η]（进
/// NTT 后由 barrett 规范化）。
fn cbd(prf: &[u8], eta: usize) -> Poly {
    debug_assert_eq!(prf.len(), 64 * eta);
    let mut out = [0i16; 256];
    let mut bitbuf: u64 = 0;
    let mut bitcnt = 0usize;
    let mut pos = 0usize;
    let coeff_bits = 2 * eta;
    for c in out.iter_mut() {
        while bitcnt < coeff_bits {
            bitbuf |= (u64::from(prf[pos])) << bitcnt;
            pos += 1;
            bitcnt += 8;
        }
        let mut x = 0u32;
        let mut y = 0u32;
        for b in 0..eta {
            x += ((bitbuf >> b) & 1) as u32;
            y += ((bitbuf >> (eta + b)) & 1) as u32;
        }
        *c = (x as i32 - y as i32) as i16;
        bitbuf >>= coeff_bits;
        bitcnt -= coeff_bits;
    }
    out
}

// ---------------------------------------------------------------------------
// 位编解码（ByteEncode/ByteDecode，d ∈ {1, 4, 10, 12}；小端位流）
// ---------------------------------------------------------------------------

fn encode_d(coeffs: &[i16], d: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), 256 * d / 8);
    let mut acc: u32 = 0;
    let mut bits = 0usize;
    let mut oi = 0usize;
    for &c in coeffs {
        debug_assert!((0..(1 << d)).contains(&c));
        acc |= (c as u32) << bits;
        bits += d;
        while bits >= 8 {
            out[oi] = (acc & 0xff) as u8;
            oi += 1;
            acc >>= 8;
            bits -= 8;
        }
    }
}

fn decode_d(data: &[u8], d: usize) -> Poly {
    debug_assert_eq!(data.len(), 256 * d / 8);
    let mut out = [0i16; 256];
    let mask = (1u32 << d) - 1;
    let mut acc: u32 = 0;
    let mut bits = 0usize;
    let mut oi = 0usize;
    for &b in data {
        acc |= u32::from(b) << bits;
        bits += 8;
        while bits >= d && oi < 256 {
            out[oi] = (acc & mask) as i16;
            oi += 1;
            acc >>= d;
            bits -= d;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 压缩（FIPS 203 §4.2.1，公式 4.5/4.6）
// ---------------------------------------------------------------------------

#[inline]
fn compress_d(x: i16, d: usize) -> i16 {
    const SHIFT: u64 = 34;
    const DIV_MUL: u64 = (1u64 << SHIFT) / Q as u64;
    let q_half = u64::from((Q + 1) as u16) / 2;
    let y = (u64::from(u32::from(x as u16) << d) + q_half) * DIV_MUL;
    ((y >> SHIFT) as u32 & ((1u32 << d) - 1)) as i16
}

#[inline]
fn decompress_d(x: i16, d: usize) -> i16 {
    let y = (u32::from(x as u16) * Q as u32 + (1u32 << (d - 1))) >> d;
    y as i16
}

fn poly_compress_d(p: &mut Poly, d: usize) {
    for c in p.iter_mut() {
        *c = compress_d(*c, d);
    }
}

fn poly_decompress_d(p: &mut Poly, d: usize) {
    for c in p.iter_mut() {
        *c = decompress_d(*c, d);
    }
}

// ---------------------------------------------------------------------------
// 哈希封装（FIPS 203 §4.3：G/H/J/PRF/XOF）
// ---------------------------------------------------------------------------

/// PRF_η（SHAKE-256 挤出 64η 字节）→ SamplePolyCBD_η 的组合步骤
/// （FIPS 203 算法 8 的输入生成与采样一体完成，避免长度截断遗漏）。
fn prf_cbd(sigma: &[u8; 32], n: u8, eta: usize) -> Poly {
    let mut buf = [0u8; PRF_LEN_MAX];
    let mut s = Shake256::new();
    s.update(sigma);
    s.update(&[n]);
    let mut x = s.finalize_xof();
    x.fill(&mut buf[..64 * eta]);
    cbd(&buf[..64 * eta], eta)
}

fn hash_j(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut s = Shake256::new();
    s.update(a);
    s.update(b);
    let mut x = s.finalize_xof();
    let mut out = [0u8; 32];
    x.fill(&mut out);
    out
}

/// 矩阵元素 Â[i][j] = SampleNTT(XOF(ρ‖j‖i))。
fn matrix_entry(rho: &[u8; 32], i: usize, j: usize) -> Poly {
    let mut s = Shake128::new();
    s.update(rho);
    s.update(&[j as u8, i as u8]);
    let mut x = s.finalize_xof();
    sample_ntt(&mut x)
}

// ---------------------------------------------------------------------------
// K-PKE（FIPS 203 算法 12–14；k 为运行时参数——公开的参数集信息）
// ---------------------------------------------------------------------------

/// K-PKE.KeyGen：返回写入调用方缓冲的 (dk_PKE 编码, t̂ 编码) 与 ρ。
/// s/e 的 CBD 与 PRF 长度由 η₁ 决定。
fn kpke_keygen(
    d: &[u8; 32],
    k: usize,
    eta1: usize,
    dk_out: &mut [u8],
    ek_t_out: &mut [u8],
) -> [u8; 32] {
    debug_assert_eq!(dk_out.len(), 384 * k);
    debug_assert_eq!(ek_t_out.len(), 384 * k);
    let mut din = [0u8; 33];
    din[..32].copy_from_slice(d);
    din[32] = k as u8;
    let mut g = sha3_512(&din);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);
    g.zeroize();

    let mut s_hat: [Poly; K_MAX] = [[0; 256]; K_MAX];
    let mut t_hat: [Poly; K_MAX] = [[0; 256]; K_MAX];
    for (i, item) in s_hat.iter_mut().enumerate().take(k) {
        let mut p = prf_cbd(&sigma, i as u8, eta1);
        ntt(&mut p);
        *item = p;
    }
    for (i, item) in t_hat.iter_mut().enumerate().take(k) {
        let mut acc = prf_cbd(&sigma, (k + i) as u8, eta1);
        ntt(&mut acc); // ê 的 NTT
        for (j, sh) in s_hat[..k].iter().enumerate() {
            let a = matrix_entry(&rho, i, j); // Â[i][j]：XOF(ρ‖j‖i)
            let m = ntt_mul(&a, sh);
            poly_add(&mut acc, &m);
        }
        *item = acc;
    }

    for i in 0..k {
        encode_d(&s_hat[i], 12, &mut dk_out[i * 384..(i + 1) * 384]);
        encode_d(&t_hat[i], 12, &mut ek_t_out[i * 384..(i + 1) * 384]);
    }
    sigma.zeroize();
    for p in s_hat.iter_mut() {
        p.zeroize(); // ŝ 为秘密（dk_PKE 编码后仍保留于 dk，副本清零）
    }
    rho
}

/// K-PKE.Encrypt（确定性：外部供给 32 字节消息 m 与随机数 r）。
/// r 的 CBD/PRF 长度由 η₁ 决定；e₁/e₂ 恒用 η₂ = 2；u/v 的压缩宽度
/// 由 (du, dv) 决定（1024 为 (11, 5)，每 u 多项式 352 字节）。
fn kpke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32], k: usize, eta1: usize, du: usize, dv: usize) -> [u8; CT_MAX] {
    debug_assert_eq!(ek.len(), 384 * k + 32);
    let poly_bytes = 32 * du;
    let ek_len = 384 * k;
    let mut t_hat: [Poly; K_MAX] = [[0; 256]; K_MAX];
    for (i, item) in t_hat.iter_mut().enumerate().take(k) {
        *item = decode_d(&ek[i * 384..(i + 1) * 384], 12);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[ek_len..ek_len + 32]);

    let mut r_hat: [Poly; K_MAX] = [[0; 256]; K_MAX];
    for (i, item) in r_hat.iter_mut().enumerate().take(k) {
        let mut p = prf_cbd(r, i as u8, eta1);
        ntt(&mut p);
        *item = p;
    }

    let mut u: [Poly; K_MAX] = [[0; 256]; K_MAX];
    for (i, item) in u.iter_mut().enumerate().take(k) {
        let e1 = prf_cbd(r, (k + i) as u8, ETA2); // 系数域，逆变换之后加入
        let mut acc: Poly = [0; 256];
        for (j, rh) in r_hat[..k].iter().enumerate() {
            // (Âᵀ)[i][j] = Â[j][i]：XOF(ρ‖i‖j)——与 KeyGen 的 (ρ‖j‖i)
            // 参数互换（matrix_entry(a,b) = XOF(ρ‖b‖a)）
            let a = matrix_entry(&rho, j, i);
            let m = ntt_mul(&a, rh);
            poly_add(&mut acc, &m);
        }
        ntt_inverse(&mut acc);
        poly_add(&mut acc, &e1);
        *item = acc;
    }
    let mut e2 = prf_cbd(r, (2 * k) as u8, ETA2);

    // v = NTT⁻¹(t̂∘r̂) + e₂ + μ
    let mut v: Poly = [0; 256];
    for (th, rh) in t_hat[..k].iter().zip(r_hat[..k].iter()) {
        let m = ntt_mul(th, rh);
        poly_add(&mut v, &m);
    }
    ntt_inverse(&mut v);
    poly_add(&mut v, &e2);
    e2.zeroize();
    let mu = decode_d(m, 1);
    for (x, y) in v.iter_mut().zip(mu.iter()) {
        *x = barrett(i32::from(*x) + i32::from(decompress_d(*y, 1)));
    }

    let mut ct = [0u8; CT_MAX];
    for i in 0..k {
        poly_compress_d(&mut u[i], du);
        encode_d(&u[i], du, &mut ct[i * poly_bytes..(i + 1) * poly_bytes]);
    }
    poly_compress_d(&mut v, dv);
    encode_d(&v, dv, &mut ct[k * poly_bytes..k * poly_bytes + 32 * dv]);
    ct
}

/// K-PKE.Decrypt（u/v 的解压宽度由 (du, dv) 决定）。
fn kpke_decrypt(dk_pke: &[u8], ct: &[u8], k: usize, du: usize, dv: usize) -> [u8; 32] {
    debug_assert_eq!(dk_pke.len(), 384 * k);
    debug_assert_eq!(ct.len(), 32 * (du * k + dv));
    let poly_bytes = 32 * du;
    let mut u: [Poly; K_MAX] = [[0; 256]; K_MAX];
    for (i, item) in u.iter_mut().enumerate().take(k) {
        let mut p = decode_d(&ct[i * poly_bytes..(i + 1) * poly_bytes], du);
        poly_decompress_d(&mut p, du);
        ntt(&mut p);
        *item = p;
    }
    let mut v = decode_d(&ct[k * poly_bytes..k * poly_bytes + 32 * dv], dv);
    poly_decompress_d(&mut v, dv);

    // w = v − NTT⁻¹(ŝ∘û)
    let mut sv: Poly = [0; 256];
    for (i, ui) in u[..k].iter().enumerate() {
        let s = decode_d(&dk_pke[i * 384..(i + 1) * 384], 12);
        let m = ntt_mul(&s, ui);
        poly_add(&mut sv, &m);
    }
    ntt_inverse(&mut sv);
    for (x, y) in v.iter_mut().zip(sv.iter()) {
        *x = barrett(i32::from(*x) - i32::from(*y));
    }
    poly_compress_d(&mut v, 1);
    let mut m = [0u8; 32];
    encode_d(&v, 1, &mut m);
    m
}

// ---------------------------------------------------------------------------
// 引擎级 KEM 入口（运行时 k；per-set 子模块是其类型化包装）
// ---------------------------------------------------------------------------

/// 检查 k 为支持的参数集（2/3/4）。公开入口只经类型化包装到达，
/// 该断言属内部不变量，不构成攻击者可达 panic 面。
fn check_k(k: usize) {
    assert!((2..=K_MAX).contains(&k), "ML-KEM k must be 2, 3 or 4");
}

/// FIPS 203 算法 15 的引擎形态：返回 (ek, dk) 的最大档缓冲（有效
/// 长度 384k+32 / 384k + ek + 64，余量为零）。参数由 k 查表派生。
fn keypair_from_seed_k(k: usize, d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_MAX], [u8; DK_MAX]) {
    check_k(k);
    let (eta1, _du, _dv) = fips203_params(k);
    let ek_len = 384 * k + 32;
    let mut dk_pke = [0u8; DK_PKE_MAX];
    let mut ek_t = [0u8; DK_PKE_MAX];
    let rho = kpke_keygen(d, k, eta1, &mut dk_pke[..384 * k], &mut ek_t[..384 * k]);

    let mut ek = [0u8; EK_MAX];
    ek[..384 * k].copy_from_slice(&ek_t[..384 * k]);
    ek[384 * k..ek_len].copy_from_slice(&rho);
    let h = sha3_256(&ek[..ek_len]);

    let mut dk = [0u8; DK_MAX];
    dk[..384 * k].copy_from_slice(&dk_pke[..384 * k]);
    dk[384 * k..384 * k + ek_len].copy_from_slice(&ek[..ek_len]);
    dk[384 * k + ek_len..384 * k + ek_len + 32].copy_from_slice(&h);
    dk[384 * k + ek_len + 32..384 * k + ek_len + 64].copy_from_slice(z);
    dk_pke.zeroize();
    ek_t.zeroize();
    (ek, dk)
}

/// FIPS 203 算法 16 的引擎形态：返回 (密文, K)。`ek_bytes` 长度须为
/// 384k + 32（调用方的类型化入口已承载 §7.2 检查）。
fn encapsulate_k(k: usize, ek_bytes: &[u8], m: &[u8; 32]) -> ([u8; CT_MAX], [u8; 32]) {
    check_k(k);
    let (eta1, du, dv) = fips203_params(k);
    debug_assert_eq!(ek_bytes.len(), 384 * k + 32);
    let h = sha3_256(ek_bytes);
    let mut hin = [0u8; 64];
    hin[..32].copy_from_slice(m);
    hin[32..].copy_from_slice(&h);
    let mut g = sha3_512(&hin);
    let mut kp = [0u8; 32];
    let mut rp = [0u8; 32];
    kp.copy_from_slice(&g[..32]);
    rp.copy_from_slice(&g[32..]);
    g.zeroize();

    let ct = kpke_encrypt(ek_bytes, m, &rp, k, eta1, du, dv);
    rp.zeroize();
    (ct, kp)
}

/// FIPS 203 算法 17 的引擎形态（FO 变换 + 隐式拒绝）：对任何输入
/// 密文都返回一个共享秘密——重加密密文 c′ 与 c 的比较经 `subtle`
/// 常数时间完成，匹配取 K′，不匹配取 K̃ = J(z‖c)；比较与选择全程
/// 无分支。
fn decapsulate_k(k: usize, dk_bytes: &[u8], ct_bytes: &[u8]) -> [u8; 32] {
    check_k(k);
    let (eta1, du, dv) = fips203_params(k);
    let ek_len = 384 * k + 32;
    debug_assert_eq!(dk_bytes.len(), 384 * k + ek_len + 64);
    debug_assert_eq!(ct_bytes.len(), 32 * (du * k + dv));

    let mut ek = [0u8; EK_MAX];
    ek[..ek_len].copy_from_slice(&dk_bytes[384 * k..384 * k + ek_len]);
    let mut h = [0u8; 32];
    h.copy_from_slice(&dk_bytes[384 * k + ek_len..384 * k + ek_len + 32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&dk_bytes[384 * k + ek_len + 32..384 * k + ek_len + 64]);

    let mut m = kpke_decrypt(&dk_bytes[..384 * k], ct_bytes, k, du, dv);

    let mut hin = [0u8; 64];
    hin[..32].copy_from_slice(&m);
    hin[32..].copy_from_slice(&h);
    let mut g = sha3_512(&hin);
    let mut kp = [0u8; 32];
    let mut rp = [0u8; 32];
    kp.copy_from_slice(&g[..32]);
    rp.copy_from_slice(&g[32..]);
    g.zeroize();

    let mut kbar = hash_j(&z, ct_bytes);
    let cp = kpke_encrypt(&ek[..ek_len], &m, &rp, k, eta1, du, dv);
    let ct_len = 32 * (du * k + dv);

    // 常数时间选择：c′ == c ? K′ : K̃（conditional_select 在 choice=1
    // 时取后者，故参数序为 (K̃, K′)）
    let choice: Choice = cp[..ct_len].ct_eq(ct_bytes);
    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = u8::conditional_select(&kbar[i], &kp[i], choice);
    }

    m.zeroize();
    kp.zeroize();
    rp.zeroize();
    kbar.zeroize();
    let mut cp = cp;
    cp.zeroize();
    ek.zeroize();
    h.zeroize();
    z.zeroize();
    ss
}

// ---------------------------------------------------------------------------
// 公开容器类型（裸 const 长度参数；per-set 子模块给出类型别名）
// ---------------------------------------------------------------------------

/// ML-KEM 封装密钥（ek；公开数据）。
///
/// `EK` 为参数集对应的 ek 字节长度（800/1184/1568）。只能经
/// [`MlkemEncapsKey::from_bytes`]（含 §7.2 模校验）或各参数集的
/// `keypair_from_seed` 构造，类型系统保证进入 `encapsulate` 的密钥
/// 必已通过检查。
#[derive(Clone)]
pub struct MlkemEncapsKey<const EK: usize> {
    bytes: [u8; EK],
}

/// §7.2 封装密钥检查的公共实现（对 ek 编码的每 384 字节多项式做
/// 解码系数 < q 的范围断言）。
///
/// 注：规范原文写作 `ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))` 的
/// 往返比较，但 12 位位打包下往返恒等——检查的实质是系数范围
/// （规范实现的字段元素类型会把 ≥ q 的系数按 mod q 规范化，使
/// 重编码错位）；这里直接做范围断言，语义相同且不依赖隐藏的
/// 规范化行为。
fn validate_ek_bytes(ek: &[u8]) -> Result<(), Error> {
    let (chunks, rest) = ek.as_chunks::<384>();
    if !rest.is_empty() {
        return Err(Error::InvalidInput);
    }
    for chunk in chunks {
        let p = decode_d(chunk, 12);
        if p.iter().any(|&c| i32::from(c) >= Q) {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

impl<const EK: usize> MlkemEncapsKey<EK> {
    /// 从字节构造，执行 FIPS 203 §7.2 封装密钥检查（长度检查由类型
    /// 承载；模校验 = 解码系数全部落在 [0, q)），失败返回
    /// [`Error::InvalidInput`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; EK] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        validate_ek_bytes(&arr[..EK - 32])?;
        Ok(MlkemEncapsKey { bytes: arr })
    }

    /// 导出封装密钥字节（公开数据）。
    pub fn as_bytes(&self) -> &[u8; EK] {
        &self.bytes
    }
}

impl<const EK: usize> std::fmt::Debug for MlkemEncapsKey<EK> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlkemEncapsKey")
    }
}

/// ML-KEM 解封装密钥（dk，展开编码 dk_PKE‖ek‖H(ek)‖z；秘密材料）。
///
/// `DK` 为参数集对应的 dk 字节长度（1632/2400/3168）。
pub struct MlkemDecapsKey<const DK: usize> {
    bytes: [u8; DK],
}

impl<const DK: usize> MlkemDecapsKey<DK> {
    /// 从展开编码构造：校验内嵌 `h = H(ek)` 与 ek 模校验，失败返回
    /// [`Error::InvalidInput`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; DK] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        debug_assert!(DK >= 96 && (DK - 96) % 768 == 0, "not a valid DK length");
        let k = (DK - 96) / 768; // DK = 384k + (384k + 32) + 64
        let ek_len = 384 * k + 32;
        let ek_start = 384 * k;
        // 模校验只覆盖 ek 的 t̂ 编码部分（前 384k 字节）；尾部 32 字节
        // 是 ρ，不是多项式数据
        validate_ek_bytes(&arr[ek_start..ek_start + ek_len - 32])?;
        let h = sha3_256(&arr[ek_start..ek_start + ek_len]);
        if h.as_slice() != &arr[ek_start + ek_len..ek_start + ek_len + 32] {
            return Err(Error::InvalidInput);
        }
        Ok(MlkemDecapsKey { bytes: arr })
    }

    /// 导出展开编码字节（**秘密材料**，调用方负责零化副本）。
    pub fn expose_bytes(&self) -> &[u8; DK] {
        &self.bytes
    }
}

impl<const DK: usize> Drop for MlkemDecapsKey<DK> {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl<const DK: usize> std::fmt::Debug for MlkemDecapsKey<DK> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlkemDecapsKey")
    }
}

/// ML-KEM 密文（c；公开数据）。`CT` 为参数集对应的密文字节长度
/// （768/1088/1568）。
#[derive(Clone)]
pub struct MlkemCiphertext<const CT: usize> {
    bytes: [u8; CT],
}

impl<const CT: usize> MlkemCiphertext<CT> {
    /// 从字节构造（长度由类型检查）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; CT] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        Ok(MlkemCiphertext { bytes: arr })
    }

    /// 导出密文字节。
    pub fn as_bytes(&self) -> &[u8; CT] {
        &self.bytes
    }
}

impl<const CT: usize> std::fmt::Debug for MlkemCiphertext<CT> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlkemCiphertext")
    }
}

/// ML-KEM 共享秘密（32 字节，全部参数集一致；秘密材料）。
pub struct MlkemSharedSecret {
    bytes: [u8; 32],
}

impl MlkemSharedSecret {
    /// 导出共享秘密字节（**秘密材料**，调用方负责零化副本）。
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for MlkemSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for MlkemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlkemSharedSecret")
    }
}

// ---------------------------------------------------------------------------
// per-set 入口（宏展开为 k512 / k768 / k1024 三个子模块）
// ---------------------------------------------------------------------------

macro_rules! mlkem_param_set {
    ($k:literal, $name:ident, $ps:literal) => {
        #[doc = concat!(
            "ML-KEM-", $ps, "（FIPS 203 参数集，k = ", stringify!($k),
            "；η₁/du/dv 由 [`super::fips203_params`] 参数表给出）：",
            "本参数集的类型别名与入口函数。"
        )]
        pub mod $name {
            use zeroize::Zeroize;

            use super::{MlkemCiphertext, MlkemDecapsKey, MlkemEncapsKey, MlkemSharedSecret};

            /// 模秩 k（决定密钥/密文长度）。
            pub const K: usize = $k;
            /// 秘密噪声参数（**ML-KEM-512 为 3**，768/1024 为 2）。
            pub const ETA1: usize = super::fips203_params($k).0;
            /// 密文压缩宽度 u 分量（**ML-KEM-1024 为 11**，其余 10）。
            pub const DU: usize = super::fips203_params($k).1;
            /// 密文压缩宽度 v 分量（**ML-KEM-1024 为 5**，其余 4）。
            pub const DV: usize = super::fips203_params($k).2;
            /// 封装密钥长度（384k + 32 字节）。
            pub const EK_BYTES: usize = 384 * $k + 32;
            /// 解封装密钥长度（dk_PKE‖ek‖H(ek)‖z）。
            pub const DK_BYTES: usize = 384 * $k + EK_BYTES + 64;
            /// 密文长度（32·(du·k + dv) 字节）。
            pub const CT_BYTES: usize = 32 * (DU * $k + DV);
            /// 共享秘密长度（32 字节）。
            pub const SS_BYTES: usize = 32;

            const _: () = {
                assert!(EK_BYTES == 384 * $k + 32);
                assert!(DK_BYTES == 384 * $k + EK_BYTES + 64);
                assert!(CT_BYTES == 32 * (super::fips203_params($k).1 * $k + super::fips203_params($k).2));
            };

            /// 本参数集的封装密钥（ek）。
            pub type EncapsKey = MlkemEncapsKey<EK_BYTES>;
            /// 本参数集的解封装密钥（dk）。
            pub type DecapsKey = MlkemDecapsKey<DK_BYTES>;
            /// 本参数集的密文（c）。
            pub type Ciphertext = MlkemCiphertext<CT_BYTES>;
            /// 共享秘密（32 字节）。
            pub type SharedSecret = MlkemSharedSecret;

            /// 确定性密钥生成（FIPS 203 算法 15 以 (d, z) 为种子）——
            /// 向量测试与上电自检入口；生产路径走 [`generate_keypair`]。
            pub fn keypair_from_seed(d: &[u8; 32], z: &[u8; 32]) -> (EncapsKey, DecapsKey) {
                let (ek, dk) = super::keypair_from_seed_k($k, d, z);
                let mut ek_arr = [0u8; EK_BYTES];
                ek_arr.copy_from_slice(&ek[..EK_BYTES]);
                let mut dk_arr = [0u8; DK_BYTES];
                dk_arr.copy_from_slice(&dk[..DK_BYTES]);
                (EncapsKey { bytes: ek_arr }, DecapsKey { bytes: dk_arr })
            }

            /// 随机密钥生成（64 字节种子经 OS 熵直读；批准模式的 DRBG
            /// 路径由 provider 的 `secure_random` 与自检守卫覆盖，同
            /// [`crate::ecdh`] 口径）。
            pub fn generate_keypair() -> Result<(EncapsKey, DecapsKey), crate::Error> {
                let mut seed = [0u8; 64];
                crate::entropy::fill(&mut seed)?;
                let (ek, dk) = keypair_from_seed(
                    &seed[..32].try_into().expect("32 bytes"),
                    &seed[32..].try_into().expect("32 bytes"),
                );
                seed.zeroize();
                Ok((ek, dk))
            }

            /// 确定性封装（FIPS 203 算法 16，随机 m 外部供给）——向量
            /// 测试与上电自检入口；生产路径走 [`encapsulate`]。
            pub fn encapsulate_with_seed(
                ek: &EncapsKey,
                m: &[u8; 32],
            ) -> Result<(Ciphertext, SharedSecret), crate::Error> {
                let (ct, kp) = super::encapsulate_k($k, ek.as_bytes(), m);
                let mut ct_arr = [0u8; CT_BYTES];
                ct_arr.copy_from_slice(&ct[..CT_BYTES]);
                Ok((Ciphertext { bytes: ct_arr }, SharedSecret { bytes: kp }))
            }

            /// 随机封装（m 经 OS 熵直读）。
            pub fn encapsulate(ek: &EncapsKey) -> Result<(Ciphertext, SharedSecret), crate::Error> {
                let mut m = [0u8; 32];
                crate::entropy::fill(&mut m)?;
                let out = encapsulate_with_seed(ek, &m);
                m.zeroize();
                out
            }

            /// 解封装（FIPS 203 算法 17，FO 变换 + 隐式拒绝）。
            pub fn decapsulate(dk: &DecapsKey, ct: &Ciphertext) -> SharedSecret {
                SharedSecret {
                    bytes: super::decapsulate_k($k, dk.expose_bytes(), ct.as_bytes()),
                }
            }
        }
    };
}

mlkem_param_set!(2, k512, "512");
mlkem_param_set!(3, k768, "768");
mlkem_param_set!(4, k1024, "1024");

// ---------------------------------------------------------------------------
// ML-KEM-768 兼容别名与再导出（M8.3 公共 API 原样保留）
// ---------------------------------------------------------------------------

/// ML-KEM-768 封装密钥（ek，1184 字节；公开数据）。
pub type Mlkem768EncapsKey = k768::EncapsKey;
/// ML-KEM-768 解封装密钥（dk，2400 字节展开编码；秘密材料）。
pub type Mlkem768DecapsKey = k768::DecapsKey;
/// ML-KEM-768 密文（c，1088 字节；公开数据）。
pub type Mlkem768Ciphertext = k768::Ciphertext;
/// ML-KEM-768 共享秘密（32 字节；秘密材料）。
pub type Mlkem768SharedSecret = k768::SharedSecret;

/// 封装密钥长度（ML-KEM-768：384k + 32 = 1184 字节）。
pub const EK_BYTES: usize = k768::EK_BYTES;
/// 解封装密钥长度（ML-KEM-768：dk_PKE‖ek‖H(ek)‖z = 2400 字节）。
pub const DK_BYTES: usize = k768::DK_BYTES;
/// 密文长度（ML-KEM-768：32·(d_u·k + d_v) = 32·34 = 1088 字节）。
pub const CT_BYTES: usize = k768::CT_BYTES;
/// 共享秘密长度（32 字节）。
pub const SS_BYTES: usize = 32;

pub use k768::{decapsulate, encapsulate, encapsulate_with_seed, generate_keypair, keypair_from_seed};

#[cfg(test)]
mod tests {
    use super::*;

    /// NTT/NTT⁻¹ 互逆 + 与 schoolbook 多项式乘法（模 X²⁵⁶+1）互检。
    #[test]
    fn ntt_roundtrip_and_schoolbook() {
        let mut rng_state = 0x12345678u64;
        let mut next = || {
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            (rng_state % Q as u64) as i16
        };
        for _ in 0..4 {
            let mut a = [0i16; 256];
            let mut b = [0i16; 256];
            for i in 0..256 {
                a[i] = next();
                b[i] = next();
            }
            // schoolbook：c_k = Σ_{i+j=k} aᵢbⱼ − Σ_{i+j=k+256} aᵢbⱼ
            let mut c = [0i64; 256];
            for i in 0..256 {
                for j in 0..256 {
                    let prod = i64::from(a[i]) * i64::from(b[j]);
                    if i + j < 256 {
                        c[i + j] += prod;
                    } else {
                        c[i + j - 256] -= prod;
                    }
                }
            }
            let mut a_hat = a;
            let mut b_hat = b;
            ntt(&mut a_hat);
            ntt(&mut b_hat);
            let mut c_hat = ntt_mul(&a_hat, &b_hat);
            ntt_inverse(&mut c_hat);
            for k in 0..256 {
                assert_eq!(
                    i64::from(c_hat[k]),
                    c[k].rem_euclid(i64::from(Q)),
                    "coeff {k}"
                );
            }
            ntt_inverse(&mut a_hat);
            assert_eq!(a_hat, a);
        }
    }

    /// zeta 表锚点：BitRev₇(1) = 64、BitRev₇(64) = 1（首层蝶形用 ζ⁶⁴）。
    #[test]
    fn zeta_table_anchors() {
        assert_eq!(ZETA_POW_BITREV[0], 1);
        assert_eq!(ZETA_POW_BITREV[64], 17);
        assert_eq!(ZETA_POW_BITREV[1], {
            // ζ⁶⁴ mod q（独立平算）
            let mut z: i64 = 1;
            for _ in 0..64 {
                z = z * 17 % i64::from(Q);
            }
            z as i16
        });
        // GAMMA[0] = ζ^(2·BitRev₇(0)+1) = ζ
        assert_eq!(GAMMA[0], 17);
    }

    /// 编解码 + 压缩/解压缩的规范性质（d ∈ {1,4,10,12} 全值扫描）。
    #[test]
    fn codec_and_compress_full_sweep() {
        for &d in &[1usize, 4, 10, 12] {
            let mut data = vec![0u8; 256 * d / 8];
            for (i, b) in data.iter_mut().enumerate() {
                *b = (i * 7 + 3) as u8;
            }
            let p = decode_d(&data, d);
            let mut re = vec![0u8; 256 * d / 8];
            encode_d(&p, d, &mut re);
            assert_eq!(re, data, "encode∘decode roundtrip d={d}");
            // 解压后重压可还原仅对 d < 12 成立（q/2¹² < 1 时多对一）
            if d < 12 {
                for x in 0..(1i16 << d) {
                    let y = decompress_d(x, d);
                    let z = compress_d(y, d);
                    assert_eq!(z, x, "decompress∘compress d={d} x={x}");
                }
            }
            for x in 0..Q {
                let c = compress_d(x as i16, d);
                assert!((0..(1 << d)).contains(&c));
            }
        }
    }

    /// SampleNTT 输出全部 < q（固定 ρ 抽查 + 分布健全性）。
    #[test]
    fn sample_ntt_bounds() {
        let mut s = Shake128::new();
        s.update(&[0u8; 32]);
        let mut x = s.finalize_xof();
        let p = sample_ntt(&mut x);
        assert!(p.iter().all(|&c| (0..Q).contains(&i32::from(c))));
    }

    /// 三参数集端到端：keygen → encapsulate_with_seed → decapsulate
    /// 共享秘密一致；跨参数集长度必须被 from_bytes 拒绝。
    #[test]
    fn param_sets_roundtrip_and_cross_length_rejected() {
        // (d, z) 固定种子，三集同种子展开
        let d = [0x03u8; 32];
        let z = [0x5au8; 32];
        let m = [0x11u8; 32];

        let (ek2, dk2) = k512::keypair_from_seed(&d, &z);
        let (c2, ss2) = k512::encapsulate_with_seed(&ek2, &m).expect("encaps 512");
        assert_eq!(ss2.expose_bytes(), k512::decapsulate(&dk2, &c2).expose_bytes());
        assert_eq!(k512::EK_BYTES, 800);
        assert_eq!(k512::DK_BYTES, 1632);
        assert_eq!(k512::CT_BYTES, 768);

        let (ek3, dk3) = k768::keypair_from_seed(&d, &z);
        let (c3, ss3) = k768::encapsulate_with_seed(&ek3, &m).expect("encaps 768");
        assert_eq!(ss3.expose_bytes(), k768::decapsulate(&dk3, &c3).expose_bytes());

        let (ek4, dk4) = k1024::keypair_from_seed(&d, &z);
        let (c4, ss4) = k1024::encapsulate_with_seed(&ek4, &m).expect("encaps 1024");
        assert_eq!(ss4.expose_bytes(), k1024::decapsulate(&dk4, &c4).expose_bytes());
        assert_eq!(k1024::EK_BYTES, 1568);
        assert_eq!(k1024::DK_BYTES, 3168);
        assert_eq!(k1024::CT_BYTES, 1568);
        assert_eq!(k512::ETA1, 3);
        assert_eq!(k768::ETA1, 2);
        assert_eq!(k1024::DU, 11);
        assert_eq!(k1024::DV, 5);

        // 跨参数集：512 的 ek 塞进 768 的 from_bytes → 长度拒绝；密文同理
        assert!(k768::EncapsKey::from_bytes(ek2.as_bytes()).is_err());
        assert!(k512::Ciphertext::from_bytes(c3.as_bytes()).is_err());
        assert!(k768::DecapsKey::from_bytes(dk2.expose_bytes()).is_err());
    }

    /// 对抗性输入：任意垃圾 dk/ct 解封装不 panic 且确定性（隐式拒绝
    /// 语义；三参数集同查，与 fuzz 目标 `mlkem-decaps` 的核心断言
    /// 一致）。
    #[test]
    fn decapsulate_garbage_never_panics() {
        macro_rules! garbage_case {
            ($set:ident) => {{
                let cases: [(&[u8], &[u8]); 3] = [
                    (&[0u8; $set::DK_BYTES], &[0u8; $set::CT_BYTES]),
                    (&[0xffu8; $set::DK_BYTES], &[0xffu8; $set::CT_BYTES]),
                    (
                        // 合法形状但随机内容（dk 无法通过 h 校验则跳过）
                        &[
                            0x73, 0x0e, 0x8b, 0x11, 0x92, 0xc4, 0x5d, 0x0a, 0x33, 0xf1, 0x77,
                            0x62, 0x08, 0xde, 0x91, 0x44,
                        ],
                        &[0x5a, 0xc4, 0x11, 0x99, 0xe2, 0x77, 0x03, 0xbb],
                    ),
                ];
                for (dkp, ctp) in cases {
                    let mut dk_bytes = [0u8; $set::DK_BYTES];
                    let n = dkp.len().min($set::DK_BYTES);
                    dk_bytes[..n].copy_from_slice(&dkp[..n]);
                    let mut ct_bytes = [0u8; $set::CT_BYTES];
                    let n = ctp.len().min($set::CT_BYTES);
                    ct_bytes[..n].copy_from_slice(&ctp[..n]);
                    let Ok(dk) = $set::DecapsKey::from_bytes(&dk_bytes) else {
                        continue;
                    };
                    let ct = $set::Ciphertext::from_bytes(&ct_bytes).expect("fixed width");
                    let a = $set::decapsulate(&dk, &ct);
                    let b = $set::decapsulate(&dk, &ct);
                    assert_eq!(a.expose_bytes(), b.expose_bytes(), "must be deterministic");
                }
            }};
        }
        garbage_case!(k512);
        garbage_case!(k768);
        garbage_case!(k1024);
    }
}
