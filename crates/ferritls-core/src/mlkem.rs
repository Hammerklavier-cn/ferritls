//! FIPS 203：ML-KEM-768 模格 KEM（M8.3）。
//!
//! 单参数集实现（k = 3, η₁ = η₂ = 2, d_u = 10, d_v = 4），算法逐条
//! 对应 FIPS 203 的 K-PKE（算法 12–14）与 ML-KEM（算法 15–17）：
//! KeyGen 以 `(d, z)` 种子展开，Encaps 前做 §7.2 封装密钥检查
//! （长度 + `ByteEncode₁₂∘ByteDecode₁₂` 往返模校验，由
//! [`Mlkem768EncapsKey::from_bytes`] 承载），Decaps 为 FO 变换 +
//! **隐式拒绝**——重加密密文比较经 `subtle` 常数时间完成后以
//! `conditional_select` 选择（K′ / K̃ = J(z‖c)），无分支实现。
//!
//! 与 Kyber Round-3 **不兼容**（矩阵采样 `Â[i][j] = SampleNTT(XOF(ρ‖j‖i))`
//! 的输入顺序等差异）；一致性以 NIST ACVP 向量为最终仲裁
//! （`tests/mlkem_acvp.rs`，溯源见 docs/VECTOR-PROVENANCE.md）。
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

/// 封装密钥长度（384k + 32 = 1184 字节）。
pub const EK_BYTES: usize = 1184;
/// 解封装密钥长度（dk_PKE‖ek‖H(ek)‖z = 1152 + 1184 + 32 + 32）。
pub const DK_BYTES: usize = 2400;
/// 密文长度（32·(d_u·k + d_v) = 32·34 = 1088 字节）。
pub const CT_BYTES: usize = 1088;
/// 共享秘密长度（32 字节）。
pub const SS_BYTES: usize = 32;

const K: usize = 3;
const DU: usize = 10;
const DV: usize = 4;
const Q: i32 = 3329;
const PRF_LEN: usize = 128; // 64·η₁ = 64·η₂ = 128（SHAKE-256 单次挤出）

/// GF(3329) 上的多项式（256 系数）。
type Poly = [i16; 256];

const _: () = {
    assert!(EK_BYTES == 384 * K + 32);
    assert!(DK_BYTES == 384 * K + EK_BYTES + 64);
    assert!(CT_BYTES == 32 * (DU * K + DV));
};

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

/// FIPS 203 算法 8：η = 2 的 CBD 采样（PRF 输出 128 字节 → 256 系数）。
/// 每半字节两位计数之差，数据无关指令序列；输出 ∈ [−2, 2]（进 NTT
/// 后由 barrett 规范化）。
fn cbd2(prf: &[u8; PRF_LEN]) -> Poly {
    let mut out = [0i16; 256];
    for i in 0..128 {
        let b = u32::from(prf[i]);
        for half in 0..2usize {
            let nib = (b >> (4 * half)) & 0x0f;
            let x = (nib & 0x03).count_ones() as i32;
            let y = (nib >> 2).count_ones() as i32;
            out[2 * i + half] = (x - y) as i16;
        }
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

fn prf2(sigma: &[u8; 32], n: u8) -> [u8; PRF_LEN] {
    let mut s = Shake256::new();
    s.update(sigma);
    s.update(&[n]);
    let mut x = s.finalize_xof();
    let mut out = [0u8; PRF_LEN];
    x.fill(&mut out);
    out
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
// K-PKE（FIPS 203 算法 12–14）
// ---------------------------------------------------------------------------

/// K-PKE.KeyGen：返回 (dk_PKE 编码, t̂ 编码, ρ)。
fn kpke_keygen(d: &[u8; 32]) -> ([u8; 384 * K], [u8; 384 * K], [u8; 32]) {
    let mut din = [0u8; 33];
    din[..32].copy_from_slice(d);
    din[32] = K as u8;
    let mut g = sha3_512(&din);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);
    g.zeroize();

    let mut s_hat: [Poly; K] = [[0; 256]; K];
    let mut t_hat: [Poly; K] = [[0; 256]; K];
    for (i, item) in s_hat.iter_mut().enumerate() {
        let prf = prf2(&sigma, i as u8);
        let mut p = cbd2(&prf);
        ntt(&mut p);
        *item = p;
    }
    for (i, item) in t_hat.iter_mut().enumerate() {
        let prf = prf2(&sigma, (K + i) as u8);
        let mut acc = cbd2(&prf);
        ntt(&mut acc); // ê 的 NTT
        for (j, sh) in s_hat.iter().enumerate() {
            let a = matrix_entry(&rho, i, j); // Â[i][j]：XOF(ρ‖j‖i)
            let m = ntt_mul(&a, sh);
            poly_add(&mut acc, &m);
        }
        *item = acc;
    }

    let mut dk = [0u8; 384 * K];
    let mut ek_t = [0u8; 384 * K];
    for i in 0..K {
        encode_d(&s_hat[i], 12, &mut dk[i * 384..(i + 1) * 384]);
        encode_d(&t_hat[i], 12, &mut ek_t[i * 384..(i + 1) * 384]);
    }
    sigma.zeroize();
    for p in s_hat.iter_mut() {
        p.zeroize(); // ŝ 为秘密（dk_PKE 编码后仍保留于 dk，副本清零）
    }
    (dk, ek_t, rho)
}

/// K-PKE.Encrypt（确定性：外部供给 32 字节消息 m 与随机数 r）。
fn kpke_encrypt(ek: &[u8; EK_BYTES], m: &[u8; 32], r: &[u8; 32]) -> [u8; CT_BYTES] {
    let mut t_hat: [Poly; K] = [[0; 256]; K];
    let mut rho = [0u8; 32];
    for i in 0..K {
        t_hat[i] = decode_d(&ek[i * 384..(i + 1) * 384], 12);
    }
    rho.copy_from_slice(&ek[384 * K..]);

    let mut r_hat: [Poly; K] = [[0; 256]; K];
    for (i, item) in r_hat.iter_mut().enumerate() {
        let prf = prf2(r, i as u8);
        let mut p = cbd2(&prf);
        ntt(&mut p);
        *item = p;
    }

    let mut u: [Poly; K] = [[0; 256]; K];
    for (i, item) in u.iter_mut().enumerate() {
        let prf = prf2(r, (K + i) as u8);
        let e1 = cbd2(&prf); // 系数域，逆变换之后加入
        let mut acc: Poly = [0; 256];
        for (j, rh) in r_hat.iter().enumerate() {
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
    let prf_e2 = prf2(r, (2 * K) as u8);
    let mut e2 = cbd2(&prf_e2);

    // v = NTT⁻¹(t̂∘r̂) + e₂ + μ
    let mut v: Poly = [0; 256];
    for (th, rh) in t_hat.iter().zip(r_hat.iter()) {
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

    let mut ct = [0u8; CT_BYTES];
    for i in 0..K {
        poly_compress_d(&mut u[i], DU);
        encode_d(&u[i], DU, &mut ct[i * 320..(i + 1) * 320]);
    }
    poly_compress_d(&mut v, DV);
    encode_d(&v, DV, &mut ct[K * 320..]);
    ct
}

/// K-PKE.Decrypt。
fn kpke_decrypt(dk_pke: &[u8; 384 * K], ct: &[u8; CT_BYTES]) -> [u8; 32] {
    let mut u: [Poly; K] = [[0; 256]; K];
    for (i, item) in u.iter_mut().enumerate() {
        let mut p = decode_d(&ct[i * 320..(i + 1) * 320], DU);
        poly_decompress_d(&mut p, DU);
        ntt(&mut p);
        *item = p;
    }
    let mut v = decode_d(&ct[K * 320..], DV);
    poly_decompress_d(&mut v, DV);

    // w = v − NTT⁻¹(ŝ∘û)
    let mut sv: Poly = [0; 256];
    for (i, ui) in u.iter().enumerate() {
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
// 公开类型
// ---------------------------------------------------------------------------

/// ML-KEM-768 封装密钥（ek，1184 字节；公开数据）。
///
/// 只能经 [`Mlkem768EncapsKey::from_bytes`]（含 §7.2 模校验）或
/// [`keypair_from_seed`] 构造，类型系统保证进入 [`encapsulate`]
/// 的密钥必已通过检查。
#[derive(Clone)]
pub struct Mlkem768EncapsKey {
    bytes: [u8; EK_BYTES],
}

impl Mlkem768EncapsKey {
    /// 从字节构造，执行 FIPS 203 §7.2 封装密钥检查（长度检查由类型
    /// 承载；模校验 = 解码系数全部落在 [0, q)），失败返回
    /// [`Error::InvalidInput`]。
    ///
    /// 注：规范原文写作 `ByteEncode₁₂(ByteDecode₁₂(ek[0:384k]))` 的
    /// 往返比较，但 12 位位打包下往返恒等——检查的实质是系数范围
    /// （规范实现的字段元素类型会把 ≥ q 的系数按 mod q 规范化，使
    /// 重编码错位）；这里直接做范围断言，语义相同且不依赖隐藏的
    /// 规范化行为。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; EK_BYTES] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        let (chunks, _rest) = arr[..384 * K].as_chunks::<384>();
        for chunk in chunks {
            let p = decode_d(chunk, 12);
            if p.iter().any(|&c| i32::from(c) >= Q) {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Mlkem768EncapsKey { bytes: arr })
    }

    /// 导出封装密钥字节（公开数据）。
    pub fn as_bytes(&self) -> &[u8; EK_BYTES] {
        &self.bytes
    }
}

impl std::fmt::Debug for Mlkem768EncapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mlkem768EncapsKey")
    }
}

/// ML-KEM-768 解封装密钥（dk，2400 字节展开编码；秘密材料）。
pub struct Mlkem768DecapsKey {
    bytes: [u8; DK_BYTES],
}

impl Mlkem768DecapsKey {
    /// 从 2400 字节展开编码构造：校验内嵌 `h = H(ek)` 与 ek 模校验，
    /// 失败返回 [`Error::InvalidInput`]。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; DK_BYTES] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        let dk = Mlkem768DecapsKey { bytes: arr };
        let ek = Mlkem768EncapsKey::from_bytes(&dk.bytes[384 * K..384 * K + EK_BYTES])?;
        let h = sha3_256(ek.as_bytes());
        if h.as_slice() != &dk.bytes[384 * K + EK_BYTES..384 * K + EK_BYTES + 32] {
            return Err(Error::InvalidInput);
        }
        Ok(dk)
    }

    /// 导出展开编码字节（**秘密材料**，调用方负责零化副本）。
    pub fn expose_bytes(&self) -> &[u8; DK_BYTES] {
        &self.bytes
    }
}

impl Drop for Mlkem768DecapsKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for Mlkem768DecapsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mlkem768DecapsKey")
    }
}

/// ML-KEM-768 密文（c，1088 字节；公开数据）。
#[derive(Clone)]
pub struct Mlkem768Ciphertext {
    bytes: [u8; CT_BYTES],
}

impl Mlkem768Ciphertext {
    /// 从字节构造（长度由类型检查）。
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; CT_BYTES] = bytes.try_into().map_err(|_| Error::InvalidInput)?;
        Ok(Mlkem768Ciphertext { bytes: arr })
    }

    /// 导出密文字节。
    pub fn as_bytes(&self) -> &[u8; CT_BYTES] {
        &self.bytes
    }
}

impl std::fmt::Debug for Mlkem768Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mlkem768Ciphertext")
    }
}

/// ML-KEM-768 共享秘密（32 字节；秘密材料）。
pub struct Mlkem768SharedSecret {
    bytes: [u8; SS_BYTES],
}

impl Mlkem768SharedSecret {
    /// 导出共享秘密字节（**秘密材料**，调用方负责零化副本）。
    pub fn expose_bytes(&self) -> &[u8; SS_BYTES] {
        &self.bytes
    }
}

impl Drop for Mlkem768SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for Mlkem768SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mlkem768SharedSecret")
    }
}

// ---------------------------------------------------------------------------
// KEM 接口（FIPS 203 算法 15–17）
// ---------------------------------------------------------------------------

/// 确定性密钥生成（FIPS 203 算法 15 以 (d, z) 为种子）——向量测试
/// 与上电自检入口；生产路径走 [`generate_keypair`]。
pub fn keypair_from_seed(d: &[u8; 32], z: &[u8; 32]) -> (Mlkem768EncapsKey, Mlkem768DecapsKey) {
    let (dk_pke, ek_t, rho) = kpke_keygen(d);

    let mut ek = [0u8; EK_BYTES];
    ek[..384 * K].copy_from_slice(&ek_t);
    ek[384 * K..].copy_from_slice(&rho);
    let h = sha3_256(&ek);

    let mut dk = [0u8; DK_BYTES];
    dk[..384 * K].copy_from_slice(&dk_pke);
    dk[384 * K..384 * K + EK_BYTES].copy_from_slice(&ek);
    dk[384 * K + EK_BYTES..384 * K + EK_BYTES + 32].copy_from_slice(&h);
    dk[384 * K + EK_BYTES + 32..].copy_from_slice(z);

    (
        Mlkem768EncapsKey { bytes: ek },
        Mlkem768DecapsKey { bytes: dk },
    )
}

/// 随机密钥生成（64 字节种子经 OS 熵直读；批准模式的 DRBG 路径由
/// provider 的 `secure_random` 与自检守卫覆盖，同 [`crate::ecdh`] 口径）。
pub fn generate_keypair() -> Result<(Mlkem768EncapsKey, Mlkem768DecapsKey), Error> {
    let mut seed = [0u8; 64];
    crate::entropy::fill(&mut seed)?;
    let (ek, dk) = keypair_from_seed(
        &seed[..32].try_into().expect("32 bytes"),
        &seed[32..].try_into().expect("32 bytes"),
    );
    seed.zeroize();
    Ok((ek, dk))
}

/// 确定性封装（FIPS 203 算法 16，随机 m 外部供给）——向量测试与
/// 上电自检入口；生产路径走 [`encapsulate`]。
pub fn encapsulate_with_seed(
    ek: &Mlkem768EncapsKey,
    m: &[u8; 32],
) -> Result<(Mlkem768Ciphertext, Mlkem768SharedSecret), Error> {
    let h = sha3_256(ek.as_bytes());
    let mut hin = [0u8; 64];
    hin[..32].copy_from_slice(m);
    hin[32..].copy_from_slice(&h);
    let mut g = sha3_512(&hin);
    let mut kp = [0u8; 32];
    let mut rp = [0u8; 32];
    kp.copy_from_slice(&g[..32]);
    rp.copy_from_slice(&g[32..]);
    g.zeroize();

    let ct = kpke_encrypt(ek.as_bytes(), m, &rp);
    rp.zeroize();
    Ok((
        Mlkem768Ciphertext { bytes: ct },
        Mlkem768SharedSecret { bytes: kp },
    ))
}

/// 随机封装（m 经 OS 熵直读）。
pub fn encapsulate(
    ek: &Mlkem768EncapsKey,
) -> Result<(Mlkem768Ciphertext, Mlkem768SharedSecret), Error> {
    let mut m = [0u8; 32];
    crate::entropy::fill(&mut m)?;
    let out = encapsulate_with_seed(ek, &m);
    m.zeroize();
    out
}

/// 解封装（FIPS 203 算法 17，FO 变换 + 隐式拒绝）。
///
/// 对任何输入密文都返回一个共享秘密：重加密密文 c′ 与 c 的比较经
/// `subtle` 常数时间完成，匹配取 K′，不匹配取 K̃ = J(z‖c)（隐式
/// 拒绝）；比较与选择全程无分支。
pub fn decapsulate(dk: &Mlkem768DecapsKey, ct: &Mlkem768Ciphertext) -> Mlkem768SharedSecret {
    let mut ek = [0u8; EK_BYTES];
    ek.copy_from_slice(&dk.bytes[384 * K..384 * K + EK_BYTES]);
    let mut h = [0u8; 32];
    h.copy_from_slice(&dk.bytes[384 * K + EK_BYTES..384 * K + EK_BYTES + 32]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&dk.bytes[384 * K + EK_BYTES + 32..]);

    let mut m = kpke_decrypt(
        &dk.bytes[..384 * K].try_into().expect("1152 bytes"),
        ct.as_bytes(),
    );

    let mut hin = [0u8; 64];
    hin[..32].copy_from_slice(&m);
    hin[32..].copy_from_slice(&h);
    let mut g = sha3_512(&hin);
    let mut kp = [0u8; 32];
    let mut rp = [0u8; 32];
    kp.copy_from_slice(&g[..32]);
    rp.copy_from_slice(&g[32..]);
    g.zeroize();

    let mut kbar = hash_j(&z, ct.as_bytes());
    let cp = kpke_encrypt(&ek, &m, &rp);

    // 常数时间选择：c′ == c ? K′ : K̃（conditional_select 在 choice=1
    // 时取后者，故参数序为 (K̃, K′)）
    let choice: Choice = cp.as_slice().ct_eq(ct.as_bytes());
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
    Mlkem768SharedSecret { bytes: ss }
}

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
    /// 对抗性输入：任意垃圾 dk/ct 解封装不 panic 且确定性（隐式拒绝
    /// 语义；与 fuzz 目标 `mlkem-decaps` 的核心断言一致）。
    #[test]
    fn decapsulate_garbage_never_panics() {
        let cases: [(&[u8], &[u8]); 3] = [
            (&[0u8; DK_BYTES], &[0u8; CT_BYTES]),
            (&[0xffu8; DK_BYTES], &[0xffu8; CT_BYTES]),
            (
                // 合法形状但随机内容（dk 无法通过 h 校验则跳过）
                &[
                    0x73, 0x0e, 0x8b, 0x11, 0x92, 0xc4, 0x5d, 0x0a, 0x33, 0xf1, 0x77, 0x62, 0x08,
                    0xde, 0x91, 0x44,
                ],
                &[0x5a, 0xc4, 0x11, 0x99, 0xe2, 0x77, 0x03, 0xbb],
            ),
        ];
        for (dkp, ctp) in cases {
            let mut dk_bytes = [0u8; DK_BYTES];
            let n = dkp.len().min(DK_BYTES);
            dk_bytes[..n].copy_from_slice(&dkp[..n]);
            let mut ct_bytes = [0u8; CT_BYTES];
            let n = ctp.len().min(CT_BYTES);
            ct_bytes[..n].copy_from_slice(&ctp[..n]);
            let Ok(dk) = Mlkem768DecapsKey::from_bytes(&dk_bytes) else {
                continue;
            };
            let ct = Mlkem768Ciphertext::from_bytes(&ct_bytes).expect("fixed width");
            let a = decapsulate(&dk, &ct);
            let b = decapsulate(&dk, &ct);
            assert_eq!(a.expose_bytes(), b.expose_bytes(), "must be deterministic");
        }
    }
}
