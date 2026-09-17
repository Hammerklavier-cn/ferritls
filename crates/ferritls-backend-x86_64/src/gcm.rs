//! AES-GCM 的 AES-NI + CLMUL kernel（除进入点 trampoline 外全部安全代码）。
//!
//! 结构与 core 的软件实现逐语义对齐（同一 SP 800-38D 数据流：J0 标签基
//! → CTR keystream → GHASH → 异或），仅替换执行原语：
//!
//! - AES 轮函数：`AESENC/AESENCLAST` 链（GCM 加解密都只用加密方向）；
//! - 密钥扩展：`AESKEYGENASSIST`（硬件指令本身常数时间，且远快于
//!   软件全表扫 S-box）；
//! - GHASH：`PCLMULQDQ` 64 位无进位乘 + 移位-异或约减。
//!
//! ## GHASH 的位序约定（自推导，差分测试锚定）
//!
//! core 软件实现的多项式约定：大端 `u128` 的整数位 p（0=LSB）对应
//! 多项式系数 X^(127-p)，约减多项式 f = X^128+X^7+X^2+X+1 表现为
//! `R = 0xE1 << 120`。PCLMULQDQ 的原生约定是"整数位 k = 系数 X^k"
//! （LSB-first）。两约定相差一个 128 位按位反转，在边界处转换：
//! 输入 `rev128` 进原生约定、结果 `rev128` 回软件约定；f 的低位
//! 部分在原生约定下是常数 `0x87`（位 0/1/2/7）。GHASH 乘数 H 在
//! 密钥构造时一次性转换并存为 `h_rev`。
//!
//! ## `#[target_feature]` 是性能关键
//!
//! 该工具链的 intrinsic 是带 feature 的函数，从无 feature 上下文调用
//! 时编译器不得内联——每个包装调用都成为真实函数调用（改造前全
//! crate 反汇编实测 103 处：aesenc 链与 PCLMULQDQ 的每条指令都伴随
//! 一次 call，还割裂了 AES 链与 GHASH 链的乱序重叠）。因此全部
//! kernel 与 `#[inline]` 辅助函数标注
//! `#[target_feature(enable = "aes,pclmulqdq")]`，体内直调 intrinsic
//! （安全、编译为裸指令）；unsafe 只出现在各进入点 trampoline
//! （`new`/`seal_kernel`/`open_kernel`，SAFETY = token 已证明 CPU
//! 支持）与内存包装（[`crate::raw`]）。对照证据与 SHA-NI 的同款修复
//! 记录见 docs/ARCHITECTURE.md §4、docs/BENCHMARKS.md §5.1。
//!
//! 常数时间：`AESENC/AESENCLAST/AESKEYGENASSIST/PCLMULQDQ` 均为
//! 数据无关的固定延迟指令；kernel 内无以秘密为条件的分支或访存
//! （AES 轮密钥按公开的轮号索引）。标签比较不在本模块——由 core
//! 公开类型经 `ct::verify_tag` 完成。

use core::arch::x86_64::{
    __m128i, _mm_aesenc_si128, _mm_aesenclast_si128, _mm_aeskeygenassist_si128,
    _mm_clmulepi64_si128, _mm_set_epi64x, _mm_shuffle_epi32, _mm_slli_si128, _mm_xor_si128,
};
use ferritls_core::ops::AeadGcm;

use crate::raw;
use crate::token::AesNi;

/// AES-GCM 执行核心。`N` = 轮密钥个数（AES-128: 11；AES-256: 15）。
///
/// 密钥材料（轮密钥与 GHASH 乘数）在 Drop 时零化；随实例携带一份
/// [`AesNi`] 能力证明（源自构造时的一次成功探测）。
pub(crate) struct NiGcm<const N: usize> {
    tok: AesNi,
    round_keys: [[u8; 16]; N],
    /// GHASH 乘数 H = E_K(0^128)（软件约定大端）。
    h: u128,
    /// `rev128(H)`（PCLMULQDQ 原生约定），kernel 直接使用。
    h_rev: u128,
}

impl<const N: usize> Drop for NiGcm<N> {
    fn drop(&mut self) {
        self.round_keys.fill([0u8; 16]);
        self.h = 0;
        self.h_rev = 0;
    }
}

impl<const N: usize> std::fmt::Debug for NiGcm<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NiGcm")
    }
}

impl NiGcm<11> {
    /// 以 128 位密钥构造（密钥扩展 + 预计算 H）。
    #[allow(unsafe_code)]
    pub(crate) fn new(tok: &AesNi, key: &[u8; 16]) -> Self {
        // SAFETY: 进入 feature kernel 前，aes+pclmulqdq 已由 tok 证明
        //（token 只能经运行时探测构造）。
        let (round_keys, h) = unsafe { init_11(key) };
        Self {
            tok: *tok,
            round_keys,
            h,
            h_rev: rev128(h),
        }
    }
}

impl NiGcm<15> {
    /// 以 256 位密钥构造（密钥扩展 + 预计算 H）。
    #[allow(unsafe_code)]
    pub(crate) fn new(tok: &AesNi, key: &[u8; 32]) -> Self {
        // SAFETY: 同 [`NiGcm::<11>::new`]——tok 证明 CPU 支持。
        let (round_keys, h) = unsafe { init_15(key) };
        Self {
            tok: *tok,
            round_keys,
            h,
            h_rev: rev128(h),
        }
    }
}

impl<const N: usize> NiGcm<N> {
    /// 加密：`buf` 明文进出密文，返回标签。
    #[allow(unsafe_code)]
    fn seal_kernel(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        // SAFETY: 进入 feature kernel 前，aes+pclmulqdq 已由 self.tok
        // 证明（token 只能经运行时探测构造）。
        unsafe { seal_hw(&self.round_keys, self.h_rev, nonce, aad, buf) }
    }

    /// 解密：`buf` 密文进出明文，返回基于密文计算的标签。
    ///
    /// 标签基于密文（GHASH 先于 keystream 异或），与解密顺序无关；
    /// 比较由 core 公开类型完成。
    #[allow(unsafe_code)]
    fn open_kernel(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        // SAFETY: 同 [`NiGcm::seal_kernel`]——self.tok 证明 CPU 支持。
        unsafe { open_hw(&self.round_keys, self.h_rev, nonce, aad, buf) }
    }
}

impl<const N: usize> AeadGcm for NiGcm<N> {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        self.seal_kernel(nonce, aad, buf)
    }

    fn open_compute_tag(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        self.open_kernel(nonce, aad, buf)
    }

    fn clone_box(&self) -> Box<dyn AeadGcm> {
        Box::new(NiGcm {
            tok: self.tok,
            round_keys: self.round_keys,
            h: self.h,
            h_rev: self.h_rev,
        })
    }
}

// —— feature 上下文的执行核心（性能关键，见模块文档） ——

/// 构造期 kernel（AES-128）：密钥扩展 + H = E_K(0^128)。
#[target_feature(enable = "aes,pclmulqdq")]
fn init_11(key: &[u8; 16]) -> ([[u8; 16]; 11], u128) {
    let round_keys = expand_128(key);
    let h = u128::from_be_bytes(raw::storeu(aes_encrypt_vec(
        &load_keys(&round_keys),
        [0u8; 16],
    )));
    (round_keys, h)
}

/// 构造期 kernel（AES-256）：语义同 [`init_11`]。
#[target_feature(enable = "aes,pclmulqdq")]
fn init_15(key: &[u8; 32]) -> ([[u8; 16]; 15], u128) {
    let round_keys = expand_256(key);
    let h = u128::from_be_bytes(raw::storeu(aes_encrypt_vec(
        &load_keys(&round_keys),
        [0u8; 16],
    )));
    (round_keys, h)
}

/// seal kernel：J0 标签基 → CTR keystream → GHASH → 标签。
///
/// 泛型 `N` 使轮数在各实例化点编译期已知（aesenc 链展开为直线代码）。
#[target_feature(enable = "aes,pclmulqdq")]
fn seal_hw<const N: usize>(
    round_keys: &[[u8; 16]; N],
    h_rev: u128,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let keys = load_keys(round_keys);
    let j0 = block_j0(nonce);
    let tag_base = u128::from_be_bytes(raw::storeu(aes_encrypt_vec(&keys, j0.to_be_bytes())));
    xor_keystream(&keys, inc32(j0), buf);
    let y = ghash(h_rev, aad, buf);
    (tag_base ^ rev128(y)).to_be_bytes()
}

/// open kernel：标签基于密文（GHASH 先于 keystream 异或）。
#[target_feature(enable = "aes,pclmulqdq")]
fn open_hw<const N: usize>(
    round_keys: &[[u8; 16]; N],
    h_rev: u128,
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; 16] {
    let keys = load_keys(round_keys);
    let j0 = block_j0(nonce);
    let tag_base = u128::from_be_bytes(raw::storeu(aes_encrypt_vec(&keys, j0.to_be_bytes())));
    let y = ghash(h_rev, aad, buf);
    xor_keystream(&keys, inc32(j0), buf);
    (tag_base ^ rev128(y)).to_be_bytes()
}

/// 轮密钥装入向量（公开的轮号索引，无秘密相关访存）。
#[inline]
fn load_keys<const N: usize>(rk: &[[u8; 16]; N]) -> [__m128i; N] {
    core::array::from_fn(|i| raw::loadu(&rk[i]))
}

/// 加密单个 16 字节块，返回**向量**形态（`AESENC` 链 + `AESENCLAST`
/// 收尾；keys 非空由调用方形状保证——轮密钥个数恒 ≥ 11。字节形态的
/// 调用方用 `raw::storeu` 自行转换，避免 keystream 路径的 store→load
/// 回环）。
#[inline]
#[target_feature(enable = "aes")]
fn aes_encrypt_vec(keys: &[__m128i], block: [u8; 16]) -> __m128i {
    let mut b = _mm_xor_si128(raw::loadu(&block), keys[0]);
    for k in &keys[1..keys.len() - 1] {
        b = _mm_aesenc_si128(b, *k);
    }
    _mm_aesenclast_si128(b, keys[keys.len() - 1])
}

/// CTR 模式 keystream 异或覆盖 `data`（`ctr_start` 为起始计数器，
/// 软件约定）。整块走向量路径，尾部不足一块按字节异或。
#[inline]
#[target_feature(enable = "aes")]
fn xor_keystream(keys: &[__m128i], ctr_start: u128, data: &mut [u8]) {
    let mut ctr = ctr_start;
    let (chunks, rem) = data.as_chunks_mut::<16>();
    for chunk in chunks {
        let ks = aes_encrypt_vec(keys, ctr.to_be_bytes());
        let v = _mm_xor_si128(raw::loadu(chunk), ks);
        raw::store_into(chunk, v);
        ctr = inc32(ctr);
    }
    if !rem.is_empty() {
        let ks = raw::storeu(aes_encrypt_vec(keys, ctr.to_be_bytes()));
        for (o, x) in rem.iter_mut().enumerate() {
            *x ^= ks[o];
        }
    }
}

// —— AES 密钥扩展（AESKEYGENASSIST 路线） ——

/// `x ^ slli4(x) ^ slli8(上述)`：字链 [x0, x1^x0, x2^x1^x0, x3^x2^x1^x0]。
#[inline]
#[target_feature(enable = "aes")]
fn chain_words(x: __m128i) -> __m128i {
    let t = _mm_xor_si128(x, _mm_slli_si128::<4>(x));
    _mm_xor_si128(t, _mm_slli_si128::<8>(t))
}

/// `AESKEYGENASSIST`（Rcon 为立即数：对合法 Rcon 集合做 match 分发，
/// 各臂编译为带立即数的单条指令；Rcon 由公开的轮号决定，非常数时间
/// 无关紧要）。
#[inline]
#[target_feature(enable = "aes")]
fn keygen_assist(a: __m128i, rcon: u8) -> __m128i {
    match rcon {
        0x00 => _mm_aeskeygenassist_si128::<0x00>(a),
        0x01 => _mm_aeskeygenassist_si128::<0x01>(a),
        0x02 => _mm_aeskeygenassist_si128::<0x02>(a),
        0x04 => _mm_aeskeygenassist_si128::<0x04>(a),
        0x08 => _mm_aeskeygenassist_si128::<0x08>(a),
        0x10 => _mm_aeskeygenassist_si128::<0x10>(a),
        0x20 => _mm_aeskeygenassist_si128::<0x20>(a),
        0x40 => _mm_aeskeygenassist_si128::<0x40>(a),
        0x80 => _mm_aeskeygenassist_si128::<0x80>(a),
        0x1B => _mm_aeskeygenassist_si128::<0x1B>(a),
        0x36 => _mm_aeskeygenassist_si128::<0x36>(a),
        // RCON 表由调用方控制（expand_128/256 的常量表），到达此分支
        // 即内部 bug：以 0 收尾的扩展结果让 KAT 必然失败。
        _ => _mm_aeskeygenassist_si128::<0x00>(a),
    }
}

/// 广播 `x` 的 word3，经 AESKEYGENASSIST 取 `Sub(Rot(w3)) ^ rcon` 广播到全字。
///
/// AESKEYGENASSIST 的输出是乱序打包：含 RotWord+Rcon 的 X0 落在
/// **word 3**（word0 = X1 = SubWord(输入 word1)，实测确认，也是经典
/// 实现两次 `0xFF` 广播的原因）——因此对输出再用 `0xFF` 提取。
#[inline]
#[target_feature(enable = "aes")]
fn bcast_subrot_rcon(x: __m128i, rcon: u8) -> __m128i {
    let w3 = _mm_shuffle_epi32::<0xFF>(x);
    let assist = keygen_assist(w3, rcon);
    _mm_shuffle_epi32::<0xFF>(assist)
}

/// 广播 `x` 的 word3，经 AESKEYGENASSIST 取 `Sub(w3)`（无 Rot/Rcon）广播。
///
/// 实测布局（distinct-word 探针，2026-09）：输出 word2 = SubWord(输入
/// word3)；带 RotWord+Rcon 的值在输出 word3（`bcast_subrot_rcon`）。
#[inline]
#[target_feature(enable = "aes")]
fn bcast_sub(x: __m128i) -> __m128i {
    let w3 = _mm_shuffle_epi32::<0xFF>(x);
    let assist = keygen_assist(w3, 0);
    _mm_shuffle_epi32::<0xAA>(assist)
}

/// AES-128：11 个轮密钥（FIPS-197）。
#[target_feature(enable = "aes")]
fn expand_128(key: &[u8; 16]) -> [[u8; 16]; 11] {
    const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    let mut rk = [[0u8; 16]; 11];
    rk[0] = *key;
    for i in 1..=10 {
        let prev = raw::loadu(&rk[i - 1]);
        let t0 = bcast_subrot_rcon(prev, RCON[i - 1]);
        rk[i] = raw::storeu(_mm_xor_si128(chain_words(prev), t0));
    }
    rk
}

/// AES-256：15 个轮密钥（FIPS-197；偶数步带 RotWord+Rcon，奇数步仅
/// SubWord）。60 字 = 输入 8 字 + 6 对推导 + 收尾单个偶数步。
#[target_feature(enable = "aes")]
fn expand_256(key: &[u8; 32]) -> [[u8; 16]; 15] {
    const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut rk = [[0u8; 16]; 15];
    rk[0] = key[..16].try_into().expect("16 bytes");
    rk[1] = key[16..].try_into().expect("16 bytes");
    for i in 0..6 {
        let a = raw::loadu(&rk[2 * i]);
        let b = raw::loadu(&rk[2 * i + 1]);
        let t0 = bcast_subrot_rcon(b, RCON[i]);
        rk[2 * i + 2] = raw::storeu(_mm_xor_si128(chain_words(a), t0));
        let s = bcast_sub(raw::loadu(&rk[2 * i + 2]));
        rk[2 * i + 3] = raw::storeu(_mm_xor_si128(chain_words(b), s));
    }
    // 第 60 字起只剩偶数步：rk[14] 基于 rk[12]，Rcon 取表尾。
    let a = raw::loadu(&rk[12]);
    let b = raw::loadu(&rk[13]);
    let t0 = bcast_subrot_rcon(b, RCON[6]);
    rk[14] = raw::storeu(_mm_xor_si128(chain_words(a), t0));
    rk
}

// —— GHASH：CLMUL 原生约定下的 GF(2^128) 算术 ——

/// GHASH：Aad(pad) || C(pad) || [len(aad)]64 || [len(ct)]64，
/// 返回**原生约定**的累加值（调用方 `rev128` 回软件约定）。
#[inline]
#[target_feature(enable = "pclmulqdq")]
fn ghash(h_rev: u128, aad: &[u8], ct: &[u8]) -> u128 {
    let mut y = 0u128;
    let (aad_blocks, aad_rem) = aad.as_chunks::<16>();
    for block in aad_blocks {
        y = ghash_step(h_rev, y, block);
    }
    y = ghash_tail(h_rev, y, aad_rem);
    let (ct_blocks, ct_rem) = ct.as_chunks::<16>();
    for block in ct_blocks {
        y = ghash_step(h_rev, y, block);
    }
    y = ghash_tail(h_rev, y, ct_rem);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
    ghash_step(h_rev, y, &len_block)
}

/// 一步：y = (y ^ block) · H（原生约定）。
#[inline]
#[target_feature(enable = "pclmulqdq")]
fn ghash_step(h_rev: u128, y: u128, block: &[u8; 16]) -> u128 {
    gfmul_native(y ^ rev128(u128::from_be_bytes(*block)), h_rev)
}

/// 尾部不足一块时零填充后再走一步（空尾部原样返回）。
#[inline]
#[target_feature(enable = "pclmulqdq")]
fn ghash_tail(h_rev: u128, y: u128, rem: &[u8]) -> u128 {
    if rem.is_empty() {
        return y;
    }
    let mut b = [0u8; 16];
    b[..rem.len()].copy_from_slice(rem);
    ghash_step(h_rev, y, &b)
}

/// PCLMULQDQ 64 位无进位乘（原生约定：位 k = X^k）。
#[inline]
#[target_feature(enable = "pclmulqdq")]
fn clmul64(a: u64, b: u64) -> u128 {
    u128::from_le_bytes(raw::storeu(_mm_clmulepi64_si128::<0x00>(
        _mm_set_epi64x(0, a as i64),
        _mm_set_epi64x(0, b as i64),
    )))
}

/// `a ⊗ 0x87`（无进位乘小常数；0x87 = f 的低位部分 X^7+X^2+X+1）。
/// 返回 (低 128 位, 高 ≤7 位)。
#[inline]
fn mul87(a: u128) -> (u128, u64) {
    let al = a as u64;
    let ah = (a >> 64) as u64;
    let al87 = ((al as u128) << 7) ^ ((al as u128) << 2) ^ ((al as u128) << 1) ^ (al as u128);
    let ah87 = ((ah as u128) << 7) ^ ((ah as u128) << 2) ^ ((ah as u128) << 1) ^ (ah as u128);
    // ah87·2^64 的第 128..134 位由 hi 捕获，其余并入 lo。
    let hi = (ah87 >> 64) as u64;
    (al87 ^ (ah87 << 64), hi)
}

/// 原生约定 GF(2^128) 乘法 mod f = X^128+X^7+X^2+X+1。
#[inline]
#[target_feature(enable = "pclmulqdq")]
fn gfmul_native(a: u128, b: u128) -> u128 {
    let (ah, al) = (((a >> 64) as u64), (a as u64));
    let (bh, bl) = (((b >> 64) as u64), (b as u64));
    let z0 = clmul64(al, bl);
    let zc1 = clmul64(ah, bl);
    let zc2 = clmul64(al, bh);
    let z2 = clmul64(ah, bh);

    // 256 位无进位积的四个 64 位 limb（xor 累加，无进位交互）。
    let r0 = z0 as u64;
    let r1 = (z0 >> 64) as u64 ^ ((zc1 ^ zc2) as u64);
    let r2 = ((zc1 >> 64) ^ (zc2 >> 64)) as u64 ^ (z2 as u64);
    let r3 = (z2 >> 64) as u64;

    // 约减：高 128 位 (r3:r2) 乘 X^128 ≡ ⊗0x87 折回，再折一次 ≤7 位余项。
    let (t_lo, t_hi) = mul87(((r3 as u128) << 64) | (r2 as u128));
    let (u_lo, _) = mul87(t_hi as u128);
    ((r1 as u128) << 64 | r0 as u128) ^ t_lo ^ u_lo
}

// —— 数据变换与 GCM 计数器（纯标量；与 core 软件实现相同的语义） ——

/// 64 位按位反转（对数步交换 + 字节反转）。
#[inline]
fn rev64(mut v: u64) -> u64 {
    v = ((v & 0x5555_5555_5555_5555) << 1) | ((v >> 1) & 0x5555_5555_5555_5555);
    v = ((v & 0x3333_3333_3333_3333) << 2) | ((v >> 2) & 0x3333_3333_3333_3333);
    v = ((v & 0x0F0F_0F0F_0F0F_0F0F) << 4) | ((v >> 4) & 0x0F0F_0F0F_0F0F_0F0F);
    v.swap_bytes()
}

/// 128 位按位反转 = 两半各自反转后交换。
#[inline]
fn rev128(v: u128) -> u128 {
    ((rev64(v as u64) as u128) << 64) | (rev64((v >> 64) as u64) as u128)
}

/// 96 位 nonce → J0 = nonce || 0x00000001。
fn block_j0(nonce: &[u8; 12]) -> u128 {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[15] = 1;
    u128::from_be_bytes(b)
}

/// 递增计数器块最低 32 位。
fn inc32(block: u128) -> u128 {
    let ctr = (block as u32).wrapping_add(1);
    (block & !0xFFFF_FFFF) | (ctr as u128)
}

// —— 安装时的上电 KAT（McGrew–Viega TC5/TC16，与 core 向量测试同源） ——

/// 安装前 KAT：两条密钥长度各跑一组已知答案，失败返回
/// [`Error::SelfTestFailed`](ferritls_core::Error::SelfTestFailed)。
pub(crate) fn power_up_kat(tok: &AesNi) -> Result<(), ferritls_core::Error> {
    kat_case(
        &NiGcm::<11>::new(tok, &hex16("feffe9928665731c6d6a8f9467308308")),
        &hexb("cafebabefacedbaddecaf888"),
        &hexb("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        &hexb(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ),
        &hexb(
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
             da80ce830cfda02da2a218a1744f4c76",
        ),
        "aes-128-gcm",
    )?;
    kat_case(
        &NiGcm::<15>::new(
            tok,
            &hex32("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"),
        ),
        &hexb("cafebabefacedbaddecaf888"),
        &hexb("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
        &hexb(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        ),
        &hexb(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad\
             2df7cd675b4f09163b41ebf980a7f638",
        ),
        "aes-256-gcm",
    )
}

/// KAT 单 case：seal 输出与期望逐字节比对 + open 往返。
fn kat_case<const N: usize>(
    g: &NiGcm<N>,
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
    expected: &[u8],
    what: &'static str,
) -> Result<(), ferritls_core::Error> {
    let nonce: [u8; 12] = nonce.try_into().expect("12-byte nonce");
    let mut buf = pt.to_vec();
    let tag = g.seal_kernel(&nonce, aad, &mut buf);
    buf.extend_from_slice(&tag);
    if !buf.iter().zip(expected).all(|(a, b)| a == b) {
        return Err(ferritls_core::Error::SelfTestFailed(what));
    }
    // open 方向：标签回算必须复现（比较在 core 语义中完成，此处仅验证
    // 计算一致性）。
    let (ct, tag_bytes) = buf.split_at(buf.len() - 16);
    let mut ct_buf = ct.to_vec();
    let computed = g.open_kernel(&nonce, aad, &mut ct_buf);
    if computed.as_slice() != tag_bytes || ct_buf != pt {
        return Err(ferritls_core::Error::SelfTestFailed(what));
    }
    Ok(())
}

// —— hex 小工具（KAT 常量用；测试文件另有完整实现） ——

fn hexb(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn hex16(s: &str) -> [u8; 16] {
    hexb(s).try_into().expect("16 bytes")
}

fn hex32(s: &str) -> [u8; 32] {
    hexb(s).try_into().expect("32 bytes")
}

#[cfg(test)]
fn hex_of(b: &[u8; 16]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 原生约定乘法的代数性质（无需 CPU 探测即可编译，运行时跳过）。
    #[test]
    #[allow(unsafe_code)]
    fn gfmul_native_properties() {
        let Some(tok) = AesNi::detect() else {
            eprintln!("AES-NI/CLMUL unavailable; skipping");
            return;
        };
        let _ = tok;
        // SAFETY: aes+pclmulqdq 已由上方探测成功证明。
        unsafe {
            // 单位元：原生约定下 X^0 = 1。
            let a = 0x0123456789abcdeffedcba9876543210u128;
            assert_eq!(gfmul_native(a, 1), a, "a·1 = a");
            assert_eq!(gfmul_native(1, a), a, "1·a = a");
            assert_eq!(gfmul_native(0, a), 0);
            // 交换律。
            let b = 0xdeadbeefcafef00d1234567890abcdefu128;
            assert_eq!(gfmul_native(a, b), gfmul_native(b, a));
            // 约减抽查：X^65 的平方 = X^130 = X^128·X^2 ≡ X^9+X^4+X^3+X^2。
            let x65 = 1u128 << 65;
            let x130 = gfmul_native(x65, x65);
            assert_eq!(x130, 0x21Cu128, "X^130 mod f = X^9+X^4+X^3+X^2");
        }
    }

    /// 密钥扩展中间值锚定：零密钥第 1 轮轮密钥（FIPS-197 递推的
    /// 公开标准结果，验证 Rcon 通路）+ H = E_0(0^128) 的著名值
    /// （验证全 10 轮扩展与块加密；TC1 的标签再独立覆盖全链）。
    #[test]
    #[allow(unsafe_code)]
    fn expansion_zero_key_anchors() {
        let Some(tok) = AesNi::detect() else {
            eprintln!("AES-NI/CLMUL unavailable; skipping");
            return;
        };
        // SAFETY: aes+pclmulqdq 已由探测成功证明。
        let rk = unsafe { expand_128(&[0u8; 16]) };
        assert_eq!(
            rk[1],
            hex16("62636363626363636263636362636363"),
            "zero-key round key 1 (SubWord(RotWord(0)) ^ Rcon1)"
        );
        let g = NiGcm::<11>::new(&tok, &[0u8; 16]);
        assert_eq!(
            format!("{:032x}", g.h),
            "66e94bd4ef8a2c3b884cfa59ca342b2e",
            "H = E_0(0^128)"
        );
    }

    /// 密钥扩展与 GCM 全链的 KAT（TC1 全零 case，经 trait 入口）。
    #[test]
    fn tc1_zero_case_via_trait() {
        let Some(tok) = AesNi::detect() else {
            eprintln!("AES-NI/CLMUL unavailable; skipping");
            return;
        };
        let g = tok.gcm128(&[0u8; 16]);
        let out = g.seal(&[0u8; 12], b"", &mut []);
        assert_eq!(
            u128::from_be_bytes(out),
            u128::from_str_radix("58e2fccefa7e3061367f1d57a4e7455a", 16).unwrap(),
            "TC1 tag"
        );
    }
}

/// AES-256 密钥扩展的独立参照表（key = 0102..20）：由 FIPS-197 递推
/// 的独立 Python 转写生成（2026-09，与本实现无共享代码），逐轮密钥
/// 比对——覆盖全部 6 对偶/奇步与收尾偶数步。
#[cfg(test)]
mod expand_256_reference {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn expand_256_matches_independent_reference() {
        let Some(tok) = AesNi::detect() else {
            return;
        };
        let _ = tok;
        let key: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
        // SAFETY: aes+pclmulqdq 已由探测成功证明。
        let rk = unsafe { expand_256(&key) };
        let expect: [&str; 15] = [
            "0102030405060708090a0b0c0d0e0f10",
            "1112131415161718191a1b1c1d1e1f20",
            "72c2b4a077c4b3a87eceb8a473c0b7b4",
            "9ea8ba998bbead8192a4b69d8fbaa9bd",
            "8411ced3f3d57d7b8d1bc5dffedb726b",
            "2511fae6aeaf57673c0be1fab3b14847",
            "48436ebebb9613c5368dd61ac856a471",
            "cda0b345630fe4225f0405d8ecb54d9f",
            "95a0b5702e36a6b518bb70afd0edd4de",
            "bdf5fb58defa1f7a81fe1aa26d4b573d",
            "36fb924c18cd34f900764456d09b9088",
            "cde19b9c131b84e692e59e44ffaec979",
            "f226245aeaeb10a3ea9d54f53a06c47d",
            "4d8e87635e950385cc709dc133de54b8",
            "af06489945ed583aaf700ccf9576c8b2",
        ];
        for (i, e) in expect.iter().enumerate() {
            let got = crate::gcm::hex_of(&rk[i]);
            assert_eq!(got, *e, "rk[{i}]: got {got} expect {e}");
        }
    }
}
