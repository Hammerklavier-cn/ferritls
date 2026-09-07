//! RSA 大数运算支撑（内部模块，M4b）。
//!
//! 固定宽度大整数（最多 [`MAX_LIMBS`] × 64 位 = RSA-4096）与
//! Montgomery 模乘/模幂，供 [`crate::sign::rsa`] 使用。
//!
//! 设计要点：
//! - 与 `fields.rs` 的 Montgomery 乘法同构（schoolbook 全积 + REDC），
//!   但模数与 limb 数为运行期参数；
//! - 私钥路径（CRT 模幂）对秘密指数常数时间：指数位经掩码选择，
//!   无秘密分支、无秘密索引访存；
//! - 进制常数（n0'、R²）在密钥装载时一次计算——这些是公开数据的
//!   运算，可用普通循环；
//! - 所有中间缓冲区固定宽度，避免以数据长度为条件的泄露。
//!
//! [`MAX_LIMBS`]: self::MAX_LIMBS

/// 单模数最大 limb 数：RSA-4096 的模数为 64 个 u64。
pub(crate) const MAX_LIMBS: usize = 64;

/// −n⁻¹ mod 2^64（n 奇；牛顿迭代，精度逐轮倍增）。
pub(crate) fn n0_inv(n0: u64) -> u64 {
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// a ≥ b（等长 LE limbs，MSB→LSB）。
pub(crate) fn geq(a: &[u64], b: &[u64]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for j in (0..a.len()).rev() {
        if a[j] > b[j] {
            return true;
        }
        if a[j] < b[j] {
            return false;
        }
    }
    true
}

/// 常数时间 limbs 选择：`out = mask ? a : b`（mask 全 1 / 全 0）。
pub(crate) fn select(mask: u64, a: &[u64], b: &[u64], out: &mut [u64]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    for j in 0..out.len() {
        out[j] = b[j] ^ ((a[j] ^ b[j]) & mask);
    }
}

/// 大端字节 → LE limbs（`out` 长度须 ≥ ceil(bytes/8)）。
pub(crate) fn os2ip_be(bytes: &[u8], out: &mut [u64]) {
    for w in out.iter_mut() {
        *w = 0;
    }
    for (i, chunk) in bytes.rchunks(8).enumerate() {
        let mut w = [0u8; 8];
        w[8 - chunk.len()..].copy_from_slice(chunk);
        out[i] = u64::from_be_bytes(w);
    }
}

/// LE limbs → 定长大端字节（高位截断/补零由调用方保证宽度合法）。
pub(crate) fn i2osp_be(limbs: &[u64], out: &mut [u8]) {
    for w in out.iter_mut() {
        *w = 0;
    }
    for (i, chunk) in out.rchunks_mut(8).enumerate() {
        let be = limbs[i].to_be_bytes();
        chunk.copy_from_slice(&be[8 - chunk.len()..]);
    }
}

/// Montgomery 乘法：`out = a·b·R⁻¹ mod n`（a, b < n，n 奇）。
///
/// 与 `fields.rs::mul` 同构：schoolbook 全积 + REDC，运行期 limb 数。
/// `out` 可与 `a`/`b` 重叠为同一缓冲区。
pub(crate) fn mont_mul(a: &[u64], b: &[u64], n: &[u64], n0: u64, out: &mut [u64]) {
    let l = n.len();
    debug_assert!(l <= MAX_LIMBS);
    debug_assert_eq!(a.len(), l);
    debug_assert_eq!(b.len(), l);
    let mut prod = [0u64; 2 * MAX_LIMBS + 1];

    // 1) schoolbook 全积
    for i in 0..l {
        let ai = a[i] as u128;
        let mut carry = 0u128;
        for j in 0..l {
            let s = (prod[i + j] as u128) + ai * (b[j] as u128) + carry;
            prod[i + j] = s as u64;
            carry = s >> 64;
        }
        let mut k = i + l;
        while carry > 0 {
            let s = (prod[k] as u128) + carry;
            prod[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    // 2) REDC：对每个低位字 m = prod[i]·n0'，累加 m·n·2^(64i)
    for i in 0..l {
        let m = prod[i].wrapping_mul(n0);
        let mut carry = 0u128;
        for j in 0..l {
            let s = (prod[i + j] as u128) + (m as u128) * (n[j] as u128) + carry;
            prod[i + j] = s as u64;
            carry = s >> 64;
        }
        let mut k = i + l;
        while carry > 0 {
            let s = (prod[k] as u128) + carry;
            prod[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    // 3) 结果 = prod[l..2l]（< 2n），常数时间条件减 n 一次
    let hi = (prod[2 * l] != 0) as u64;
    let mut r = [0u64; MAX_LIMBS];
    r[..l].copy_from_slice(&prod[l..2 * l]);
    let mut borrow = 0u64;
    let mut tmp = [0u64; MAX_LIMBS];
    for j in 0..l {
        let (v, b1) = r[j].overflowing_sub(n[j]);
        let (v, b2) = v.overflowing_sub(borrow);
        tmp[j] = v;
        borrow = (b1 as u64) | (b2 as u64);
    }
    // hi=1：无条件减（回绕等价 T − n）；hi=0：r ≥ n（borrow == 0）才减。
    let cond = if hi >= 1 {
        u64::MAX
    } else {
        ((borrow == 0) as u64).wrapping_neg()
    };
    for j in 0..l {
        out[j] = r[j] ^ ((r[j] ^ tmp[j]) & cond);
    }
}

/// x 进入 Montgomery 域：`x·R mod n`。
pub(crate) fn to_mont(x: &[u64], r2: &[u64], n: &[u64], n0: u64, out: &mut [u64]) {
    mont_mul(x, r2, n, n0, out);
}

/// x 原地离开 Montgomery 域：`x ← x·R⁻¹ mod n`（乘原始形式的 1）。
pub(crate) fn from_mont(x: &mut [u64], n: &[u64], n0: u64) {
    let l = n.len();
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let mut tmp = [0u64; MAX_LIMBS];
    tmp[..l].copy_from_slice(x);
    mont_mul(&tmp[..l], &one[..l], n, n0, x);
}

/// 逐位归约：任意宽度 limbs mod n（MSB→LSB，累加器 l+1 limbs）。
///
/// 公开数据运算（消息代表元、R²），无需常数时间；不变式
/// `acc < n`，每步 `2·acc + bit ≤ 2n − 1` 恰好落在 l+1 个 limb 内。
pub(crate) fn reduce_limbs(a: &[u64], n: &[u64], out: &mut [u64]) {
    let l = n.len();
    debug_assert!(l <= MAX_LIMBS);
    let mut acc = [0u64; MAX_LIMBS + 1];
    let mut n_ext = [0u64; MAX_LIMBS + 1];
    n_ext[..l].copy_from_slice(n);
    let mut tmp = [0u64; MAX_LIMBS + 1];

    for i in (0..a.len() * 64).rev() {
        // acc = 2·acc + bit
        let bit = (a[i / 64] >> (i % 64)) & 1;
        let mut carry = bit;
        for w in acc.iter_mut().take(l + 1) {
            let c = *w >> 63;
            *w = (*w << 1) | carry;
            carry = c;
        }
        debug_assert_eq!(carry, 0, "2·acc + bit 必须 < 2^(64(l+1))");
        // acc ≥ n ?（acc[l] != 0 ⟹ acc ≥ 2^(64l) > n）
        let ge = if acc[l] != 0 { true } else { geq(&acc[..l], n) };
        if ge {
            let mut borrow = 0u64;
            for j in 0..=l {
                let (v, b) = acc[j].overflowing_sub(n_ext[j]);
                let (v, b2) = v.overflowing_sub(borrow);
                tmp[j] = v;
                borrow = (b as u64) | (b2 as u64);
            }
            debug_assert_eq!(borrow, 0);
            acc = tmp;
        }
    }
    out[..l].copy_from_slice(&acc[..l]);
}

/// 计算 R² mod n（密钥装载时一次；R = 2^(64·n.len())）。
pub(crate) fn compute_r2(n: &[u64]) -> Vec<u64> {
    let l = n.len();
    // 2^(128·l) 的 limb 表示：limb 2l 的 bit 0
    let mut bits = vec![0u64; 2 * l + 1];
    bits[2 * l] = 1;
    let mut r2 = vec![0u64; l];
    reduce_limbs(&bits, n, &mut r2);
    r2
}

/// 全积：a·b（等长 limbs），返回 2·a.len() limbs。
pub(crate) fn mul_full(a: &[u64], b: &[u64]) -> Vec<u64> {
    let l = a.len();
    let mut out = vec![0u64; 2 * l];
    for i in 0..l {
        let ai = a[i] as u128;
        let mut carry = 0u128;
        for j in 0..l {
            let s = (out[i + j] as u128) + ai * (b[j] as u128) + carry;
            out[i + j] = s as u64;
            carry = s >> 64;
        }
        out[i + l] = carry as u64;
    }
    out
}

/// 无进位输出加法（a, b 等长；调用方保证不溢出）。
pub(crate) fn add_limbs(a: &[u64], b: &[u64], out: &mut [u64]) {
    let mut carry = 0u128;
    for j in 0..a.len() {
        let s = (a[j] as u128) + (b[j] as u128) + carry;
        out[j] = s as u64;
        carry = s >> 64;
    }
    debug_assert_eq!(carry, 0, "加法溢出须由调用方排除");
}

/// 减法：`out = a − b`，返回借位（a, b 等长）。
pub(crate) fn sub_limbs(a: &[u64], b: &[u64], out: &mut [u64]) -> u64 {
    let mut borrow = 0u64;
    for j in 0..a.len() {
        let (v, b1) = a[j].overflowing_sub(b[j]);
        let (v, b2) = v.overflowing_sub(borrow);
        out[j] = v;
        borrow = (b1 as u64) | (b2 as u64);
    }
    borrow
}

/// Montgomery 模幂：`out = base^exp mod n`（base 为 Montgomery 形式）。
///
/// 平方-乘阶梯，指数位以掩码选择（对指数常数时间）。返回 Montgomery
/// 形式；调用方按需 `from_mont`。
pub(crate) fn mont_exp(
    base: &[u64],
    exp: &[u64],
    exp_bits: usize,
    n: &[u64],
    n0: u64,
    r2: &[u64],
    out: &mut [u64],
) {
    let l = n.len();
    // result = mont(1) = R mod n（one 须为全宽 limbs）
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let mut result = [0u64; MAX_LIMBS];
    to_mont(&one[..l], r2, n, n0, &mut result[..l]);
    let mut tmp = [0u64; MAX_LIMBS];
    let mut tmp2 = [0u64; MAX_LIMBS];
    for i in (0..exp_bits).rev() {
        mont_mul(&result[..l], &result[..l], n, n0, &mut tmp[..l]);
        let mask = ((exp[i / 64] >> (i % 64)) & 1).wrapping_neg();
        mont_mul(&tmp[..l], base, n, n0, &mut tmp2[..l]);
        select(mask, &tmp2[..l], &tmp[..l], &mut result[..l]);
    }
    out[..l].copy_from_slice(&result[..l]);
}
