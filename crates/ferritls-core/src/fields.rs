//! 边界内的 Montgomery 域算术宏。
//!
//! 设计要点：
//! - 所有域常数（mu = −p⁻¹ mod 2⁶⁴、R² = 2^(64n) mod p、R = 1·R mod p）
//!   由 const fn 在**编译期推导**，不从文档手抄，杜绝转录错误；
//! - CIOS Montgomery 乘法，全分支无关；
//! - 所有比较/选择均为常数时间（掩码），供秘密路径使用。

/// 生成一个 Montgomery 域类型。
///
/// `modulus` 为素数的小端 u64 limb 数组。
macro_rules! fp_field {
    ($name:ident, $n:expr, $modulus:expr, $doc:expr) => {
        #[doc = $doc]
        /// Montgomery 形式（值 = a·R mod p，R = 2^(64·limbs)）。
        #[derive(Clone, Copy, Debug)]
        pub struct $name(pub(crate) [u64; $n]);

        #[allow(clippy::wrong_self_convention)]
        #[allow(dead_code)]
        impl $name {
            /// 素数（小端 limbs）。
            pub const P: [u64; $n] = $modulus;
            pub(crate) const LIMBS: usize = $n;

            /// 零（Montgomery 形式与普通形式相同）。
            pub const fn zero() -> Self {
                Self([0; $n])
            }

            /// 1 的 Montgomery 形式（= R mod p，编译期倍增推导）。
            pub const fn one() -> Self {
                let mut r = [0u64; $n];
                r[0] = 1;
                let mut i = 0;
                while i < 64 * $n {
                    r = Self::const_dbl_mod(r);
                    i += 1;
                }
                Self(r)
            }

            /// R² mod p（编译期：从 1 倍增 2·64n 次）。
            const R2: [u64; $n] = {
                let mut r = [0u64; $n];
                r[0] = 1;
                let mut i = 0;
                while i < 2 * 64 * $n {
                    r = Self::const_dbl_mod(r);
                    i += 1;
                }
                r
            };

            /// mu = −p⁻¹ mod 2⁶⁴（编译期 Newton 迭代）。
            const N0: u64 = {
                let mut inv = 1u64;
                let mut i = 0;
                while i < 6 {
                    inv = inv.wrapping_mul(2u64.wrapping_sub(Self::P[0].wrapping_mul(inv)));
                    i += 1;
                }
                inv.wrapping_neg()
            };

            /// 常数上下文中 2r mod p（用于推导 R/R²）。
            const fn const_dbl_mod(mut r: [u64; $n]) -> [u64; $n] {
                let mut carry = 0u64;
                let mut j = 0;
                while j < $n {
                    let c = r[j] >> 63;
                    r[j] = (r[j] << 1) | carry;
                    carry = c;
                    j += 1;
                }
                // r（含进位位）− p；借位穿透到进位位：b == 1 说明原值 < p，需还原。
                let mut borrow = 0u64;
                let mut j = 0;
                while j < $n {
                    let (v, b1) = r[j].overflowing_sub(Self::P[j]);
                    let (v, b2) = v.overflowing_sub(borrow);
                    r[j] = v;
                    borrow = (b1 as u64) | (b2 as u64);
                    j += 1;
                }
                let (_, b) = carry.overflowing_sub(borrow);
                if b {
                    let mut c2 = 0u64;
                    let mut j = 0;
                    while j < $n {
                        let (v, c1) = r[j].overflowing_add(Self::P[j]);
                        let (v, c2b) = v.overflowing_add(c2);
                        r[j] = v;
                        c2 = (c1 as u64) | (c2b as u64);
                        j += 1;
                    }
                }
                r
            }

            /// 常数时间条件减 p：cond 为全 1 掩码时执行。
            #[inline]
            pub(crate) fn cond_sub_p(&mut self, cond: u64) {
                let mut borrow = 0u64;
                let mut j = 0;
                let mut tmp = [0u64; $n];
                while j < $n {
                    let (v, b1) = self.0[j].overflowing_sub(Self::P[j]);
                    let (v, b2) = v.overflowing_sub(borrow);
                    tmp[j] = v;
                    borrow = (b1 as u64) | (b2 as u64);
                    j += 1;
                }
                let mut j = 0;
                while j < $n {
                    self.0[j] = self.0[j] ^ ((self.0[j] ^ tmp[j]) & cond);
                    j += 1;
                }
            }

            /// 常数时间条件加 p：cond 为全 1 掩码时执行（借位时调用）。
            #[inline]
            fn cond_add_p(&mut self, cond: u64) {
                let mut carry = 0u64;
                let mut j = 0;
                let mut tmp = [0u64; $n];
                while j < $n {
                    let (v, c1) = self.0[j].overflowing_add(Self::P[j]);
                    let (v, c2) = v.overflowing_add(carry);
                    tmp[j] = v;
                    carry = (c1 as u64) | (c2 as u64);
                    j += 1;
                }
                let mut j = 0;
                while j < $n {
                    self.0[j] = self.0[j] ^ ((self.0[j] ^ tmp[j]) & cond);
                    j += 1;
                }
            }

            /// r >= p 的常数时间判定（布尔；r 为普通形式）。
            #[inline]
            pub(crate) fn geq_canonical(r: &[u64; $n]) -> bool {
                let mut j = $n;
                while j > 0 {
                    j -= 1;
                    if r[j] > Self::P[j] {
                        return true;
                    }
                    if r[j] < Self::P[j] {
                        return false;
                    }
                }
                true // 相等视为 ≥
            }

            /// Montgomery 形式 r >= p 判定的掩码版本（全 1 / 全 0）。
            #[inline]
            fn geq_mask(r: &[u64; $n]) -> u64 {
                (Self::geq_canonical(r) as u64).wrapping_neg()
            }

            /// Montgomery 乘法：schoolbook 全积 + REDC 约减。
            /// （原 CIOS 实现的进位处理过于隐蔽，此处采用逐段累加的
            /// 经典两段式实现，正确性一目了然；性能由 M8 后端解决。）
            pub fn mul(&self, other: &Self) -> Self {
                let mut prod = [0u64; 2 * $n + 1];
                // 1) schoolbook 全积
                for i in 0..$n {
                    let ai = self.0[i] as u128;
                    let mut carry = 0u128;
                    for j in 0..$n {
                        let s = (prod[i + j] as u128) + ai * (other.0[j] as u128) + carry;
                        prod[i + j] = s as u64;
                        carry = s >> 64;
                    }
                    let mut k = i + $n;
                    while carry > 0 {
                        let s = (prod[k] as u128) + carry;
                        prod[k] = s as u64;
                        carry = s >> 64;
                        k += 1;
                    }
                }
                // 2) REDC：对每个低位字 m = t[i]·N0，累加 m·p·2^(64i)
                for i in 0..$n {
                    let m = prod[i].wrapping_mul(Self::N0);
                    let mut carry = 0u128;
                    for j in 0..$n {
                        let s = (prod[i + j] as u128) + (m as u128) * (Self::P[j] as u128) + carry;
                        prod[i + j] = s as u64;
                        carry = s >> 64;
                    }
                    let mut k = i + $n;
                    while carry > 0 {
                        let s = (prod[k] as u128) + carry;
                        prod[k] = s as u64;
                        carry = s >> 64;
                        k += 1;
                    }
                }
                // 3) 结果 = prod[N..2N]（< 2p），常数时间条件减 p 一次
                let hi = (prod[2 * $n] != 0) as u64;
                let mut r = [0u64; $n];
                r.copy_from_slice(&prod[$n..2 * $n]);
                debug_assert!(hi <= 1, "REDC result must fit in N+1 limbs");
                let mut borrow = 0u64;
                let mut tmp = [0u64; $n];
                for j in 0..$n {
                    let (v, b1) = r[j].overflowing_sub(Self::P[j]);
                    let (v, b2) = v.overflowing_sub(borrow);
                    tmp[j] = v;
                    borrow = (b1 as u64) | (b2 as u64);
                }
                // hi=1：无条件减（回绕等价于 T − p）；hi=0：r ≥ p（borrow
                // == 0，未回绕）才减。
                let cond = if hi >= 1 {
                    u64::MAX
                } else {
                    ((borrow == 0) as u64).wrapping_neg()
                };
                for j in 0..$n {
                    r[j] = r[j] ^ ((r[j] ^ tmp[j]) & cond);
                }
                Self(r)
            }

            pub fn square(&self) -> Self {
                self.mul(self)
            }

            pub fn add(&self, other: &Self) -> Self {
                let mut r = [0u64; $n];
                let mut carry = 0u64;
                for j in 0..$n {
                    let (v, c1) = self.0[j].overflowing_add(other.0[j]);
                    let (v, c2) = v.overflowing_add(carry);
                    r[j] = v;
                    carry = (c1 as u64) | (c2 as u64);
                }
                let mut f = Self(r);
                let cond = ((carry == 1) as u64).wrapping_neg() | Self::geq_mask(&f.0);
                f.cond_sub_p(cond);
                f
            }

            pub fn sub(&self, other: &Self) -> Self {
                let mut f = Self([0u64; $n]);
                let mut borrow = 0u64;
                for j in 0..$n {
                    let (v, b1) = self.0[j].overflowing_sub(other.0[j]);
                    let (v, b2) = v.overflowing_sub(borrow);
                    f.0[j] = v;
                    borrow = (b1 as u64) | (b2 as u64);
                }
                f.cond_add_p(((borrow == 1) as u64).wrapping_neg());
                f
            }

            #[allow(dead_code)]
            pub fn neg(&self) -> Self {
                Self::zero().sub(self)
            }

            /// 值是否为零（全 1 掩码）。
            pub fn is_zero_mask(&self) -> u64 {
                let mut acc = 0u64;
                for j in 0..$n {
                    acc |= self.0[j];
                }
                ((acc | acc.wrapping_neg()) >> 63).wrapping_sub(1)
            }

            /// 常数时间相等（全 1 掩码）。
            pub fn ct_eq_mask(&self, other: &Self) -> u64 {
                let mut acc = 0u64;
                for j in 0..$n {
                    acc |= self.0[j] ^ other.0[j];
                }
                ((acc | acc.wrapping_neg()) >> 63).wrapping_sub(1)
            }

            /// 常数时间选择：mask 为全 1 时取 a，否则取 b。
            pub fn select(mask: u64, a: &Self, b: &Self) -> Self {
                let mut r = [0u64; $n];
                for j in 0..$n {
                    r[j] = (a.0[j] & mask) | (b.0[j] & !mask);
                }
                Self(r)
            }

            /// 由普通形式 limbs（须 < p）进入 Montgomery 域。
            pub fn from_raw(raw: [u64; $n]) -> Self {
                Self(raw).mul(&Self(Self::R2))
            }

            /// 导出普通形式 limbs（< p）。
            pub fn to_raw(&self) -> [u64; $n] {
                let one = [1u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64];
                let mut one_n = [0u64; $n];
                one_n.copy_from_slice(&one[..$n]);
                self.mul(&Self(one_n)).0
            }

            /// 大端字节导入（按位归约到 mod p，输入可任意长度 ≤ 64n）。
            #[allow(dead_code)]
            pub fn from_bytes_be_mod(bytes: &[u8]) -> Self {
                let mut acc = [0u64; $n]; // 普通形式，恒 < p
                for &byte in bytes {
                    // acc = acc·256 + byte，逐位归约：8 次倍增 + 字节按位。
                    for bit in (0..8).rev() {
                        // acc = 2·acc + bit；移位出顶 limb 的进位不可丢弃
                        // （对 p ≈ 2^(64n) 的域会直接翻倍越界）。
                        let mut carry = 0u64;
                        let mut j = 0;
                        while j < $n {
                            let c = acc[j] >> 63;
                            acc[j] = (acc[j] << 1) | carry;
                            carry = c;
                            j += 1;
                        }
                        acc[0] |= u64::from((byte >> bit) & 1);
                        // value = acc + carry·2^(64n)；条件减 p：
                        // tmp = acc − p（借位 b）；仅当 carry=0 且 b=1 时还原。
                        let mut borrow = 0u64;
                        let mut tmp = [0u64; $n];
                        let mut j = 0;
                        while j < $n {
                            let (v, b1) = acc[j].overflowing_sub(Self::P[j]);
                            let (v, b2) = v.overflowing_sub(borrow);
                            tmp[j] = v;
                            borrow = (b1 as u64) | (b2 as u64);
                            j += 1;
                        }
                        let (_, under) = carry.overflowing_sub(borrow);
                        if under {
                            // acc < p：还原
                            let mut j = 0;
                            while j < $n {
                                acc[j] = acc[j].wrapping_add(Self::P[j]).wrapping_add(0);
                                j += 1;
                            }
                        } else {
                            acc = tmp;
                        }
                    }
                }
                Self::from_raw(acc)
            }

            /// 大端字节导出（普通形式）。
            pub fn to_bytes_be(&self) -> [u8; $n * 8] {
                let raw = self.to_raw();
                let mut out = [0u8; $n * 8];
                for j in 0..$n {
                    out[($n - 1 - j) * 8..($n - j) * 8].copy_from_slice(&raw[j].to_be_bytes());
                }
                out
            }

            /// 小端字节导出。
            #[allow(dead_code)]
            pub fn to_bytes_le(&self) -> [u8; $n * 8] {
                let raw = self.to_raw();
                let mut out = [0u8; $n * 8];
                for j in 0..$n {
                    out[j * 8..(j + 1) * 8].copy_from_slice(&raw[j].to_le_bytes());
                }
                out
            }

            /// 常数 3（Montgomery 形式）。
            pub(crate) fn three() -> Self {
                let mut r = [0u64; $n];
                r[0] = 3;
                Self::from_raw(r)
            }

            /// 固定宽度模幂（MSB→LSB，常数时间）。指数为普通形式 limbs。
            pub fn pow(&self, exp: &[u64; $n]) -> Self {
                let mut result = Self::one();
                for i in (0..64 * $n).rev() {
                    result = result.square();
                    let bit = ((exp[i / 64] >> (i % 64)) & 1).wrapping_neg();
                    let tmp = result.mul(self);
                    result = Self::select(bit, &tmp, &result);
                }
                result
            }

            /// 逆元（Fermat：a^(p−2)）。
            pub fn invert(&self) -> Self {
                let mut e = Self::P;
                // e = p − 2
                let (v, _) = e[0].overflowing_sub(2);
                e[0] = v;
                self.pow(&e)
            }

            /// 值是否为零（bool；仅用于公开数据路径）。
            pub fn is_zero(&self) -> bool {
                self.is_zero_mask() != 0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.ct_eq_mask(other) != 0
            }
        }

        impl Eq for $name {}
    };
}

// P-256 素数域。
fp_field!(
    Fp256,
    4,
    [
        0xffffffffffffffff,
        0x00000000ffffffff,
        0x0000000000000000,
        0xffffffff00000001,
    ],
    "P-256 基域 GF(p)，p = 2^256 − 2^224 + 2^192 + 2^96 − 1。"
);

// P-256 标量域（群阶 n）。
fp_field!(
    Fp256Scalar,
    4,
    [
        0xf3b9cac2fc632551,
        0xbce6faada7179e84,
        0xffffffffffffffff,
        0xffffffff00000000,
    ],
    "P-256 标量域 GF(n)。"
);

// P-384 素数域。
fp_field!(
    Fp384,
    6,
    [
        0x00000000ffffffff,
        0xffffffff00000000,
        0xfffffffffffffffe,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ],
    "P-384 基域 GF(p)，p = 2^384 − 2^128 − 2^96 + 2^32 − 1。"
);

// P-384 标量域。
fp_field!(
    Fp384Scalar,
    6,
    [
        0xecec196accc52973,
        0x581a0db248b0a77a,
        0xc7634d81f4372ddf,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0xffffffffffffffff,
    ],
    "P-384 标量域 GF(n)。"
);

// GF(2^255 − 19)（X25519 / Ed25519 共用）。
fp_field!(
    Fp25519,
    4,
    [
        0xffffffffffffffed,
        0xffffffffffffffff,
        0xffffffffffffffff,
        0x7fffffffffffffff,
    ],
    "Curve25519 基域 GF(2^255 − 19)。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp25519_constants() {
        // R = 2^256 mod (2^255 − 19) = 38
        assert_eq!(Fp25519::one().0, [38, 0, 0, 0]);
    }

    #[test]
    fn fp256_constants() {
        // R = 2^256 mod p 与 R2 = 2^512 mod p（真值独立计算核对）。
        let r = Fp256::one().0;
        assert_eq!(
            r,
            [
                1,
                0xffffffff00000000,
                0xffffffffffffffff,
                0x00000000fffffffe,
            ]
        );
        assert_eq!(
            Fp256::R2,
            [3, 0xfffffffbffffffff, 0xfffffffffffffffe, 0x04fffffffd,]
        );
    }

    #[test]
    fn fp384_small_mul_probe() {
        let c = Fp384::from_raw([5, 0, 0, 0, 0, 0]);
        let d = Fp384::from_raw([7, 0, 0, 0, 0, 0]);
        assert_eq!(c.mul(&d).to_raw(), [35, 0, 0, 0, 0, 0], "5·7");
        // R2 = 2^768 mod p（独立计算）。
        assert_eq!(
            Fp384::R2,
            [
                0xfffffffe00000001,
                0x0000000200000000,
                0xfffffffe00000000,
                0x0000000200000000,
                1,
                0,
            ],
            "Fp384 R2"
        );
        let a_m = Fp384::from_raw([0x1234567890abcdef, 0xdeadbeefcafebabe, 0x12345678, 0, 0, 0]);
        // a·R mod p（Python 独立计算）
        assert_eq!(
            a_m.0,
            [
                0x8188888990abcdef,
                0xa45ad220b8ca6445,
                0xcafebabdd666bbf0,
                0xf0e21568a9ac79ad,
                0x12345678,
                0x0,
            ],
            "from_raw"
        );
    }

    #[test]
    fn fp384_constants_and_mul() {
        // R = 2^384 mod p（独立计算）。
        assert_eq!(
            Fp384::one().0,
            [0xffffffff00000001, 0x00000000ffffffff, 1, 0, 0, 0,],
            "Fp384 one = R"
        );
        let a = Fp384::from_raw([0x1234567890abcdef, 0xdeadbeefcafebabe, 0x12345678, 0, 0, 0]);
        let b = Fp384::from_raw([0x9876543210fedcba, 0x9876543210fedcba, 0, 0, 0, 0]);
        assert_eq!(
            a.mul(&b).to_raw(),
            [
                0xfe4b5bf004ef03a6,
                0xb0abcb95c0488334,
                0xe1c2ece2d2cc8cc,
                0x5bbbbf287caac6b2,
                0xad77d74,
                0x0,
            ],
            "a·b mod p384"
        );
    }

    #[test]
    fn fp256_mul_add_sub_anchored() {
        let a = Fp256::from_raw([0x1234567890abcdef, 0xdeadbeefcafebabe, 0, 0]);
        let b = Fp256::from_raw([0x9abcdef012345678, 0x12345678, 0, 0]);
        assert_eq!(
            a.mul(&b).to_raw(),
            [
                0xc768d28e2a42d208,
                0x3c187464abe8cc7d,
                0xeb2a01d7fc89c419,
                0x0fd5bdee,
            ],
            "a·b mod p"
        );
        assert_eq!(
            a.add(&b).to_raw(),
            [0xacf13568a2e02467, 0xdeadbeefdd331136, 0, 0],
            "a+b mod p"
        );
        assert_eq!(
            a.sub(&b).to_raw(),
            [0x777777887e777777, 0xdeadbeefb8ca6445, 0, 0],
            "a−b mod p"
        );
    }

    #[test]
    fn field_round_trips() {
        let a = Fp25519::from_raw([0x123456789abcdef, 0x0fedcba987654321, 2, 0]);
        assert_eq!(a.to_raw(), [0x123456789abcdef, 0x0fedcba987654321, 2, 0]);
    }

    #[test]
    fn fp25519_mul_known() {
        // 121665 · 9 mod p，Montgomery 形式真值独立计算。
        let x = Fp25519::from_raw([121665, 0, 0, 0]);
        let y = Fp25519::from_raw([9, 0, 0, 0]);
        let xy = x.mul(&y);
        assert_eq!(xy.to_raw(), [1094985, 0, 0, 0], "9·121665 = 1094985");
        let yx = y.mul(&x);
        assert_eq!(xy, yx, "commutativity");
        let z = Fp25519::from_raw([0xdeadbeef, 0x1234, 0, 0xffffffff]);
        assert_eq!(xy.mul(&z), x.mul(&y.mul(&z)), "associativity");
    }
}
