//! 椭圆曲线 Diffie-Hellman 密钥交换：X25519（RFC 7748）与
//! NIST P-256/P-384（SP 800-56A）。
//!
//! 批准状态：P-256/P-384 为 FIPS 批准；**X25519 独立使用为非批准**。
//!
//! 安全设计：
//! - 全部标量乘使用 (R0, R1 = R0 + Q) 不变式阶梯：加法永不作用于相等点，
//!   配合 z=0 的无穷远表示与 `add_or_copy`，可证明无例外路径；
//! - 位选择/点选择全部常数时间；P-256/384 的 ECDH 标量加盲
//!   （d' = d + r·n，r 为 64 位随机整数，整数加法不取模）；
//! - 私钥、共享秘密 ZeroizeOnDrop；
//! - 对端公钥必须通过长度/编码/在曲线校验；X25519 全零输出（小阶点）
//!   返回 `VerificationFailed`。
//!
//! 向量：RFC 7748 §6.1（tests/x25519.rs）；k·G 与 n·G 锚值由独立实现
//! 交叉核对（ecdh 内嵌测试）；Wycheproof ECDH 在 M4 一并引入。

use crate::fields::{Fp25519, Fp256, Fp256Scalar, Fp384, Fp384Scalar};

/// 单字节 -> 掩码（全 1 / 全 0）。
#[inline]
fn bit_mask(bit: u8) -> u64 {
    (bit as u64).wrapping_neg()
}

/// X25519 标量乘（Montgomery 阶梯）。`k` 为已钳制标量（LE）。
fn x25519_ladder(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    // u 坐标导入：屏蔽最高位，若 ≥ p 做一次条件减（输入 < 2p 恒成立）。
    let mut u = *u;
    u[31] &= 127;
    let x1 = {
        let mut limbs = [0u64; 4];
        for j in 0..4 {
            let mut w = [0u8; 8];
            w.copy_from_slice(&u[j * 8..j * 8 + 8]);
            limbs[j] = u64::from_le_bytes(w);
        }
        let mut f = Fp25519(limbs);
        let cond = (Fp25519::geq_canonical(&f.0) as u64).wrapping_neg();
        f.cond_sub_p(cond);
        // 进入 Montgomery 域——后续运算均为 Montgomery 语义
        Fp25519::from_raw(f.0)
    };

    let a24 = Fp25519::from_raw([121665, 0, 0, 0]);

    let mut x2 = Fp25519::one();
    let mut z2 = Fp25519::zero();
    let mut x3 = x1;
    let mut z3 = Fp25519::one();
    let mut swap: u8 = 0;

    for t in (0..255).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        // 常数时间条件交换（按 limb 掩码）。
        let mask = bit_mask(swap);
        for (pa, pb) in [(&mut x2, &mut x3), (&mut z2, &mut z3)] {
            for j in 0..4 {
                let xor = pa.0[j] ^ pb.0[j];
                pa.0[j] ^= xor & mask;
                pb.0[j] ^= xor & mask;
            }
        }
        swap = kt;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        let dcc = da.sub(&cb).square();
        z3 = x1.mul(&dcc);
        x2 = aa.mul(&bb);
        let a24e = a24.mul(&e);
        z2 = e.mul(&aa.add(&a24e));
    }
    let mask = bit_mask(swap);
    for (pa, pb) in [(&mut x2, &mut x3), (&mut z2, &mut z3)] {
        for j in 0..4 {
            let xor = pa.0[j] ^ pb.0[j];
            pa.0[j] ^= xor & mask;
            pb.0[j] ^= xor & mask;
        }
    }

    let zinv = z2.invert();
    x2.mul(&zinv).to_bytes_le()
}

/// X25519 命名空间。
pub mod x25519 {
    use super::*;

    /// 私钥字节数。
    pub const SECRET_KEY_LEN: usize = 32;
    /// 公钥字节数。
    pub const PUBLIC_KEY_LEN: usize = 32;
    /// 共享秘密字节数。
    pub const SHARED_LEN: usize = 32;

    /// ECDH 私钥（内部持有已钳制标量，`ZeroizeOnDrop`）。
    #[derive(Clone)]
    pub struct SecretKey {
        scalar: [u8; 32],
    }

    impl SecretKey {
        /// 本曲线在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::NonApproved;

        /// 生成新私钥（OS 熵直读；M5 起批准模式改走边界内 CTR-DRBG）。
        pub fn generate() -> Result<Self, crate::Error> {
            let mut seed = [0u8; 32];
            crate::entropy::fill(&mut seed)?;
            Ok(Self::from_seed(seed))
        }

        /// 由种子确定性构造（RFC 7748 钳制）。测试/向量入口。
        pub fn from_seed(mut seed: [u8; 32]) -> Self {
            seed[0] &= 248;
            seed[31] &= 127;
            seed[31] |= 64;
            Self { scalar: seed }
        }

        /// 导出对应公钥（u 坐标小端 32 字节）= X25519(k, 9)。
        pub fn public_key(&self) -> [u8; 32] {
            let mut base = [0u8; 32];
            base[0] = 9;
            x25519_ladder(&self.scalar, &base)
        }

        /// 计算共享秘密。对端公钥长度非法返回 `InvalidInput`；
        /// 结果为全零（小阶点攻击）返回 `VerificationFailed`——TLS 必须
        /// 终止握手。
        pub fn diffie_hellman(&self, peer_public: &[u8]) -> Result<SharedSecret, crate::Error> {
            let peer: [u8; 32] = peer_public
                .try_into()
                .map_err(|_| crate::Error::InvalidInput)?;
            let shared = x25519_ladder(&self.scalar, &peer);
            let mut acc = 0u8;
            for &b in &shared {
                acc |= b;
            }
            if acc == 0 {
                return Err(crate::Error::VerificationFailed);
            }
            Ok(SharedSecret { bytes: shared })
        }
    }

    impl Drop for SecretKey {
        fn drop(&mut self) {
            self.scalar.fill(0);
        }
    }

    impl std::fmt::Debug for SecretKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("x25519::SecretKey")
        }
    }

    /// 共享秘密（`ZeroizeOnDrop`）。
    pub struct SharedSecret {
        bytes: [u8; 32],
    }

    impl SharedSecret {
        /// 共享秘密字节（TLS 1.3 中作为 HKDF-Extract 的 IKM）。
        pub fn as_bytes(&self) -> &[u8] {
            &self.bytes
        }
    }

    impl Drop for SharedSecret {
        fn drop(&mut self) {
            self.bytes.fill(0);
        }
    }

    impl std::fmt::Debug for SharedSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("x25519::SharedSecret")
        }
    }
}

// ---------------------------------------------------------------------------
// 短 Weierstrass（P-256 / P-384）
// ---------------------------------------------------------------------------

/// 生成一条短 Weierstrass 曲线的 ECDH 模块。
macro_rules! sw_curve {
    (
        $modname:ident, $field:ident, $scalar:ident, $bits:expr,
        $b:expr, $gx:expr, $gy:expr, $doc:expr
    ) => {
        pub mod $modname {
            use super::*;

            type F = $field;
            type S = $scalar;

            /// 坐标字节数。
            pub const COORD_LEN: usize = F::LIMBS * 8;
            /// 私钥字节数。
            pub const SECRET_KEY_LEN: usize = COORD_LEN;
            /// 公钥字节数（未压缩 SEC1：0x04 || X || Y）。
            pub const PUBLIC_KEY_LEN: usize = 1 + 2 * COORD_LEN;
            /// 共享秘密字节数。
            pub const SHARED_LEN: usize = COORD_LEN;

            /// 曲线参数 b。
            pub(crate) fn curve_b() -> F {
                F::from_raw($b)
            }
            /// 基点坐标。
            pub(crate) fn gx() -> F {
                F::from_raw($gx)
            }
            pub(crate) fn gy() -> F {
                F::from_raw($gy)
            }

            /// 雅可比坐标点（z = 0 表示无穷远）。
            #[derive(Clone, Copy)]
            pub(crate) struct Jac {
                pub(crate) x: F,
                pub(crate) y: F,
                pub(crate) z: F,
            }

            impl Jac {
                fn infinity() -> Self {
                    Self {
                        x: F::zero(),
                        y: F::one(),
                        z: F::zero(),
                    }
                }

                pub(crate) fn is_infinity(&self) -> bool {
                    self.z.is_zero()
                }

                /// 倍点（一般 a 公式）。
                fn double(&self) -> Self {
                    let delta = self.z.square();
                    let gamma = self.y.square();
                    let beta = self.x.mul(&gamma);
                    let alpha = self.x.sub(&delta).mul(&self.x.add(&delta)).mul(&F::three());
                    let beta4 = beta.add(&beta).add(&beta).add(&beta);
                    let x3 = alpha.square().sub(&beta4.add(&beta4));
                    let g2 = gamma.square();
                    // 8γ² = g2 的 7 次自身相加
                    let gamma8 = g2
                        .add(&g2)
                        .add(&g2)
                        .add(&g2)
                        .add(&g2)
                        .add(&g2)
                        .add(&g2)
                        .add(&g2);
                    let y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma8);
                    let z3 = self.y.add(&self.z).square().sub(&gamma).sub(&delta);
                    Self {
                        x: x3,
                        y: y3,
                        z: z3,
                    }
                }
            }

            /// 雅可比 + 仿射（madd-2007-bl 公式，含 2/4 缩放因子）；
            /// p1 为无穷远时复制仿射点。
            /// （h == 0 且 r != 0 时公式自然给出 z3 = 0，即无穷远，正确。）
            fn add_or_copy(p1: &Jac, qx: &F, qy: &F) -> Jac {
                let z1z1 = p1.z.square();
                let u2 = qx.mul(&z1z1);
                let s2 = qy.mul(&p1.z).mul(&z1z1);
                let h = u2.sub(&p1.x);
                let hh = h.square();
                let i = hh.add(&hh).add(&hh).add(&hh);
                let j = h.mul(&i);
                let dy = s2.sub(&p1.y);
                let r = dy.add(&dy);
                let v = p1.x.mul(&i);
                let x3 = r.square().sub(&j).sub(&v.add(&v));
                let y3 = r.mul(&v.sub(&x3)).sub(&p1.y.mul(&j).add(&p1.y.mul(&j)));
                let z3 = p1.z.add(&h).square().sub(&z1z1).sub(&hh);
                let std = Jac {
                    x: x3,
                    y: y3,
                    z: z3,
                };
                let copy = Jac {
                    x: *qx,
                    y: *qy,
                    z: F::one(),
                };
                let mask = p1.z.is_zero_mask();
                Jac {
                    x: F::select(mask, &copy.x, &std.x),
                    y: F::select(mask, &copy.y, &std.y),
                    z: F::select(mask, &copy.z, &std.z),
                }
            }

            /// 常数时间 (R0, R1) 阶梯。不变式 R1 = R0 + Q 保证加法永不
            /// 作用于相等点；返回 R0 = k·Q。
            fn ladder(k: &[u64], bits: usize, qx: &F, qy: &F) -> Jac {
                let mut r0 = Jac::infinity();
                let mut r1 = Jac {
                    x: *qx,
                    y: *qy,
                    z: F::one(),
                };
                for i in (0..bits).rev() {
                    let bit = (((k[i / 64] >> (i % 64)) & 1) as u64).wrapping_neg();
                    let d0 = r0.double();
                    let d1 = r1.double();
                    // sum = R0 + R1 = 2·R0 + Q
                    let sum = add_or_copy(&d0, qx, qy);
                    r0 = Jac {
                        x: F::select(bit, &sum.x, &d0.x),
                        y: F::select(bit, &sum.y, &d0.y),
                        z: F::select(bit, &sum.z, &d0.z),
                    };
                    r1 = Jac {
                        x: F::select(bit, &d1.x, &sum.x),
                        y: F::select(bit, &d1.y, &sum.y),
                        z: F::select(bit, &d1.z, &sum.z),
                    };
                }
                r0
            }

            /// 标量盲化：d' = d + r·n（整数加法，宽 L+2 limbs）。
            fn blind(d: &[u64; S::LIMBS]) -> Result<(Vec<u64>, usize), crate::Error> {
                let mut rbytes = [0u8; 8];
                crate::entropy::fill(&mut rbytes)?;
                let r = u64::from_le_bytes(rbytes);
                let l = S::LIMBS;
                let mut out = vec![0u64; l + 2];
                // out = r * n
                let mut carry = 0u128;
                for j in 0..l {
                    let prod = (r as u128) * (S::P[j] as u128) + (out[j] as u128) + carry;
                    out[j] = prod as u64;
                    carry = prod >> 64;
                }
                out[l] = carry as u64;
                // out += d
                let mut carry = 0u128;
                for j in 0..l {
                    let s = (out[j] as u128) + (d[j] as u128) + carry;
                    out[j] = s as u64;
                    carry = s >> 64;
                }
                let mut j = l;
                while carry > 0 && j < l + 2 {
                    let s = (out[j] as u128) + carry;
                    out[j] = s as u64;
                    carry = s >> 64;
                    j += 1;
                }
                Ok((out, (l + 2) * 64))
            }

            /// 解析并校验对端公钥（未压缩 SEC1），返回仿射点。
            pub(crate) fn parse_public(bytes: &[u8]) -> Result<(F, F), crate::Error> {
                if bytes.len() != PUBLIC_KEY_LEN || bytes[0] != 0x04 {
                    return Err(crate::Error::InvalidInput);
                }
                let x = canonical_field(&bytes[1..1 + COORD_LEN])?;
                let y = canonical_field(&bytes[1 + COORD_LEN..])?;
                // 在曲线检查：y² = x³ − 3x + b
                let y2 = y.square();
                let x2 = x.square();
                let x3 = x2.mul(&x);
                let three_x = x.add(&x).add(&x);
                let rhs = x3.sub(&three_x).add(&curve_b());
                if y2 != rhs {
                    return Err(crate::Error::VerificationFailed);
                }
                Ok((x, y))
            }

            /// 大端字节 -> 域元素（必须 < p，否则 InvalidInput）。
            fn canonical_field(bytes: &[u8]) -> Result<F, crate::Error> {
                let mut limbs = [0u64; F::LIMBS];
                for (i, chunk) in bytes.rchunks(8).enumerate() {
                    let mut w = [0u8; 8];
                    w[8 - chunk.len()..].copy_from_slice(chunk);
                    limbs[i] = u64::from_be_bytes(w);
                }
                if F::geq_canonical(&limbs) {
                    return Err(crate::Error::InvalidInput);
                }
                Ok(F::from_raw(limbs))
            }

            #[doc = $doc]
            #[derive(Clone)]
            pub struct SecretKey {
                /// 规范标量（mod n，普通形式 limbs）。
                d: [u64; S::LIMBS],
            }

            impl SecretKey {
                /// 本曲线在 FIPS 140-3 下的批准状态。
                pub const APPROVAL: crate::Approval = crate::Approval::Approved;

                /// 生成新私钥（OS 熵直读 + mod n 归约；M5 起批准模式走
                /// 边界内 CTR-DRBG）。
                pub fn generate() -> Result<Self, crate::Error> {
                    for _ in 0..8 {
                        let mut seed = vec![0u8; 2 * COORD_LEN];
                        crate::entropy::fill(&mut seed)?;
                        let d = S::from_bytes_be_mod(&seed);
                        if !d.is_zero() {
                            return Ok(Self { d: d.to_raw() });
                        }
                    }
                    Err(crate::Error::EntropyFailed)
                }

                /// 由种子确定性构造（mod n 归约；测试/向量入口）。
                pub fn from_seed(seed: [u8; SECRET_KEY_LEN]) -> Self {
                    let d = S::from_bytes_be_mod(&seed);
                    Self { d: d.to_raw() }
                }

                /// 导出对应公钥（未压缩 SEC1：0x04 || X || Y）。
                pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
                    let (dk, bits) = blind(&self.d).expect("entropy available");
                    let p = ladder(&dk, bits, &gx(), &gy());
                    let (x, y) = to_affine(&p);
                    let mut out = [0u8; PUBLIC_KEY_LEN];
                    out[0] = 0x04;
                    out[1..1 + COORD_LEN].copy_from_slice(&x.to_bytes_be());
                    out[1 + COORD_LEN..].copy_from_slice(&y.to_bytes_be());
                    out
                }

                /// 计算共享秘密（对端公钥须为 0x04 || X || Y；点须在
                /// 曲线上；结果为无穷远返回 `VerificationFailed`）。
                pub fn diffie_hellman(
                    &self,
                    peer_public: &[u8],
                ) -> Result<SharedSecret, crate::Error> {
                    let (qx, qy) = parse_public(peer_public)?;
                    let (dk, bits) = blind(&self.d)?;
                    let p = ladder(&dk, bits, &qx, &qy);
                    if p.is_infinity() {
                        return Err(crate::Error::VerificationFailed);
                    }
                    let (x, _) = to_affine(&p);
                    let xb = x.to_bytes_be();
                    let mut bytes = [0u8; SHARED_LEN];
                    bytes.copy_from_slice(&xb);
                    Ok(SharedSecret { bytes })
                }
            }

            impl Drop for SecretKey {
                fn drop(&mut self) {
                    self.d.fill(0);
                }
            }

            impl std::fmt::Debug for SecretKey {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(stringify!($modname))
                }
            }

            fn to_affine(p: &Jac) -> (F, F) {
                let zinv = p.z.invert();
                let zinv2 = zinv.square();
                let zinv3 = zinv2.mul(&zinv);
                (p.x.mul(&zinv2), p.y.mul(&zinv3))
            }

            /// 共享秘密（`ZeroizeOnDrop`；TLS 1.3 中作为 HKDF-Extract 的
            /// IKM，取 x 坐标）。
            pub struct SharedSecret {
                bytes: [u8; SHARED_LEN],
            }

            impl SharedSecret {
                /// 共享秘密字节。
                pub fn as_bytes(&self) -> &[u8] {
                    &self.bytes
                }
            }

            impl Drop for SharedSecret {
                fn drop(&mut self) {
                    self.bytes.fill(0);
                }
            }

            impl std::fmt::Debug for SharedSecret {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str(stringify!($modname))
                }
            }

            /// M4 复用：标量乘基点（ECDSA r = x(k·G)）。
            #[allow(dead_code)]
            pub(crate) fn mul_base(d: &[u64; S::LIMBS]) -> (F, F) {
                let (dk, bits) = blind(d).expect("entropy available");
                let p = ladder(&dk, bits, &gx(), &gy());
                to_affine(&p)
            }

            /// M4/测试复用：任意点标量乘（验证路径，公开数据）。
            #[allow(dead_code)]
            pub(crate) fn mul_point_pub(k: &[u64], bits: usize, qx: &F, qy: &F) -> Jac {
                ladder(k, bits, qx, qy)
            }

            /// M4/测试复用：雅可比 -> 仿射。
            #[allow(dead_code)]
            pub(crate) fn to_affine_pub(p: &Jac) -> (F, F) {
                to_affine(p)
            }

            /// M4 复用：两仿射点相加（ECDSA 验证 u1G + u2Q；公开数据，
            /// 可变时间；相等点走仿射倍点，互逆点返回无穷远错误）。
            #[allow(dead_code)]
            pub(crate) fn add_points_affine_pub(
                p1: &(F, F),
                p2: &(F, F),
            ) -> Result<(F, F), crate::Error> {
                let (x1, y1) = *p1;
                let (x2, y2) = *p2;
                if x1 == x2 {
                    if y1 == y2 {
                        // 仿射倍点：λ = (3x² + a) / (2y)，a = −3
                        let x2m = x1.square();
                        let num = x2m.add(&x2m).add(&x2m).sub(&F::three());
                        let den = y1.add(&y1);
                        let lam = num.mul(&den.invert());
                        let x3 = lam.square().sub(&x1).sub(&x1);
                        let y3 = lam.mul(&x1.sub(&x3)).sub(&y1);
                        return Ok((x3, y3));
                    }
                    return Err(crate::Error::VerificationFailed); // 无穷远
                }
                // 一般弦切公式
                let h = x2.sub(&x1);
                let lam = y2.sub(&y1).mul(&h.invert());
                let x3 = lam.square().sub(&x1).sub(&x2);
                let y3 = lam.mul(&x1.sub(&x3)).sub(&y1);
                Ok((x3, y3))
            }
        }
    };
}

sw_curve!(
    p256,
    Fp256,
    Fp256Scalar,
    256,
    [
        0x3bce3c3e27d2604b,
        0x651d06b0cc53b0f6,
        0xb3ebbd55769886bc,
        0x5ac635d8aa3a93e7,
    ],
    [
        0xf4a13945d898c296,
        0x77037d812deb33a0,
        0xf8bce6e563a440f2,
        0x6b17d1f2e12c4247,
    ],
    [
        0xcbb6406837bf51f5,
        0x2bce33576b315ece,
        0x8ee7eb4a7c0f9e16,
        0x4fe342e2fe1a7f9b,
    ],
    "P-256（secp256r1）ECDH 命名空间。"
);

sw_curve!(
    p384,
    Fp384,
    Fp384Scalar,
    384,
    [
        0x2a85c8edd3ec2aef,
        0xc656398d8a2ed19d,
        0x0314088f5013875a,
        0x181d9c6efe814112,
        0x988e056be3f82d19,
        0xb3312fa7e23ee7e4,
    ],
    [
        0x3a545e3872760ab7,
        0x5502f25dbf55296c,
        0x59f741e082542a38,
        0x6e1d3b628ba79b98,
        0x8eb1c71ef320ad74,
        0xaa87ca22be8b0537,
    ],
    [
        0x7a431d7c90ea0e5f,
        0x0a60b1ce1d7e819d,
        0xe9da3113b5f0b8c0,
        0xf8f41dbd289a147c,
        0x5d9e98bf9292dc29,
        0x3617de4a96262c6f,
    ],
    "P-384（secp384r1）ECDH 命名空间。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p256_generator_on_curve_and_order() {
        let gx = p256::gx();
        let gy = p256::gy();
        let b = p256::curve_b();
        let lhs = gy.square();
        let x3 = gx.square().mul(&gx);
        let rhs = x3.sub(&gx.add(&gx).add(&gx)).add(&b);
        assert_eq!(lhs, rhs, "G must be on P-256");

        let p = p256::mul_point_pub(&Fp256Scalar::P, 256, &gx, &gy);
        assert!(p.is_infinity(), "n·G must be infinity");
    }

    #[test]
    fn p384_generator_on_curve_and_order() {
        let gx = p384::gx();
        let gy = p384::gy();
        let b = p384::curve_b();
        let lhs = gy.square();
        // 逐步锚值（独立计算）定位域运算
        assert_eq!(
            lhs.to_raw(),
            [
                0x526d1dda240d560e,
                0x08dff93308d2ee64,
                0xc2701ace3fc91bf7,
                0xbc27d9e01dd940b9,
                0xe1d86567d28802d3,
                0xdda3f84d36cf26f1,
            ],
            "gy^2"
        );
        let x3 = gx.square().mul(&gx);
        let x3_m = x3;
        assert_eq!(
            x3_m.to_raw(),
            [
                0xd6e46f93a7834b46,
                0x419296c0bca3990b,
                0xcd41d7e076b21347,
                0xee61ef98c24ed270,
                0xf55fb558c7f1de17,
                0x2a0a270d90314eb3,
            ],
            "x^3"
        );
        let rhs = x3_m.sub(&gx.add(&gx).add(&gx)).add(&b);
        assert_eq!(
            rhs.to_raw(),
            [
                0x526d1dda240d560e,
                0x08dff93308d2ee64,
                0xc2701ace3fc91bf7,
                0xbc27d9e01dd940b9,
                0xe1d86567d28802d3,
                0xdda3f84d36cf26f1,
            ],
            "rhs"
        );
        assert_eq!(lhs, rhs, "G must be on P-384");

        let p = p384::mul_point_pub(&Fp384Scalar::P, 384, &gx, &gy);
        assert!(p.is_infinity(), "n·G must be infinity");
    }

    #[test]
    fn p256_scalar_mult_anchored() {
        // k·G 锚值（x/y 坐标）由独立实现交叉核对。
        let cases: [(u64, [u64; 4], [u64; 4]); 4] = [
            (
                2,
                [
                    0xa60b48fc47669978,
                    0xc08969e277f21b35,
                    0x8a52380304b51ac3,
                    0x7cf27b188d034f7e,
                ],
                [
                    0x9e04b79d227873d1,
                    0xba7dade63ce98229,
                    0x293d9ac69f7430db,
                    0x7775510db8ed040,
                ],
            ),
            (
                3,
                [
                    0xfb41661bc6e7fd6c,
                    0xe6c6b721efada985,
                    0xc8f7ef951d4bf165,
                    0x5ecbe4d1a6330a44,
                ],
                [
                    0x9a79b127a27d5032,
                    0xd82ab036384fb83d,
                    0x374b06ce1a64a2ec,
                    0x8734640c4998ff7e,
                ],
            ),
            (
                5,
                [
                    0x21554a0dc3d033ed,
                    0xef8c82fd1f5be524,
                    0xd784c85608668fdf,
                    0x51590b7a515140d2,
                ],
                [
                    0xd1d0bb44fda16da4,
                    0x0d012f00d4d80888,
                    0x8ae1bf36bf8a7926,
                    0xe0c17da8904a727d,
                ],
            ),
            (
                12345,
                [
                    0xf9f921e9f9dad812,
                    0xb2f733945b649cc9,
                    0x669187e18b3a9122,
                    0x26efcebd0ee9e34a,
                ],
                [
                    0xbf4070745872d0e6,
                    0xe7055205744b6f31,
                    0xd150c67704dd25a,
                    0x90238bde9cc7bb33,
                ],
            ),
        ];
        let gx = p256::gx();
        let gy = p256::gy();
        for (k, x_exp, y_exp) in cases {
            let p = p256::mul_point_pub(&[k, 0, 0, 0], 256, &gx, &gy);
            assert!(!p.is_infinity(), "{k}G infinity");
            let (x, y) = p256::to_affine_pub(&p);
            assert_eq!(x.to_raw(), x_exp, "{k}G x");
            assert_eq!(y.to_raw(), y_exp, "{k}G y");
        }
    }
}
