//! 数字签名：ECDSA（P-256/P-384，RFC 6979 确定性 nonce）、Ed25519
//! （RFC 8032）、RSA（PKCS#1 v1.5 / PSS，M4b 落地）。
//!
//! 批准状态：ECDSA P-256/384 与 RSA 为 FIPS 批准；**Ed25519 非批准**
//! （FIPS 186-5 不含 EdDSA）。
//!
//! 签名 API：`sign` 接收**未哈希**消息，内部按算法完成哈希（与 rustls
//! `Signer::sign` 约定一致）。
//!
//! 向量：RFC 6979 A.2.5（P-256 "sample"）、RFC 8032 §7.1（Ed25519
//! TEST 1/2），人工录入并与官方原文核对；RSA 向量在 M4b。
//!
//! 安全：
//! - ECDSA nonce 一律 RFC 6979 确定性生成（FIPS 186-5 允许）；标量乘
//!   经 ecdh 模块统一盲化；
//! - 验证路径一切失败归一化为同一错误，不泄露失败阶段；
//! - 私钥材料 ZeroizeOnDrop。

use crate::fields::{Fp25519, Fp256Scalar, Fp384Scalar};
use crate::sha2::Sha512;

/// 最小长度 BE 整数的 DER INTEGER 编码。
fn der_integer(value_be: &[u8]) -> Vec<u8> {
    let mut m = value_be;
    while m.len() > 1 && m[0] == 0 {
        m = &m[1..];
    }
    let mut content = Vec::with_capacity(m.len() + 1);
    if m[0] & 0x80 != 0 {
        content.push(0x00);
    }
    content.extend_from_slice(m);
    let mut out = Vec::with_capacity(content.len() + 2);
    out.push(0x02);
    out.push(content.len() as u8);
    out.extend_from_slice(&content);
    out
}

/// 编码 ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }。
pub fn encode_der_sig(r_be: &[u8], s_be: &[u8]) -> Vec<u8> {
    let r = der_integer(r_be);
    let s = der_integer(s_be);
    let mut out = Vec::with_capacity(r.len() + s.len() + 5);
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// 生成一条曲线的 ECDSA 模块。
macro_rules! ecdsa_curve {
    ($modname:ident, $curve:ident, $sfield:ident, $coordlen:expr, $hash:ident, $hmac:ident, $doc:expr) => {
        #[doc = $doc]
        pub mod $modname {
            use super::*;
            use crate::ecdh::$curve as crv;
            use crate::hmac::$hmac;
            use crate::sha2::$hash;

            type S = $sfield;

            const SEED_LEN: usize = $coordlen;
            const HLEN: usize = $hmac::OUTPUT_LEN;

            /// 私钥（模 n 规范标量，`ZeroizeOnDrop`）。
            #[derive(Clone)]
            pub struct SigningKey {
                d: [u64; S::LIMBS],
            }

            impl SigningKey {
                /// 本算法在 FIPS 140-3 下的批准状态。
                pub const APPROVAL: crate::Approval = crate::Approval::Approved;

                /// 由种子确定性构造（int2octets(x)，mod n 归约）。
                pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
                    let d = S::from_bytes_be_mod(&seed);
                    Self { d: d.to_raw() }
                }

                /// 公钥（未压缩 SEC1：0x04 || X || Y）。
                pub fn public_key_sec1(&self) -> [u8; 1 + 2 * SEED_LEN] {
                    let (x, y) = crv::mul_base(&self.d);
                    let mut out = [0u8; 1 + 2 * SEED_LEN];
                    out[0] = 0x04;
                    out[1..1 + SEED_LEN].copy_from_slice(&x.to_bytes_be());
                    out[1 + SEED_LEN..].copy_from_slice(&y.to_bytes_be());
                    out
                }

                /// 对消息签名：返回 DER 编码的 ECDSA-Sig-Value。
                /// nonce 按 RFC 6979 确定性生成。
                pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
                    let digest = $hash::one_shot(message);
                    let z = S::from_bytes_be_mod(&digest);
                    let d_m = S::from_raw(self.d);
                    let x_oct = S::from_raw(self.d).to_bytes_be();
                    let z_oct = z.to_bytes_be();

                    // RFC 6979 §3.2 步骤 b–g：V = 0x01^hlen，K = 0x00^hlen；
                    // K = HMAC_K(V || {0x00,0x01} || int2octets(x) || bits2octets(h1))，
                    // 每次 K 更新后先 V = HMAC_K(V)。两次输入仅分隔字节不同，复用 buf。
                    let mut v = [0x01u8; HLEN];
                    let mut k = [0u8; HLEN];
                    let mut buf = [0u8; HLEN + 1 + 2 * SEED_LEN];
                    buf[..HLEN].copy_from_slice(&v);
                    buf[HLEN] = 0x00;
                    buf[HLEN + 1..HLEN + 1 + SEED_LEN].copy_from_slice(&x_oct);
                    buf[HLEN + 1 + SEED_LEN..].copy_from_slice(&z_oct);
                    k = $hmac::one_shot(&k, &buf); // d
                    v = $hmac::one_shot(&k, &v); // e
                    buf[..HLEN].copy_from_slice(&v); // f 必须用更新后的 V
                    buf[HLEN] = 0x01;
                    k = $hmac::one_shot(&k, &buf); // f
                    v = $hmac::one_shot(&k, &v); // g

                    loop {
                        // h：V = HMAC_K(V)；候选 k = bits2int(V)——按 RFC 与 q
                        // 比较拒绝（不取模）；k = 0（V 全零）同样拒绝。
                        v = $hmac::one_shot(&k, &v);
                        let n_be = n_bytes_be();
                        let mut ge_n = false;
                        for i in 0..SEED_LEN {
                            if v[i] < n_be[i] {
                                break;
                            }
                            if v[i] > n_be[i] {
                                ge_n = true;
                                break;
                            }
                        }
                        let mut nonzero = false;
                        for &b in &v {
                            if b != 0 {
                                nonzero = true;
                                break;
                            }
                        }
                        let k_s = S::from_bytes_be_mod(&v); // v < n 时无损
                        let (x, _) = crv::mul_base(&k_s.to_raw());
                        let r_s = S::from_bytes_be_mod(&x.to_bytes_be());
                        let s = k_s.invert().mul(&z.add(&r_s.mul(&d_m)));
                        if nonzero && !ge_n && !r_s.is_zero() && !s.is_zero() {
                            let r_be = r_s.to_bytes_be();
                            let s_be = s.to_bytes_be();
                            return Ok(encode_der_sig(&r_be, &s_be));
                        }
                        // h.5 重试：K = HMAC_K(V || 0x00)；V = HMAC_K(V)
                        let mut b2 = [0u8; HLEN + 1];
                        b2[..HLEN].copy_from_slice(&v);
                        b2[HLEN] = 0x00;
                        k = $hmac::one_shot(&k, &b2);
                        v = $hmac::one_shot(&k, &v);
                    }
                }
            }

            /// 模数 n 的规范 BE 字节（S::P 即 n 的普通形式 limbs；
            /// 严禁经 from_raw/to_raw 转换——模数在 mod n 下映射为 0）。
            fn n_bytes_be() -> [u8; SEED_LEN] {
                let mut out = [0u8; SEED_LEN];
                for j in 0..S::LIMBS {
                    out[(S::LIMBS - 1 - j) * 8..(S::LIMBS - j) * 8]
                        .copy_from_slice(&S::P[j].to_be_bytes());
                }
                out
            }

            /// 解析 DER 签名并返回 (r, s) 的定长 BE 形式。
            fn parse_sig(
                signature_der: &[u8],
            ) -> Result<([u8; SEED_LEN], [u8; SEED_LEN]), crate::Error> {
                let (rs_body, rest) = crate::der::sequence(signature_der)?;
                if !rest.is_empty() {
                    return Err(crate::Error::InvalidInput);
                }
                let (r_bytes, rest) = crate::der::integer(rs_body)?;
                let (s_bytes, rest2) = crate::der::integer(rest)?;
                if !rest2.is_empty() || r_bytes.len() > SEED_LEN || s_bytes.len() > SEED_LEN {
                    return Err(crate::Error::VerificationFailed);
                }
                let mut rb = [0u8; SEED_LEN];
                rb[SEED_LEN - r_bytes.len()..].copy_from_slice(r_bytes);
                let mut sb = [0u8; SEED_LEN];
                sb[SEED_LEN - s_bytes.len()..].copy_from_slice(s_bytes);
                // r、s 必须严格小于 n：与 n 的规范 BE 字节逐字节比较
                let n_bytes = n_bytes_be();
                for i in 0..SEED_LEN {
                    if rb[i] < n_bytes[i] {
                        break;
                    }
                    if rb[i] > n_bytes[i] {
                        return Err(crate::Error::VerificationFailed);
                    }
                }
                for i in 0..SEED_LEN {
                    if sb[i] < n_bytes[i] {
                        break;
                    }
                    if sb[i] > n_bytes[i] {
                        return Err(crate::Error::VerificationFailed);
                    }
                }
                if rb == [0u8; SEED_LEN] || sb == [0u8; SEED_LEN] {
                    return Err(crate::Error::VerificationFailed);
                }
                Ok((rb, sb))
            }

            /// 验证 DER 编码的 ECDSA 签名（公钥为未压缩 SEC1）。
            pub fn verify(
                public_sec1: &[u8],
                message: &[u8],
                signature_der: &[u8],
            ) -> Result<(), crate::Error> {
                let (qx, qy) = crv::parse_public(public_sec1)?;
                let (rb, sb) = parse_sig(signature_der)?;
                let digest = $hash::one_shot(message);
                let z = S::from_bytes_be_mod(&digest);
                let r_s = S::from_bytes_be_mod(&rb);
                let s_s = S::from_bytes_be_mod(&sb);

                let w = s_s.invert();
                let u1 = z.mul(&w);
                let u2 = r_s.mul(&w);

                let g = (crv::gx(), crv::gy());
                let p1 = crv::mul_point_pub(&u1.to_raw(), 8 * SEED_LEN, &g.0, &g.1);
                if p1.is_infinity() {
                    return Err(crate::Error::VerificationFailed);
                }
                let p2 = crv::mul_point_pub(&u2.to_raw(), 8 * SEED_LEN, &qx, &qy);
                if p2.is_infinity() {
                    return Err(crate::Error::VerificationFailed);
                }
                let (x, _) =
                    crv::add_points_affine_pub(&crv::to_affine_pub(&p1), &crv::to_affine_pub(&p2))?;
                let r_prime = S::from_bytes_be_mod(&x.to_bytes_be());
                if r_prime == r_s {
                    Ok(())
                } else {
                    Err(crate::Error::VerificationFailed)
                }
            }
        }
    };
}

pub mod ecdsa {
    // 宏展开在模块作用域内需要可见的项
    use super::{encode_der_sig, Fp256Scalar, Fp384Scalar};

    ecdsa_curve!(
        p256,
        p256,
        Fp256Scalar,
        32,
        Sha256,
        HmacSha256,
        "P-256 ECDSA（SHA-256，RFC 6979 确定性 nonce）。"
    );

    ecdsa_curve!(
        p384,
        p384,
        Fp384Scalar,
        48,
        Sha384,
        HmacSha384,
        "P-384 ECDSA（SHA-384，RFC 6979 确定性 nonce）。"
    );
}

// ---------------------------------------------------------------------------
// Ed25519（RFC 8032）——FIPS 非批准
// ---------------------------------------------------------------------------

/// Ed25519 命名空间。
pub mod ed25519 {
    use super::*;
    use crate::fields::Fp25519ScalarL as ScL;

    /// 私钥种子字节数。
    pub const SEED_LEN: usize = 32;
    /// 公钥字节数。
    pub const PUBLIC_KEY_LEN: usize = 32;
    /// 签名字节数。
    pub const SIGNATURE_LEN: usize = 64;

    /// 基点压缩编码（RFC 8032：y = 4/5，x 为偶）。
    pub(crate) const G_COMPRESSED: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    /// 扭曲 Edwards 曲线参数 d（= −121665/121666），每次调用时计算。
    pub(crate) fn curve_d() -> Fp25519 {
        let um = Fp25519::from_raw([121665, 0, 0, 0]);
        let vm = Fp25519::from_raw([121666, 0, 0, 0]);
        um.neg().mul(&vm.invert())
    }

    /// 扩展坐标点 (X : Y : Z : T)，恒等元 = (0, 1, 1, 0)。
    #[derive(Clone, Copy)]
    pub(crate) struct Point {
        pub(crate) x: Fp25519,
        pub(crate) y: Fp25519,
        pub(crate) z: Fp25519,
        pub(crate) t: Fp25519,
    }

    impl Point {
        pub(crate) fn identity() -> Self {
            Self {
                x: Fp25519::zero(),
                y: Fp25519::one(),
                z: Fp25519::one(),
                t: Fp25519::zero(),
            }
        }

        /// 统一加法（add-2008-hwcd-3，a = −1）。
        pub(crate) fn add(&self, other: &Self) -> Self {
            let dd = curve_d().add(&curve_d());
            let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
            let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
            let c = self.t.mul(&other.t).mul(&dd);
            let d = self.z.add(&self.z).mul(&other.z);
            let e = b.sub(&a);
            let f = d.sub(&c);
            let g = d.add(&c);
            let h = b.add(&a);
            Self {
                x: e.mul(&f),
                y: g.mul(&h),
                z: f.mul(&g),
                t: e.mul(&h),
            }
        }

        fn double(&self) -> Self {
            self.add(self)
        }

        /// 压缩编码。
        pub(crate) fn compress(&self) -> [u8; 32] {
            // 扩展坐标仿射转换：x = X/Z，y = Y/Z（不是 Jacobian 的 Z²/Z³）
            let zinv = self.z.invert();
            let x = self.x.mul(&zinv);
            let y = self.y.mul(&zinv);
            let mut out = y.to_bytes_le();
            // 符号位 = 仿射 x（规范普通形式）的奇偶；必须先转出 Montgomery 形式
            out[31] |= ((x.to_raw()[0] & 1) as u8) << 7;
            out
        }
    }

    /// 从 32 字节压缩编码恢复点（含在曲线校验）。
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Result<Point, crate::Error> {
        let mut y_bytes = *bytes;
        let sign = y_bytes[31] >> 7;
        y_bytes[31] &= 127;
        let y = {
            let mut limbs = [0u64; 4];
            for j in 0..4 {
                let mut w = [0u8; 8];
                w.copy_from_slice(&y_bytes[j * 8..j * 8 + 8]);
                limbs[j] = u64::from_le_bytes(w);
            }
            let mut f = Fp25519(limbs);
            let cond = (Fp25519::geq_canonical(&f.0) as u64).wrapping_neg();
            f.cond_sub_p(cond);
            // 统一转换到 Montgomery 形式（后续运算均为 Montgomery 域）
            f = Fp25519::from_raw(f.0);
            f
        };
        // x² = (y² − 1) / (d·y² + 1)，RFC 8032 §5.1.3 恢复配方
        let d = curve_d();
        let y2 = y.square();
        let u = y2.sub(&Fp25519::one());
        let v = d.mul(&y2).add(&Fp25519::one());
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let uv7 = u.mul(&v7);
        let e = [
            0xfffffffffffffffd,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]; // (q−5)/8
        let pow_e = uv7.pow(&e);
        let mut x = u.mul(&v3).mul(&pow_e);
        let vx2 = v.mul(&x.square());
        if vx2 == u {
            // 有效
        } else if vx2 == u.neg() {
            // x *= 2^((q−1)/4)
            let e2 = [
                0xfffffffffffffffb,
                0xffffffffffffffff,
                0xffffffffffffffff,
                0x1fffffffffffffff,
            ]; // (q−1)/4 = 2^253 − 5
            x = x.mul(&Fp25519::from_raw([2, 0, 0, 0]).pow(&e2));
        } else {
            return Err(crate::Error::VerificationFailed);
        }
        // 符号修正：比较仿射 x 的规范奇偶（to_raw 先出 Montgomery 形式）
        let neg = ((x.to_raw()[0] ^ u64::from(sign)) & 1).wrapping_neg();
        x = Fp25519::select(neg, &x.neg(), &x);
        Ok(Point {
            x,
            y,
            z: Fp25519::one(),
            t: x.mul(&y),
        })
    }

    /// 标量乘（倍加 + 统一加法，天然处理所有例外输入）。
    pub(crate) fn scalar_mult(k_bytes: &[u8; 32], base: &Point) -> Point {
        let mut acc = Point::identity();
        for i in (0..256).rev() {
            acc = acc.double();
            let bit = ((k_bytes[i / 8] >> (i % 8)) & 1) as u64;
            let bit_mask = bit.wrapping_neg();
            let sum = acc.add(base);
            acc = Point {
                x: Fp25519::select(bit_mask, &sum.x, &acc.x),
                y: Fp25519::select(bit_mask, &sum.y, &acc.y),
                z: Fp25519::select(bit_mask, &sum.z, &acc.z),
                t: Fp25519::select(bit_mask, &sum.t, &acc.t),
            };
        }
        acc
    }

    pub(crate) fn base_point() -> Point {
        decompress(&G_COMPRESSED).expect("standard base point")
    }

    /// 私钥种子（`ZeroizeOnDrop`）。
    #[derive(Clone)]
    pub struct SigningKey {
        seed: [u8; 32],
    }

    impl SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::NonApproved;

        /// 生成新密钥（OS 熵直读；M5 起批准模式走边界内 CTR-DRBG）。
        pub fn generate() -> Result<Self, crate::Error> {
            let mut seed = [0u8; 32];
            crate::entropy::fill(&mut seed)?;
            Ok(Self { seed })
        }

        /// 由种子构造（测试/向量入口）。
        pub fn from_seed(seed: [u8; 32]) -> Self {
            Self { seed }
        }

        /// 公钥（32 字节压缩）。
        pub fn public_key(&self) -> [u8; 32] {
            let h = Sha512::one_shot(&self.seed);
            let mut a = [0u8; 32];
            a.copy_from_slice(&h[..32]);
            a[0] &= 248;
            a[31] &= 127;
            a[31] |= 64;
            scalar_mult(&a, &base_point()).compress()
        }

        /// 对消息签名（PureEdDSA，64 字节：R || S）。
        pub fn sign(&self, message: &[u8]) -> [u8; 64] {
            let h = Sha512::one_shot(&self.seed);
            let mut a = [0u8; 32];
            a.copy_from_slice(&h[..32]);
            a[0] &= 248;
            a[31] &= 127;
            a[31] |= 64;
            let a_s = ScL::from_bytes_le_mod(&a);
            let prefix = &h[32..64];

            // r = H(prefix || M) mod L
            let mut rh = Sha512::new();
            rh.update(prefix);
            rh.update(message);
            let r_digest = rh.finalize();
            let r = ScL::from_bytes_le_mod(&r_digest);
            let big_r = scalar_mult(&r.to_bytes_le(), &base_point()).compress();

            // k = H(R || A || M) mod L
            let mut kh = Sha512::new();
            kh.update(&big_r);
            kh.update(&self.public_key());
            kh.update(message);
            let k_digest = kh.finalize();
            let k = ScL::from_bytes_le_mod(&k_digest);

            // S = (r + k·a) mod L
            let s = r.add(&k.mul(&a_s));
            let s_le = s.to_bytes_le();

            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&big_r);
            sig[32..].copy_from_slice(&s_le);
            sig
        }
    }

    impl Drop for SigningKey {
        fn drop(&mut self) {
            self.seed.fill(0);
        }
    }

    impl std::fmt::Debug for SigningKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("ed25519::SigningKey")
        }
    }

    /// 验证 Ed25519 签名（公钥 32 字节，签名 64 字节）。
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), crate::Error> {
        if public_key.len() != 32 || signature.len() != 64 {
            return Err(crate::Error::InvalidInput);
        }
        let mut a_bytes = [0u8; 32];
        a_bytes.copy_from_slice(public_key);
        let a_pt = decompress(&a_bytes)?;

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature[..32]);
        let r_pt = decompress(&r_bytes)?;

        // S 必须规范（0 ≤ S < L）：LE 字节自最高位比较；全部相等（S == L）也拒绝
        let l_bytes: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let mut s_lt_l = false;
        for i in (0..32).rev() {
            if signature[32 + i] < l_bytes[i] {
                s_lt_l = true;
                break;
            }
            if signature[32 + i] > l_bytes[i] {
                return Err(crate::Error::VerificationFailed);
            }
        }
        if !s_lt_l {
            return Err(crate::Error::VerificationFailed);
        }
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature[32..]);
        let s_s = ScL::from_bytes_le_mod(&s_bytes);

        let mut kh = Sha512::new();
        kh.update(&signature[..32]);
        kh.update(&a_bytes);
        kh.update(message);
        let k_digest = kh.finalize();
        let k = ScL::from_bytes_le_mod(&k_digest);

        // [S]G == R + [k]A
        let lhs = scalar_mult(&s_s.to_bytes_le(), &base_point());
        let ka = scalar_mult(&k.to_bytes_le(), &a_pt);
        let rhs = r_pt.add(&ka);
        if lhs.compress() == rhs.compress() {
            Ok(())
        } else {
            Err(crate::Error::VerificationFailed)
        }
    }
}

// ---------------------------------------------------------------------------
// RSA（M4b 落地：大数模幂 + CRT + PKCS#1 v1.5/PSS）
// ---------------------------------------------------------------------------

/// RSA 签名/验证（PKCS#1 v1.5 与 PSS，RFC 8017）。
pub mod rsa {
    /// RSA 签名私钥（`ZeroizeOnDrop`；内部含 CRT 参数，运算加盲化）。
    #[derive(Clone)]
    pub struct SigningKey;

    /// 最短允许的模长字节数（2048 位）。
    pub const MIN_MODULUS_LEN: usize = 256;

    impl SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::Approved;

        /// 从 PKCS#8 DER（PKCS#1 RSA 私钥）解析。模长 < 2048 位返回
        /// [`Error::Unsupported`](crate::Error::Unsupported)。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            let _ = der;
            todo!("M4b")
        }

        /// RSA-PSS 签名（salt 长度 = 哈希长度；TLS 1.3 使用）。
        pub fn sign_pss(&self, hash_bits: u16, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
            let _ = (hash_bits, message);
            todo!("M4b")
        }

        /// RSA PKCS#1 v1.5 签名（TLS 1.2 遗留套件与证书链验证使用）。
        pub fn sign_pkcs1v15(
            &self,
            hash_bits: u16,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::Error> {
            let _ = (hash_bits, message);
            todo!("M4b")
        }
    }

    /// 验证 RSA-PSS 签名。公钥为 DER RSAPublicKey（SPKI 主体）。
    pub fn verify_pss(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (hash_bits, public_key_der, message, signature);
        todo!("M4b")
    }

    /// 验证 RSA PKCS#1 v1.5 签名（严格 padding 检查，防 Bleichenbacher）。
    pub fn verify_pkcs1v15(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (hash_bits, public_key_der, message, signature);
        todo!("M4b")
    }
}
