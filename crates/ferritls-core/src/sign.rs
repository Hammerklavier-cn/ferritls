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
        // 符号修正：比较仿射 x 的规范奇偶（to_raw 先出 Montgomery 形式）。
        // RFC 8032 §5.1.3：奇偶必须与符号位一致——x=0 且 sign=1 无法通过
        // 取负满足（-0 = 0，奇偶仍为 0），必须拒绝解码。
        let neg = ((x.to_raw()[0] ^ u64::from(sign)) & 1).wrapping_neg();
        x = Fp25519::select(neg, &x.neg(), &x);
        if (x.to_raw()[0] ^ u64::from(sign)) & 1 == 1 {
            return Err(crate::Error::VerificationFailed);
        }
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
// RSA（M4b/M4c：固定宽度大数模幂 + CRT + 盲化 + PKCS#1 v1.5/PSS，RFC 8017）
// ---------------------------------------------------------------------------

/// RSA 签名/验证（RSASSA-PKCS1-v1_5 与 RSASSA-PSS，RFC 8017）。
///
/// 批准状态：FIPS 批准（FIPS 186-5 RSASSA；TLS 1.3 首选 PSS）。
///
/// 安全：
/// - 私钥运算走 CRT（p/q 各自模幂，Garner 重组），指数位经掩码选择，
///   对秘密指数常数时间（见 [`crate::rsabig`]）；Garner 回绕修正为
///   常数时间掩码选择；
/// - 乘法盲化（Kocher，M4c）：每次签名取单次使用随机 r ∈ [1, n)
///   （OS 熵 + 拒绝采样），先算 EM′ = EM·rᵉ mod n 的 CRT 私钥运算，
///   再乘 r⁻¹ 去盲——CRT 内全部中间值随 r 随机化，秘密与观测
///   时序/访存解耦；r⁻¹ 经变量时间 binary xgcd 求得，输入为单次
///   随机值与公开模数，时序不泄露可利用信息（Go/OpenSSL 同实践，
///   见 [`crate::rsabig::mod_inverse_odd`]）；r 与盲化中间值退出前零化；
/// - 验证 padding 检查严格，一切失败归一化为
///   [`Error::VerificationFailed`](crate::Error::VerificationFailed)；
/// - 模长 < 2048 位拒绝（[`MIN_MODULUS_LEN`]），> 4096 位拒绝
///   （受 [`crate::rsabig::MAX_LIMBS`] 限制）；
/// - 密钥装载做结构校验：p·q = n、q·qInv ≡ 1 (mod p)、dp < p、
///   dq < q、qInv < p、n/p/q 为奇数、e ≥ 3 且为奇数；不做素性检测
///   （密钥来源为本机信任输入，素性由密钥生成方保证）。
pub mod rsa {
    use crate::ct::zeroize::Zeroize;
    use crate::rsabig;
    use crate::sha2::{Sha256, Sha384, Sha512};

    /// 盲化因子采样/求逆的最大尝试次数。每轮拒绝概率 ≤ 1/2
    /// （n 顶位为 1），128 轮全部失败概率 ≤ 2⁻¹²⁸，视为熵源异常。
    const BLIND_ATTEMPTS: usize = 128;

    /// 最短允许的模长字节数（2048 位）。
    pub const MIN_MODULUS_LEN: usize = 256;
    /// 最长支持的模长字节数（4096 位）。
    pub const MAX_MODULUS_LEN: usize = rsabig::MAX_LIMBS * 8;

    /// RSA 私钥（CRT 参数；`Drop` 零化秘密分量）。
    #[derive(Clone)]
    pub struct SigningKey {
        n_len: usize,
        n_bytes: usize,
        em_mask: u8,
        // 公开参数（盲化的预乘 rᵉ 与去盲 r⁻¹ 在 mod n 下进行）
        n: Vec<u64>,
        e: Vec<u64>,
        e_bits: usize,
        n0_n: u64,
        r2_n: Vec<u64>,
        // 秘密参数（CRT）
        p: Vec<u64>,
        q: Vec<u64>,
        dp: Vec<u64>,
        dq: Vec<u64>,
        qinv: Vec<u64>,
        n0_p: u64,
        r2_p: Vec<u64>,
        n0_q: u64,
        r2_q: Vec<u64>,
        pl: usize,
    }

    impl SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::Approved;

        /// 从 PKCS#8 DER（内层 PKCS#1 RSAPrivateKey）解析。模长 < 2048 位
        /// 返回 [`Error::Unsupported`](crate::Error::Unsupported)。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            match crate::der::parse_pkcs8_private_key(der)? {
                crate::der::ParsedPrivateKey::RsaPkcs1(pkcs1) => Self::from_pkcs1_der(&pkcs1),
                _ => Err(crate::Error::InvalidInput),
            }
        }

        /// 解析 PKCS#1 RSAPrivateKey DER 并做结构一致性校验
        ///（rustls KeyProvider 的 PKCS#1 入口）。
        pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::Error> {
            let (seq, rest) = crate::der::sequence(der)?;
            if !rest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }
            let (version, rest) = crate::der::integer(seq)?;
            if version.len() != 1 || version[0] != 0 {
                return Err(crate::Error::InvalidInput);
            }
            // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q,
            //   d mod p-1, d mod q-1, qInv, otherPrimeInfos [0] OPTIONAL }
            let (n_b, rest) = crate::der::integer(rest)?;
            let (e_b, rest) = crate::der::integer(rest)?;
            let (_d_b, rest) = crate::der::integer(rest)?; // CRT 路径不使用 d
            let (p_b, rest) = crate::der::integer(rest)?;
            let (q_b, rest) = crate::der::integer(rest)?;
            let (dp_b, rest) = crate::der::integer(rest)?;
            let (dq_b, rest) = crate::der::integer(rest)?;
            let (qinv_b, rest) = crate::der::integer(rest)?;
            // 多素数扩展不支持
            if !rest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }

            // 模长范围
            let n_bytes = n_b.len();
            if n_bytes < MIN_MODULUS_LEN {
                return Err(crate::Error::Unsupported);
            }
            if n_bytes > MAX_MODULUS_LEN {
                return Err(crate::Error::InvalidInput);
            }
            let n_len = n_bytes.div_ceil(8);
            let pl = n_len.div_ceil(2);
            // EM 左端必须清零的位数 = 8·emLen − emBits（emBits = modBits − 1）
            let n_bitlen = 8 * n_bytes - n_b[0].leading_zeros() as usize;
            let em_left_bits = 8 * n_bytes + 1 - n_bitlen;
            let em_mask: u8 = (0xffu32 >> em_left_bits) as u8;

            let mut n = vec![0u64; n_len];
            rsabig::os2ip_be(n_b, &mut n);
            if n[0] & 1 == 0 {
                return Err(crate::Error::InvalidInput); // n 必须为奇
            }

            // e：≤ 8 字节、奇数且 ≥ 3
            if e_b.is_empty() || e_b.len() > 8 {
                return Err(crate::Error::InvalidInput);
            }
            let mut e = vec![0u64; 1];
            rsabig::os2ip_be(e_b, &mut e);
            if e[0] < 3 || e[0] & 1 == 0 {
                return Err(crate::Error::InvalidInput);
            }

            // p、q：≤ pl limbs、奇数
            if p_b.len() > pl * 8 || q_b.len() > pl * 8 {
                return Err(crate::Error::InvalidInput);
            }
            let mut p = vec![0u64; pl];
            let mut q = vec![0u64; pl];
            rsabig::os2ip_be(p_b, &mut p);
            rsabig::os2ip_be(q_b, &mut q);
            if p[0] & 1 == 0
                || q[0] & 1 == 0
                || p.iter().all(|&x| x == 0)
                || q.iter().all(|&x| x == 0)
            {
                return Err(crate::Error::InvalidInput);
            }

            // dp < p、dq < q、qInv < p
            if dp_b.len() > pl * 8 || dq_b.len() > pl * 8 || qinv_b.len() > pl * 8 {
                return Err(crate::Error::InvalidInput);
            }
            let mut dp = vec![0u64; pl];
            let mut dq = vec![0u64; pl];
            let mut qinv = vec![0u64; pl];
            rsabig::os2ip_be(dp_b, &mut dp);
            rsabig::os2ip_be(dq_b, &mut dq);
            rsabig::os2ip_be(qinv_b, &mut qinv);
            if rsabig::geq(&dp, &p) || rsabig::geq(&dq, &q) || rsabig::geq(&qinv, &p) {
                return Err(crate::Error::InvalidInput);
            }

            // p·q = n
            let pq = rsabig::mul_full(&p, &q);
            if pq[..n_len] != n[..] || pq[n_len..].iter().any(|&x| x != 0) {
                return Err(crate::Error::InvalidInput);
            }

            // Montgomery 常数（CRT 侧 + 盲化用的 n 侧）
            let n0_p = rsabig::n0_inv(p[0]);
            let n0_q = rsabig::n0_inv(q[0]);
            let r2_p = rsabig::compute_r2(&p);
            let r2_q = rsabig::compute_r2(&q);
            let n0_n = rsabig::n0_inv(n[0]);
            let r2_n = rsabig::compute_r2(&n);
            let e_bits = 64 - e[0].leading_zeros() as usize;

            // q·qInv ≡ 1 (mod p)
            let mut mq = vec![0u64; pl];
            let mut mqinv = vec![0u64; pl];
            rsabig::to_mont(&q, &r2_p, &p, n0_p, &mut mq);
            rsabig::to_mont(&qinv, &r2_p, &p, n0_p, &mut mqinv);
            let mut chk = vec![0u64; pl];
            rsabig::mont_mul(&mq, &mqinv, &p, n0_p, &mut chk);
            rsabig::from_mont(&mut chk, &p, n0_p);
            if chk[0] != 1 || chk[1..].iter().any(|&x| x != 0) {
                return Err(crate::Error::InvalidInput);
            }

            Ok(Self {
                n_len,
                n_bytes,
                em_mask,
                n,
                e,
                e_bits,
                n0_n,
                r2_n,
                p,
                q,
                dp,
                dq,
                qinv,
                n0_p,
                r2_p,
                n0_q,
                r2_q,
                pl,
            })
        }

        /// 均匀采样 r ∈ [1, n)：OS 熵 + 拒绝采样（n 顶位为 1，每轮
        /// 拒绝概率 ≤ 1/2）。任何失败路径上 `out` 与采样缓冲均已零化。
        fn sample_blinding_factor(&self, out: &mut [u64]) -> Result<(), crate::Error> {
            debug_assert_eq!(out.len(), self.n_len);
            let mut buf = vec![0u8; self.n_bytes];
            for _ in 0..BLIND_ATTEMPTS {
                if let Err(e) = crate::entropy::fill(&mut buf) {
                    buf.zeroize();
                    out.zeroize();
                    return Err(e);
                }
                rsabig::os2ip_be(&buf, out);
                let zero = out.iter().all(|&w| w == 0);
                if !zero && !rsabig::geq(out, &self.n) {
                    buf.zeroize();
                    return Ok(());
                }
            }
            buf.zeroize();
            out.zeroize();
            Err(crate::Error::EntropyFailed)
        }

        /// CRT 私钥运算：m^d mod n（m 为普通形式 limbs 且 m < n，
        /// 返回 n_len limbs）。本函数的输入应为**盲化后**的值——
        /// 内部中间值（mp/mq/sp/sq/h 等）随盲化因子随机化；
        /// 秘密中间缓冲退出前零化。
        fn crt(&self, m: &[u64]) -> Vec<u64> {
            let l = self.pl;
            let nl = self.n_len;

            let mut mp = vec![0u64; l];
            rsabig::reduce_limbs(m, &self.p, &mut mp);
            let mut mq = vec![0u64; l];
            rsabig::reduce_limbs(m, &self.q, &mut mq);

            // sp = m^dp mod p、sq = m^dq mod q（Montgomery 域内完成）
            let mut sp = vec![0u64; l];
            let mut sq = vec![0u64; l];
            {
                let mut base = vec![0u64; l];
                let mut res = vec![0u64; l];
                rsabig::to_mont(&mp, &self.r2_p, &self.p, self.n0_p, &mut base);
                rsabig::mont_exp(
                    &base,
                    &self.dp,
                    64 * l,
                    &self.p,
                    self.n0_p,
                    &self.r2_p,
                    &mut res,
                );
                rsabig::from_mont(&mut res, &self.p, self.n0_p);
                sp.copy_from_slice(&res);
                rsabig::to_mont(&mq, &self.r2_q, &self.q, self.n0_q, &mut base);
                rsabig::mont_exp(
                    &base,
                    &self.dq,
                    64 * l,
                    &self.q,
                    self.n0_q,
                    &self.r2_q,
                    &mut res,
                );
                rsabig::from_mont(&mut res, &self.q, self.n0_q);
                sq.copy_from_slice(&res);
                base.zeroize();
                res.zeroize();
            }

            // Garner（qInv = q⁻¹ mod p）：h = (sp − sq)·qInv mod p；
            // s′ = sq + q·h ≤ (q−1) + q(p−1) = n − 1 < n。
            // 回绕修正无条件计算 diff + p，按借位掩码选取（常数时间；
            // 借位为 1 时加法跨过 2^(64l) 恰一次，进位按同余定义丢弃，
            // 结果落在 [0, p)）。
            let mut diff = vec![0u64; l];
            let borrow = rsabig::sub_limbs(&sp, &sq, &mut diff);
            let mut sum = vec![0u64; l];
            {
                let mut carry = 0u64;
                for ((dv, pv), sv) in diff.iter().zip(self.p.iter()).zip(sum.iter_mut()) {
                    let (v, c1) = dv.overflowing_add(*pv);
                    let (v, c2) = v.overflowing_add(carry);
                    *sv = v;
                    carry = (c1 as u64) | (c2 as u64);
                }
            }
            let mut fixed = vec![0u64; l];
            rsabig::select(borrow.wrapping_neg(), &sum, &diff, &mut fixed);
            sum.zeroize();
            diff.copy_from_slice(&fixed); // 修正后的 (sp − sq) mod p
            fixed.zeroize();
            // h = diff·qInv mod p：diff 先入 Montgomery 域，与 raw qInv 相乘
            // 的结果即为 raw（mont(diff)·qInv·R⁻¹ = diff·qInv）
            let mut hm = vec![0u64; l];
            rsabig::to_mont(&diff, &self.r2_p, &self.p, self.n0_p, &mut hm);
            let mut h = vec![0u64; l];
            rsabig::mont_mul(&hm, &self.qinv, &self.p, self.n0_p, &mut h);

            let mut qh = rsabig::mul_full(&self.q, &h); // 2l limbs
            qh.truncate(nl);
            let mut sqx = vec![0u64; nl];
            sqx[..l].copy_from_slice(&sq);
            let mut sres = vec![0u64; nl];
            rsabig::add_limbs(&sqx, &qh, &mut sres); // < n，无进位

            for v in [
                &mut mp, &mut mq, &mut sp, &mut sq, &mut diff, &mut hm, &mut h, &mut qh, &mut sqx,
            ] {
                v.zeroize();
            }
            sres
        }

        /// 对消息代表元 EM 私钥运算（乘法盲化 + CRT + Garner 重组），
        /// 返回定长签名。
        ///
        /// 盲化（M4c）：单次随机 r ∈ [1, n)，s = (EM·rᵉ)^d·r⁻¹ mod n
        /// ——盲化在数学上精确抵消，签名结果与无盲化实现逐字节一致
        /// （PKCS#1 v1.5 的 openssl 逐字节锚定与 selftest KAT 即为
        /// 盲化正确性的回归门）。
        fn sign_em(&self, em: &[u8]) -> Result<Vec<u8>, crate::Error> {
            debug_assert_eq!(em.len(), self.n_bytes);
            let nl = self.n_len;

            let mut m = vec![0u64; nl];
            rsabig::os2ip_be(em, &mut m);

            let mut r = vec![0u64; nl];
            let mut rinv = vec![0u64; nl];
            let mut re = vec![0u64; nl]; // rᵉ（Montgomery 域）
            let mut t = vec![0u64; nl];
            let mut t2 = vec![0u64; nl];
            let mut sig = vec![0u64; nl];
            let mut ok = false;
            let mut err = None;
            'blind: for _ in 0..BLIND_ATTEMPTS {
                if let Err(e) = self.sample_blinding_factor(&mut r) {
                    err = Some(e);
                    break 'blind;
                }
                // gcd(r, n) ≠ 1：合法密钥（n = p·q，p/q 为大素数）下
                // 概率 ~2⁻¹⁰²³；换 r 重试
                match rsabig::mod_inverse_odd(&r, &self.n) {
                    Some(inv) => rinv.copy_from_slice(&inv),
                    None => continue,
                }
                // re = rᵉ mod n（e 为公开指数，mont_exp 对其常数时间）
                rsabig::to_mont(&r, &self.r2_n, &self.n, self.n0_n, &mut t);
                rsabig::mont_exp(
                    &t,
                    &self.e,
                    self.e_bits,
                    &self.n,
                    self.n0_n,
                    &self.r2_n,
                    &mut re,
                );
                // m′ = m·rᵉ mod n
                rsabig::to_mont(&m, &self.r2_n, &self.n, self.n0_n, &mut t);
                rsabig::mont_mul(&t, &re, &self.n, self.n0_n, &mut t2);
                rsabig::from_mont(&mut t2, &self.n, self.n0_n);
                // s′ = CRT(m′)；s = s′·r⁻¹ mod n（去盲）
                let mut s_blind = self.crt(&t2);
                rsabig::to_mont(&s_blind, &self.r2_n, &self.n, self.n0_n, &mut t);
                rsabig::to_mont(&rinv, &self.r2_n, &self.n, self.n0_n, &mut t2);
                rsabig::mont_mul(&t, &t2, &self.n, self.n0_n, &mut sig);
                rsabig::from_mont(&mut sig, &self.n, self.n0_n);
                s_blind.zeroize();
                ok = true;
                break 'blind;
            }
            // 零化盲化因子与中间值（成功/失败路径统一覆盖）
            for v in [&mut m, &mut r, &mut rinv, &mut re, &mut t, &mut t2] {
                v.zeroize();
            }
            if let Some(e) = err {
                return Err(e);
            }
            if !ok {
                // 全部尝试的 r 均与 n 不互素：模数不是半素数（结构异常）
                return Err(crate::Error::Unsupported);
            }
            let mut out = vec![0u8; self.n_bytes];
            rsabig::i2osp_be(&sig, &mut out);
            sig.zeroize();
            Ok(out)
        }

        /// RSA-PSS 签名（salt 长度 = 哈希长度；TLS 1.3 使用）。
        pub fn sign_pss(&self, hash_bits: u16, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
            let mhash = hash_msg(hash_bits, message)?;
            let hlen = mhash.len();
            let emlen = self.n_bytes;
            // emLen ≥ hLen + sLen + 2（sLen = hLen）
            if emlen < 2 * hlen + 2 {
                return Err(crate::Error::InvalidInput);
            }
            let mut salt = vec![0u8; hlen];
            crate::entropy::fill(&mut salt)?;
            // M' = 0x00 × 8 || mHash || salt
            let mut mprime = vec![0u8; 8 + 2 * hlen];
            mprime[8..8 + hlen].copy_from_slice(&mhash);
            mprime[8 + hlen..].copy_from_slice(&salt);
            let h = hash_msg(hash_bits, &mprime)?;
            // DB = PS(0x00 × (emLen − hLen − sLen − 2)) || 0x01 || salt
            let dblen = emlen - hlen - 1;
            let mut db = vec![0u8; dblen];
            db[dblen - hlen - 1] = 0x01;
            db[dblen - hlen..].copy_from_slice(&salt);
            let mut dbmask = vec![0u8; dblen];
            mgf1(hash_bits, &h, &mut dbmask)?;
            for i in 0..dblen {
                db[i] ^= dbmask[i];
            }
            db[0] &= self.em_mask;
            let mut em = Vec::with_capacity(emlen);
            em.extend_from_slice(&db);
            em.extend_from_slice(&h);
            em.push(0xbc);
            self.sign_em(&em)
        }

        /// RSA PKCS#1 v1.5 签名（TLS 1.2 遗留套件与证书链验证使用）。
        pub fn sign_pkcs1v15(
            &self,
            hash_bits: u16,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::Error> {
            let mhash = hash_msg(hash_bits, message)?;
            let prefix = digestinfo_prefix(hash_bits)?;
            let tlen = prefix.len() + mhash.len();
            let emlen = self.n_bytes;
            if emlen < tlen + 11 {
                return Err(crate::Error::InvalidInput);
            }
            let mut em = vec![0u8; emlen];
            em[0] = 0x00;
            em[1] = 0x01;
            for b in em[2..emlen - tlen - 1].iter_mut() {
                *b = 0xff;
            }
            em[emlen - tlen - 1] = 0x00;
            em[emlen - tlen..emlen - mhash.len()].copy_from_slice(prefix);
            em[emlen - mhash.len()..].copy_from_slice(&mhash);
            self.sign_em(&em)
        }
    }

    impl Drop for SigningKey {
        fn drop(&mut self) {
            // n/e 及其 Montgomery 常数（n0_n/r2_n）是公开钥分量，不零化；
            // r2_p/r2_q/n0_p/n0_q 派生自秘密素数，随秘密一并零化。
            for v in [
                &mut self.p,
                &mut self.q,
                &mut self.dp,
                &mut self.dq,
                &mut self.qinv,
                &mut self.r2_p,
                &mut self.r2_q,
            ] {
                for w in v.iter_mut() {
                    *w = 0;
                }
            }
            self.n0_p = 0;
            self.n0_q = 0;
        }
    }

    impl std::fmt::Debug for SigningKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("rsa::SigningKey")
        }
    }

    /// RSA 公钥（验证用；全部为公开数据）。
    struct RsaPublicKey {
        n: Vec<u64>,
        e: Vec<u64>,
        n0_n: u64,
        r2_n: Vec<u64>,
        n_len: usize,
        n_bytes: usize,
        e_len: usize,
        em_mask: u8,
    }

    impl RsaPublicKey {
        /// 解析 SPKI（SubjectPublicKeyInfo）内的 RSAPublicKey。
        fn from_spki_der(der: &[u8]) -> Result<Self, crate::Error> {
            let (seq, rest) = crate::der::sequence(der)?;
            if !rest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }
            let (alg, rest) = crate::der::sequence(seq)?;
            let (oid, _params) = crate::der::object_identifier(alg)?;
            if oid != crate::der::oid::RSA_ENCRYPTION {
                return Err(crate::Error::InvalidInput);
            }
            let (keybits, rest) = crate::der::bit_string(rest)?;
            if !rest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }
            let (keyseq, krest) = crate::der::sequence(keybits)?;
            if !krest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }
            let (n_b, r) = crate::der::integer(keyseq)?;
            let (e_b, erest) = crate::der::integer(r)?;
            if !erest.is_empty() {
                return Err(crate::Error::InvalidInput);
            }
            if n_b.len() < MIN_MODULUS_LEN || n_b.len() > MAX_MODULUS_LEN {
                return Err(crate::Error::Unsupported);
            }
            if e_b.is_empty() || e_b.len() > 8 {
                return Err(crate::Error::InvalidInput);
            }
            let n_len = n_b.len().div_ceil(8);
            let n_bitlen = 8 * n_b.len() - n_b[0].leading_zeros() as usize;
            let em_left_bits = 8 * n_b.len() + 1 - n_bitlen;
            let mut n = vec![0u64; n_len];
            rsabig::os2ip_be(n_b, &mut n);
            if n[0] & 1 == 0 {
                return Err(crate::Error::InvalidInput);
            }
            let mut e = vec![0u64; 1];
            rsabig::os2ip_be(e_b, &mut e);
            if e[0] < 3 || e[0] & 1 == 0 {
                return Err(crate::Error::InvalidInput);
            }
            let n0_n = rsabig::n0_inv(n[0]);
            let r2_n = rsabig::compute_r2(&n);
            Ok(Self {
                n,
                e,
                n0_n,
                r2_n,
                n_len,
                n_bytes: n_b.len(),
                e_len: 1,
                em_mask: (0xffu32 >> em_left_bits) as u8,
            })
        }

        /// s^e mod n，返回 I2OSP 定长编码（含签名长度与 s < n 校验）。
        fn public_exponentiate(&self, signature: &[u8]) -> Result<Vec<u8>, crate::Error> {
            if signature.len() != self.n_bytes {
                return Err(crate::Error::InvalidInput);
            }
            let mut s = vec![0u64; self.n_len];
            rsabig::os2ip_be(signature, &mut s);
            if rsabig::geq(&s, &self.n) {
                return Err(crate::Error::VerificationFailed);
            }
            let mut base = vec![0u64; self.n_len];
            rsabig::to_mont(&s, &self.r2_n, &self.n, self.n0_n, &mut base);
            let mut m = vec![0u64; self.n_len];
            rsabig::mont_exp(
                &base,
                &self.e,
                64 * self.e_len,
                &self.n,
                self.n0_n,
                &self.r2_n,
                &mut m,
            );
            rsabig::from_mont(&mut m, &self.n, self.n0_n);
            let mut out = vec![0u8; self.n_bytes];
            rsabig::i2osp_be(&m, &mut out);
            Ok(out)
        }
    }

    fn hash_msg(hash_bits: u16, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
        match hash_bits {
            256 => Ok(Sha256::one_shot(message).to_vec()),
            384 => Ok(Sha384::one_shot(message).to_vec()),
            512 => Ok(Sha512::one_shot(message).to_vec()),
            _ => Err(crate::Error::Unsupported),
        }
    }

    /// DigestInfo 前缀（RFC 8017 §9.2 注 1）。
    fn digestinfo_prefix(hash_bits: u16) -> Result<&'static [u8], crate::Error> {
        match hash_bits {
            256 => Ok(&[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ]),
            384 => Ok(&[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ]),
            512 => Ok(&[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ]),
            _ => Err(crate::Error::Unsupported),
        }
    }

    /// MGF1（RFC 8017 附录 B.2.1）。
    fn mgf1(hash_bits: u16, seed: &[u8], mask: &mut [u8]) -> Result<(), crate::Error> {
        let mut counter = 0u32;
        let mut filled = 0usize;
        while filled < mask.len() {
            let mut input = Vec::with_capacity(seed.len() + 4);
            input.extend_from_slice(seed);
            input.extend_from_slice(&counter.to_be_bytes());
            let h = hash_msg(hash_bits, &input)?;
            let take = core::cmp::min(h.len(), mask.len() - filled);
            mask[filled..filled + take].copy_from_slice(&h[..take]);
            filled += take;
            counter += 1;
        }
        Ok(())
    }

    /// 验证 RSA-PSS 签名。公钥为 DER SPKI（SubjectPublicKeyInfo）。
    pub fn verify_pss(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let pk = RsaPublicKey::from_spki_der(public_key_der)?;
        let em = pk.public_exponentiate(signature)?;
        let mhash = hash_msg(hash_bits, message)?;
        let hlen = mhash.len();
        let emlen = em.len();
        // 一切 padding 失败归一化为同一错误（不泄露失败阶段）
        if emlen < 2 * hlen + 2 || em[emlen - 1] != 0xbc {
            return Err(crate::Error::VerificationFailed);
        }
        if em[0] & !pk.em_mask != 0 {
            return Err(crate::Error::VerificationFailed);
        }
        let h = &em[emlen - hlen - 1..emlen - 1];
        let dblen = emlen - hlen - 1;
        let mut db = em[..dblen].to_vec();
        let mut dbmask = vec![0u8; dblen];
        mgf1(hash_bits, h, &mut dbmask)?;
        for i in 0..dblen {
            db[i] ^= dbmask[i];
        }
        db[0] &= pk.em_mask;
        let ps_len = dblen - hlen - 1;
        if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
            return Err(crate::Error::VerificationFailed);
        }
        let salt = &db[ps_len + 1..];
        let mut mprime = vec![0u8; 8 + 2 * hlen];
        mprime[8..8 + hlen].copy_from_slice(&mhash);
        mprime[8 + hlen..].copy_from_slice(salt);
        let h2 = hash_msg(hash_bits, &mprime)?;
        if h2[..] != *h {
            return Err(crate::Error::VerificationFailed);
        }
        Ok(())
    }

    /// 验证 RSA PKCS#1 v1.5 签名（严格 padding 检查，防 Bleichenbacher）。
    pub fn verify_pkcs1v15(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let pk = RsaPublicKey::from_spki_der(public_key_der)?;
        let em = pk.public_exponentiate(signature)?;
        let mhash = hash_msg(hash_bits, message)?;
        let prefix = digestinfo_prefix(hash_bits)?;
        let tlen = prefix.len() + mhash.len();
        let emlen = em.len();
        if emlen < tlen + 11 {
            return Err(crate::Error::VerificationFailed);
        }
        // 逐字节重构期望 EM 并全等比较（拒绝非规范 0xFF 串等一切变体）
        let mut expected = vec![0u8; emlen];
        expected[0] = 0x00;
        expected[1] = 0x01;
        for b in expected[2..emlen - tlen - 1].iter_mut() {
            *b = 0xff;
        }
        expected[emlen - tlen - 1] = 0x00;
        expected[emlen - tlen..emlen - mhash.len()].copy_from_slice(prefix);
        expected[emlen - mhash.len()..].copy_from_slice(&mhash);
        if em != expected {
            return Err(crate::Error::VerificationFailed);
        }
        Ok(())
    }
}
