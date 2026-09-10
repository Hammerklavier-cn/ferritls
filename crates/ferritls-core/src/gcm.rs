//! AES-GCM（NIST SP 800-38D），认证加密。
//!
//! FIPS 批准；TLS 1.3 批准套件 `TLS_AES_128_GCM_SHA256` /
//! `TLS_AES_256_GCM_SHA384` 的记录层 AEAD。上电自检覆盖（M5）。
//!
//! 公开类型是薄壳：未安装后端时**直连**软件实现（零分发开销）；
//! 安装硬件后端后，新构造的实例经 [`crate::ops`] 取 trait 对象执行
//! 核心。软件核心的常数时间策略：GHASH 的 GF(2^128) 乘法有两条
//! 路径——小块（< [`GHASH_TABLE_MIN_BLOCKS`]）走逐位掩码乘；大块构建
//! **瞬态** H 倍数 4-bit 表（组内查表索引仅公开的 AAD/密文/长度字节，
//! 内容含秘密 H，判据见 AGENTS §5.1；表在调用结束前零化丢弃，不常驻
//! 实例内存）。CTR keystream 走位切片批量路径
//! （[`crate::aes::CTR_BATCH_BLOCKS`]）。路径选择只依赖公开长度。
//! **标签验证在返回任何明文前完成**（open 路径失败统一同一错误码，
//! 比较经 [`crate::ct::verify_tag`]，失败时明文缓冲零化）。nonce
//! 唯一性由 rustls 记录层保证。密钥材料（含 GHASH 的 H）Drop 时零化。
//!
//! 向量：McGrew–Viega TC5/TC16（`tests/aes_gcm.rs`）+ FIPS-197 AES KAT。

use crate::aes::{Aes128, Aes256, CTR_BATCH_BLOCKS};
use crate::ops::AeadGcm as _;
use zeroize::Zeroize;

macro_rules! gcm_impl {
    (
        $name:ident, $inner:ident, $soft:ident, $aes:ident, $factory:ident,
        $keylen:literal, $doc:expr
    ) => {
        #[doc = $doc]
        pub struct $name {
            inner: $inner,
        }

        /// 执行核心：软件直连或已安装后端的 trait 对象。
        enum $inner {
            Soft($soft),
            Ext(Box<dyn crate::ops::AeadGcm>),
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $keylen;
            /// 标准 96 位 nonce（TLS 1.3 固定长度）。
            pub const NONCE_LEN: usize = 12;
            /// 标签字节数（TLS 1.3 只用 128 位标签）。
            pub const TAG_LEN: usize = 16;

            /// 本算法在 FIPS 140-3 下的批准状态。
            pub const APPROVAL: crate::Approval = crate::Approval::Approved;

            /// 展开密钥（内部同时预计算 GHASH 的 H）。
            ///
            /// 执行核心取自当前安装的后端（[`crate::ops::installed_aead`]；
            /// 未安装 → 软件直连）；进程内安装新后端不影响已构造的实例。
            pub fn new(key: &[u8; $keylen]) -> Self {
                let inner = match crate::ops::installed_aead() {
                    Some(backend) => $inner::Ext(backend.$factory(key)),
                    None => $inner::Soft($soft::new(key)),
                };
                Self { inner }
            }

            /// 加密：返回 `密文 || 标签`（长度 = `plaintext.len() + 16`）。
            pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
                let mut out = plaintext.to_vec();
                let tag = match &self.inner {
                    $inner::Soft(s) => s.seal(nonce, aad, &mut out),
                    $inner::Ext(c) => c.seal(nonce, aad, &mut out),
                };
                out.extend_from_slice(&tag);
                out
            }

            /// 解密并验证；任何失败（含输入过短）统一返回
            /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
            ///
            /// 明文在标签验证通过前不返回；验证失败时解密缓冲被零化。
            pub fn open(
                &self,
                nonce: &[u8; 12],
                aad: &[u8],
                ct_and_tag: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                if ct_and_tag.len() < 16 {
                    return Err(crate::Error::VerificationFailed);
                }
                let split = ct_and_tag.len() - 16;
                let (ct, tag_bytes) = ct_and_tag.split_at(split);

                let mut pt = ct.to_vec();
                let computed = match &self.inner {
                    $inner::Soft(s) => s.open_compute_tag(nonce, aad, &mut pt),
                    $inner::Ext(c) => c.open_compute_tag(nonce, aad, &mut pt),
                };
                if crate::ct::verify_tag(&computed, tag_bytes).is_err() {
                    pt.zeroize();
                    return Err(crate::Error::VerificationFailed);
                }
                Ok(pt)
            }
        }

        impl Clone for $name {
            fn clone(&self) -> Self {
                Self {
                    inner: match &self.inner {
                        $inner::Soft(s) => $inner::Soft(s.clone()),
                        $inner::Ext(c) => $inner::Ext(c.clone_box()),
                    },
                }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        /// 软件执行核心（私有；`Soft` 分支直连使用）。
        struct $soft {
            aes: $aes,
            /// GHASH 乘数 H = CIPH_K(0^128)，大端 u128 视图。
            h: u128,
        }

        impl $soft {
            fn new(key: &[u8; $keylen]) -> Self {
                let aes = $aes::new(key);
                let mut h_block = [0u8; 16];
                aes.encrypt_block(&mut h_block);
                Self {
                    aes,
                    h: u128::from_be_bytes(h_block),
                }
            }

            /// J0 的加密值，即标签的异或基。
            fn tag_base(&self, nonce: &[u8; 12]) -> u128 {
                let mut b = block_j0(nonce).to_be_bytes();
                self.aes.encrypt_block(&mut b);
                u128::from_be_bytes(b)
            }

            /// CTR 密钥流异或覆盖 `buf`（P1 位切片批量路径）：每批
            /// [`CTR_BATCH_BLOCKS`] 块经
            /// [`encrypt_ctr_batch`](crate::aes::Aes128::encrypt_ctr_batch)
            /// 生成密钥流后整批异或；计数器推进只依赖公开长度。
            fn ctr_xor(&self, j0: u128, buf: &mut [u8]) {
                let mut ctr = inc32(j0);
                let mut ks = [0u8; CTR_BATCH_BLOCKS * 16];
                for chunk in buf.chunks_mut(CTR_BATCH_BLOCKS * 16) {
                    let n = chunk.len().div_ceil(16);
                    self.aes.encrypt_ctr_batch(ctr.to_be_bytes(), n, &mut ks);
                    let ks_slice = &ks[..chunk.len()];
                    for (o, k) in chunk.iter_mut().zip(ks_slice) {
                        *o ^= k;
                    }
                    ctr = (ctr & !0xFFFF_FFFFu128) | (ctr as u32).wrapping_add(n as u32) as u128;
                }
            }

            /// GHASH：Aad(pad) || C(pad) || [len(aad)]64 || [len(ct)]64。
            ///
            /// 小输入走逐位 [`gf128_mul`]；大输入（≥ [`GHASH_TABLE_MIN_BLOCKS`]
            /// 块）构建瞬态 H 倍数表走分组路径（见 [`GhashTables`]）。
            /// 路径选择只依赖公开长度（§5.1）。
            fn ghash(&self, aad: &[u8], ct: &[u8]) -> u128 {
                let block = |c: &[u8]| -> u128 {
                    let mut b = [0u8; 16];
                    b[..c.len()].copy_from_slice(c);
                    u128::from_be_bytes(b)
                };
                let mut len_b = [0u8; 16];
                len_b[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
                len_b[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
                let mut it = aad
                    .chunks(16)
                    .map(|c| block(c))
                    .chain(ct.chunks(16).map(|c| block(c)))
                    .chain(std::iter::once(u128::from_be_bytes(len_b)));
                let total = aad.len().div_ceil(16) + ct.len().div_ceil(16) + 1;
                if total < GHASH_TABLE_MIN_BLOCKS {
                    let mut y = 0u128;
                    for x in it {
                        y = gf128_mul(y ^ x, self.h);
                    }
                    y
                } else {
                    let mut tables = GhashTables::build(self.h);
                    let out = tables.ghash_grouped(&mut it);
                    tables.zeroize();
                    out
                }
            }
        }

        impl Drop for $soft {
            fn drop(&mut self) {
                // aes 字段由 Aes* 自身 Drop 零化；这里补 GHASH 的 H。
                self.h = 0;
            }
        }

        impl Clone for $soft {
            fn clone(&self) -> Self {
                Self {
                    aes: self.aes.clone(),
                    h: self.h,
                }
            }
        }

        impl crate::ops::AeadGcm for $soft {
            fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
                let tag_base = self.tag_base(nonce);
                self.ctr_xor(block_j0(nonce), buf);
                let s = self.ghash(aad, buf);
                (tag_base ^ s).to_be_bytes()
            }

            fn open_compute_tag(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
                // 计算标签基于密文，与解密顺序无关；比较由公开类型完成。
                let tag_base = self.tag_base(nonce);
                let s = self.ghash(aad, buf);
                self.ctr_xor(block_j0(nonce), buf);
                (tag_base ^ s).to_be_bytes()
            }

            fn clone_box(&self) -> Box<dyn crate::ops::AeadGcm> {
                Box::new(self.clone())
            }
        }
    };
}

/// 96 位 nonce → J0 = nonce || 0x00000001。
fn block_j0(nonce: &[u8; 12]) -> u128 {
    let mut b = [0u8; 16];
    b[..12].copy_from_slice(nonce);
    b[15] = 1;
    u128::from_be_bytes(b)
}

/// 递增计数器块的最低 32 位（RFC 5116 inc32）。
fn inc32(block: u128) -> u128 {
    let ctr = (block as u32).wrapping_add(1);
    (block & !0xFFFF_FFFF) | (ctr as u128)
}

/// GF(2^128) 乘法，SP 800-38D 算法 1 的分支无关实现。
/// 块以大端 u128 表示，约减多项式 R = 0xE1 << 120。
fn gf128_mul(x: u128, y: u128) -> u128 {
    const R: u128 = 0xE1u128 << 120;
    let mut z: u128 = 0;
    let mut v = y;
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        z ^= v & bit.wrapping_neg();
        let lsb = v & 1;
        v >>= 1;
        v ^= R.wrapping_mul(lsb);
    }
    z
}

/// GHASH 分组大小（H 倍数表的幂数上限）：每 GROUP 块做一次秘密累加器
/// 的逐位乘，组内全部为公开索引查表。
const GHASH_GROUP: usize = 8;

/// 低于此块数走逐位路径（瞬态表构建成本不划算）。阈值只依赖公开
/// 长度，路径选择不构成秘密相关的控制流（§5.1）。
const GHASH_TABLE_MIN_BLOCKS: usize = 64;

/// 单个乘数 G 的 4-bit 倍数表：`table[k][m]` = 输入第 k 个 nibble
/// （MSB 起）取值 m 时的部分积。构建自 V 链（V₀ = G，V_{i+1} 为 V_i
/// 的折叠右移），与 [`gf128_mul`] 的循环结构逐位对应——因此
/// `tbl_mul(build_gf128_table(g), x) == gf128_mul(x, g)` 恒成立。
fn build_gf128_table(mut g: u128) -> [[u128; 16]; 32] {
    const R: u128 = 0xE1u128 << 120;
    let mut table = [[0u128; 16]; 32];
    for row in &mut table {
        for j in 0..4 {
            for (m, slot) in row.iter_mut().enumerate() {
                if (m >> (3 - j)) & 1 == 1 {
                    *slot ^= g;
                }
            }
            let lsb = g & 1;
            g >>= 1;
            g ^= R.wrapping_mul(lsb);
        }
    }
    table
}

/// 公开索引查表乘：z = x·G（G 为建表乘数）。x 为公开数据
/// （AAD/密文/长度块），索引不含秘密（§5.1 查表判据）。
#[inline]
fn tbl_mul(table: &[[u128; 16]; 32], x: u128) -> u128 {
    let mut z = table[0][((x >> 124) & 0xF) as usize];
    for k in 1..32 {
        z ^= table[k][((x >> (124 - 4 * k)) & 0xF) as usize];
    }
    z
}

/// 瞬态 GHASH 表集：H¹..H^GROUP 的倍数表与幂值。每次大输入 ghash
/// 调用时构建，用完 [`zeroize`](Self::zeroize) 丢弃，不常驻实例
/// （常驻 64 KiB/实例对多连接服务器的内存不可接受）。
struct GhashTables {
    tables: Vec<[[u128; 16]; 32]>,
    powers: [u128; GHASH_GROUP],
}

impl GhashTables {
    fn build(h: u128) -> Self {
        let mut powers = [0u128; GHASH_GROUP];
        powers[0] = h;
        for i in 1..GHASH_GROUP {
            powers[i] = gf128_mul(powers[i - 1], h);
        }
        let tables = powers.iter().map(|&g| build_gf128_table(g)).collect();
        Self { tables, powers }
    }

    fn zeroize(&mut self) {
        for t in &mut self.tables {
            for row in t.iter_mut() {
                row.fill(0);
            }
        }
        self.powers.fill(0);
    }

    /// 分组前向 Horner：对每组大小 s，
    /// `R ← R·Hˢ ^ Σ_idx X_idx·H^{s-idx}`（组内查表全为公开索引），
    /// 组间乘以秘密累加器时回落到逐位 [`gf128_mul`]。展开恒等式
    /// `Y_m = Σ X_i·H^{m+1-i}` 可逐项验证。
    fn ghash_grouped(&self, it: &mut dyn Iterator<Item = u128>) -> u128 {
        let mut y = 0u128;
        let mut started = false;
        loop {
            let mut buf = [0u128; GHASH_GROUP];
            let mut s = 0usize;
            while s < GHASH_GROUP {
                match it.next() {
                    Some(x) => {
                        buf[s] = x;
                        s += 1;
                    }
                    None => break,
                }
            }
            if s == 0 {
                return y;
            }
            let mut z = 0u128;
            for (idx, &x) in buf.iter().enumerate().take(s) {
                z ^= tbl_mul(&self.tables[s - 1 - idx], x);
            }
            if started {
                y = gf128_mul(y, self.powers[s - 1]);
            }
            y ^= z;
            started = true;
        }
    }
}

gcm_impl!(
    Aes128Gcm,
    Aes128GcmInner,
    SoftAes128Gcm,
    Aes128,
    aes128_gcm,
    16,
    "AES-128-GCM AEAD 实例（密钥 Drop 时零化）。"
);
gcm_impl!(
    Aes256Gcm,
    Aes256GcmInner,
    SoftAes256Gcm,
    Aes256,
    aes256_gcm,
    32,
    "AES-256-GCM AEAD 实例（密钥 Drop 时零化）。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf128_properties() {
        let a = u128::from_be_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        // GF(2^128) 单位元（x^0）在本表示（左位=低位次）下为最高位。
        let one = 1u128 << 127;
        assert_eq!(gf128_mul(a, one), a, "X·1 = X");
        assert_eq!(gf128_mul(one, a), a, "1·Y = Y");
        assert_eq!(gf128_mul(0, a), 0);
        // 交换律。
        let b = 0xdeadbeefcafef00d1234567890abcdefu128;
        assert_eq!(gf128_mul(a, b), gf128_mul(b, a));
    }

    #[test]
    fn tbl_mul_matches_bitwise() {
        let mut x = 0x1234_5678_9abc_def0_0fed_cba9_8765_4321u128;
        let g = 0xdead_beef_cafe_babe_0123_4567_89ab_cdefu128;
        let table = build_gf128_table(g);
        assert_eq!(tbl_mul(&table, x), gf128_mul(x, g));
        assert_eq!(tbl_mul(&table, g), gf128_mul(g, g));
        assert_eq!(tbl_mul(&table, 0), 0);
        let one = 1u128 << 127;
        assert_eq!(tbl_mul(&build_gf128_table(x), one), x);
        for _ in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            assert_eq!(tbl_mul(&table, x), gf128_mul(x, g));
        }
    }

    #[test]
    fn grouped_ghash_matches_horner() {
        // 独立参考实现（不复用 ghash 的小路径，避免同错比对）。
        let reference = |h: u128, aad: &[u8], ct: &[u8]| -> u128 {
            let block = |c: &[u8]| {
                let mut b = [0u8; 16];
                b[..c.len()].copy_from_slice(c);
                u128::from_be_bytes(b)
            };
            let mut y = 0u128;
            for x in aad.chunks(16).map(&block).chain(ct.chunks(16).map(&block)) {
                y = gf128_mul(y ^ x, h);
            }
            let mut len_b = [0u8; 16];
            len_b[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
            len_b[8..].copy_from_slice(&((ct.len() as u64) * 8).to_be_bytes());
            gf128_mul(y ^ u128::from_be_bytes(len_b), h)
        };

        // 伪随机数据 + 覆盖：空/部分块、单组边界（m=7/8/9）、阈值两侧
        // （63/64/65 块）、整组倍数（200 = 8×25）与余数（199+1）。
        let mut seed = 0x9E37_79B9u32;
        let mut data = vec![0u8; 16 * 210 + 64];
        for b in data.iter_mut() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            *b = seed as u8;
        }
        let soft = SoftAes128Gcm::new(&[0x42u8; 16]);
        let h = soft.h;
        for aad_len in [0usize, 5, 31] {
            for ct_len in [
                0usize, 1, 15, 16, 17, 95, 96, 97, 111, 112, 113, 975, 976, 977, 991, 3199, 3215,
            ] {
                let aad = &data[..aad_len];
                let ct = &data[100..100 + ct_len];
                assert_eq!(
                    soft.ghash(aad, ct),
                    reference(h, aad, ct),
                    "aad={aad_len} ct={ct_len}"
                );
            }
        }
    }

    /// seal→open 往返（软件默认路径；密封性与失败路径由集成测试覆盖）。
    #[test]
    fn seal_open_roundtrip() {
        let g = Aes256Gcm::new(&[0x42; 32]);
        let nonce = [0x11; 12];
        let sealed = g.seal(&nonce, b"aad", b"plaintext, longer than one block ~~");
        let opened = g.open(&nonce, b"aad", &sealed).expect("roundtrip");
        assert_eq!(opened, b"plaintext, longer than one block ~~");
        // 篡改任意密文字节 → 失败。
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(g.open(&nonce, b"aad", &bad).is_err());
        // 篡改标签 → 失败。
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(g.open(&nonce, b"aad", &bad).is_err());
    }
}
