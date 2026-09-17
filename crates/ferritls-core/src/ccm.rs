//! AES-CCM（RFC 3610 / SP 800-38C），认证加密。
//!
//! FIPS 批准（SP 800-38C 对 M ∈ {4,6,8,10,12,14,16} 均批准；但 SP
//! 800-52r2 的 TLS 批准套件面只含 M=16 的 [`Aes128CcmTls`]，见适配层
//! 套件表）。标签长度 M 与 nonce 长度（↔ 长度域 L = 15 − nonce 长度）
//! 为**运行时参数**，两条入口：
//!
//! - 固定参数集类型（宏生成，委托引擎，nonce 以 `&[u8; N]` 类型化）：
//!   - [`Aes128Ccm`]：M=16、13 字节 nonce、L=2；
//!   - [`Aes128CcmTls`]：M=16、12 字节 nonce、L=3（RFC 8446 §B.5 的
//!     AEAD_AES_128_CCM，TLS 1.3 记录层使用）；
//!   - [`Aes128Ccm8Tls`]：M=8、12 字节 nonce、L=3（RFC 8446 §B.5 的
//!     AEAD_AES_128_CCM_8；非批准 TLS 套件，仅默认模式装配）。
//! - 全参数空间 [`Aes128CcmAny`]：构造时选 M，调用时传任意合法长度
//!   nonce（7..=13 字节）。M=4/6 标签强度低于 RFC 3610 作者建议
//!   （≥ 8），仅为兼容既有协议而提供。
//!
//! AES-192/256-CCM 未提供：无 TLS 消费者（TLS 1.3 套件表只有
//! AES-128 两档），属显式省略。
//!
//! 外部锚定：RFC 3610 §8 全部 24 个官方分组向量（M=8/L=2 与
//! M=10/L=2，含 AAD 路径）经程序化提取（tools 流程同 RFC 8448：
//! python 解析官方原文 + python-cryptography 双向复算）后直跑；
//! M=16 与全 M 矩阵的 TLS 形态期望值由 python-cryptography（OpenSSL
//! 后端，先对官方原文校验通过）生成——见 `tests/ccm.rs` 与
//! docs/VECTOR-PROVENANCE.md。上电自检覆盖（M5）。

use crate::aes::Aes128;

// ---------------------------------------------------------------------------
// 运行时引擎：标签长/nonce 长均为协议协商的**公开量**，分支与长度域
// 计算不引入任何常数时间顾虑；秘密仅经 Aes128（ZeroizeOnDrop）持有。
// ---------------------------------------------------------------------------

/// 参数校验：nonce ∈ 7..=13 字节（L = 15 − nonce ∈ [2,8]，RFC 3610
/// §2，L=1 为规范保留值）、M ∈ {4,6,8,10,12,14,16}（B0 的 3 位 M'
/// 字段编码域，偶数）。返回 L。
fn validate_params(nonce_len: usize, tag_len: usize) -> Result<usize, crate::Error> {
    if !(7..=13).contains(&nonce_len) || !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2)
    {
        return Err(crate::Error::InvalidInput);
    }
    Ok(15 - nonce_len)
}

/// B0 首字节 flags：64·Adata + 8·M' + L'（RFC 3610 §2.2；
/// M' = (M−2)/2，L' = L−1）。
fn b0_flags(tag_len: usize, has_aad: bool, l: usize) -> u8 {
    ((((tag_len - 2) / 2) << 3) | (u8::from(has_aad) << 6) as usize | (l - 1)) as u8
}

/// 长度域检查（RFC 3610 §2.2）：明文 < 2^(8L)（L=8 时上限为 2^64，
/// usize 无法越过，免检）；AAD < 2^16 − 2^8——两字节短形编码上限
/// （RFC 3610 §2.2 的长形 0xfffe 转义无 TLS 消费者，不支持）。
fn check_length_domain(l: usize, pt_len: usize, aad_len: usize) -> Result<(), crate::Error> {
    if l < 8 && pt_len >= 1usize << (8 * l) {
        return Err(crate::Error::InvalidInput);
    }
    if aad_len >= 0xff00 {
        return Err(crate::Error::InvalidInput);
    }
    Ok(())
}

/// 原始 CTR 块（未加密）：A_i = (L−1) || nonce || counter（L 字节 BE）。
/// counter 为 u32，但 L 可达 8（移位量至多 56）——经 u64 展开字节。
fn ctr_raw(nonce: &[u8], l: usize, counter: u32) -> [u8; 16] {
    debug_assert!(1 + nonce.len() + l == 16);
    let mut block = [0u8; 16];
    block[0] = l as u8 - 1;
    block[1..1 + nonce.len()].copy_from_slice(nonce);
    let ctr = counter as u64;
    for i in 0..l {
        block[16 - l + i] = (ctr >> (8 * (l - 1 - i))) as u8;
    }
    block
}

fn ctr_block(aes: &Aes128, nonce: &[u8], l: usize, counter: u32) -> [u8; 16] {
    let mut block = ctr_raw(nonce, l, counter);
    aes.encrypt_block(&mut block);
    block
}

/// CTR 密钥流异或（P1 位切片批量路径，同 gcm.rs）。L ≤ 8 时最大块号
/// ceil(2^(8L)/16) 在 u32 内不可能回绕。
fn ctr_xor(aes: &Aes128, nonce: &[u8], l: usize, start: u32, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut counter = start;
    let mut ks = [0u8; crate::aes::CTR_BATCH_BLOCKS * 16];
    for (in_chunk, out_chunk) in data
        .chunks(crate::aes::CTR_BATCH_BLOCKS * 16)
        .zip(out.chunks_mut(crate::aes::CTR_BATCH_BLOCKS * 16))
    {
        let n = in_chunk.len().div_ceil(16);
        aes.encrypt_ctr_batch(ctr_raw(nonce, l, counter), n, &mut ks);
        let ks_slice = &ks[..out_chunk.len()];
        for (o, (b, k)) in out_chunk.iter_mut().zip(in_chunk.iter().zip(ks_slice)) {
            *o = b ^ k;
        }
        counter = counter.wrapping_add(n as u32);
    }
    out
}

/// CBC-MAC over B0 || 格式化 AAD || 明文（均补齐到 16 字节块）。
fn cbc_mac(
    aes: &Aes128,
    nonce: &[u8],
    l: usize,
    tag_len: usize,
    aad: &[u8],
    pt: &[u8],
) -> [u8; 16] {
    let mut buf: Vec<u8> = Vec::with_capacity(16 + aad.len() + pt.len() + 32);
    // B0: flags || nonce || 明文长度（L 字节 BE）；Flags 第 6 位
    // 为 Adata（RFC 3610 §2.2：64·Adata + 8·M' + L'）——带 AAD
    // 时必须置位，否则与规范实现不互操作。
    buf.push(b0_flags(tag_len, !aad.is_empty(), l));
    buf.extend_from_slice(nonce);
    // 明文长度用 L 字节 BE；seal/open 已拒绝超长度域的输入
    //（L 可达 8，移位量至多 56——经 u64 展开以保 32 位目标可移植）
    let plen = pt.len() as u64;
    for i in (0..l).rev() {
        buf.push((plen >> (8 * i)) as u8);
    }

    // AAD 编码：2 字节长度 + 数据 + 补零（RFC 3610 §2.2，
    // len < 2^16-2^8）。**AAD 段在此独立补齐到 16 字节边界**
    //（add-auth-data 与 payload 各自补齐）——若与 payload 连续
    // 排列仅在末尾补一次，MAC 与规范实现（OpenSSL 等）不一致。
    if !aad.is_empty() {
        buf.extend_from_slice(&(aad.len() as u16).to_be_bytes());
        buf.extend_from_slice(aad);
        let rem = buf.len() % 16;
        if rem != 0 {
            buf.resize(buf.len() + 16 - rem, 0);
        }
    }

    buf.extend_from_slice(pt);

    let mut t = [0u8; 16];
    for chunk in buf.chunks(16) {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        for i in 0..16 {
            block[i] ^= t[i];
        }
        aes.encrypt_block(&mut block);
        t = block;
    }
    t
}

/// 先截断 CBC-MAC 到 M 字节、再与前 M 字节 S0 异或（RFC 3610 §2.4/
/// §2.5 的顺序，**不可**先全宽异或再截断——两者对 M<16 结果不同）。
fn tag_finish(t: &mut [u8; 16], s0: &[u8; 16], tag_len: usize) {
    for i in 0..tag_len {
        t[i] ^= s0[i];
    }
}

fn seal_core(
    aes: &Aes128,
    nonce: &[u8],
    tag_len: usize,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let l = validate_params(nonce.len(), tag_len)?;
    check_length_domain(l, plaintext.len(), aad.len())?;
    let mut t = cbc_mac(aes, nonce, l, tag_len, aad, plaintext);
    let ct = ctr_xor(aes, nonce, l, 1, plaintext);
    let s0 = ctr_block(aes, nonce, l, 0);
    tag_finish(&mut t, &s0, tag_len);
    let mut out = ct;
    out.extend_from_slice(&t[..tag_len]);
    Ok(out)
}

fn open_core(
    aes: &Aes128,
    nonce: &[u8],
    tag_len: usize,
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let l = validate_params(nonce.len(), tag_len)?;
    if ct_and_tag.len() < tag_len {
        return Err(crate::Error::VerificationFailed);
    }
    // 密文长度受同一长度域约束（超出必非本模块产物）；校验先于任何
    // AES 运算。
    if l < 8 && ct_and_tag.len() - tag_len >= 1usize << (8 * l) {
        return Err(crate::Error::VerificationFailed);
    }
    let split = ct_and_tag.len() - tag_len;
    let (ct, tag) = ct_and_tag.split_at(split);

    let pt = ctr_xor(aes, nonce, l, 1, ct);
    let mut t = cbc_mac(aes, nonce, l, tag_len, aad, &pt);
    let s0 = ctr_block(aes, nonce, l, 0);
    tag_finish(&mut t, &s0, tag_len);
    crate::ct::verify_tag(&t[..tag_len], tag)?;
    Ok(pt)
}

// ---------------------------------------------------------------------------
// 全参数公开类型
// ---------------------------------------------------------------------------

/// AES-128-CCM，标签长度运行时可配的全参数实例（RFC 3610 完整参数
/// 空间：M ∈ {4,6,8,10,12,14,16}，nonce 7..=13 字节）。
///
/// M=4/6 的完整性标签弱于 RFC 3610 作者建议（≥ 8），仅为兼容既有
/// 协议提供；TLS 批准套件面（SP 800-52r2）只使用 M=16（见模块头）。
#[derive(Clone)]
pub struct Aes128CcmAny {
    aes: Aes128,
    tag_len: usize,
}

impl Aes128CcmAny {
    /// 密钥字节数。
    pub const KEY_LEN: usize = 16;

    /// 本算法在 FIPS 140-3 下的批准状态：SP 800-38C 对全部受支持
    /// M 值批准（TLS 批准套件面不含 M=8，见模块头）。
    pub const APPROVAL: crate::Approval = crate::Approval::Approved;

    /// 构造：`tag_len` 必须 ∈ {4,6,8,10,12,14,16}，否则返回
    /// [`Error::InvalidInput`](crate::Error)。
    pub fn new(key: &[u8; 16], tag_len: usize) -> Result<Self, crate::Error> {
        if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
            return Err(crate::Error::InvalidInput);
        }
        Ok(Self {
            aes: Aes128::new(key),
            tag_len,
        })
    }

    /// 加密：返回 `密文 || 标签`（标签 `tag_len` 字节）。
    ///
    /// `nonce` 长度必须为 7..=13 字节；长度域限制见内部 `check_length_domain`。
    pub fn seal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        seal_core(&self.aes, nonce, self.tag_len, aad, plaintext)
    }

    /// 解密并验证；失败统一返回
    /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, crate::Error> {
        open_core(&self.aes, nonce, self.tag_len, aad, ct_and_tag)
    }
}

impl std::fmt::Debug for Aes128CcmAny {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes128CcmAny")
            .field("tag_len", &self.tag_len)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 固定参数集类型（nonce 长度类型化；委托运行时引擎）
// ---------------------------------------------------------------------------

/// 生成一个固定 nonce/标签长度的 CCM 实例类型（薄包装，委托
/// [`Aes128CcmAny`] 的引擎函数）。
macro_rules! ccm_impl {
    ($name:ident, $nonce_len:expr, $tag_len:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            any: Aes128CcmAny,
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = 16;
            /// nonce 长度（L = 15 − nonce_len）。
            pub const NONCE_LEN: usize = $nonce_len;
            /// 标签字节数。
            pub const TAG_LEN: usize = $tag_len;

            /// 本算法在 FIPS 140-3 下的批准状态。
            pub const APPROVAL: crate::Approval = crate::Approval::Approved;

            /// 展开密钥。
            pub fn new(key: &[u8; 16]) -> Self {
                Self {
                    // 参数为编译期常量，构造必不失败
                    any: Aes128CcmAny::new(key, $tag_len).expect("fixed parameter set"),
                }
            }

            /// 加密：返回 `密文 || 标签`。
            ///
            /// 长度域限制（RFC 3610 §2.2）：明文长度必须 < 2^(8L)、AAD
            /// 长度必须 < 2^16 − 2^8（两字节长度编码上限），超限返回
            /// [`Error::InvalidInput`](crate::Error)（规范要求的显式拒绝，
            /// 不得按位截断后继续）。
            pub fn seal(
                &self,
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                self.any.seal(nonce, aad, plaintext)
            }

            /// 解密并验证；失败统一返回
            /// [`Error::VerificationFailed`](crate::Error::VerificationFailed)。
            pub fn open(
                &self,
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                ct_and_tag: &[u8],
            ) -> Result<Vec<u8>, crate::Error> {
                self.any.open(nonce, aad, ct_and_tag)
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

ccm_impl!(
    Aes128Ccm,
    13,
    16,
    "AES-128-CCM 实例（M=16，13 字节 nonce，L=2）。"
);
ccm_impl!(
    Aes128CcmTls,
    12,
    16,
    "AES-128-CCM 实例（M=16，12 字节 nonce，L=3）——RFC 8446 §B.5 TLS 1.3 参数集。"
);
ccm_impl!(
    Aes128Ccm8Tls,
    12,
    8,
    "AES-128-CCM 实例（M=8，12 字节 nonce，L=3）——RFC 8446 §B.5 的 \
     AEAD_AES_128_CCM_8；8 字节标签不在 SP 800-52r2 TLS 批准套件面。"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tamper() {
        let key = [0x07u8; 16];
        let nonce13 = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        ];
        let aead = Aes128Ccm::new(&key);

        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = aead.seal(&nonce13, b"aad", &pt).unwrap();
            assert_eq!(sealed.len(), len + 16);
            let opened = aead.open(&nonce13, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "len {len}");
        }

        let sealed = aead.seal(&nonce13, b"aad", b"hello ccm").unwrap();
        let mut bad = sealed.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert_eq!(
            aead.open(&nonce13, b"aad", &bad),
            Err(crate::Error::VerificationFailed)
        );
        assert_eq!(
            aead.open(&nonce13, b"bad", &sealed),
            Err(crate::Error::VerificationFailed)
        );

        // TLS 参数集（nonce 12 / L=3）：同往返回归
        let nonce12 = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let tls = Aes128CcmTls::new(&key);
        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = tls.seal(&nonce12, b"aad", &pt).unwrap();
            assert_eq!(sealed.len(), len + 16);
            let opened = tls.open(&nonce12, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "tls len {len}");
        }
        // 两参数集对同一 (key, 数据) 输出必须不同（nonce/L 均不同）
        assert_ne!(
            aead.seal(&nonce13, b"aad", b"x").unwrap(),
            tls.seal(&nonce12, b"aad", b"x").unwrap()
        );

        // CCM_8 TLS 参数集：标签 8 字节，往返 + 与 Any(M=8) 输出一致
        let ccm8 = Aes128Ccm8Tls::new(&key);
        let any8 = Aes128CcmAny::new(&key, 8).unwrap();
        for len in [0usize, 1, 15, 16, 17, 33, 64] {
            let pt: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let sealed = ccm8.seal(&nonce12, b"aad", &pt).unwrap();
            assert_eq!(sealed.len(), len + 8);
            let opened = ccm8.open(&nonce12, b"aad", &sealed).expect("round trip");
            assert_eq!(opened, pt, "ccm8 len {len}");
            assert_eq!(
                sealed,
                any8.seal(nonce12.as_slice(), b"aad", &pt).unwrap(),
                "fixed Ccm8Tls must match Any(M=8), len {len}"
            );
        }

        // 长度域拒绝（RFC 3610 §2.2）：L=2 明文上限 65535 字节；
        // AAD 两字节编码上限 0xff00。L=3 上限为 2^24 字节，端到端构造
        // 过慢，经由 open 的长度域检查覆盖（校验先于任何 AES 运算）。
        let big = vec![0u8; 1 << 16];
        assert_eq!(
            aead.seal(&nonce13, b"", &big),
            Err(crate::Error::InvalidInput)
        );
        assert_eq!(
            aead.seal(&nonce13, &[0u8; 0xff00], &[0u8; 16]),
            Err(crate::Error::InvalidInput)
        );
        assert_eq!(
            tls.open(&nonce12, b"", &vec![0u8; 16 + (1 << 24)]),
            Err(crate::Error::VerificationFailed)
        );
    }

    /// 全参数 API 的参数校验面（RFC 3610 §2 的合法/非法边界）。
    #[test]
    fn any_param_validation() {
        let key = [0x11u8; 16];
        // 非法 tag_len：奇数、<4、>16
        for bad in [2usize, 18, 9, 5, 0] {
            assert!(
                matches!(
                    Aes128CcmAny::new(&key, bad),
                    Err(crate::Error::InvalidInput)
                ),
                "tag_len {bad} must be rejected"
            );
        }
        // 全部 7 个合法 M 可构造
        for m in [4usize, 6, 8, 10, 12, 14, 16] {
            assert!(Aes128CcmAny::new(&key, m).is_ok(), "tag_len {m}");
        }

        let any = Aes128CcmAny::new(&key, 8).unwrap();
        // 非法 nonce 长度：6 / 14（L=1 为规范保留）
        for bad_nonce in [vec![0u8; 6], vec![0u8; 14]] {
            assert_eq!(
                any.seal(&bad_nonce, b"", b"pt"),
                Err(crate::Error::InvalidInput),
                "nonce len {} must be rejected",
                bad_nonce.len()
            );
            assert_eq!(
                any.open(&bad_nonce, b"", &[0u8; 24]),
                Err(crate::Error::InvalidInput),
                "nonce len {} must be rejected on open",
                bad_nonce.len()
            );
        }
        // 全 nonce 长度面 7..=13 往返一致
        for n in 7usize..=13 {
            let nonce = vec![0xa0u8; n];
            let sealed = any.seal(&nonce, b"aad", b"payload").unwrap();
            assert_eq!(sealed.len(), 7 + 8);
            assert_eq!(any.open(&nonce, b"aad", &sealed).unwrap(), b"payload");
        }
        // 过短 ct+tag（< M）在 open 上统一 VerificationFailed
        let nonce12 = [0u8; 12];
        assert_eq!(
            any.open(&nonce12, b"", &[0u8; 7]),
            Err(crate::Error::VerificationFailed)
        );
    }
}
