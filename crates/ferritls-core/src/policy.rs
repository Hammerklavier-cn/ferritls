//! 批准策略：FIPS 140-3 下各算法的批准状态与批准模式门控。
//!
//! 依据 NIST SP 800-52r2（TLS 配置）与 FIPS 186-5 等：
//!
//! | 算法 | 状态 | 备注 |
//! |---|---|---|
//! | AES-128/256-GCM、AES-128-CCM | 批准 | TLS 1.3 批准套件 |
//! | SHA-256/384/512、HMAC、HKDF | 批准 | |
//! | ECDSA P-256/P-384、ECDH（同曲线） | 批准 | |
//! | RSA-PSS、RSA-PKCS#1 v1.5（SHA-256+） | 批准 | PKCS#1 仅限证书验证等遗留用途 |
//! | CTR-DRBG（SP 800-90A） | 批准 | FIPS 模式强制使用 |
//! | X25519（独立使用） | 非批准 | 仅可作为 ML-KEM 混合组件进入（M8+ 预研） |
//! | ChaCha20-Poly1305 | 非批准 | |
//! | Ed25519 | 非批准 | FIPS 186-5 不含 EdDSA |
//!
//! “非批准”不等于“移除”：它们继续在非批准模式（默认 provider）提供，
//! 但 [`crate::fips_mode_enabled`] 为真时不得进入套件清单，上电自检也不
//! 覆盖它们。

/// 单个算法/原语在 FIPS 140-3 下的批准状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Approval {
    /// FIPS 批准：可进入批准模式的套件清单，上电自检必须覆盖。
    Approved,
    /// 非批准：仅在非批准模式提供（X25519、ChaCha20-Poly1305、Ed25519）。
    NonApproved,
}

/// 当前构建是否处于批准模式（`fips` feature）。
///
/// 批准模式 = 仅批准算法 + 强制 CTR-DRBG + 上电自检路径。
/// 它**不是**“已通过 CMVP 认证”的声明；认证落地前 rustls 侧 `fips()`
/// 恒为 `false`（AGENTS.md 硬性规则 3/4）。
pub fn fips_mode_enabled() -> bool {
    cfg!(feature = "fips")
}
