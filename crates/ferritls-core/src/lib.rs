//! # ferritls-core
//!
//! 纯 Rust 实现的密码学核心，为 [ferritls-rustls](https://docs.rs/ferritls-rustls)
//! （rustls `CryptoProvider` 适配层）提供全部密码原语。
//!
//! ## FIPS 140-3 模块边界
//!
//! 本 crate 是规划中提交 CMVP 验证的**模块边界**：所有算法在边界内用纯 Rust
//! 自研实现（无 C、无汇编、`#![forbid(unsafe_code)]`），依赖白名单仅
//! [`subtle`] 与 [`zeroize`]（M3 起增加 `getrandom` 作为边界外熵源输入）。
//! 任何新依赖都必须先更新 `docs/FIPS.md` 的白名单与审计依据（见 AGENTS.md
//! 硬性规则 2）。
//!
//! ## 模块地图
//!
//! | 模块 | 内容 | FIPS 批准状态 | 落地里程碑 |
//! |---|---|---|---|
//! | [`sha2`] | SHA-256/384/512 | 批准 | M1 |
//! | [`hmac`] / [`hkdf`] | HMAC、HKDF | 批准 | M1 |
//! | [`aes`] / [`gcm`] / [`ccm`] | AES、AES-GCM、AES-CCM | 批准 | M2 |
//! | [`chacha20poly1305`] | ChaCha20-Poly1305 | 非批准 | M2 |
//! | [`ecdh`] | X25519（非批准）、P-256/384（批准） | 混合 | M3 |
//! | [`sign`] | ECDSA、RSA、Ed25519（非批准） | 混合 | M4 |
//! | [`drbg`] / [`entropy`] | SP 800-90A CTR-DRBG、OS 熵 | 批准 | M5 |
//! | [`selftest`] | 上电自检（KAT） | 要求项 | M5 |
//! | [`der`] | 最小 DER/PKCS#8/SEC1 解析 | — | M4 |
//! | [`ct`] / [`policy`] / [`ops`] | 常数时间工具、批准策略、后端入口 | — | M0 |
//!
//! ## 骨架状态
//!
//! 当前为 M0 骨架：公开 API 形状已定型，函数体为 `todo!("Mx")`，对应的
//! NIST/RFC/Wycheproof 向量测试已预置在 `tests/` 并标记 `#[ignore = "Mx"]`。
//! 实现某个里程碑时：落地实现 → 与官方文档核对向量 → 移除 `#[ignore]` →
//! CI 全绿（流程见 AGENTS.md“测试体系”）。

#![forbid(unsafe_code)]
// 未来硬件加速后端（AES-NI/SHA 扩展）必然需要 unsafe；它们不得进入本 crate，
// 而是作为边界外的独立后端 crate 通过 ops 模块的 trait 挂接（见 ops 模块文档
// 与 docs/ARCHITECTURE.md），届时是否将后端纳入 FIPS 边界需重新评估。

pub mod aes;
pub mod ccm;
pub mod chacha20poly1305;
pub mod ct;
pub mod der;
pub mod drbg;
pub mod ecdh;
pub mod entropy;
mod fields;
pub mod gcm;
pub mod hkdf;
pub mod hmac;
pub mod ops;
pub mod policy;
pub mod selftest;
pub mod sha2;
pub mod sign;

pub use policy::Approval;

/// 边界内统一的错误类型。
///
/// 规则：攻击者可控输入（网络数据、证书、密钥文件）不得引发 panic，
/// 一切失败以本错误返回（AGENTS.md 硬性规则 5）。`non_exhaustive`：
/// 实现里程碑落地时允许追加变体。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 输入长度或格式不满足算法要求。
    InvalidInput,
    /// 密钥/IV/标签等验证失败（认证加密打开失败、签名验证失败等）。
    /// 比较必须常数时间，不得通过错误类型区分失败原因。
    VerificationFailed,
    /// 请求的算法或曲线在当前构建（批准模式）下不可用。
    Unsupported,
    /// 熵源失败（OS 随机数不可用）。
    EntropyFailed,
    /// DRBG 失败（健康测试不过、超出生成上限等）。
    RngError,
    /// 上电自检失败：模块处于错误状态，拒绝服务，直到重新初始化。
    SelfTestFailed(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "invalid input length or format"),
            Error::VerificationFailed => write!(f, "verification failed"),
            Error::Unsupported => write!(f, "algorithm unavailable in this build/mode"),
            Error::EntropyFailed => write!(f, "OS entropy source failed"),
            Error::RngError => write!(f, "DRBG failure"),
            Error::SelfTestFailed(which) => {
                write!(f, "power-up self-test failed: {which}")
            }
        }
    }
}

impl std::error::Error for Error {}
