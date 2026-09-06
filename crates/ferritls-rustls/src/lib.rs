//! # ferritls-rustls
//!
//! 把 [`ferritls_core`] 的密码原语装配成 rustls 0.23 的
//! `rustls::crypto::CryptoProvider`。
//!
//! 本 crate 位于 FIPS 边界**之外**：它只做 trait 适配与套件装配，不含
//! 密码学实现。rustls 版本演进的冲击被隔离在这一层（AGENTS.md
//! “rustls 对接层速查”）。
//!
//! ## 用法（M6 落地后）
//!
//! ```no_run
//! let provider = ferritls_rustls::default_provider();
//! provider.install_default().expect("install provider");
//! // 之后 ClientConfig::builder() / ServerConfig::builder() 默认使用它。
//! ```
//!
//! ## fips() 语义（重要）
//!
//! ferritls **尚未**通过 CMVP 认证。因此本 provider 一切 `fips()` 钩子
//! 恒返回 `false`——`fips_mode_provider()` 提供的只是“批准算法运行模式”
//! （仅批准套件 + CTR-DRBG + 上电自检），不代表任何官方认证状态。
//! 认证落地后会在锁定的版本快照上引入独立的 `fips-validated` feature
//! 翻转该语义（见 docs/FIPS.md 阶段 C）。

#![forbid(unsafe_code)]

pub mod cipher;
pub mod kx;
pub mod provider;
pub mod random;
pub mod sign;
pub mod verify;

pub use provider::{default_provider, fips_mode_provider};
