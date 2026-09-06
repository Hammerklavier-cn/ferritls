//! 常数时间工具与边界内标准 crate 的统一出口。
//!
//! 边界内所有“秘密影响控制流或内存访问”的操作必须经由本模块（或直接使用
//! [`subtle`]），禁止手写可能被优化器破坏的尝试（如 `if a == b`、逐字节短路
//! 比较）。见 AGENTS.md“安全注意事项”。

pub use subtle;
pub use zeroize;

use subtle::ConstantTimeEq;

/// 常数时间字节串相等比较。长度不同直接返回 `false`（长度本身不是秘密）。
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// 常数时间 MAC/标签验证：相等返回 `Ok(())`，否则 [`crate::Error::VerificationFailed`]。
pub fn verify_tag(computed: &[u8], received: &[u8]) -> Result<(), crate::Error> {
    if ct_eq(computed, received) {
        Ok(())
    } else {
        Err(crate::Error::VerificationFailed)
    }
}
