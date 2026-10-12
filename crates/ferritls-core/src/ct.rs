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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_matches_and_length_mismatch() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abcdef", b"abcdef"));
        assert!(!ct_eq(b"abcdef", b"abcdeg"));
        // 同长度不同内容：每个字节位都要能区分
        for i in 0..6 {
            let mut b = *b"abcdef";
            b[i] ^= 1;
            assert!(!ct_eq(b"abcdef", &b), "bit flip at byte {i} must differ");
        }
        // 长度不等（长度非秘密，可短路）恒 false，包括空 vs 非空
        assert!(!ct_eq(b"", b"a"));
        assert!(!ct_eq(b"ab", b"abc"));
    }

    #[test]
    fn verify_tag_maps_to_verification_failed() {
        assert_eq!(verify_tag(b"tag-value-16byt", b"tag-value-16byt"), Ok(()));
        assert_eq!(
            verify_tag(b"tag-value-16byt", b"tag-value-16byz"),
            Err(crate::Error::VerificationFailed)
        );
        // 长度不等也归一到同一错误（AEAD open 的统一契约）
        assert_eq!(
            verify_tag(b"short", b"shorter"),
            Err(crate::Error::VerificationFailed)
        );
    }
}
