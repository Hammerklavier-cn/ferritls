//! 测试共享工具（每个集成测试通过 `mod common;` 引入）。
//!
//! 仅测试基础设施代码——真正的密码学实现绝不出现在 tests/ 下。
//! 各测试文件只用其中一部分工具，统一豁免 dead_code。

#![allow(dead_code)]

/// 十六进制解码（忽略空白与换行，便于粘贴官方向量）。
pub fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(clean.len().is_multiple_of(2), "hex string has odd length");
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

/// 十六进制编码（失败输出与期望值 diff 用）。
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 断言实际字节等于期望的十六进制串，失败时打印两侧十六进制。
#[track_caller]
pub fn assert_hex(actual: &[u8], expected_hex: &str, what: &str) {
    let expected = hex(expected_hex);
    assert_eq!(
        to_hex(actual),
        to_hex(&expected),
        "{what} mismatch\n  actual:   {}\n  expected: {}",
        to_hex(actual),
        expected_hex
    );
}
