//! 测试共享工具（与 ferritls-core tests/common 同款，仅测试基础设施）。

#![allow(dead_code)]

/// 十六进制解码（忽略空白与换行）。
pub fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex digit"))
        .collect()
}

/// 十六进制编码。
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 断言实际字节等于期望十六进制串。
#[track_caller]
pub fn assert_hex(actual: &[u8], expected_hex: &str, what: &str) {
    let expected = hex(expected_hex);
    assert_eq!(
        to_hex(actual),
        to_hex(&expected),
        "{what} mismatch\n  actual:   {}\n  expected: {expected_hex}",
        to_hex(actual)
    );
}
