//! RSA 与 DER 解析测试（M4）。
//!
//! RSA 向量：Wycheproof `rsa_signature_test.json`（PKCS#1 v1.5）与
//! `rsa_pss_signature_test.json`（2048/3072 位，含 invalid 分组）——
//! 文件较大，M4 时以 git-lfs 或裁剪子集形式引入 `tests/vectors/rsa/`。
//! DER 畸形输入：配合 cargo-fuzz 持续回归（fuzz 目标 M6 建立）。
//! 两者本文件先固化调用形态与必须满足的性质。

mod common;

use ferritls_core::der;

#[test]
#[ignore = "M4: 待实现 + Wycheproof 向量引入后启用"]
fn der_malformed_inputs_return_error_not_panic() {
    // 性质测试：任意截断/变长的 DER 输入必须返回 Err，绝不 panic。
    // 这里是一组代表性畸形样例；fuzz 目标建立后做全覆盖。
    let malformed: &[&[u8]] = &[
        b"",
        b"\x30",
        b"\x30\x03\x02\x01",         // 截断的 SEQUENCE
        b"\xff\xff\xff\xff",         // 非法 tag
        b"\x30\x80\x00\x00",         // indefinite length（不允许）
        &[0x30, 0x7f, 0x00],         // 声称长度远超输入
        b"\x30\x00\x30\x00\x30\x00", // 空嵌套结构
    ];
    for input in malformed {
        assert!(
            der::parse_pkcs8_private_key(input).is_err(),
            "malformed input must be rejected: {:?}",
            common::to_hex(input)
        );
    }
}

#[test]
#[ignore = "M4"]
fn rsa_pss_round_trip_and_tamper() {
    // 形态：解析 PKCS#8 → PSS 签名 → verify_pss 通过；篡改消息后失败。
    // 具体测试密钥与 Wycheproof 向量在 M4 引入后填充。
}
