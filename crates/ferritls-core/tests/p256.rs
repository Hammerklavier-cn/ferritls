//! P-256 向量测试（M3 ECDH / M4 ECDSA）。
//!
//! ECDSA 验证方向来源：RFC 6979 附录 A.2.5（P-256/SHA-256，“sample”）。
//! ECDH 方向：M3 时引入 Wycheproof `ecdh_secp256r1_test.json`。
//! 向量为人工录入——启用前必须与官方文档核对。

mod common;

use common::hex;
use ferritls_core::ecdh::p256;

#[test]
#[ignore = "M3: 待实现后启用（Wycheproof JSON 向量一并引入）"]
fn p256_ecdh_round_trip() {
    let a = p256::SecretKey::generate().expect("generate A");
    let b = p256::SecretKey::generate().expect("generate B");
    let ss_a = a.diffie_hellman(&b.public_key()).expect("A completes");
    let ss_b = b.diffie_hellman(&a.public_key()).expect("B completes");
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    // 非法对端公钥（点不在曲线上）必须被拒绝——具体向量 M3 从
    // Wycheproof “invalid” 分组引入。
}

#[test]
#[ignore = "M4: 待实现后启用（对照 RFC 6979 A.2.5 原文核对）"]
fn p256_ecdsa_verify_rfc6979_sample() {
    // 公钥 Q（未压缩 SEC1）与消息 "sample" 的有效签名 (r, s)。
    let public_sec1 = [
        // 0x04 || Qx || Qy
        0x04, // Qx
        0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35, 0x6d,
        0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60, 0xf2,
        0x9f, 0xb6, // Qy
        0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9, 0x56, 0x28, 0xbc,
        0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2, 0x94, 0xd4, 0x46,
        0x22, 0x99,
    ];
    // DER: SEQUENCE { r INTEGER, s INTEGER }（由下方 r/s 构造，M4 实现时
    // 可先用签名 API 自产再对照 RFC 数值断言 r、s 分量）。
    let r = hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716");
    let s = hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8");

    // 结构占位：M4 实现签名自测后，用 RFC 6979 的确定性签名断言 r/s，
    // 并用 verify_p256_sha256 完成验证方向的断言（需要 DER 编码工具，
    // 实现时在此文件内补充最小 DER SEQUENCE 构造）。
    let _ = (public_sec1, r, s);
}

// M4 扩展：RFC 6979 A.2.5 全部消息（"sample"/"test" 及 SHA-224/256/384/512
// 变体）+ Wycheproof ecdsa_secp256r1_test.json（含 invalid 分组）。
