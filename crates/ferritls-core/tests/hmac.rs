//! HMAC-SHA-256 向量测试（M1）。
//!
//! 来源：RFC 4231 Test Cases 1–3（SHA-256 族）。
//! 向量为人工录入——启用前必须与 RFC 4231 原文核对。

mod common;

use common::assert_hex;
use ferritls_core::hmac::HmacSha256;

#[test]
fn hmac_sha256_rfc4231() {
    // Test Case 1: key = 0x0b × 20, data = "Hi There"
    let key = [0x0bu8; 20];
    let tag = HmacSha256::one_shot(&key, b"Hi There");
    assert_hex(
        &tag,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "RFC 4231 TC1",
    );

    // Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
    let tag = HmacSha256::one_shot(b"Jefe", b"what do ya want for nothing?");
    assert_hex(
        &tag,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "RFC 4231 TC2",
    );

    // Test Case 3: key = 0xaa × 20, data = 0xdd × 50
    let key = [0xaau8; 20];
    let data = [0xddu8; 50];
    let tag = HmacSha256::one_shot(&key, &data);
    assert_hex(
        &tag,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "RFC 4231 TC3",
    );
}

#[test]
fn hmac_verify_and_tamper() {
    let key = [0x0bu8; 20];
    let mut m = HmacSha256::new(&key);
    m.update(b"Hi There");
    let tag = m.finalize();
    let mut m = HmacSha256::new(&key);
    m.update(b"Hi There");
    assert!(m.verify(&tag).is_ok());

    let mut bad = tag;
    bad[0] ^= 1;
    let mut m = HmacSha256::new(&key);
    m.update(b"Hi There");
    assert_eq!(
        m.verify(&bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

// M1 扩展：RFC 4231 TC4–TC7（>块长密钥、>128B 数据）与 SHA-384 族
// （HmacSha384 的向量在 TC 对应小节）。
