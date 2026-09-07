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

/// RFC 4231 Test Case 6/7：131 字节密钥（超过 SHA-256 块长 64 与
/// SHA-384/512 块长 128，必须先哈希密钥再填充）。期望值与 RFC 4231
/// 原文逐字节核对（摘要折行片段均与计算值精确匹配），并经
/// `openssl dgst -mac hmac` 独立复算一致（2026-09-07）。
mod rfc4231_large_keys {
    use crate::common::assert_hex;
    use ferritls_core::hmac::{HmacSha256, HmacSha384, HmacSha512};

    const KEY131: [u8; 131] = [0xaa; 131];

    #[test]
    fn hmac_tc6_larger_than_block_key_sha256() {
        assert_hex(
            &HmacSha256::one_shot(
                &KEY131,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            ),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            "RFC 4231 TC6 SHA-256",
        );
    }

    #[test]
    fn hmac_tc6_larger_than_block_key_sha384() {
        assert_hex(
            &HmacSha384::one_shot(
                &KEY131,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            ),
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
            "RFC 4231 TC6 SHA-384",
        );
    }

    #[test]
    fn hmac_tc6_larger_than_block_key_sha512() {
        assert_hex(
            &HmacSha512::one_shot(
                &KEY131,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
            ),
            "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            "RFC 4231 TC6 SHA-512",
        );
    }

    #[test]
    fn hmac_tc7_larger_than_block_key_sha256() {
        assert_hex(
            &HmacSha256::one_shot(&KEY131, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            "RFC 4231 TC7 SHA-256",
        );
    }

    #[test]
    fn hmac_tc7_larger_than_block_key_sha384() {
        assert_hex(
            &HmacSha384::one_shot(&KEY131, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
            "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
            "RFC 4231 TC7 SHA-384",
        );
    }

    #[test]
    fn hmac_tc7_larger_than_block_key_sha512() {
        assert_hex(
            &HmacSha512::one_shot(&KEY131, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
            "RFC 4231 TC7 SHA-512",
        );
    }
}

/// verify 路径：错误长度标签必须失败（不得 panic、不得意外通过），
/// 正确标签通过；翻转任一比特失败。
#[test]
fn hmac_verify_rejects_wrong_length_and_wrong_tag() {
    use ferritls_core::hmac::HmacSha256;
    let key = [0x0bu8; 20];
    let tag = HmacSha256::one_shot(&key, b"Hi There");

    // 正确标签必须通过
    let mut m = HmacSha256::new(&key);
    m.update(b"Hi There");
    assert!(m.verify(&tag).is_ok(), "correct tag must verify");

    // 错误长度：过短一律失败，绝不 panic
    for bad_len in [0usize, 1, 16, 31] {
        let mut m = HmacSha256::new(&key);
        m.update(b"Hi There");
        assert!(
            m.verify(&tag[..bad_len]).is_err(),
            "tag len {bad_len} must fail"
        );
    }
    // 过长同样失败（33/64 字节候选标签）
    for long_len in [33usize, 64] {
        let mut long = vec![0u8; long_len];
        long[..32].copy_from_slice(&tag);
        let mut m = HmacSha256::new(&key);
        m.update(b"Hi There");
        assert!(m.verify(&long).is_err(), "tag len {long_len} must fail");
    }

    // 翻转任一字节失败（首/中/尾）
    for i in [0usize, 15, 31] {
        let mut flipped = tag;
        flipped[i] ^= 0x01;
        let mut m = HmacSha256::new(&key);
        m.update(b"Hi There");
        assert!(m.verify(&flipped).is_err(), "flip byte {i} must fail");
    }
}
