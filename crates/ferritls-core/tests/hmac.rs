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

/// 密钥长度边界矩阵（RFC 2104 §2 的三种密钥形态）：空密钥、恰短于
/// 块长、恰等块长、恰长于块长——三个实例（SHA-256 块长 64、
/// SHA-384/512 块长 128）逐一验证：一次性计算确定性、流式与一次性
/// 入口恒等（BLOCK_LEN 边界即 `new` 的补零/先哈希分岔点，身份性质
/// 钉死）、验证通过、标签翻转单字节失败。全程不得 panic。
#[test]
fn hmac_key_length_boundaries_all_instances() {
    use ferritls_core::hmac::{HmacSha256, HmacSha384, HmacSha512};
    use ferritls_core::sha2::{Sha256, Sha384, Sha512};

    macro_rules! boundary_matrix {
        ($mac:ident, $hash:ident, $name:expr) => {{
            let data = b"boundary matrix payload";
            let block = $mac::BLOCK_LEN;
            for key_len in [0usize, block - 1, block, block + 1] {
                let key = vec![0xaau8; key_len];
                let tag = $mac::one_shot(&key, data);

                // 确定性：两次一次性计算逐字节一致
                assert_eq!(
                    $mac::one_shot(&key, data),
                    tag,
                    "{} key len {key_len}: one_shot must be deterministic",
                    $name
                );

                // 流式 == 一次性（同一密钥两条入口恒等）
                let mut m = $mac::new(&key);
                m.update(data);
                assert_eq!(
                    m.finalize(),
                    tag,
                    "{} key len {key_len}: streaming must equal one_shot",
                    $name
                );

                // 正确标签验证通过
                let mut m = $mac::new(&key);
                m.update(data);
                assert!(
                    m.verify(&tag).is_ok(),
                    "{} key len {key_len}: correct tag must verify",
                    $name
                );

                // 翻转标签单字节必须失败（错误变体钉死）
                let mut flipped = tag;
                flipped[0] ^= 0x01;
                let mut m = $mac::new(&key);
                m.update(data);
                assert_eq!(
                    m.verify(&flipped),
                    Err(ferritls_core::Error::VerificationFailed),
                    "{} key len {key_len}: flipped tag must fail",
                    $name
                );
            }

            // 结构性质（RFC 2104：密钥长于块长先哈希再填充）——
            // BLOCK_LEN + 1 的 HMAC 必须等于以"哈希后的密钥"重入 HMAC
            let long_key = vec![0xaau8; block + 1];
            let hashed = $hash::one_shot(&long_key);
            assert_eq!(
                $mac::one_shot(&long_key, b"data"),
                $mac::one_shot(&hashed, b"data"),
                "{}: key longer than block must be hashed first",
                $name
            );
        }};
    }

    boundary_matrix!(HmacSha256, Sha256, "HmacSha256");
    boundary_matrix!(HmacSha384, Sha384, "HmacSha384");
    boundary_matrix!(HmacSha512, Sha512, "HmacSha512");
}
