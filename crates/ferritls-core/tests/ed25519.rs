//! Ed25519 向量测试（M4）。
//!
//! 来源：RFC 8032 §7.1 TEST 1/2。向量为人工录入——启用前必须与
//! RFC 原文核对。

mod common;

use common::assert_hex;
use ferritls_core::sign::ed25519;

#[test]
#[ignore = "M4: 待实现后启用（对照 RFC 8032 原文核对）"]
fn ed25519_rfc8032_test1_empty_message() {
    let seed = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let sk = ed25519::SigningKey::from_seed(seed);
    assert_hex(
        &sk.public_key(),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "TEST1 public key",
    );
    let sig = sk.sign(b"");
    assert_hex(
        &sig,
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
         fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "TEST1 signature",
    );
    assert!(ed25519::verify(&sk.public_key(), b"", &sig).is_ok());
    // 篡改消息必须验证失败。
    assert_eq!(
        ed25519::verify(&sk.public_key(), b"x", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

#[test]
#[ignore = "M4"]
fn ed25519_rfc8032_test2_one_byte_message() {
    let seed = [
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e,
        0x0f, 0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8,
        0xa6, 0xfb,
    ];
    let sk = ed25519::SigningKey::from_seed(seed);
    assert_hex(
        &sk.public_key(),
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "TEST2 public key",
    );
    assert_hex(
        &sk.sign(b"\x72"),
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "TEST2 signature",
    );
}
