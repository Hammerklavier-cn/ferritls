//! Ed25519 向量测试（M4）。
//!
//! 来源：RFC 8032 §7.1 TEST 1/2/3 与 TEST SHA(abc)。已于 2026-09-07
//! 与 RFC 原文逐字节核对。

mod common;

use common::assert_hex;
use ferritls_core::sign::ed25519;

#[test]
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

#[test]
fn ed25519_rfc8032_test3_two_byte_message() {
    let seed = [
        0xc5, 0xaa, 0x8d, 0xf4, 0x3f, 0x9f, 0x83, 0x7b, 0xed, 0xb7, 0x44, 0x2f, 0x31, 0xdc, 0xb7,
        0xb1, 0x66, 0xd3, 0x85, 0x35, 0x07, 0x6f, 0x09, 0x4b, 0x85, 0xce, 0x3a, 0x2e, 0x0b, 0x44,
        0x58, 0xf7,
    ];
    let sk = ed25519::SigningKey::from_seed(seed);
    assert_hex(
        &sk.public_key(),
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "TEST3 public key",
    );
    let sig = sk.sign(&[0xaf, 0x82]);
    assert_hex(
        &sig,
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
         18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "TEST3 signature",
    );
    assert!(ed25519::verify(&sk.public_key(), &[0xaf, 0x82], &sig).is_ok());
}

#[test]
fn ed25519_rfc8032_test_sha_abc() {
    // SHA-512("abc") 作为 64 字节消息
    let msg: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    let seed = [
        0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d, 0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91,
        0x1e, 0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b, 0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca,
        0x3d, 0x42,
    ];
    let sk = ed25519::SigningKey::from_seed(seed);
    assert_hex(
        &sk.public_key(),
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "SHA(abc) public key",
    );
    let sig = sk.sign(&msg);
    assert_hex(
        &sig,
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
         09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        "SHA(abc) signature",
    );
    assert!(ed25519::verify(&sk.public_key(), &msg, &sig).is_ok());
    // 篡改签名首字节必须失败（无效曲线点也应拒绝而非 panic）
    let mut bad = sig;
    bad[0] ^= 1;
    assert_eq!(
        ed25519::verify(&sk.public_key(), &msg, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}
