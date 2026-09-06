//! HKDF-SHA-256 向量测试（M1）。
//!
//! 来源：RFC 5869 Test Cases 1–3。
//! 向量为人工录入——启用前必须与 RFC 5869 原文核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::hkdf::{expand_sha256, extract_sha256};

#[test]
#[ignore = "M1: 待 HKDF 实现后启用（对照 RFC 5869 原文核对）"]
fn hkdf_sha256_rfc5869_tc1() {
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = extract_sha256(&salt, &ikm);
    assert_hex(
        &prk,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "TC1 PRK",
    );

    let mut okm = [0u8; 42];
    expand_sha256(&prk, &info, &mut okm);
    assert_hex(
        &okm,
        "3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
        "TC1 OKM",
    );
}

#[test]
#[ignore = "M1"]
fn hkdf_sha256_rfc5869_tc2_long_inputs() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();

    let prk = extract_sha256(&salt, &ikm);
    assert_hex(
        &prk,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "TC2 PRK",
    );

    let mut okm = [0u8; 82];
    expand_sha256(&prk, &info, &mut okm);
    assert_hex(
        &okm,
        "b11e398dc80327a1c8e7f78c596a4934\
         4f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09\
         da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f\
         1d87",
        "TC2 OKM",
    );
}

#[test]
#[ignore = "M1"]
fn hkdf_sha256_rfc5869_tc3_empty_salt_info() {
    let ikm = [0x0bu8; 22];
    let prk = extract_sha256(&[], &ikm);
    assert_hex(
        &prk,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "TC3 PRK",
    );

    let mut okm = [0u8; 42];
    expand_sha256(&prk, &[], &mut okm);
    assert_hex(
        &okm,
        "8da4e775a563c18f715f802a063c5a31\
         b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8",
        "TC3 OKM",
    );
}
