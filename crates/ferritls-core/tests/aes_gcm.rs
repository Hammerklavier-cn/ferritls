//! AES-GCM 向量测试（M2）。
//!
//! 来源：McGrew–Viega GCM 规范测试样例 TC5 / TC16（NIST CAVP GCMVS
//! 的前身样例，RustCrypto aes-gcm 亦采用）。
//! 向量为人工录入——启用前必须与官方文件核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

#[test]
#[ignore = "M2: 待 AES-GCM 实现后启用（对照 GCMVS/规范原文核对）"]
fn aes128_gcm_tc5_empty_plaintext() {
    let key = hex("feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aead = Aes128Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), b"", b"");
    assert_eq!(out.len(), 16, "empty PT → tag only");
    assert_hex(&out, "58e2fccefa7e3061367f1d57a4e7455a", "TC5 tag");

    let pt = aead
        .open(nonce.as_slice().try_into().unwrap(), b"", &out)
        .expect("TC5 round-trip");
    assert!(pt.is_empty());
}

#[test]
#[ignore = "M2"]
fn aes256_gcm_tc16_with_aad() {
    let key = hex("feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex("d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255");
    let expect_ct_and_tag = hex("522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662898015ad\
         b094dac5d93471bdec1a502270e3cc6c");

    let aead = Aes256Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, &pt);
    assert_hex(&out, &common::to_hex(&expect_ct_and_tag), "TC16 CT||tag");

    let rt = aead
        .open(nonce.as_slice().try_into().unwrap(), &aad, &out)
        .expect("TC16 round-trip");
    assert_hex(&rt, &common::to_hex(&pt), "TC16 PT");
}

#[test]
#[ignore = "M2: 篡改密文/AAD/nonce 任一必须验证失败"]
fn aes_gcm_tamper_rejected() {
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aead = Aes256Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), b"", b"hello, gcm!");

    let mut bad = out.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), b"", &bad),
        Err(ferritls_core::Error::VerificationFailed),
        "flipped tag bit must fail"
    );

    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), b"x", &out),
        Err(ferritls_core::Error::VerificationFailed),
        "wrong AAD must fail"
    );
}

// M2 扩展：引入完整 NIST CAVP GCMVS 向量集（含非 96 位 nonce、不同标签
// 长度的拒绝用例）到 tests/vectors/。
