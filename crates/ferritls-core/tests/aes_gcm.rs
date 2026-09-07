//! AES-GCM 向量测试（M2）。
//!
//! 来源：McGrew–Viega GCM 测试样例（TC1 / TC5 / TC16），期望值已与
//! OpenSSL（RFC 5116 口径）逐字节核对。
//!
//! 注意：TC1 = 全零密钥/IV/空明文（tag = 58e2fcce…）；TC5 = 128 位密钥
//! + 64B 明文 + AAD；TC16 = 256 位密钥 + 64B 明文 + AAD。

mod common;

use common::{assert_hex, hex};
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

#[test]
fn aes128_gcm_tc1_zero_everything() {
    let aead = Aes128Gcm::new(&[0u8; 16]);
    let out = aead.seal(&[0u8; 12], b"", b"");
    assert_eq!(out.len(), 16, "empty PT → tag only");
    assert_hex(&out, "58e2fccefa7e3061367f1d57a4e7455a", "TC1 tag");

    let pt = aead.open(&[0u8; 12], b"", &out).expect("TC1 round-trip");
    assert!(pt.is_empty());
}

#[test]
fn aes128_gcm_tc5_64b_pt_with_aad() {
    let key = hex("feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex("d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255");

    let aead = Aes128Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, &pt);
    assert_hex(
        &out,
        "42831ec2217774244b7221b784d0d49c\
         e3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa05\
         1ba30b396a0aac973d58e091473f5985\
         da80ce830cfda02da2a218a1744f4c76",
        "TC5 CT||tag",
    );

    let rt = aead
        .open(nonce.as_slice().try_into().unwrap(), &aad, &out)
        .expect("TC5 round-trip");
    assert_eq!(rt, pt);
}

#[test]
fn aes256_gcm_tc16_with_aad() {
    let key = hex("feffe9928665731c6d6a8f9467308308\
         feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex("d9313225f88406e5a55909c5aff5269a\
         86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525\
         b16aedf5aa0de657ba637b391aafd255");

    let aead = Aes256Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, &pt);
    assert_hex(
        &out,
        "522dc1f099567d07f47f37a32a84427d\
         643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838\
         c5f61e6393ba7a0abcc9f662898015ad\
         2df7cd675b4f09163b41ebf980a7f638",
        "TC16 CT||tag",
    );

    let rt = aead
        .open(nonce.as_slice().try_into().unwrap(), &aad, &out)
        .expect("TC16 round-trip");
    assert_eq!(rt, pt);
}

#[test]
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

    // 多块消息（跨 16 字节边界）往返。
    let big: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let sealed = aead.seal(nonce.as_slice().try_into().unwrap(), b"multi", &big);
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), b"multi", &sealed)
            .expect("multi round-trip"),
        big
    );
}
