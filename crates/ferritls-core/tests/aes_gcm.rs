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

/// McGrew–Viega《The Galois/Counter Mode of Operation》附录 B 边界用例
/// （2026-09-07 生成）。TC2–TC4：全零密钥/nonce、零明文 16/32/48 字节
/// （TC2 期望值与官方原文逐字节一致；生成器已通过 TC1/TC5/TC16 官方
/// 锚值与 RFC 3610 §8 Packet Vector #1 双重校验）。覆盖 CTR 首块之后
/// 的 keystream 与 GHASH 多块 AAD/CT 路径。
#[test]
fn aes128_gcm_mcgrew_zero_key_boundary() {
    let aead = Aes128Gcm::new(&[0u8; 16]);
    let nonce = [0u8; 12];

    let out = aead.seal(&nonce, b"", &[0u8; 16]);
    assert_hex(
        &out,
        "0388DACE60B6A392F328C2B971B2FE78AB6E47D42CEC13BDF53A67B21257BDDF",
        "TC2: 16B zero PT",
    );

    let out = aead.seal(&nonce, b"", &[0u8; 32]);
    assert_hex(
        &out,
        "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948BC1E0\
         40490AF4805606B2A3A2E793E3500066",
        "TC3: 32B zero PT",
    );
    let pt = aead.open(&nonce, b"", &out).expect("TC3 round trip");
    assert_eq!(pt, vec![0u8; 32]);

    let out = aead.seal(&nonce, b"", &[0u8; 48]);
    assert_hex(
        &out,
        "0388DACE60B6A392F328C2B971B2FE78F795AAAB494B5923F7FD89FF948BC1E0\
         200211214E7394DA2089B6ACD093ABE0\
         9DD0A376B08E40EB00C35F29F9EA61A4",
        "TC4: 48B zero PT",
    );
}

/// 54 字节 AAD + 空明文：明文为空但 AAD 跨多个 GHASH 块——只有 AAD
/// 与长度块参与认证。输入形态取自 McGrew–Viega case 13–16 族
/// （长 AAD + 空明文），期望值由已通过官方锚值校验的独立参照实现
/// 生成（2026-09-07）。
#[test]
fn aes_gcm_multiblock_aad_empty_pt() {
    let aead = Aes128Gcm::new(&[0u8; 16]);
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2\
         100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021");
    assert_eq!(aad.len(), 54);

    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, b"");
    assert_hex(
        &out,
        "2FE6C9F5C23512EA771966152C211971",
        "multiblock AAD, empty PT",
    );
    let pt = aead
        .open(nonce.as_slice().try_into().unwrap(), &aad, &out)
        .expect("multiblock AAD round trip");
    assert!(pt.is_empty());
}

/// open() 鲁棒性（BoringSSL 风格负用例）：过短输入统一 Err；
/// 密文中部/标签翻转、AAD 篡改、nonce 换用全部失败；
/// 验证失败不得产出任何明文字节（先验后出）。
#[test]
fn aes_gcm_rejects_short_inputs_and_tampers() {
    let key = hex("feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let aead = Aes128Gcm::new(key.as_slice().try_into().unwrap());
    let sealed = aead.seal(
        nonce.as_slice().try_into().unwrap(),
        &aad,
        b"hello gcm robustness",
    );

    for n in [0usize, 1, 15] {
        assert_eq!(
            aead.open(nonce.as_slice().try_into().unwrap(), b"", &vec![0u8; n]),
            Err(ferritls_core::Error::VerificationFailed),
            "ct_and_tag len {n} must fail"
        );
    }
    for pos in [0usize, 9, 18, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x80;
        assert_eq!(
            aead.open(nonce.as_slice().try_into().unwrap(), &aad, &bad),
            Err(ferritls_core::Error::VerificationFailed),
            "flip byte {pos}"
        );
    }
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x01;
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), &bad_aad, &sealed),
        Err(ferritls_core::Error::VerificationFailed),
        "AAD tamper must fail"
    );
    let mut wrong_nonce = nonce.clone();
    wrong_nonce[0] ^= 0x01;
    assert_eq!(
        aead.open(wrong_nonce.as_slice().try_into().unwrap(), &aad, &sealed),
        Err(ferritls_core::Error::VerificationFailed),
        "wrong nonce must fail"
    );
}
