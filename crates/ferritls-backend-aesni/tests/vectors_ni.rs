//! Ni 路径的向量锚定测试（经 install + core 公开 API）。
//!
//! 本二进制安装后端后，用与 `ferritls-core` 向量测试**完全相同**的
//! McGrew–Viega 用例（TC1/TC5/TC16，期望值已与 OpenSSL 核对，
//! 见 docs/VECTOR-PROVENANCE.md）驱动 AES-NI/CLMUL 路径。CPU 不支持
//! 时 install 返回 Err，测试打印后跳过（CI x86_64 runner 均支持）。
//!
//! 注意：安装是进程级的——本二进制只含 Ni 路径测试；软件默认路径的
//! 同一批向量在 ferritls-core 的测试里独立运行。

mod common;

use common::{assert_hex, hex};
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

fn setup() -> bool {
    match ferritls_backend_aesni::install() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("backend unavailable ({e:?}); skipping Ni vector tests");
            false
        }
    }
}

/// TC1：全零密钥/nonce、空明文（tag-only）。
#[test]
fn ni_tc1_zero_everything() {
    if !setup() {
        return;
    }
    let aead = Aes128Gcm::new(&[0u8; 16]);
    let out = aead.seal(&[0u8; 12], b"", b"");
    assert_eq!(out.len(), 16);
    assert_hex(&out, "58e2fccefa7e3061367f1d57a4e7455a", "TC1 tag");
    assert!(aead.open(&[0u8; 12], b"", &out).unwrap().is_empty());
}

/// TC5：AES-128 + 64B 明文 + AAD。
#[test]
fn ni_tc5_64b_pt_with_aad() {
    if !setup() {
        return;
    }
    let key = hex("feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );

    let aead = Aes128Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, &pt);
    assert_hex(
        &out,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
         21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985\
         da80ce830cfda02da2a218a1744f4c76",
        "TC5 CT||tag",
    );
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), &aad, &out)
            .unwrap(),
        pt
    );
}

/// TC16：AES-256 + 64B 明文 + AAD。
#[test]
fn ni_tc16_with_aad() {
    if !setup() {
        return;
    }
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let pt = hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
         1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
    );

    let aead = Aes256Gcm::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, &pt);
    assert_hex(
        &out,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
         8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad\
         2df7cd675b4f09163b41ebf980a7f638",
        "TC16 CT||tag",
    );
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), &aad, &out)
            .unwrap(),
        pt
    );
}

/// 多块 AAD + 空明文（GHASH 只有 AAD 与长度块参与）。
#[test]
fn ni_multiblock_aad_empty_pt() {
    if !setup() {
        return;
    }
    let aead = Aes128Gcm::new(&[0u8; 16]);
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2\
         100102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021");
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, b"");
    assert_hex(&out, "2FE6C9F5C23512EA771966152C211971", "multiblock AAD");
}

/// 跨块明文往返 + 密封性负例（密文/标签/AAD/nonce 篡改全失败）。
#[test]
fn ni_roundtrip_and_tamper_negatives() {
    if !setup() {
        return;
    }
    let key = hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let nonce = hex("cafebabefacedbaddecaf888");
    let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let aead = Aes256Gcm::new(key.as_slice().try_into().unwrap());

    let big: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
    let sealed = aead.seal(nonce.as_slice().try_into().unwrap(), b"multi", &big);
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), b"multi", &sealed)
            .unwrap(),
        big
    );

    for pos in [0usize, 1, 16, 17, 999, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x80;
        assert_eq!(
            aead.open(nonce.as_slice().try_into().unwrap(), b"multi", &bad),
            Err(ferritls_core::Error::VerificationFailed),
            "flip byte {pos}"
        );
    }
    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 0x01;
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), &bad_aad, &sealed),
        Err(ferritls_core::Error::VerificationFailed),
        "AAD tamper"
    );
    let mut wrong_nonce = nonce.clone();
    wrong_nonce[0] ^= 0x01;
    assert_eq!(
        aead.open(
            wrong_nonce.as_slice().try_into().unwrap(),
            b"multi",
            &sealed
        ),
        Err(ferritls_core::Error::VerificationFailed),
        "wrong nonce"
    );
    // 过短输入统一失败。
    for n in [0usize, 1, 15] {
        assert_eq!(
            aead.open(nonce.as_slice().try_into().unwrap(), b"", &vec![0u8; n]),
            Err(ferritls_core::Error::VerificationFailed)
        );
    }
}

/// Clone 的实例与原实例行为一致（clone_box 路径）。
#[test]
fn ni_clone_consistency() {
    if !setup() {
        return;
    }
    let aead = Aes128Gcm::new(&[0x42; 16]);
    let sealed = aead.seal(&[1u8; 12], b"aad", b"payload payload payload");
    let cloned = aead.clone();
    assert_eq!(
        cloned.open(&[1u8; 12], b"aad", &sealed).unwrap(),
        b"payload payload payload"
    );
    assert_eq!(
        aead.seal(&[1u8; 12], b"aad", b"payload payload payload"),
        sealed
    );
}
