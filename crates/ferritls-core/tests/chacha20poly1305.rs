//! ChaCha20-Poly1305 向量测试（M2）。
//!
//! 来源：RFC 8439 §2.8.2。向量为人工录入——启用前必须与 RFC 原文核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::chacha20poly1305::ChaCha20Poly1305;

#[test]
fn chacha20poly1305_rfc8439_2_8_2() {
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aad = hex("50515253c0c1c2c3c4c5c6c7");
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

    let expect_ct_and_tag = hex("d31a8d34648e60db7b86afbc53ef7ec2\
         a4aded51296e08fea9e2b5a736ee62d6\
         3dbea45e8ca9671282fafb69da92728b\
         1a71de0a9e060b2905d6a5b67ecd3b36\
         92ddbd7f2d778b8c9803aee328091b58\
         fab324e4fad675945585808b4831d7bc\
         3ff4def08e4b7a9de576d26586cec64b\
         6116\
         1ae10b594f09e26a7e902ecbd0600691");

    let aead = ChaCha20Poly1305::new(key.as_slice().try_into().unwrap());
    let out = aead.seal(nonce.as_slice().try_into().unwrap(), &aad, plaintext);
    assert_hex(
        &out,
        &common::to_hex(&expect_ct_and_tag),
        "RFC 8439 §2.8.2 CT||tag",
    );

    let rt = aead
        .open(nonce.as_slice().try_into().unwrap(), &aad, &out)
        .expect("round-trip");
    assert_eq!(rt.as_slice(), plaintext.as_slice());

    // 篡改密文首字节必须失败。
    let mut bad = out.clone();
    bad[0] ^= 1;
    assert_eq!(
        aead.open(nonce.as_slice().try_into().unwrap(), &aad, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

/// open() 鲁棒性（对齐 tests/aes_gcm.rs 的同名负用例，补齐本 AEAD
/// 缺失的负面路径）：密文+标签总长不足 16 字节（0/1/15）统一返回
/// `VerificationFailed`——标签域不足即视为认证失败，绝不 panic、
/// 绝不越界读。
#[test]
fn chacha20poly1305_rejects_short_ciphertext_and_tag() {
    let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = hex("070000004041424344454647");
    let aead = ChaCha20Poly1305::new(key.as_slice().try_into().unwrap());

    for n in [0usize, 1, 15] {
        assert_eq!(
            aead.open(nonce.as_slice().try_into().unwrap(), b"", &vec![0u8; n]),
            Err(ferritls_core::Error::VerificationFailed),
            "ct_and_tag len {n} must fail"
        );
    }
}
