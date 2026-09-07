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

/// RFC 8032 §7.1 TEST 1024：1023 字节消息（SHA-512 两段式哈希路径）。
/// 消息/公钥/签名于 2026-09-07 从 RFC 原文提取；签名另经
/// python-cryptography 与 OpenSSL 3.2.4 两个独立实现复算一致。
#[test]
fn ed25519_rfc8032_test1024_large_message() {
    let seed = common::hex("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    let sk = ed25519::SigningKey::from_seed(seed.as_slice().try_into().unwrap());
    common::assert_hex(
        &sk.public_key(),
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "TEST1024 public key",
    );

    let msg = common::hex(concat!(
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb",
        "98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be",
        "84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b",
        "20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e2664",
        "0f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e",
        "82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100",
        "ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6",
        "ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1",
        "231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c",
        "53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8",
        "ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6e",
        "b6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187e",
        "bb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad5",
        "75f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf",
        "80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a",
        "569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b",
        "82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af896",
        "9be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf26",
        "8cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297",
        "d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda08",
        "47dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92",
        "b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b0",
        "1e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65",
        "040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f",
        "64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610",
        "b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc",
        "820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9",
        "cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6",
        "b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334b",
        "a77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef13695",
        "46868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2",
        "eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c",
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
    ));
    assert_eq!(msg.len(), 1023, "TEST1024 message length");

    // 确定性签名必须与 RFC 官方签名逐字节一致
    let sig = sk.sign(&msg);
    common::assert_hex(
        &sig,
        concat!(
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec3",
            "50aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a18",
            "8a03"
        ),
        "TEST1024 signature",
    );

    // 验证方向：官方签名对官方公钥/消息必须通过
    let pk = common::hex("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    let sig_bytes = common::hex(concat!(
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec3",
        "50aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a18",
        "8a03"
    ));
    ed25519::verify(&pk, &msg, &sig_bytes).expect("TEST1024 official signature verifies");
}
