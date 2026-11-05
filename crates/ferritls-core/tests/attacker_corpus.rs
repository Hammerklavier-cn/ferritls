//! 攻击者语料回归测试（2026-11 测试完备性轮）。
//!
//! **来源与许可**（完整记录见 docs/VECTOR-PROVENANCE.md）：
//! - `tests/vectors/d2i/`：OpenSSL master `test/d2i-tests/` 的 10 个
//!   坏 DER 回归文件（Apache-2.0；CVE-2016-2108/2109/7053 等历史
//!   缺陷的官方回归锚 + 非最小 INTEGER 填充 ×2 符号 + 高 tag 号）。
//! - `tests/vectors/corpus/`：BoringSSL master `fuzz/{pkcs8,privkey,
//!   spki,cert,der_roundtrip}_corpus` 的精选 31 文件（ISC License /
//!   OpenSSL dual；LibFuzzer 演化出的解析器对抗语料）。
//!
//! 断言两层：
//! 1. **逐文件结果钉住**——每个语料文件的 PKCS#8 / RSA-SPKI 解析
//!    结果（Ok/Err）与采集时刻一致（防"静默从拒绝变接受"回归）；
//! 2. **全解析面 no-panic**——每个文件喂给全部解析/验证入口
//!    （DER 原语、PKCS#8、SPKI、裸 RSA、EC 点、Ed25519、ECDH 对端、
//!    三个 AEAD open），Err 或 Ok 皆可、panic 即失败（AGENTS.md
//!    硬性规则 4）。
//!
//! BoringSSL 全量语料（438 文件）的一次性烟测已完成（2026-11-05，
//! 零 panic）；此处入库的是精选回归子集。

mod common;

use ferritls_core::{ccm, chacha20poly1305, der, ecdh, gcm, sign};

/// 全解析面 no-panic 驱动：任何入口 panic 即测试失败。
fn feed_everything(bytes: &[u8]) {
    let _ = der::parse_pkcs8_private_key(bytes);
    let _ = der::read_tlv(bytes);
    let _ = der::integer(bytes);
    let _ = sign::rsa::VerifyKey::from_spki_der(bytes);
    let _ = sign::rsa::VerifyKey::from_rsapublickey_der(bytes);
    let _ = sign::ecdsa::p256::VerifyKey::from_sec1_point(bytes);
    let _ = sign::ecdsa::p384::VerifyKey::from_sec1_point(bytes);
    let _ = sign::ed25519::VerifyKey::from_raw_bytes(bytes);
    let _ = ecdh::p256::SecretKey::from_seed([0u8; 32]).diffie_hellman(bytes);
    let g = gcm::Aes128Gcm::new(&[0u8; 16]);
    let _ = g.open(&[0u8; 12], b"", bytes);
    let c = chacha20poly1305::ChaCha20Poly1305::new(&[0u8; 32]);
    let _ = c.open(&[0u8; 12], b"", bytes);
    let any = ccm::Aes128CcmAny::new(&[0u8; 16], 16).unwrap();
    let _ = any.open(&[0u8; 12], b"", bytes);
}

/// d2i 语料：`der::integer` 的钉住结果（合法/非法 INTEGER）。
const D2I_INTEGER_REJECTED: &[&str] = &[
    "bad-int-pad0.der",      // 非最小前导 0x00（正数）
    "bad-int-padminus1.der", // 非最小 0xFF 填充（负数）
    "intminus1.der",         // 负 INTEGER（高位 bit）——本实现按无符号解释并拒绝
    "high_tag.der",          // 高 tag 号形式（CVE-2016-2108 回归）
    "bad_bio.der",
    "bad_cert.der", // CVE-2016-2109 回归
    "bad-cms.der",
    "bad_generalname.der",
];

/// corpus 语料的逐文件钉住表：(文件名, pkcs8_ok, spki_ok)。
/// 采集：BoringSSL master 语料 2026-11-05，与本实现的解析器快照一致。
const CORPUS_PINNED: &[(&str, bool, bool)] = &[
    // pkcs8_corpus：3 个合法密钥（RSA/EC 族）+ 12 个变异体
    (
        "pkcs8_129ebe4bf8b167a37741c9c470fd7c4a0359ad63",
        true,
        false,
    ),
    (
        "pkcs8_3f7e0b4378403f44de34874789bce582790a1348",
        true,
        false,
    ),
    (
        "pkcs8_89db3807a0d30e36007b74c8ee4aac912fe3fd75",
        true,
        false,
    ),
    (
        "pkcs8_1bf03b5d9f129cd80513b820a55c9568eb1d350b",
        false,
        false,
    ),
    (
        "pkcs8_225df81ad5fc9783575b57e20207645e55a8fa3f",
        false,
        false,
    ),
    (
        "pkcs8_3033b336d833baef80981f40394c281c20677f53",
        false,
        false,
    ),
    (
        "pkcs8_31aa87887801ac3f6eaab0bade714e56fcb5fab7",
        false,
        false,
    ),
    (
        "pkcs8_40d5a9f71cacb2389b58a8a24cfa52d6b51bf046",
        false,
        false,
    ),
    (
        "pkcs8_57e8e625f2f2313f2ec174a3209972e9bc5125ab",
        false,
        false,
    ),
    (
        "pkcs8_d38e79992de4ffaf585a6450ba2e6f21188fdd08",
        false,
        false,
    ),
    (
        "pkcs8_d9206dbdd26c06ee8de4e587553e72b3bb22d36b",
        false,
        false,
    ),
    (
        "pkcs8_e0a0b34deb64510a36919a13258bd2c8725e41fe",
        false,
        false,
    ),
    (
        "pkcs8_e5cfb9f3e23eda47731b1cf3414df1bd408179b7",
        false,
        false,
    ),
    (
        "pkcs8_efb2c016e9375355e04a5d99e2a17415c9d4f648",
        false,
        false,
    ),
    (
        "pkcs8_fc0fad9f9fb142dee99a03a50a64d10767f9f18e",
        false,
        false,
    ),
    // privkey_corpus
    (
        "privkey_corpus_00c42569d947a510cf9797c6f57e072aa0ca5bb3",
        false,
        false,
    ),
    (
        "privkey_corpus_040e09a6e89086dfd9260699f1dd27f1ac8fc608",
        false,
        false,
    ),
    (
        "privkey_corpus_05a573fb3bb39c31923a303fc2792e72eff61cc4",
        false,
        false,
    ),
    (
        "privkey_corpus_09db9192b630c602121231a0de852de7888af92f",
        false,
        false,
    ),
    // spki_corpus
    (
        "spki_corpus_04f58baf6e4bba0bb3094e2e26d3a531a7c263ee",
        false,
        false,
    ),
    (
        "spki_corpus_079bdf85c086ad0a92bd01f1f70c645d81053f3a",
        false,
        false,
    ),
    (
        "spki_corpus_0f5bd094b20a4632f14903bf62db8d467d2c548f",
        false,
        false,
    ),
    (
        "spki_corpus_183c579d75863c1e10100f76e3ffb757b44a9587",
        false,
        false,
    ),
    // der_roundtrip_corpus（原始 ASN.1 结构碎片）
    (
        "der_roundtrip_corpus_0461791e54b4840c109637952eab43d9b938cab8",
        false,
        false,
    ),
    (
        "der_roundtrip_corpus_06e57a7b98a403a00822739739924b97ae6c74e9",
        false,
        false,
    ),
    (
        "der_roundtrip_corpus_078c3c1199930781466871c8dda69bec379286a4",
        false,
        false,
    ),
    (
        "der_roundtrip_corpus_082a991742f652549e4b207100ee521f474e0a99",
        false,
        false,
    ),
    // cert_corpus（X.509 结构——本实现的密钥解析器一律拒绝）
    (
        "cert_corpus_01f0bc1bd4b94f8f8c0867d289ec8a4b3c8905fe",
        false,
        false,
    ),
    (
        "cert_corpus_031c5183d8c8c560e8e1818ff82aabf33973f770",
        false,
        false,
    ),
    (
        "cert_corpus_047746a08d38a07ce30952f8992e47e6f9c42c02",
        false,
        false,
    ),
    (
        "cert_corpus_07802918a9947a2b9b3db9e93b92acaa04010a65",
        false,
        false,
    ),
];

fn read_fixture(dir: &str, name: &str) -> Vec<u8> {
    let path =
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors").to_string() + "/" + dir + "/" + name;
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn openssl_d2i_fixtures_pinned() {
    // 合法 INTEGER 锚（int0/int1：解析 Ok 且内容/尾随钉住）。
    let bytes = read_fixture("d2i", "int0.der");
    let (v, rest) = der::integer(&bytes).expect("int0");
    assert_eq!(v, [0u8], "int0 value");
    assert_eq!(rest.len(), 0, "int0 no trailing");
    let bytes = read_fixture("d2i", "int1.der");
    let (v, rest) = der::integer(&bytes).expect("int1");
    assert_eq!(v, [1u8], "int1 value");
    assert_eq!(rest.len(), 0, "int1 no trailing");

    for name in D2I_INTEGER_REJECTED {
        let bytes = read_fixture("d2i", name);
        assert!(
            der::integer(&bytes).is_err(),
            "{name}: must be rejected by der::integer"
        );
        // 全体 d2i 文件：PKCS#8 解析拒绝 + 全解析面不 panic。
        assert!(
            der::parse_pkcs8_private_key(&bytes).is_err(),
            "{name}: must not parse as PKCS#8"
        );
        feed_everything(&bytes);
    }
}

#[test]
fn boringssl_corpus_fixtures_pinned() {
    let mut valid = 0usize;
    for (name, pk8_ok, spki_ok) in CORPUS_PINNED {
        let bytes = read_fixture("corpus", name);
        let pk8 = der::parse_pkcs8_private_key(&bytes).is_ok();
        let spki = sign::rsa::VerifyKey::from_spki_der(&bytes).is_ok();
        assert_eq!(pk8, *pk8_ok, "{name}: pkcs8 outcome drift");
        assert_eq!(spki, *spki_ok, "{name}: spki outcome drift");
        if pk8 {
            valid += 1;
        }
        feed_everything(&bytes);
    }
    // 采集时的合法密钥数（3 个 PKCS#8）——防语料目录被静默裁剪。
    assert_eq!(valid, 3, "3 valid PKCS#8 keys expected in curated corpus");
    assert!(
        CORPUS_PINNED.len() >= 31,
        "curated corpus unexpectedly small"
    );
}
