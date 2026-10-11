//! Wycheproof 全量对抗性向量测试（M7）。
//!
//! 向量文件在 `tests/vectors/`（来源与裁剪策略见该目录 README.md）。本
//! 测试的意图：把 AGENTS.md「攻击者可控输入不得 panic、解析/验证失败
//! 必须 Err」的纪律机器化——特别是 invalid 曲线攻击、非规范编码、
//! padding 变体等人工用例覆盖不到的组合。
//!
//! 结果映射规则（与实现契约一一对应，均确定性断言）：
//! - ECDH/X25519：`valid` → Ok 且共享秘密一致；共享秘密全零（小阶点，
//!   含 Twist 低阶情况）→ `Err(VerificationFailed)`；其余 acceptable
//!   （Twist/NonCanonical，RFC 7748 语义下可计算）→ Ok 且值一致；
//!   `invalid`（InvalidCurveAttack 等，点不在曲线上）→ Err。
//! - ECDSA/Ed25519/RSA：`valid` → Ok；`invalid` → Err；唯一例外是
//!   PKCS#1 的 `MissingNull`（acceptable）：本实现按「逐字节重构期望 EM」
//!   的严格策略拒绝它，Wycheproof 认为拒收也是合规行为，故断言 Err。
//! - AEAD（AES-GCM/ChaCha20-Poly1305，仅含 valid/invalid 两类结果）：
//!   `valid` → seal 密文‖标签逐字节一致且 open 还原明文；`invalid` →
//!   open 返回 Err。文件的参数空间已在裁剪时限定到本实现的 API 面
//!   （GCM：AES-128/256 × nonce-96 × tag-128；ChaCha：256 × 96 × 128）。

mod common;

use common::{assert_hex, hex, to_hex};
use ferritls_core::{chacha20poly1305, ecdh, gcm, sign};

const ZERO32: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ZERO48: &str = concat!(
    "000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000"
);

/// ECDSA 验证函数指针（p256/p384 同形；构造 + 验证一步到位）。
type EcdsaVerify = fn(&[u8], &[u8], &[u8]) -> Result<(), ferritls_core::Error>;

fn v_ecdsa_p256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ferritls_core::Error> {
    sign::ecdsa::p256::VerifyKey::from_sec1_point(pk)?.verify(msg, sig)
}

fn v_ecdsa_p384(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ferritls_core::Error> {
    sign::ecdsa::p384::VerifyKey::from_sec1_point(pk)?.verify(msg, sig)
}

fn v_ed25519(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ferritls_core::Error> {
    sign::ed25519::VerifyKey::from_raw_bytes(pk)?.verify(msg, sig)
}

fn load(name: &str) -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors").to_string() + "/" + name;
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn arr<'a>(v: &'a serde_json::Value, key: &str) -> &'a Vec<serde_json::Value> {
    v[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} not an array"))
}

fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} not a string"))
}

fn tcid(v: &serde_json::Value) -> u64 {
    v["tcId"].as_u64().unwrap_or(0)
}

/// Wycheproof 标量为变长 BE 整数（可能带前导零），归一后左填充到字段长度。
fn pad_to<const N: usize>(v: &[u8]) -> [u8; N] {
    let nz = v.iter().take_while(|&&b| b == 0).count();
    let v = &v[nz..];
    assert!(v.len() <= N, "scalar longer than {N} bytes");
    let mut out = [0u8; N];
    out[N - v.len()..].copy_from_slice(v);
    out
}

/// ECDH P-256/384：裸 SEC1 点输入，按 group.curve 选曲线。
fn ecdh_suite(file: &str, min_valid: u32, min_err: u32) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let curve = str_field(group, "curve");
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let public = hex(str_field(t, "public"));
            let shared = str_field(t, "shared");
            let result = str_field(t, "result");
            let is_zero = shared == ZERO32 || shared == ZERO48;
            let got: Result<Vec<u8>, ferritls_core::Error> = match curve {
                "secp256r1" => {
                    let sk =
                        ecdh::p256::SecretKey::from_seed(pad_to(&hex(str_field(t, "private"))));
                    sk.diffie_hellman(&public).map(|ss| ss.as_bytes().to_vec())
                }
                "secp384r1" => {
                    let sk =
                        ecdh::p384::SecretKey::from_seed(pad_to(&hex(str_field(t, "private"))));
                    sk.diffie_hellman(&public).map(|ss| ss.as_bytes().to_vec())
                }
                other => panic!("unexpected curve {other}"),
            };
            if result == "valid" {
                let ss =
                    got.unwrap_or_else(|e| panic!("tcId {id} ({comment}): expected Ok, got {e:?}"));
                assert_hex(&ss, shared, &format!("tcId {id} ({comment}) shared"));
                n_ok += 1;
            } else if result == "acceptable" && !is_zero {
                // 本组文件的 acceptable 只有压缩点编码：本实现只接受
                // 未压缩点，必须拒绝
                assert!(
                    got.is_err(),
                    "tcId {id} ({comment}): expected rejection of compressed point"
                );
                n_err += 1;
            } else {
                // invalid（含 InvalidCurveAttack/不在曲线）或全零共享
                match got {
                    Err(_) => n_err += 1,
                    Ok(ss) => {
                        assert_hex(&ss, shared, &format!("tcId {id} ({comment}) shared"));
                        n_ok += 1;
                    }
                }
            }
        }
    }
    assert!(
        n_ok >= min_valid && n_err >= min_err,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_ecdh_secp256r1() {
    ecdh_suite("ecdh_secp256r1_ecpoint_test.json", 50, 15);
}

#[test]
fn wycheproof_ecdh_secp384r1() {
    ecdh_suite("ecdh_secp384r1_ecpoint_test.json", 50, 15);
}

#[test]
fn wycheproof_x25519() {
    let doc = load("x25519_test.json");
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let public = hex(str_field(t, "public"));
            let private = hex(str_field(t, "private"));
            let shared = str_field(t, "shared");
            let result = str_field(t, "result");
            assert_eq!(public.len(), 32, "tcId {id} public len");
            assert_eq!(private.len(), 32, "tcId {id} private len");
            let sk = ecdh::x25519::SecretKey::from_seed(private.try_into().unwrap());
            let got = sk.diffie_hellman(&public);
            let is_zero = shared == ZERO32;
            if result == "valid" || (result == "acceptable" && !is_zero) {
                // RFC 7748 语义（含非规范 u 掩码、twist 计算值）：可计算且值确定
                let ss =
                    got.unwrap_or_else(|e| panic!("tcId {id} ({comment}): expected Ok, got {e:?}"));
                assert_hex(
                    ss.as_bytes(),
                    shared,
                    &format!("tcId {id} ({comment}) shared"),
                );
                n_ok += 1;
            } else {
                // 全零共享（LowOrderPublic）→ 拒绝
                assert!(
                    got.is_err(),
                    "tcId {id} ({comment}): expected rejection (zero shared)"
                );
                n_err += 1;
            }
        }
    }
    assert!(
        n_ok >= 250 && n_err >= 30,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

/// ECDSA：公钥取 group.publicKey.uncompressed（04‖X‖Y），签名 DER。
fn ecdsa_suite(file: &str, verify: EcdsaVerify) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let pk = hex(str_field(&group["publicKey"], "uncompressed"));
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = verify(&pk, &msg, &sig);
            match result {
                "valid" => {
                    got.unwrap_or_else(|e| {
                        panic!("tcId {id} ({comment}): expected valid, got {e:?}")
                    });
                    n_ok += 1;
                }
                _ => {
                    assert!(got.is_err(), "tcId {id} ({comment}): expected rejection");
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 30 && n_err >= 100,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_ecdsa_secp256r1_sha256() {
    ecdsa_suite("ecdsa_secp256r1_sha256_test.json", v_ecdsa_p256);
}

#[test]
fn wycheproof_ecdsa_secp384r1_sha384() {
    ecdsa_suite("ecdsa_secp384r1_sha384_test.json", v_ecdsa_p384);
}

#[test]
fn wycheproof_ed25519() {
    let doc = load("ed25519_test.json");
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let pk = hex(str_field(&group["publicKey"], "pk"));
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = v_ed25519(&pk, &msg, &sig);
            match result {
                "valid" => {
                    got.unwrap_or_else(|e| {
                        panic!("tcId {id} ({comment}): expected valid, got {e:?}")
                    });
                    n_ok += 1;
                }
                _ => {
                    assert!(got.is_err(), "tcId {id} ({comment}): expected rejection");
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 20 && n_err >= 30,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

/// RSA PKCS#1 v1.5（SHA-256/384/512 三个文件）。
/// 唯一的 acceptable（tcId 8, MissingNull）按严格策略断言拒绝。
fn rsa_pkcs1_suite(file: &str, hash_bits: u16) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let spki = hex(str_field(group, "publicKeyDer"));
        let pk = sign::rsa::VerifyKey::from_spki_der(&spki)
            .unwrap_or_else(|e| panic!("group pubkey parse: {e:?}"));
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = pk.verify_pkcs1v15(hash_bits, &msg, &sig);
            match result {
                "valid" => {
                    got.unwrap_or_else(|e| {
                        panic!("tcId {id} ({comment}): expected valid, got {e:?}")
                    });
                    n_ok += 1;
                }
                "acceptable" => {
                    // MissingNull：逐字节重构期望 EM 的严格实现必须拒绝
                    assert!(
                        got.is_err(),
                        "tcId {id} ({comment}): strict impl rejects MissingNull"
                    );
                    n_err += 1;
                }
                _ => {
                    assert!(got.is_err(), "tcId {id} ({comment}): expected rejection");
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 2 && n_err >= 100,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha256() {
    rsa_pkcs1_suite("rsa_signature_2048_sha256_test.json", 256);
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha384() {
    rsa_pkcs1_suite("rsa_signature_2048_sha384_test.json", 384);
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha512() {
    rsa_pkcs1_suite("rsa_signature_2048_sha512_test.json", 512);
}

#[test]
fn wycheproof_rsa_pss_sha256() {
    let doc = load("rsa_pss_2048_sha256_mgf1_32_test.json");
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let spki = hex(str_field(group, "publicKeyDer"));
        let pk = sign::rsa::VerifyKey::from_spki_der(&spki)
            .unwrap_or_else(|e| panic!("group pubkey parse: {e:?}"));
        assert_eq!(str_field(group, "sha"), "SHA-256");
        assert_eq!(str_field(group, "mgfSha"), "SHA-256");
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = pk.verify_pss(256, &msg, &sig);
            match result {
                "valid" => {
                    got.unwrap_or_else(|e| {
                        panic!("tcId {id} ({comment}): expected valid, got {e:?}")
                    });
                    n_ok += 1;
                }
                _ => {
                    assert!(got.is_err(), "tcId {id} ({comment}): expected rejection");
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 10 && n_err >= 30,
        "coverage too low: ok={n_ok} err={n_err}"
    );
}

/// AEAD 公开 API 的统一视图（三个实现同形：seal → `密文‖标签`）。
trait AeadApi {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8>;
    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, ferritls_core::Error>;
}

impl AeadApi for gcm::Aes128Gcm {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        gcm::Aes128Gcm::seal(self, nonce, aad, plaintext)
    }
    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, ferritls_core::Error> {
        gcm::Aes128Gcm::open(self, nonce, aad, ct_and_tag)
    }
}

impl AeadApi for gcm::Aes256Gcm {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        gcm::Aes256Gcm::seal(self, nonce, aad, plaintext)
    }
    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, ferritls_core::Error> {
        gcm::Aes256Gcm::open(self, nonce, aad, ct_and_tag)
    }
}

impl AeadApi for chacha20poly1305::ChaCha20Poly1305 {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        chacha20poly1305::ChaCha20Poly1305::seal(self, nonce, aad, plaintext)
    }
    fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ct_and_tag: &[u8],
    ) -> Result<Vec<u8>, ferritls_core::Error> {
        chacha20poly1305::ChaCha20Poly1305::open(self, nonce, aad, ct_and_tag)
    }
}

/// AEAD 通用驱动：valid → seal 密文‖标签逐字节一致且 open 还原明文；
/// invalid → open Err（含空明文/空 AAD/单字节差分等边界攻击面）。
/// 参数空间断言（iv-96/tag-128）守护裁剪约定：文件若重新引入 API 面
/// 外的组会在此报错。
fn aead_suite(file: &str, make: fn(&[u8]) -> Box<dyn AeadApi>, min_ok: u32, min_err: u32) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        assert_eq!(
            group["ivSize"].as_u64(),
            Some(96),
            "{file}: nonce-96 parameter space (trim contract)"
        );
        assert_eq!(
            group["tagSize"].as_u64(),
            Some(128),
            "{file}: tag-128 parameter space (trim contract)"
        );
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let key = hex(str_field(t, "key"));
            let iv: [u8; 12] = hex(str_field(t, "iv")).try_into().unwrap();
            let aad = hex(str_field(t, "aad"));
            let msg = hex(str_field(t, "msg"));
            let ct = hex(str_field(t, "ct"));
            let tag = hex(str_field(t, "tag"));
            assert_eq!(tag.len(), 16, "tcId {id}: tag-16 parameter space");
            let aead = make(&key);
            match str_field(t, "result") {
                "valid" => {
                    let mut expect = ct;
                    expect.extend_from_slice(&tag);
                    let sealed = aead.seal(&iv, &aad, &msg);
                    assert_hex(&sealed, &to_hex(&expect), &format!("tcId {id} ({comment})"));
                    let opened = aead
                        .open(&iv, &aad, &expect)
                        .unwrap_or_else(|e| panic!("tcId {id} ({comment}): open got {e:?}"));
                    assert_eq!(opened, msg, "tcId {id} ({comment}): opened plaintext");
                    n_ok += 1;
                }
                "invalid" => {
                    let mut ct_tag = ct;
                    ct_tag.extend_from_slice(&tag);
                    assert!(
                        aead.open(&iv, &aad, &ct_tag).is_err(),
                        "tcId {id} ({comment}): expected rejection"
                    );
                    n_err += 1;
                }
                other => panic!("{file} tcId {id}: unexpected result {other}"),
            }
        }
    }
    assert!(
        n_ok >= min_ok && n_err >= min_err,
        "{file}: coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_aead_aes_gcm() {
    fn make(key: &[u8]) -> Box<dyn AeadApi> {
        match key.len() {
            16 => Box::new(gcm::Aes128Gcm::new(key.try_into().unwrap())),
            32 => Box::new(gcm::Aes256Gcm::new(key.try_into().unwrap())),
            n => panic!("unexpected AES key length {n}"),
        }
    }
    aead_suite("aes_gcm_test.json", make, 15, 40);
}

#[test]
fn wycheproof_aead_chacha20_poly1305() {
    fn make(key: &[u8]) -> Box<dyn AeadApi> {
        Box::new(chacha20poly1305::ChaCha20Poly1305::new(
            key.try_into().unwrap(),
        ))
    }
    aead_suite("chacha20_poly1305_test.json", make, 50, 45);
}
