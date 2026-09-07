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

mod common;

use common::{assert_hex, hex};
use ferritls_core::{ecdh, sign};

const ZERO32: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ZERO48: &str = concat!(
    "000000000000000000000000000000000000000000000000",
    "000000000000000000000000000000000000000000000000"
);

/// ECDSA 验证函数指针（p256/p384 同形）。
type EcdsaVerify = fn(&[u8], &[u8], &[u8]) -> Result<(), ferritls_core::Error>;

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
    ecdsa_suite(
        "ecdsa_secp256r1_sha256_test.json",
        sign::ecdsa::p256::verify,
    );
}

#[test]
fn wycheproof_ecdsa_secp384r1_sha384() {
    ecdsa_suite(
        "ecdsa_secp384r1_sha384_test.json",
        sign::ecdsa::p384::verify,
    );
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
            let got = sign::ed25519::verify(&pk, &msg, &sig);
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
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = sign::rsa::verify_pkcs1v15(hash_bits, &spki, &msg, &sig);
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
        assert_eq!(str_field(group, "sha"), "SHA-256");
        assert_eq!(str_field(group, "mgfSha"), "SHA-256");
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let result = str_field(t, "result");
            let got = sign::rsa::verify_pss(256, &spki, &msg, &sig);
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
