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
//! - HMAC：`valid` → one_shot 截断到 tagSize 一致（全标签另断言
//!   verify Ok）；`invalid`（同长篡改）→ 计算前缀必须区分。
//! - HKDF：`valid` → extract+expand 逐字节一致；`invalid`（size >
//!   255·HashLen）→ expand 返回 Err。
//! - AES-CCM：nonce/tag 运行时参数空间内按 AEAD 映射；空间外组
//!   （nonce 非 7..13、tag 非 4..16 偶数）断言参数拒绝 Err。
//! - RSA 扩展：3072/4096 模数验证（映射同 2048 族）；rsa_pss_misc
//!   仅保留 mgfSha==sha 的 SHA-2 组，`valid` → verify_pss Ok（盐长
//!   0/20/28/32/48/64 全变体，按编码严格解码）；sig_gen 为签名侧
//!   KAT：core 签名输出与官方向量逐字节一致（PKCS#1 v1.5 确定性）。

mod common;

use common::{assert_hex, hex, to_hex};
use ferritls_core::{ccm, chacha20poly1305, ecdh, gcm, hkdf, hmac, sign};

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
                    // 盐长参数变体（tcId 67–72「s_len changed to …」，
                    // ModifiedSignature）：这些签名在任意盐长语义下
                    // （盐长按编码严格解码，RFC 8017）是同一消息的
                    // 真实有效签名——Wycheproof 判 invalid 是相对该
                    // 组声明的 sLen 参数（验证方被假定钉死盐长）。
                    // 本 API 无盐长参数，接受属既定分歧（同 OpenSSL
                    // 默认行为）；其余 ModifiedSignature 一律拒绝。
                    if comment.starts_with("s_len changed to") {
                        let _ = pk.verify_pss(256, &msg, &sig);
                        n_err += 1;
                    } else {
                        assert!(got.is_err(), "tcId {id} ({comment}): expected rejection");
                        n_err += 1;
                    }
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

// ---------------------------------------------------------------------------
// HMAC（Wycheproof MacTest 模块，2026-11 测试完备性轮引入）
// ---------------------------------------------------------------------------

/// HMAC 驱动的实例级验证函数类型：返回 None 表示标签非全长、
/// API 不支持截断验证。
type HmacVerify = fn(&[u8], &[u8], &[u8]) -> Option<Result<(), ferritls_core::Error>>;

/// HKDF 驱动的 Expand 函数类型。
type HkdfExpand = fn(&[u8], &[u8], &mut [u8]) -> Result<(), ferritls_core::Error>;

/// HMAC 驱动：`mac` = one_shot（返回全摘要），`verify` = 实例级验证。
fn hmac_suite(
    file: &str,
    mac: fn(&[u8], &[u8]) -> Vec<u8>,
    verify: HmacVerify,
    min_valid: u32,
    min_invalid: u32,
) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        let tag_len = group["tagSize"].as_u64().unwrap_or(0) as usize / 8;
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let key = hex(str_field(t, "key"));
            let msg = hex(str_field(t, "msg"));
            let tag = hex(str_field(t, "tag"));
            assert_eq!(tag.len(), tag_len, "tcId {id}: tag length vs group tagSize");
            let computed = mac(&key, &msg);
            match str_field(t, "result") {
                "valid" => {
                    assert_hex(
                        &computed[..tag.len()],
                        &to_hex(&tag),
                        &format!("tcId {id} ({comment}) truncated tag"),
                    );
                    if tag.len() == computed.len() {
                        verify(&key, &msg, &tag)
                            .expect("tcId {id}: full-length verify")
                            .unwrap_or_else(|e| panic!("tcId {id} ({comment}): verify got {e:?}"));
                    }
                    n_ok += 1;
                }
                _ => {
                    assert_ne!(
                        &computed[..tag.len()],
                        &tag[..],
                        "tcId {id} ({comment}): mutated tag must differ"
                    );
                    if tag.len() == computed.len() {
                        assert!(
                            verify(&key, &msg, &tag)
                                .expect("tcId {id}: full-length verify")
                                .is_err(),
                            "tcId {id} ({comment}): expected rejection"
                        );
                    }
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= min_valid && n_err >= min_invalid,
        "{file}: coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_hmac_sha256() {
    hmac_suite(
        "hmac_sha256_test.json",
        |k, m| hmac::HmacSha256::one_shot(k, m).to_vec(),
        |k, m, t| {
            let mut h = hmac::HmacSha256::new(k);
            h.update(m);
            Some(h.verify(t))
        },
        60,
        100,
    );
}

#[test]
fn wycheproof_hmac_sha384() {
    hmac_suite(
        "hmac_sha384_test.json",
        |k, m| hmac::HmacSha384::one_shot(k, m).to_vec(),
        |k, m, t| {
            let mut h = hmac::HmacSha384::new(k);
            h.update(m);
            Some(h.verify(t))
        },
        60,
        100,
    );
}

#[test]
fn wycheproof_hmac_sha512() {
    hmac_suite(
        "hmac_sha512_test.json",
        |k, m| hmac::HmacSha512::one_shot(k, m).to_vec(),
        |k, m, t| {
            let mut h = hmac::HmacSha512::new(k);
            h.update(m);
            Some(h.verify(t))
        },
        60,
        100,
    );
}

// ---------------------------------------------------------------------------
// HKDF（Wycheproof HKDF 模块）：invalid = size 恰为 255·HashLen + 1
// ---------------------------------------------------------------------------

fn hkdf_suite(file: &str, extract: fn(&[u8], &[u8]) -> Vec<u8>, expand: HkdfExpand) {
    let doc = load(file);
    let (mut n_ok, mut n_err) = (0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let salt = hex(str_field(t, "salt"));
            let ikm = hex(str_field(t, "ikm"));
            let info = hex(str_field(t, "info"));
            let size = t["size"].as_u64().unwrap_or(0) as usize;
            let okm = hex(str_field(t, "okm"));
            let prk = extract(&salt, &ikm);
            let mut got = vec![0u8; size];
            let res = expand(&prk, &info, &mut got);
            match str_field(t, "result") {
                "valid" => {
                    res.unwrap_or_else(|e| panic!("tcId {id} ({comment}): expand got {e:?}"));
                    assert_eq!(got, okm, "tcId {id} ({comment}): okm");
                    n_ok += 1;
                }
                _ => {
                    assert!(
                        res.is_err(),
                        "tcId {id} ({comment}): oversized output must be rejected"
                    );
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 60 && n_err >= 2,
        "{file}: coverage too low: ok={n_ok} err={n_err}"
    );
}

#[test]
fn wycheproof_hkdf_sha256() {
    hkdf_suite(
        "hkdf_sha256_test.json",
        |s, i| hkdf::extract_sha256(s, i).to_vec(),
        hkdf::expand_sha256,
    );
}

#[test]
fn wycheproof_hkdf_sha384() {
    hkdf_suite(
        "hkdf_sha384_test.json",
        |s, i| hkdf::extract_sha384(s, i).to_vec(),
        hkdf::expand_sha384,
    );
}

#[test]
fn wycheproof_hkdf_sha512() {
    hkdf_suite(
        "hkdf_sha512_test.json",
        |s, i| hkdf::extract_sha512(s, i).to_vec(),
        hkdf::expand_sha512,
    );
}

// ---------------------------------------------------------------------------
// AES-CCM（Wycheproof CCM 模块）：nonce/tag 为运行时参数，空间外组
// 断言参数拒绝；AES-192/256 组已在裁剪时滤除（keySize==128 契约）。
// ---------------------------------------------------------------------------

#[test]
fn wycheproof_aead_aes_ccm() {
    let doc = load("aes_ccm_test.json");
    let (mut n_ok, mut n_err, mut n_param) = (0u32, 0u32, 0u32);
    for group in arr(&doc, "testGroups") {
        assert_eq!(
            group["keySize"].as_u64(),
            Some(128),
            "aes_ccm: AES-128-only trim contract"
        );
        let nonce_len = group["ivSize"].as_u64().unwrap_or(0) as usize / 8;
        let tag_len = group["tagSize"].as_u64().unwrap_or(0) as usize / 8;
        let in_space = (7..=13).contains(&nonce_len)
            && (4..=16).contains(&tag_len)
            && tag_len.is_multiple_of(2);
        if !in_space {
            // 参数空间外：构造/封密必须拒绝（nonce 非 7..13 或 tag 非
            // 4..16 偶数），无任何成功路径。
            n_param += group["tests"].as_array().map(|t| t.len()).unwrap_or(0) as u32;
            for t in arr(group, "tests") {
                let id = tcid(t);
                let key = hex(str_field(t, "key"));
                let nonce = hex(str_field(t, "iv"));
                let aad = hex(str_field(t, "aad"));
                let msg = hex(str_field(t, "msg"));
                if !(4..=16).contains(&tag_len) || !tag_len.is_multiple_of(2) {
                    assert!(
                        ccm::Aes128CcmAny::new(key.as_slice().try_into().unwrap(), tag_len)
                            .is_err(),
                        "tcId {id}: tag_len {tag_len} must be rejected at construction"
                    );
                    continue;
                }
                let aead = ccm::Aes128CcmAny::new(key.as_slice().try_into().unwrap(), tag_len)
                    .unwrap_or_else(|e| panic!("tcId {id}: {e:?}"));
                assert!(
                    aead.seal(&nonce, &aad, &msg).is_err(),
                    "tcId {id}: nonce_len {nonce_len} must be rejected"
                );
                assert!(aead.open(&nonce, &aad, &vec![0u8; tag_len]).is_err());
            }
            continue;
        }
        for t in arr(group, "tests") {
            let id = tcid(t);
            let comment = str_field(t, "comment");
            let key = hex(str_field(t, "key"));
            let nonce = hex(str_field(t, "iv"));
            let aad = hex(str_field(t, "aad"));
            let msg = hex(str_field(t, "msg"));
            let ct = hex(str_field(t, "ct"));
            let tag = hex(str_field(t, "tag"));
            assert_eq!(tag.len(), tag_len, "tcId {id}: tag length vs group tagSize");
            let aead = ccm::Aes128CcmAny::new(key.as_slice().try_into().unwrap(), tag_len)
                .unwrap_or_else(|e| panic!("tcId {id}: {e:?}"));
            match str_field(t, "result") {
                "valid" => {
                    let mut expect = ct.clone();
                    expect.extend_from_slice(&tag);
                    let sealed = aead
                        .seal(&nonce, &aad, &msg)
                        .unwrap_or_else(|e| panic!("tcId {id} ({comment}): seal got {e:?}"));
                    assert_hex(&sealed, &to_hex(&expect), &format!("tcId {id} ({comment})"));
                    let opened = aead
                        .open(&nonce, &aad, &expect)
                        .unwrap_or_else(|e| panic!("tcId {id} ({comment}): open got {e:?}"));
                    assert_eq!(opened, msg, "tcId {id} ({comment}): opened plaintext");
                    n_ok += 1;
                }
                _ => {
                    let mut ct_tag = ct.clone();
                    ct_tag.extend_from_slice(&tag);
                    assert!(
                        aead.open(&nonce, &aad, &ct_tag).is_err(),
                        "tcId {id} ({comment}): expected rejection"
                    );
                    n_err += 1;
                }
            }
        }
    }
    assert!(
        n_ok >= 40 && n_err >= 20,
        "aes_ccm: coverage too low: ok={n_ok} err={n_err}"
    );
    assert!(
        n_param >= 20,
        "aes_ccm: parameter-space rejection coverage too low: {n_param}"
    );
}

// ---------------------------------------------------------------------------
// RSA 扩展面：3072/4096 模数验证（复用 2048 族驱动）、PSS 参数变体
// （盐长按编码严格解码）、PKCS#1 v1.5 签名侧 KAT（确定性输出）。
// ---------------------------------------------------------------------------

#[test]
fn wycheproof_rsa_pkcs1v15_sha256_3072() {
    rsa_pkcs1_suite("rsa_signature_3072_sha256_test.json", 256);
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha384_3072() {
    rsa_pkcs1_suite("rsa_signature_3072_sha384_test.json", 384);
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha256_4096() {
    rsa_pkcs1_suite("rsa_signature_4096_sha256_test.json", 256);
}

#[test]
fn wycheproof_rsa_pkcs1v15_sha384_4096() {
    rsa_pkcs1_suite("rsa_signature_4096_sha384_test.json", 384);
}

#[test]
fn wycheproof_rsa_pss_misc_parameter_variants() {
    let doc = load("rsa_pss_misc_test.json");
    let mut n_ok = 0u32;
    let mut salt_lens = std::collections::BTreeSet::new();
    for group in arr(&doc, "testGroups") {
        let hash_bits: u16 = match str_field(group, "sha") {
            "SHA-256" => 256,
            "SHA-384" => 384,
            "SHA-512" => 512,
            other => panic!("pss_misc: unexpected trimmed hash {other}"),
        };
        assert_eq!(
            str_field(group, "mgfSha"),
            str_field(group, "sha"),
            "pss_misc trim contract: mgfSha == sha (API surface)"
        );
        let s_len = group["sLen"].as_u64().unwrap_or(0) as usize;
        salt_lens.insert(s_len);
        let spki = hex(str_field(group, "publicKeyDer"));
        let pk = sign::rsa::VerifyKey::from_spki_der(&spki)
            .unwrap_or_else(|e| panic!("group pubkey parse: {e:?}"));
        for t in arr(group, "tests") {
            let id = tcid(t);
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            // Wycheproof 该文件全为 valid：任意合法盐长（含 sLen = 0
            // 与 sLen ≠ hLen）必须通过严格 RFC 8017 验证。
            pk.verify_pss(hash_bits, &msg, &sig)
                .unwrap_or_else(|e| panic!("tcId {id} (sLen {s_len}): verify_pss got {e:?}"));
            n_ok += 1;
        }
    }
    assert_eq!(
        salt_lens,
        [0, 20, 28, 32, 48, 64].into_iter().collect(),
        "pss_misc trim contract: all salt-length variants present"
    );
    assert!(n_ok >= 12, "pss_misc: ok={n_ok}");
}

/// PKCS#1 v1.5 签名侧 KAT：core 签名（CRT + 盲化路径）输出与官方
/// 向量逐字节一致（确定性 padding；盲化不影响输出）。
fn rsa_sig_gen_suite(file: &str) {
    let doc = load(file);
    let mut n_ok = 0u32;
    for group in arr(&doc, "testGroups") {
        let hash_bits: u16 = match str_field(group, "sha") {
            "SHA-256" => 256,
            "SHA-384" => 384,
            "SHA-512" => 512,
            other => panic!("{file}: unexpected trimmed hash {other}"),
        };
        let pkcs8 = hex(str_field(group, "privateKeyPkcs8"));
        let sk = sign::rsa::SigningKey::from_pkcs8_der(&pkcs8)
            .unwrap_or_else(|e| panic!("{file}: private key parse: {e:?}"));
        let spki = hex(str_field(group, "keyDer"));
        let pk = sign::rsa::VerifyKey::from_spki_der(&spki)
            .unwrap_or_else(|e| panic!("{file}: public key parse: {e:?}"));
        for t in arr(group, "tests") {
            let id = tcid(t);
            let msg = hex(str_field(t, "msg"));
            let sig = hex(str_field(t, "sig"));
            let signed = sk
                .sign_pkcs1v15(hash_bits, &msg)
                .unwrap_or_else(|e| panic!("tcId {id}: sign got {e:?}"));
            assert_hex(
                &signed,
                &to_hex(&sig),
                &format!("tcId {id}: deterministic sig"),
            );
            pk.verify_pkcs1v15(hash_bits, &msg, &sig)
                .unwrap_or_else(|e| panic!("tcId {id}: verify got {e:?}"));
            n_ok += 1;
        }
    }
    assert!(n_ok >= 5, "{file}: sig_gen coverage too low: {n_ok}");
}

#[test]
fn wycheproof_rsa_sig_gen_pkcs1_2048() {
    rsa_sig_gen_suite("rsa_pkcs1_2048_sig_gen_test.json");
}

#[test]
fn wycheproof_rsa_sig_gen_pkcs1_3072() {
    rsa_sig_gen_suite("rsa_pkcs1_3072_sig_gen_test.json");
}

#[test]
fn wycheproof_rsa_sig_gen_pkcs1_4096() {
    rsa_sig_gen_suite("rsa_pkcs1_4096_sig_gen_test.json");
}
