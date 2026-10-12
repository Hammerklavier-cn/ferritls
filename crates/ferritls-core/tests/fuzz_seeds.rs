//! fuzz 种子语料冒烟（长期防漂移护栏）。
//!
//! 直接读取 `fuzz/corpus/` 下的种子文件，用与对应 fuzz target **同构**
//! 的逻辑跑一遍：入口不得 panic，valid 形状的种子必须走通成功路径、
//! 篡改形状必须 Err——种子若与实现漂移（格式改动后忘同步语料），本
//! 测试先于 CI fuzz 冒烟拦截。
//!
//! mlkem-decaps 种子由 `tools/gen_mlkem_fuzz_seeds.py` 从
//! `tests/mlkem_acvp.rs` 的 ACVP 解封装用例生成，格式：
//! `byte0 = sel（%3：0→512, 1→768, 2→1024），随后 = dk ‖ ct`。
//!
//! 其余种子的布局即对应 target 的输入协议（sel 字节 + 按固定长度切
//! 割的字段）；valid/tampered 对由真实密钥材料（python-cryptography
//! 生成或 wycheproof 用例）构造。

use ferritls_core::mlkem::{k512, k768, k1024};
use ferritls_core::{ccm, chacha20poly1305::ChaCha20Poly1305, der, gcm::Aes128Gcm, gcm::Aes256Gcm};
use std::path::{Path, PathBuf};

fn corpus_dir(name: &str) -> PathBuf {
    // 测试的 cwd = crate 清单目录（crates/ferritls-core）
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(name)
}

fn read_seeds(name: &str) -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir(name);
    assert!(dir.is_dir(), "语料目录不存在: {}", dir.display());
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("读 {} 失败: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin" || x == "der"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "{} 语料为空", dir.display());
    entries
        .into_iter()
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), data)
        })
        .collect()
}

macro_rules! check_set {
    ($set:ident, $dk:expr, $ct:expr) => {{
        let dk = $set::DecapsKey::from_bytes($dk);
        let ct = $set::Ciphertext::from_bytes($ct);
        if let (Ok(dk), Ok(ct)) = (dk, ct) {
            let ss = $set::decapsulate(&dk, &ct);
            let ss2 = $set::decapsulate(&dk, &ct);
            assert_eq!(
                ss.expose_bytes(),
                ss2.expose_bytes(),
                "decapsulate must be deterministic"
            );
            true
        } else {
            false
        }
    }};
}

#[test]
fn mlkem_decaps_seeds_parse_and_stay_deterministic() {
    for (name, data) in read_seeds("mlkem-decaps") {
        assert!(data.len() >= 2, "{name}: 种子过短");
        let sel = data[0] % 3;
        let rest = &data[1..];
        let parsed = match sel {
            0 => check_set!(
                k512,
                &rest[..rest.len().min(k512::DK_BYTES)],
                &rest[k512::DK_BYTES.min(rest.len())..]
            ),
            1 => check_set!(
                k768,
                &rest[..rest.len().min(k768::DK_BYTES)],
                &rest[k768::DK_BYTES.min(rest.len())..]
            ),
            _ => check_set!(
                k1024,
                &rest[..rest.len().min(k1024::DK_BYTES)],
                &rest[k1024::DK_BYTES.min(rest.len())..]
            ),
        };
        // 种子源自 ACVP valid 用例，dk/ct 必须解析成功（防漂移）
        assert!(parsed, "{name}: dk/ct 未通过解析（种子已漂移？）");
    }
}

// ---------------------------------------------------------------------------
// 其余 target 的同构冒烟：与 fuzz_targets/*.rs 的分发逻辑逐字段一致。
// ---------------------------------------------------------------------------

/// aead-open：全部形状种子必须解密成功（valid 形状），解密不出 panic。
#[test]
fn aead_open_seeds_open_to_plaintext() {
    use ferritls_core::Error;
    for (name, data) in read_seeds("aead-open") {
        let (&sel, rest) = data.split_first().unwrap_or_else(|| panic!("{name}: 空"));
        let (key_len, nonce_len) = match sel % 4 {
            0 => (16usize, 12usize),
            1 => (32, 12),
            2 => (16, 13),
            _ => (32, 12),
        };
        let (key_bytes, rest) = rest.split_at(key_len);
        let (nonce_bytes, rest) = rest.split_at(rest.len().min(nonce_len));
        let (aad, ct) = rest.split_at(rest.len() / 2);
        let mut key = [0u8; 32];
        key[..key_bytes.len()].copy_from_slice(key_bytes);
        let mut nonce = [0u8; 13];
        nonce[..nonce_bytes.len()].copy_from_slice(nonce_bytes);
        let got: Result<Vec<u8>, Error> = match sel % 4 {
            0 => Aes128Gcm::new(&key[..16].try_into().unwrap()).open(
                &nonce[..12].try_into().unwrap(),
                aad,
                ct,
            ),
            1 => Aes256Gcm::new(&key).open(&nonce[..12].try_into().unwrap(), aad, ct),
            2 if sel & 4 == 0 => ccm::Aes128CcmTls::new(&key[..16].try_into().unwrap()).open(
                &nonce[..12].try_into().unwrap(),
                aad,
                ct,
            ),
            2 => ccm::Aes128Ccm::new(&key[..16].try_into().unwrap()).open(
                &nonce[..13].try_into().unwrap(),
                aad,
                ct,
            ),
            _ => ChaCha20Poly1305::new(&key).open(&nonce[..12].try_into().unwrap(), aad, ct),
        };
        assert!(got.is_ok(), "{name}: valid 形状种子必须可解密（防漂移）");
    }
}

/// verify-ecdsa：valid P-384 种子必须验证通过，篡改副本必须 Err。
#[test]
fn verify_ecdsa_seeds_valid_and_tampered() {
    use ferritls_core::sign::ecdsa;
    let seeds = read_seeds("verify-ecdsa");
    for (name, data) in &seeds {
        let (&sel, rest) = data.split_first().unwrap_or_else(|| panic!("{name}: 空"));
        let (public, rest) = if sel & 1 == 0 {
            rest.split_at(rest.len().min(65))
        } else {
            rest.split_at(rest.len().min(97))
        };
        let (msg, sig) = rest.split_at(rest.len() / 2);
        let got = if sel & 1 == 0 {
            ecdsa::p256::VerifyKey::from_sec1_point(public).and_then(|vk| vk.verify(msg, sig))
        } else {
            ecdsa::p384::VerifyKey::from_sec1_point(public).and_then(|vk| vk.verify(msg, sig))
        };
        if name.starts_with("valid") {
            assert!(got.is_ok(), "{name}: valid 种子必须验证通过");
        } else {
            assert!(got.is_err(), "{name}: 篡改种子必须拒绝");
        }
    }
}

/// verify-ed25519：valid 种子通过、篡改副本拒绝。
#[test]
fn verify_ed25519_seeds_valid_and_tampered() {
    use ferritls_core::sign::ed25519;
    for (name, data) in read_seeds("verify-ed25519") {
        let (public, rest) = data.split_at(32);
        let (msg, sig) = rest.split_at(rest.len() / 2);
        let got = ed25519::VerifyKey::from_raw_bytes(public).and_then(|vk| vk.verify(msg, sig));
        if name.starts_with("valid") {
            assert!(got.is_ok(), "{name}: valid 种子必须验证通过");
        } else {
            assert!(got.is_err(), "{name}: 篡改种子必须拒绝");
        }
    }
}

/// verify-rsa：SPKI 干净解析种子必须走到 verify 入口（解析 Ok）；
/// 既有 512 字节截断种子走「尾随字节拒绝」路径（解析 Err）。
#[test]
fn verify_rsa_seeds_parse_paths() {
    use ferritls_core::sign::rsa;
    for (name, data) in read_seeds("verify-rsa") {
        let (&sel, rest) = data.split_first().unwrap_or_else(|| panic!("{name}: 空"));
        let (key_der, rest) = rest.split_at(rest.len().min(512));
        let (msg, sig) = rest.split_at(rest.len() / 2);
        let hash_bits = match sel % 3 {
            0 => 256u16,
            1 => 384,
            _ => 512,
        };
        let parsed = rsa::VerifyKey::from_spki_der(key_der);
        if name.starts_with("spki") || name.starts_with("pss") {
            assert!(parsed.is_ok(), "{name}: SPKI 种子必须解析成功（防漂移）");
            let pk = parsed.unwrap();
            if sel & 4 == 0 {
                assert!(pk.verify_pkcs1v15(hash_bits, msg, sig).is_err());
            } else {
                assert!(pk.verify_pss(hash_bits, msg, sig).is_err());
            }
        } else {
            // valid_pkcs1.bin：key_der 恒带尾随（target 的 512 截断所致），
            // 走解析拒绝路径
            assert!(parsed.is_err(), "{name}: 截断种子必须解析失败");
        }
    }
}

/// parse-pkcs8：三个合法 PKCS#8 必须解析成功，截断样本必须 Err。
#[test]
fn parse_pkcs8_seeds_valid_and_truncated() {
    for (name, data) in read_seeds("parse-pkcs8") {
        let got = der::parse_pkcs8_private_key(&data);
        if name.starts_with("truncated") {
            assert!(got.is_err(), "{name}: 截断样本必须拒绝");
        } else {
            assert!(got.is_ok(), "{name}: 合法 PKCS#8 必须解析成功");
        }
    }
}

/// ecdh-peer：valid 种子必须完成密钥交换（小阶点拒绝在 Wycheproof 覆盖）。
#[test]
fn ecdh_peer_seeds_complete_exchange() {
    use ferritls_core::ecdh;
    for (name, data) in read_seeds("ecdh-peer") {
        let (&sel, rest) = data.split_first().unwrap_or_else(|| panic!("{name}: 空"));
        let got = match sel % 3 {
            0 => ecdh::x25519::SecretKey::from_seed([7u8; 32])
                .diffie_hellman(rest)
                .map(|ss| ss.as_bytes().to_vec()),
            1 => ecdh::p256::SecretKey::from_seed([7u8; 32])
                .diffie_hellman(rest)
                .map(|ss| ss.as_bytes().to_vec()),
            _ => ecdh::p384::SecretKey::from_seed([7u8; 48])
                .diffie_hellman(rest)
                .map(|ss| ss.as_bytes().to_vec()),
        };
        assert!(got.is_ok(), "{name}: valid 点必须完成交换");
    }
}
