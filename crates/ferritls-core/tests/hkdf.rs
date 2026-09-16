//! HKDF-SHA-256 向量测试（M1）。
//!
//! 来源：RFC 5869 Test Cases 1–3。
//! 向量为人工录入——启用前必须与 RFC 5869 原文核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::hkdf::{expand_sha256, extract_sha256};

#[test]
fn hkdf_sha256_rfc5869_tc1() {
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = extract_sha256(&salt, &ikm);
    assert_hex(
        &prk,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "TC1 PRK",
    );

    let mut okm = [0u8; 42];
    expand_sha256(&prk, &info, &mut okm).unwrap();
    assert_hex(
        &okm,
        "3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
        "TC1 OKM",
    );
}

#[test]
fn hkdf_sha256_rfc5869_tc2_long_inputs() {
    let ikm: Vec<u8> = (0x00..=0x4f).collect();
    let salt: Vec<u8> = (0x60..=0xaf).collect();
    let info: Vec<u8> = (0xb0..=0xff).collect();

    let prk = extract_sha256(&salt, &ikm);
    assert_hex(
        &prk,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "TC2 PRK",
    );

    let mut okm = [0u8; 82];
    expand_sha256(&prk, &info, &mut okm).unwrap();
    assert_hex(
        &okm,
        "b11e398dc80327a1c8e7f78c596a4934\
         4f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09\
         da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f\
         1d87",
        "TC2 OKM",
    );
}

#[test]
fn hkdf_sha256_rfc5869_tc3_empty_salt_info() {
    let ikm = [0x0bu8; 22];
    let prk = extract_sha256(&[], &ikm);
    assert_hex(
        &prk,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "TC3 PRK",
    );

    let mut okm = [0u8; 42];
    expand_sha256(&prk, &[], &mut okm).unwrap();
    assert_hex(
        &okm,
        "8da4e775a563c18f715f802a063c5a31\
         b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8",
        "TC3 OKM",
    );
}

/// HKDF-Expand 输出前缀性质（RFC 5869 §2.3 构造的直接推论）：
/// OKM(L1) 必须是 OKM(L2) 的前缀（L1 < L2）。该性质能抓住 T 链/计数器
/// 的任何实现偏差，且不依赖新向量。
#[test]
fn hkdf_expand_prefix_property() {
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let prk = extract_sha256(&salt, &ikm);
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let mut long = vec![0u8; 255 * 32]; // 计数器上限 255 块，恰好合法
    expand_sha256(&prk, &info, &mut long).expect("255 blocks is within RFC 5869 limit");
    for l1 in [1usize, 31, 32, 33, 64, 1000, 255 * 32 - 1] {
        let mut short = vec![0u8; l1];
        expand_sha256(&prk, &info, &mut short).unwrap();
        assert_eq!(short, long[..l1], "OKM({l1}) must prefix OKM(255*32)");
    }
}

/// 超过 255×HashLen 的 OKM 请求必须显式报错（RFC 5869 §2.3），
/// 不得静默回绕计数器产出错误密钥材料。
#[test]
fn hkdf_expand_over_limit_rejected() {
    let prk = [0x07u8; 32];
    let mut okm = vec![0u8; 255 * 32 + 1];
    assert_eq!(
        expand_sha256(&prk, b"info", &mut okm),
        Err(ferritls_core::Error::InvalidInput)
    );
}

/// HKDF-SHA-384：RFC 5869 TC1/TC3 输入形态。RFC 5869 附录 A 无 SHA-384
/// 用例——期望值由双参照链生成互验（纯 python RFC 5869 参照实现 +
/// python-cryptography（OpenSSL 后端）HKDF，两者输出一致），2026-09-17。
#[test]
fn hkdf_sha384_reference_vectors() {
    use ferritls_core::hkdf::{expand_sha384, extract_sha384};
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = extract_sha384(&salt, &ikm);
    assert_hex(
        &prk,
        "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8de\
         c70ee9a7e1f3e293ef68eceb072a5ade",
        "SHA-384 TC1-shape PRK",
    );
    let mut okm = [0u8; 82];
    expand_sha384(&prk, &info, &mut okm).unwrap();
    assert_hex(
        &okm,
        "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f\
         748b6457763e4f0204fc5d95d1da3e62587b22eb8943d0fab6bb631a2fe9df1\
         a68c6ce5d56116a52005b3f122b88b39b7251f",
        "SHA-384 TC1-shape OKM(82)",
    );

    // TC3 形态（空 salt/info）
    let prk = extract_sha384(&[], &ikm);
    assert_hex(
        &prk,
        "10e40cf072a4c5626e43dd22c1cf727d4bb140975c9ad0cbc8e45b40068f8f0b\
         a57cdb598af9dfa6963a96899af047e5",
        "SHA-384 TC3-shape PRK",
    );
    let mut okm = [0u8; 42];
    expand_sha384(&prk, &[], &mut okm).unwrap();
    assert_hex(
        &okm,
        "c8c96e710f89b0d7990bca68bcdec8cf854062e54c73a7abc743fade9b242daa\
         cc1cea5670415b52849c",
        "SHA-384 TC3-shape OKM(42)",
    );
}

/// HKDF-SHA-512：同上，双参照链生成互验（2026-09-17）。
#[test]
fn hkdf_sha512_reference_vectors() {
    use ferritls_core::hkdf::{expand_sha512, extract_sha512};
    let ikm = [0x0bu8; 22];
    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    let prk = extract_sha512(&salt, &ikm);
    assert_hex(
        &prk,
        "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26\
         c36238127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
        "SHA-512 TC1-shape PRK",
    );
    let mut okm = [0u8; 82];
    expand_sha512(&prk, &info, &mut okm).unwrap();
    assert_hex(
        &okm,
        "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793\
         38da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137\
         be3fb62f3cf32b84feba8f1eb1b563e20d97",
        "SHA-512 TC1-shape OKM(82)",
    );

    // TC3 形态（空 salt/info）
    let prk = extract_sha512(&[], &ikm);
    assert_hex(
        &prk,
        "fd200c4987ac491313bd4a2a13287121247239e11c9ef82802044b66ef357e5b\
         194498d0682611382348572a7b1611de54764094286320578a863f36562b0df6",
        "SHA-512 TC3-shape PRK",
    );
    let mut okm = [0u8; 42];
    expand_sha512(&prk, &[], &mut okm).unwrap();
    assert_hex(
        &okm,
        "f5fa02b18298a72a8c23898a8703472c6eb179dc204c03425c970e3b164bf90f\
         ff22d04836d0e2343bac",
        "SHA-512 TC3-shape OKM(42)",
    );
}

/// 前缀性质与 255 块上限对三个 hash 一致成立（宏实例的行为一致性，
/// 抓任一实例的 T 链/上限偏差）。
#[test]
fn hkdf_macro_instances_share_structural_properties() {
    use ferritls_core::hkdf::{expand_sha384, expand_sha512, extract_sha384, extract_sha512};

    let salt = hex("000102030405060708090a0b0c");
    let info = hex("f0f1f2f3f4f5f6f7f8f9");

    // SHA-384：OKM 前缀性质 + 255×48 上限
    let prk = extract_sha384(&salt, &[0x0bu8; 22]);
    let mut long = vec![0u8; 255 * 48];
    expand_sha384(&prk, &info, &mut long).expect("255 blocks within limit");
    let mut short = vec![0u8; 1000];
    expand_sha384(&prk, &info, &mut short).unwrap();
    assert_eq!(short[..], long[..1000], "SHA-384 prefix property");
    let mut over = vec![0u8; 255 * 48 + 1];
    assert_eq!(
        expand_sha384(&prk, &info, &mut over),
        Err(ferritls_core::Error::InvalidInput),
        "SHA-384 over 255×48 must be rejected"
    );

    // SHA-512：同上（上限 255×64）
    let prk = extract_sha512(&salt, &[0x0bu8; 22]);
    let mut long = vec![0u8; 255 * 64];
    expand_sha512(&prk, &info, &mut long).expect("255 blocks within limit");
    let mut short = vec![0u8; 1000];
    expand_sha512(&prk, &info, &mut short).unwrap();
    assert_eq!(short[..], long[..1000], "SHA-512 prefix property");
    let mut over = vec![0u8; 255 * 64 + 1];
    assert_eq!(
        expand_sha512(&prk, &info, &mut over),
        Err(ferritls_core::Error::InvalidInput),
        "SHA-512 over 255×64 must be rejected"
    );
}

// 跨 hash PRK 必须不同（防宏展开时类型错绑——错绑实例仍会自洽通过
// 自家向量，唯有跨实例比对能暴露）。
#[test]
fn hkdf_cross_hash_prk_differ() {
    let salt = hex("000102030405060708090a0b0c");
    let ikm = [0x0bu8; 22];
    let p256 = ferritls_core::hkdf::extract_sha256(&salt, &ikm);
    let p384 = ferritls_core::hkdf::extract_sha384(&salt, &ikm);
    let p512 = ferritls_core::hkdf::extract_sha512(&salt, &ikm);
    assert_ne!(
        &p256[..],
        &p384[..32],
        "SHA-256 vs SHA-384 PRK prefix must differ"
    );
    assert_ne!(
        &p384[..32],
        &p512[..32],
        "SHA-384 vs SHA-512 PRK prefix must differ"
    );
}
