//! 证书/握手签名验证算法（rustls-webpki 经由
//! `rustls::crypto::WebPkiSupportedAlgorithms` 消费）。
//!
//! 注意：TLS 1.3 对每个 scheme 只取 `mapping` 的**第一个**算法，
//! TLS 1.2 会尝试全部——当前映射 1:1；若 M8 需要跨曲线容错
//! （同 scheme 兼容 P-256/P-384 验证器，rustls-rustcrypto 的做法），
//! 在此扩展即可。
//!
//! `public_key_alg_id()` / `signature_alg_id()` 的字节语义（pki-types
//! 1.15 实测，以 `src/data/alg-*.der` 与 rustls-webpki 的比对逻辑为准）：
//! 返回 **AlgorithmIdentifier 的 SEQUENCE 内容**（即内层 TLV 序列，不带
//! 外层 `30 xx` 头）——webpki 用 `der::expect_tag` 剥掉外层后逐字节比对。
//! 注意与 RSA 相关的 NULL 参数是内容的一部分，必须保留：
//! - EC：公钥 = ecPublicKey OID + 命名曲线 OID；签名 = ecdsa-with-SHA*
//!   （RFC 5758：不带 NULL 参数）；
//! - Ed25519：公钥/签名同 OID（1.3.101.112，无参数）；
//! - RSA PKCS#1：公钥 = rsaEncryption + NULL；签名 = sha*WithRSA + NULL；
//! - RSA-PSS：公钥同 RSA；签名 = RSASSA-PSS OID + PSS 参数
//!   （RFC 4055：hash/MGF1-SHA*/salt=哈希长）。
//!
//! `verify_signature` 的 `public_key` 参数语义（rustls-webpki 0.103.x
//! `signed_data.rs` 实测）：webpki 传入的是 **subjectPublicKey 的
//! BIT STRING 内容（key_value）**——即裸密钥本体（RSA = 裸
//! `RSAPublicKey` DER；EC = 未压缩 SEC1 点；Ed25519 = 32 字节裸
//! 公钥），**不含** SPKI/AlgorithmIdentifier 包装。ferritls-core
//! 的 `VerifyKey` 构造器即按该裸格式定义，此处直接透传。

use rustls::SignatureScheme;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};

use ferritls_core::sign::{ecdsa, ed25519, rsa};

macro_rules! verifier {
    ($name:ident, $pk_alg_id:expr, $sig_alg_id:expr, $verify:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name;

        impl SignatureVerificationAlgorithm for $name {
            fn verify_signature(
                &self,
                public_key: &[u8],
                message: &[u8],
                signature: &[u8],
            ) -> Result<(), InvalidSignature> {
                $verify(public_key, message, signature).map_err(|_| InvalidSignature)
            }

            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                AlgorithmIdentifier::from_slice($pk_alg_id)
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                AlgorithmIdentifier::from_slice($sig_alg_id)
            }

            fn fips(&self) -> bool {
                // 认证前恒 false（lib.rs“fips() 语义”）。
                false
            }
        }
    };
}

// ---------------------------------------------------------------------------
// AlgorithmIdentifier 静态表（均为 SEQUENCE 内容，无外层 30 xx 头；
// 与 pki-types src/data/alg-*.der 逐字节一致）
// ---------------------------------------------------------------------------

/// ecPublicKey + prime256v1
const PK_EC_P256: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x03, 0x01, 0x07,
];
/// ecPublicKey + secp384r1
const PK_EC_P384: &[u8] = &[
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
];
/// ecdsa-with-SHA256（无参数）
const SIG_ECDSA_SHA256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// ecdsa-with-SHA384（无参数）
const SIG_ECDSA_SHA384: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// Ed25519（公钥/签名同形）
const ID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// rsaEncryption + NULL
const PK_RSA: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// sha256WithRSAEncryption + NULL
const SIG_RSA_PKCS1_SHA256: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];
/// sha384WithRSAEncryption + NULL
const SIG_RSA_PKCS1_SHA384: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00,
];
/// sha512WithRSAEncryption + NULL
const SIG_RSA_PKCS1_SHA512: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
];
/// RSASSA-PSS（SHA-256 / MGF1-SHA256 / salt 32）：OID + 参数
const SIG_RSA_PSS_SHA256: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x20,
];
/// RSASSA-PSS（SHA-384 / MGF1-SHA384 / salt 48）
const SIG_RSA_PSS_SHA384: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x30,
];
/// RSASSA-PSS（SHA-512 / MGF1-SHA512 / salt 64）
const SIG_RSA_PSS_SHA512: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0, 0x0f, 0x30,
    0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa1, 0x1c,
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01,
    0x40,
];

fn v_ecdsa_p256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    ecdsa::p256::VerifyKey::from_sec1_point(public_key)?.verify(message, signature)
}

fn v_ecdsa_p384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    ecdsa::p384::VerifyKey::from_sec1_point(public_key)?.verify(message, signature)
}

fn v_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    ed25519::VerifyKey::from_raw_bytes(public_key)?.verify(message, signature)
}

/// 解析裸 `RSAPublicKey` DER（webpki 传入的 key_value 格式）。
/// 解析失败统一归一化为 `InvalidSignature`，不区分密钥格式错误
/// 与签名验证失败。
fn v_rsa_pkcs1_256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pkcs1v15(256, message, signature)
}

fn v_rsa_pkcs1_384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pkcs1v15(384, message, signature)
}

fn v_rsa_pkcs1_512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pkcs1v15(512, message, signature)
}

fn v_rsa_pss_256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pss(256, message, signature)
}

fn v_rsa_pss_384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pss(384, message, signature)
}

fn v_rsa_pss_512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::VerifyKey::from_rsapublickey_der(public_key)?.verify_pss(512, message, signature)
}

verifier!(
    EcdsaP256Sha256,
    PK_EC_P256,
    SIG_ECDSA_SHA256,
    v_ecdsa_p256,
    "ECDSA P-256/SHA-256（批准）。"
);
verifier!(
    EcdsaP384Sha384,
    PK_EC_P384,
    SIG_ECDSA_SHA384,
    v_ecdsa_p384,
    "ECDSA P-384/SHA-384（批准）。"
);
verifier!(
    Ed25519,
    ID_ED25519,
    ID_ED25519,
    v_ed25519,
    "Ed25519（非批准）。"
);
verifier!(
    RsaPkcs1Sha256,
    PK_RSA,
    SIG_RSA_PKCS1_SHA256,
    v_rsa_pkcs1_256,
    "RSA PKCS#1 v1.5/SHA-256（批准；仅证书链验证遗留用途）。"
);
verifier!(
    RsaPkcs1Sha384,
    PK_RSA,
    SIG_RSA_PKCS1_SHA384,
    v_rsa_pkcs1_384,
    "RSA PKCS#1 v1.5/SHA-384（批准；遗留用途）。"
);
verifier!(
    RsaPkcs1Sha512,
    PK_RSA,
    SIG_RSA_PKCS1_SHA512,
    v_rsa_pkcs1_512,
    "RSA PKCS#1 v1.5/SHA-512（批准；遗留用途）。"
);
verifier!(
    RsaPssSha256,
    PK_RSA,
    SIG_RSA_PSS_SHA256,
    v_rsa_pss_256,
    "RSA-PSS/SHA-256（批准）。"
);
verifier!(
    RsaPssSha384,
    PK_RSA,
    SIG_RSA_PSS_SHA384,
    v_rsa_pss_384,
    "RSA-PSS/SHA-384（批准）。"
);
verifier!(
    RsaPssSha512,
    PK_RSA,
    SIG_RSA_PSS_SHA512,
    v_rsa_pss_512,
    "RSA-PSS/SHA-512（批准）。"
);

/// 供 `WebPkiSupportedAlgorithms::all` 使用的完整清单。
pub static ALL_VERIFIERS: &[&dyn SignatureVerificationAlgorithm] = &[
    &EcdsaP256Sha256,
    &EcdsaP384Sha384,
    &Ed25519,
    &RsaPkcs1Sha256,
    &RsaPkcs1Sha384,
    &RsaPkcs1Sha512,
    &RsaPssSha256,
    &RsaPssSha384,
    &RsaPssSha512,
];

/// scheme → 验证算法映射（TLS 1.3 只取各组首项）。
pub static SCHEME_MAP: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] = &[
    (SignatureScheme::ECDSA_NISTP256_SHA256, &[&EcdsaP256Sha256]),
    (SignatureScheme::ECDSA_NISTP384_SHA384, &[&EcdsaP384Sha384]),
    (SignatureScheme::ED25519, &[&Ed25519]),
    (SignatureScheme::RSA_PKCS1_SHA256, &[&RsaPkcs1Sha256]),
    (SignatureScheme::RSA_PKCS1_SHA384, &[&RsaPkcs1Sha384]),
    (SignatureScheme::RSA_PKCS1_SHA512, &[&RsaPkcs1Sha512]),
    (SignatureScheme::RSA_PSS_SHA256, &[&RsaPssSha256]),
    (SignatureScheme::RSA_PSS_SHA384, &[&RsaPssSha384]),
    (SignatureScheme::RSA_PSS_SHA512, &[&RsaPssSha512]),
];

/// 默认（非批准模式）的 webpki 验证算法集。
pub static SUPPORTED_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: ALL_VERIFIERS,
    mapping: SCHEME_MAP,
};

/// 批准模式的 webpki 验证算法集（无 Ed25519）。
pub static FIPS_SUPPORTED_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: FIPS_ALL_VERIFIERS,
    mapping: FIPS_SCHEME_MAP,
};

static FIPS_ALL_VERIFIERS: &[&dyn SignatureVerificationAlgorithm] = &[
    &EcdsaP256Sha256,
    &EcdsaP384Sha384,
    &RsaPkcs1Sha256,
    &RsaPkcs1Sha384,
    &RsaPkcs1Sha512,
    &RsaPssSha256,
    &RsaPssSha384,
    &RsaPssSha512,
];

static FIPS_SCHEME_MAP: &[(SignatureScheme, &[&dyn SignatureVerificationAlgorithm])] = &[
    (SignatureScheme::ECDSA_NISTP256_SHA256, &[&EcdsaP256Sha256]),
    (SignatureScheme::ECDSA_NISTP384_SHA384, &[&EcdsaP384Sha384]),
    (SignatureScheme::RSA_PKCS1_SHA256, &[&RsaPkcs1Sha256]),
    (SignatureScheme::RSA_PKCS1_SHA384, &[&RsaPkcs1Sha384]),
    (SignatureScheme::RSA_PKCS1_SHA512, &[&RsaPkcs1Sha512]),
    (SignatureScheme::RSA_PSS_SHA256, &[&RsaPssSha256]),
    (SignatureScheme::RSA_PSS_SHA384, &[&RsaPssSha384]),
    (SignatureScheme::RSA_PSS_SHA512, &[&RsaPssSha512]),
];

// ---------------------------------------------------------------------------
// AlgorithmIdentifier 静态表锚定：webpki 用 `der::expect_tag` 剥外层
// SEQUENCE 后与 `public_key_alg_id()` / `signature_alg_id()` 的返回
// 逐字节比对（pki-types 1.15 本地实测语义），因此表内容必须与
// rustls-pki-types 的权威算法标识数据逐字节一致。
//
// 权威来源：rustls-pki-types 1.15.1 `src/data/alg-*.der`（该 crate 经
// `AlgorithmIdentifier::from_slice(include_bytes!(...))` 直接装载这些
// 文件为 `alg_id::*` 常量）。下方 hex 为开发期从上述文件 `xxd -p`
// 读出后录入（文件：版本见 Cargo.lock 锚定的 rustls-pki-types
// 1.15.1），并与 `rustls::pki_types::alg_id::*` 常量双重比对——两个
// 断言任一漂移都会被拦截。
// ---------------------------------------------------------------------------
#[cfg(test)]
mod alg_id_tests {
    use super::*;
    use rustls::pki_types::alg_id;

    /// 表常量 = 权威文件的逐字节 SEQUENCE 内容（无外层 30 xx 头）。
    #[test]
    fn alg_id_tables_match_pki_types_authority_files() {
        // 来源：rustls-pki-types 1.15.1 src/data/alg-ecdsa-p256.der
        assert_eq!(
            PK_EC_P256,
            &[
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
                0xce, 0x3d, 0x03, 0x01, 0x07,
            ][..],
        );
        // 来源：alg-ecdsa-p384.der
        assert_eq!(
            PK_EC_P384,
            &[
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04,
                0x00, 0x22,
            ][..],
        );
        // 来源：alg-ecdsa-sha256.der
        assert_eq!(
            SIG_ECDSA_SHA256,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02][..],
        );
        // 来源：alg-ecdsa-sha384.der
        assert_eq!(
            SIG_ECDSA_SHA384,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03][..],
        );
        // 来源：alg-ed25519.der
        assert_eq!(ID_ED25519, &[0x06, 0x03, 0x2b, 0x65, 0x70][..]);
        // 来源：alg-rsa-encryption.der（rsaEncryption + NULL 参数）
        assert_eq!(
            PK_RSA,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
            ][..],
        );
        // 来源：alg-rsa-pkcs1-sha256.der
        assert_eq!(
            SIG_RSA_PKCS1_SHA256,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00
            ][..],
        );
        // 来源：alg-rsa-pkcs1-sha384.der
        assert_eq!(
            SIG_RSA_PKCS1_SHA384,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00
            ][..],
        );
        // 来源：alg-rsa-pkcs1-sha512.der
        assert_eq!(
            SIG_RSA_PKCS1_SHA512,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00
            ][..],
        );
        // 来源：alg-rsa-pss-sha256.der（RSASSA-PSS OID + RFC 4055 §3.1
        // 参数：SHA-256 / MGF1-SHA256 / salt 32）
        assert_eq!(
            SIG_RSA_PSS_SHA256,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
                0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                0x02, 0x01, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x20,
            ][..],
        );
        // 来源：alg-rsa-pss-sha384.der（SHA-384 / MGF1-SHA384 / salt 48）
        assert_eq!(
            SIG_RSA_PSS_SHA384,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
                0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
                0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                0x02, 0x02, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x30,
            ][..],
        );
        // 来源：alg-rsa-pss-sha512.der（SHA-512 / MGF1-SHA512 / salt 64）
        assert_eq!(
            SIG_RSA_PSS_SHA512,
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x34, 0xa0,
                0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
                0x05, 0x00, 0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
                0x02, 0x03, 0x05, 0x00, 0xa2, 0x03, 0x02, 0x01, 0x40,
            ][..],
        );
    }

    /// 每个 verifier 实例的 `public_key_alg_id()` / `signature_alg_id()`
    /// 必须逐字节等于对应静态表条目，且等于 pki-types 装载权威 .der
    /// 文件得到的 `alg_id::*` 常量（双重锚定，pki-types 升级若改动
    /// 权威数据即刻暴露）。
    #[test]
    fn verifier_alg_ids_match_tables_and_pki_types_constants() {
        use rustls::pki_types::SignatureVerificationAlgorithm as SVA;

        type VerifierCase = (
            &'static dyn SVA,
            &'static [u8],
            &'static [u8],
            AlgorithmIdentifier,
            AlgorithmIdentifier,
        );
        let cases: &[VerifierCase] = &[
            (
                &EcdsaP256Sha256,
                PK_EC_P256,
                SIG_ECDSA_SHA256,
                alg_id::ECDSA_P256,
                alg_id::ECDSA_SHA256,
            ),
            (
                &EcdsaP384Sha384,
                PK_EC_P384,
                SIG_ECDSA_SHA384,
                alg_id::ECDSA_P384,
                alg_id::ECDSA_SHA384,
            ),
            (
                &Ed25519,
                ID_ED25519,
                ID_ED25519,
                alg_id::ED25519,
                alg_id::ED25519,
            ),
            (
                &RsaPkcs1Sha256,
                PK_RSA,
                SIG_RSA_PKCS1_SHA256,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA256,
            ),
            (
                &RsaPkcs1Sha384,
                PK_RSA,
                SIG_RSA_PKCS1_SHA384,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA384,
            ),
            (
                &RsaPkcs1Sha512,
                PK_RSA,
                SIG_RSA_PKCS1_SHA512,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PKCS1_SHA512,
            ),
            (
                &RsaPssSha256,
                PK_RSA,
                SIG_RSA_PSS_SHA256,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA256,
            ),
            (
                &RsaPssSha384,
                PK_RSA,
                SIG_RSA_PSS_SHA384,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA384,
            ),
            (
                &RsaPssSha512,
                PK_RSA,
                SIG_RSA_PSS_SHA512,
                alg_id::RSA_ENCRYPTION,
                alg_id::RSA_PSS_SHA512,
            ),
        ];
        for (v, pk, sig, pk_const, sig_const) in cases {
            assert_eq!(
                v.public_key_alg_id().as_ref(),
                *pk,
                "{v:?} public_key_alg_id"
            );
            assert_eq!(
                v.signature_alg_id().as_ref(),
                *sig,
                "{v:?} signature_alg_id"
            );
            assert_eq!(
                v.public_key_alg_id(),
                *pk_const,
                "{v:?} public_key_alg_id vs pki-types 常量"
            );
            assert_eq!(
                v.signature_alg_id(),
                *sig_const,
                "{v:?} signature_alg_id vs pki-types 常量"
            );
        }
    }

    /// verifier 的 `fips()` 恒 false（规则 3：认证前；默认实现在
    /// pki-types 1.15 返回 false，此处显式锚定我们覆写后的语义）。
    #[test]
    fn verifier_fips_is_false_before_validation() {
        for v in ALL_VERIFIERS {
            assert!(!v.fips(), "认证前 fips() 恒 false");
        }
    }
}
