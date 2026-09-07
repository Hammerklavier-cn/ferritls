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
    ecdsa::p256::verify(public_key, message, signature)
}

fn v_ecdsa_p384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    ecdsa::p384::verify(public_key, message, signature)
}

fn v_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    ed25519::verify(public_key, message, signature)
}

fn v_rsa_pkcs1_256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pkcs1v15(256, public_key, message, signature)
}

fn v_rsa_pkcs1_384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pkcs1v15(384, public_key, message, signature)
}

fn v_rsa_pkcs1_512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pkcs1v15(512, public_key, message, signature)
}

fn v_rsa_pss_256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pss(256, public_key, message, signature)
}

fn v_rsa_pss_384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pss(384, public_key, message, signature)
}

fn v_rsa_pss_512(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ferritls_core::Error> {
    rsa::verify_pss(512, public_key, message, signature)
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
