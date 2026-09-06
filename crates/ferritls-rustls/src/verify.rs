//! 证书/握手签名验证算法（rustls-webpki 经由
//! `rustls::crypto::WebPkiSupportedAlgorithms` 消费）。
//!
//! 骨架期静态表全部就位（编译期锁定 pki-types trait 形状与 scheme
//! 映射）；`verify` 逻辑在 M4/M6 接入 ferritls-core。
//!
//! 注意：TLS 1.3 对每个 scheme 只取 `mapping` 的**第一个**算法，
//! TLS 1.2 会尝试全部——当前映射 1:1；若 M8 需要跨曲线容错
//! （同 scheme 兼容 P-256/P-384 验证器，rustls-rustcrypto 的做法），
//! 在此扩展即可。

use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::AlgorithmIdentifier;
use rustls::pki_types::InvalidSignature;
use rustls::pki_types::SignatureVerificationAlgorithm;
use rustls::SignatureScheme;

macro_rules! verifier {
    ($name:ident, $doc:expr) => {
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
                let _ = (public_key, message, signature);
                todo!("M4/M6")
            }

            fn public_key_alg_id(&self) -> AlgorithmIdentifier {
                todo!("M4/M6")
            }

            fn signature_alg_id(&self) -> AlgorithmIdentifier {
                todo!("M4/M6")
            }

            fn fips(&self) -> bool {
                // 认证前恒 false（lib.rs“fips() 语义”）。
                false
            }
        }
    };
}

verifier!(EcdsaP256Sha256, "ECDSA P-256/SHA-256（批准）。");
verifier!(EcdsaP384Sha384, "ECDSA P-384/SHA-384（批准）。");
verifier!(Ed25519, "Ed25519（非批准）。");
verifier!(
    RsaPkcs1Sha256,
    "RSA PKCS#1 v1.5/SHA-256（批准；仅证书链验证遗留用途）。"
);
verifier!(
    RsaPkcs1Sha384,
    "RSA PKCS#1 v1.5/SHA-384（批准；遗留用途）。"
);
verifier!(
    RsaPkcs1Sha512,
    "RSA PKCS#1 v1.5/SHA-512（批准；遗留用途）。"
);
verifier!(RsaPssSha256, "RSA-PSS/SHA-256（批准）。");
verifier!(RsaPssSha384, "RSA-PSS/SHA-384（批准）。");
verifier!(RsaPssSha512, "RSA-PSS/SHA-512（批准）。");

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
