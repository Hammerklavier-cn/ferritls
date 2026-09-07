//! 签名适配：`SigningKey` / `Signer` / `KeyProvider`。
//!
//! rustls 0.23 的签名 trait 位于 `rustls::sign`（不在 `rustls::crypto`
//! 下）；`Signer::sign` 的输入是**未哈希**消息，与 ferritls-core 的
//! 约定一致。

use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

use ferritls_core::sign::{ecdsa, ed25519, rsa};

/// P-256/SHA-256 签名密钥。
pub struct EcdsaP256Key(ecdsa::p256::SigningKey);

/// P-384/SHA-384 签名密钥。
pub struct EcdsaP384Key(ecdsa::p384::SigningKey);

/// Ed25519 签名密钥（非批准）。
pub struct Ed25519Key(ed25519::SigningKey);

/// RSA 签名密钥（PSS 与 PKCS#1 v1.5，按对端 offer 选择）。
pub struct RsaKey(rsa::SigningKey);

impl std::fmt::Debug for EcdsaP256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdsaP256Key")
    }
}

impl std::fmt::Debug for EcdsaP384Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdsaP384Key")
    }
}

impl std::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Key")
    }
}

impl std::fmt::Debug for RsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaKey")
    }
}

impl EcdsaP256Key {
    /// 由 32 字节标量构造。
    pub fn new(d: &[u8; 32]) -> Self {
        Self(ecdsa::p256::SigningKey::from_seed(*d))
    }
}

impl EcdsaP384Key {
    /// 由 48 字节标量构造。
    pub fn new(d: &[u8; 48]) -> Self {
        Self(ecdsa::p384::SigningKey::from_seed(*d))
    }
}

impl Ed25519Key {
    /// 由 32 字节种子构造。
    pub fn new(seed: &[u8; 32]) -> Self {
        Self(ed25519::SigningKey::from_seed(*seed))
    }
}

impl RsaKey {
    /// 由 PKCS#1 RSAPrivateKey DER 构造（含结构一致性校验）。
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, RustlsError> {
        rsa::SigningKey::from_pkcs1_der(der)
            .map(Self)
            .map_err(|_| RustlsError::General("invalid RSA private key".into()))
    }

    /// 由 PKCS#8 PrivateKeyInfo DER 构造。
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, RustlsError> {
        rsa::SigningKey::from_pkcs8_der(der)
            .map(Self)
            .map_err(|_| RustlsError::General("invalid RSA private key".into()))
    }
}

impl SigningKey for EcdsaP256Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(EcdsaP256Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl SigningKey for EcdsaP384Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP384_SHA384) {
            Some(Box::new(EcdsaP384Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Ed25519Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl SigningKey for RsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // 优先级：TLS 1.3 首选 PSS（SHA-256/384/512），随后 v1.5
        const PREFERRED: [SignatureScheme; 6] = [
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ];
        PREFERRED.iter().find_map(|s| {
            if offered.contains(s) {
                Some(Box::new(RsaSigner {
                    scheme: *s,
                    key: self.0.clone(),
                }) as Box<dyn Signer>)
            } else {
                None
            }
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// ECDSA P-256/SHA-256 签名器（`choose_scheme` 的产物）。
pub struct EcdsaP256Signer(ecdsa::p256::SigningKey);

/// ECDSA P-384/SHA-384 签名器。
pub struct EcdsaP384Signer(ecdsa::p384::SigningKey);

/// Ed25519 签名器。
pub struct Ed25519Signer(ed25519::SigningKey);

/// RSA（PSS / PKCS#1 × SHA-2 按 scheme 变化）签名器。
pub struct RsaSigner {
    /// 目标签名方案。
    pub scheme: SignatureScheme,
    key: rsa::SigningKey,
}

impl std::fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdsaP256Signer")
    }
}

impl std::fmt::Debug for EcdsaP384Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EcdsaP384Signer")
    }
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Ed25519Signer")
    }
}

impl std::fmt::Debug for RsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RsaSigner")
    }
}

fn map_sign_err(_: ferritls_core::Error) -> RustlsError {
    RustlsError::General("signing failed".into())
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        self.0.sign(message).map_err(map_sign_err)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

impl Signer for EcdsaP384Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        self.0.sign(message).map_err(map_sign_err)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP384_SHA384
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        Ok(self.0.sign(message).to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let bits = match self.scheme {
            SignatureScheme::RSA_PSS_SHA256 | SignatureScheme::RSA_PKCS1_SHA256 => 256,
            SignatureScheme::RSA_PSS_SHA384 | SignatureScheme::RSA_PKCS1_SHA384 => 384,
            SignatureScheme::RSA_PSS_SHA512 | SignatureScheme::RSA_PKCS1_SHA512 => 512,
            _ => return Err(RustlsError::General("unsupported RSA scheme".into())),
        };
        let pss = matches!(
            self.scheme,
            SignatureScheme::RSA_PSS_SHA256
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA512
        );
        let result = if pss {
            self.key.sign_pss(bits, message)
        } else {
            self.key.sign_pkcs1v15(bits, message)
        };
        result.map_err(map_sign_err)
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// rustls `CryptoProvider::key_provider` 字段的实现：把
/// `PrivateKeyDer`（PKCS#8/SEC1/PKCS#1）分派到对应签名密钥类型。
#[derive(Debug)]
pub struct KeyLoader;

impl KeyLoader {
    /// PKCS#8 通用分派（对 `any_supported_type` 与本 trait 共用）。
    pub fn from_pkcs8(der: &[u8]) -> Result<Arc<dyn SigningKey>, RustlsError> {
        let parsed = ferritls_core::der::parse_pkcs8_private_key(der)
            .map_err(|_| RustlsError::General("invalid private key".into()))?;
        match parsed {
            ferritls_core::der::ParsedPrivateKey::P256 { scalar, .. } => {
                Ok(Arc::new(EcdsaP256Key::new(&scalar)))
            }
            ferritls_core::der::ParsedPrivateKey::P384 { scalar, .. } => {
                Ok(Arc::new(EcdsaP384Key::new(&scalar)))
            }
            ferritls_core::der::ParsedPrivateKey::RsaPkcs1(pkcs1) => {
                RsaKey::from_pkcs1_der(&pkcs1).map(|k| Arc::new(k) as Arc<dyn SigningKey>)
            }
            ferritls_core::der::ParsedPrivateKey::Ed25519(seed) => Ok(Arc::new(Ed25519Key::new(
                seed.as_slice().try_into().expect("32-byte seed"),
            ))),
        }
    }
}

impl rustls::crypto::KeyProvider for KeyLoader {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, RustlsError> {
        any_supported_type(&key_der)
    }

    fn fips(&self) -> bool {
        // 认证前恒 false（lib.rs“fips() 语义”）。
        false
    }
}

/// 兼容任意支持类型的密钥加载（ECDSA → Ed25519 → RSA 依次尝试）。
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, RustlsError> {
    let der_bytes = der.secret_der();
    // PKCS#8 优先（四种算法统一入口）
    if let Ok(key) = KeyLoader::from_pkcs8(der_bytes) {
        return Ok(key);
    }
    // PKCS#1 RSA
    if let Ok(key) = RsaKey::from_pkcs1_der(der_bytes) {
        return Ok(Arc::new(key));
    }
    Err(RustlsError::General(
        "unsupported private key format or algorithm".into(),
    ))
}

/// 仅接受 ECDSA（P-256/P-384）密钥。
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, RustlsError> {
    let der_bytes = der.secret_der();
    if let Ok(key) = KeyLoader::from_pkcs8(der_bytes) {
        let alg = key.algorithm();
        if alg == SignatureAlgorithm::ECDSA {
            return Ok(key);
        }
    }
    Err(RustlsError::General("not an ECDSA key".into()))
}

/// `KeyProvider` 单例（填入 `CryptoProvider::key_provider`）。
pub static KEY_LOADER: &dyn rustls::crypto::KeyProvider = &KeyLoader;
