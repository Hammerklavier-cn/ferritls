//! 签名适配：`SigningKey` / `Signer` / `KeyProvider`。
//!
//! rustls 0.23 的签名 trait 位于 `rustls::sign`（不在 `rustls::crypto`
//! 下）；`Signer::sign` 的输入是**未哈希**消息，与 ferritls-core 的
//! 约定一致。

use std::sync::Arc;

use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{Error as RustlsError, SignatureAlgorithm, SignatureScheme};

/// P-256/SHA-256 签名密钥。
#[derive(Debug)]
pub struct EcdsaP256Key;

/// P-384/SHA-384 签名密钥。
#[derive(Debug)]
pub struct EcdsaP384Key;

/// Ed25519 签名密钥（非批准）。
#[derive(Debug)]
pub struct Ed25519Key;

/// RSA 签名密钥（PSS 与 PKCS#1 v1.5，按对端 offer 选择）。
#[derive(Debug)]
pub struct RsaKey;

impl SigningKey for EcdsaP256Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let _ = offered;
        todo!("M4/M6")
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl SigningKey for EcdsaP384Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let _ = offered;
        todo!("M4/M6")
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

impl SigningKey for Ed25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let _ = offered;
        todo!("M4/M6")
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

impl SigningKey for RsaKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let _ = offered;
        todo!("M4/M6")
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::RSA
    }
}

/// ECDSA P-256/SHA-256 签名器（`choose_scheme` 的产物）。
#[derive(Debug)]
pub struct EcdsaP256Signer;

/// ECDSA P-384/SHA-384 签名器。
#[derive(Debug)]
pub struct EcdsaP384Signer;

/// Ed25519 签名器。
#[derive(Debug)]
pub struct Ed25519Signer;

/// RSA-PSS（SHA-256/384/512 按 scheme 变化）签名器。
#[derive(Debug)]
pub struct RsaSigner {
    /// 目标签名方案（RSA-PSS / PKCS#1 × SHA-2 组合）。
    pub scheme: SignatureScheme,
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let _ = message;
        todo!("M4/M6")
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

impl Signer for EcdsaP384Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let _ = message;
        todo!("M4/M6")
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP384_SHA384
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let _ = message;
        todo!("M4/M6")
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl Signer for RsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let _ = message;
        todo!("M4/M6")
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

/// rustls `CryptoProvider::key_provider` 字段的实现：把
/// `PrivateKeyDer`（PKCS#8/SEC1/PKCS#1）分派到对应签名密钥类型。
#[derive(Debug)]
pub struct KeyLoader;

impl rustls::crypto::KeyProvider for KeyLoader {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, RustlsError> {
        let _ = key_der;
        todo!("M4/M6")
    }

    fn fips(&self) -> bool {
        // 认证前恒 false（lib.rs“fips() 语义”）。
        false
    }
}

/// 兼容任意支持类型的密钥加载（ECDSA → Ed25519 → RSA 依次尝试）。
pub fn any_supported_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, RustlsError> {
    let _ = der;
    todo!("M4/M6")
}

/// 仅接受 ECDSA（P-256/P-384）密钥。
pub fn any_ecdsa_type(der: &PrivateKeyDer<'_>) -> Result<Arc<dyn SigningKey>, RustlsError> {
    let _ = der;
    todo!("M4/M6")
}
