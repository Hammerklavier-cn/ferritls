//! 密钥交换组：`SupportedKxGroup` / `ActiveKeyExchange` 适配。
//!
//! X25519 = 非批准；secp256r1/secp384r1 = 批准（但认证前 `fips()` 恒
//! `false`，见 lib.rs“fips() 语义”）。
//!
//! 私钥由 ferritls-core 的 OS 熵直读生成（批准模式的 DRBG 路径由
//! `CryptoProvider::secure_random` 与密钥生成入口的自检守卫覆盖；
//! ECDH 私钥生成熵需求为曲线阶长，风险敞口极小）。

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error as RustlsError, NamedGroup, PeerMisbehaved};

use ferritls_core::ecdh::{p256, p384, x25519};

/// 把 core 的共享秘密错误映射为 rustls 的 InvalidKeyShare。
fn map_dh_err(_: ferritls_core::Error) -> RustlsError {
    RustlsError::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
}

/// X25519（RFC 7748）密钥交换组。
#[derive(Debug)]
pub struct X25519;

/// secp256r1（NIST P-256）密钥交换组。
#[derive(Debug)]
pub struct SecP256R1;

/// secp384r1（NIST P-384）密钥交换组。
#[derive(Debug)]
pub struct SecP384R1;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let sk = x25519::SecretKey::generate().map_err(map_dh_err)?;
        let pk = sk.public_key();
        Ok(Box::new(ActiveX25519 { sk, pk }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        // X25519 独立使用为非批准算法；即便认证后也不会在批准模式提供。
        false
    }
}

impl SupportedKxGroup for SecP256R1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let sk = p256::SecretKey::generate().map_err(map_dh_err)?;
        let pk = sk.public_key();
        Ok(Box::new(ActiveSecP256R1 { sk, pk }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn fips(&self) -> bool {
        // 认证（阶段 C）落地前恒 false。
        false
    }
}

impl SupportedKxGroup for SecP384R1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let sk = p384::SecretKey::generate().map_err(map_dh_err)?;
        let pk = sk.public_key();
        Ok(Box::new(ActiveSecP384R1 { sk, pk }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }

    fn fips(&self) -> bool {
        false
    }
}

/// 进行中的 X25519 密钥交换。
pub(crate) struct ActiveX25519 {
    sk: x25519::SecretKey,
    pk: [u8; 32],
}

/// 进行中的 P-256 密钥交换。
pub(crate) struct ActiveSecP256R1 {
    sk: p256::SecretKey,
    pk: [u8; p256::PUBLIC_KEY_LEN],
}

/// 进行中的 P-384 密钥交换。
pub(crate) struct ActiveSecP384R1 {
    sk: p384::SecretKey,
    pk: [u8; p384::PUBLIC_KEY_LEN],
}

impl std::fmt::Debug for ActiveX25519 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveX25519")
    }
}

impl std::fmt::Debug for ActiveSecP256R1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveSecP256R1")
    }
}

impl std::fmt::Debug for ActiveSecP384R1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ActiveSecP384R1")
    }
}

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let ss = self.sk.diffie_hellman(peer_pub_key).map_err(map_dh_err)?;
        Ok(SharedSecret::from(ss.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pk
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ActiveSecP256R1 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let ss = self.sk.diffie_hellman(peer_pub_key).map_err(map_dh_err)?;
        Ok(SharedSecret::from(ss.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pk
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

impl ActiveKeyExchange for ActiveSecP384R1 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let ss = self.sk.diffie_hellman(peer_pub_key).map_err(map_dh_err)?;
        Ok(SharedSecret::from(ss.as_bytes().to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pk
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

/// X25519 组单例。
pub static X25519_GROUP: &dyn SupportedKxGroup = &X25519;
/// P-256 组单例。
pub static SECP256R1_GROUP: &dyn SupportedKxGroup = &SecP256R1;
/// P-384 组单例。
pub static SECP384R1_GROUP: &dyn SupportedKxGroup = &SecP384R1;

/// 默认（非批准模式）密钥交换组清单；顺序即偏好，首项为 TLS 1.3
/// 默认 key share（X25519：非 FIPS 模式下的主流互操作选择）。
pub static ALL_KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[&X25519, &SecP256R1, &SecP384R1];

/// 批准模式密钥交换组清单（无 X25519）。
pub static FIPS_KX_GROUPS: &[&'static dyn SupportedKxGroup] = &[&SecP256R1, &SecP384R1];
