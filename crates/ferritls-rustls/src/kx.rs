//! 密钥交换组：`SupportedKxGroup` / `ActiveKeyExchange` 适配。
//!
//! X25519 = 非批准；secp256r1/secp384r1 = 批准（但认证前 `fips()` 恒
//! `false`，见 lib.rs“fips() 语义”）。

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error as RustlsError, NamedGroup};

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
        todo!("M3/M6")
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
        todo!("M3/M6")
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
        todo!("M3/M6")
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }

    fn fips(&self) -> bool {
        false
    }
}

/// 进行中的 X25519 密钥交换（持有未消费的私钥，M3 起为真类型）。
// M3/M6 起由 SupportedKxGroup::start() 构造；此前保留以锁定 trait 形状。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ActiveX25519;

/// 进行中的 P-256 密钥交换。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ActiveSecP256R1;

/// 进行中的 P-384 密钥交换。
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct ActiveSecP384R1;

impl ActiveKeyExchange for ActiveX25519 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let _ = peer_pub_key;
        todo!("M3/M6")
    }

    fn pub_key(&self) -> &[u8] {
        todo!("M3/M6")
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl ActiveKeyExchange for ActiveSecP256R1 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let _ = peer_pub_key;
        todo!("M3/M6")
    }

    fn pub_key(&self) -> &[u8] {
        todo!("M3/M6")
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

impl ActiveKeyExchange for ActiveSecP384R1 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        let _ = peer_pub_key;
        todo!("M3/M6")
    }

    fn pub_key(&self) -> &[u8] {
        todo!("M3/M6")
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
