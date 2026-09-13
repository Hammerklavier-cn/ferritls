//! 密钥交换组：`SupportedKxGroup` / `ActiveKeyExchange` 适配。
//!
//! X25519 = 非批准；secp256r1/secp384r1 = 批准（但认证前 `fips()` 恒
//! `false`，见 lib.rs“fips() 语义”）。
//!
//! 私钥由 ferritls-core 的 OS 熵直读生成（批准模式的 DRBG 路径由
//! `CryptoProvider::secure_random` 与密钥生成入口的自检守卫覆盖；
//! ECDH 私钥生成熵需求为曲线阶长，风险敞口极小）。

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error as RustlsError, NamedGroup, PeerMisbehaved};

use ferritls_core::ecdh::{p256, p384, x25519};
use ferritls_core::mlkem;

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

/// X25519MLKEM768（draft-ietf-tls-ecdhe-mlkem，codepoint 0x11EC）混合
/// 密钥交换组（M8.3）。
///
/// 角色与线格式（TLS 1.3，密钥交换数据依赖 ⇒ KEM 角色**不对称**）：
/// - 客户端 = ML-KEM **解封装方**：`start()` 生成 (ek, dk) + X25519
///   ephemeral，share = ek(1184)‖X25519 pk(32) = 1216 B；
/// - 服务端 = ML-KEM **封装方**：走 [`SupportedKxGroup::start_and_complete`]
///   覆写——对客户端 ek 先做 FIPS 203 §7.2 封装密钥检查再封装，
///   share = ct(1088)‖X25519 pk(32) = 1120 B；
/// - 共享秘密 = ML-KEM ss(32) ‖ X25519 ss(32) = 64 B。
///
/// X25519 独立使用为非批准算法；本混合组是其进入批准模式配置的
/// 通道（SP 800-52r2 口径）。CMVP 认证前 `fips()` 恒 `false`。
#[derive(Debug)]
pub struct X25519Mlkem768;

/// 进行中的 X25519MLKEM768 客户端侧密钥交换（持有解封装密钥）。
pub(crate) struct ActiveX25519Mlkem768 {
    dk: mlkem::Mlkem768DecapsKey,
    sk: x25519::SecretKey,
    share: Vec<u8>,
}

impl SupportedKxGroup for X25519Mlkem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, RustlsError> {
        let (ek, dk) = mlkem::generate_keypair().map_err(map_dh_err)?;
        let sk = x25519::SecretKey::generate().map_err(map_dh_err)?;
        let mut share = Vec::with_capacity(mlkem::EK_BYTES + 32);
        share.extend_from_slice(ek.as_bytes());
        share.extend_from_slice(&sk.public_key());
        Ok(Box::new(ActiveX25519Mlkem768 { dk, sk, share }))
    }

    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, RustlsError> {
        // 服务端：peer share = ek(1184) ‖ X25519 pk(32)
        let invalid = || RustlsError::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
        if peer_pub_key.len() != mlkem::EK_BYTES + 32 {
            return Err(invalid());
        }
        // FIPS 203 §7.2 封装密钥检查（含模校验）在此发生
        let ek = mlkem::Mlkem768EncapsKey::from_bytes(&peer_pub_key[..mlkem::EK_BYTES])
            .map_err(|_| invalid())?;
        let (ct, ss_m) = mlkem::encapsulate(&ek).map_err(map_dh_err)?;
        let sk = x25519::SecretKey::generate().map_err(map_dh_err)?;
        let ss_x = self_x25519(&sk, &peer_pub_key[mlkem::EK_BYTES..])?;

        let mut secret = Vec::with_capacity(mlkem::SS_BYTES + 32);
        secret.extend_from_slice(ss_m.expose_bytes());
        secret.extend_from_slice(ss_x.as_bytes());
        let mut pub_key = Vec::with_capacity(mlkem::CT_BYTES + 32);
        pub_key.extend_from_slice(ct.as_bytes());
        pub_key.extend_from_slice(&sk.public_key());
        Ok(CompletedKeyExchange {
            group: NamedGroup::X25519MLKEM768,
            pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }

    fn fips(&self) -> bool {
        // 认证（阶段 C）落地前恒 false（AGENTS.md 规则 3）。
        false
    }
}

impl ActiveKeyExchange for ActiveX25519Mlkem768 {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, RustlsError> {
        // 客户端：服务端 share = ct(1088) ‖ X25519 pk(32)；密文长度
        // 不符必须中止（draft-ietf-tls-ecdhe-mlkem §3）。
        let invalid = || RustlsError::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare);
        if peer_pub_key.len() != mlkem::CT_BYTES + 32 {
            return Err(invalid());
        }
        let ct = mlkem::Mlkem768Ciphertext::from_bytes(&peer_pub_key[..mlkem::CT_BYTES])
            .map_err(|_| invalid())?;
        let ss_m = mlkem::decapsulate(&self.dk, &ct);
        let ss_x = self_x25519(&self.sk, &peer_pub_key[mlkem::CT_BYTES..])?;

        let mut secret = Vec::with_capacity(mlkem::SS_BYTES + 32);
        secret.extend_from_slice(ss_m.expose_bytes());
        secret.extend_from_slice(ss_x.as_bytes());
        Ok(SharedSecret::from(secret))
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519MLKEM768
    }
}

fn self_x25519(sk: &x25519::SecretKey, peer: &[u8]) -> Result<x25519::SharedSecret, RustlsError> {
    sk.diffie_hellman(peer).map_err(map_dh_err)
}

/// X25519 组单例。
pub static X25519_GROUP: &dyn SupportedKxGroup = &X25519;
/// P-256 组单例。
pub static SECP256R1_GROUP: &dyn SupportedKxGroup = &SecP256R1;
/// P-384 组单例。
pub static SECP384R1_GROUP: &dyn SupportedKxGroup = &SecP384R1;

/// X25519MLKEM768 混合组单例（默认列表首项：PQ 优先，同主流
/// provider/浏览器实践；1216 B ClientHello share）。
pub static X25519MLKEM768_GROUP: &dyn SupportedKxGroup = &X25519Mlkem768;

/// 默认（非批准模式）密钥交换组清单；顺序即偏好，首项为 TLS 1.3
/// 默认 key share（X25519MLKEM768 混合优先，其后经典 X25519）。
pub static ALL_KX_GROUPS: &[&'static dyn SupportedKxGroup] =
    &[&X25519Mlkem768, &X25519, &SecP256R1, &SecP384R1];

/// 批准模式密钥交换组清单：混合组（X25519 进批准模式的通道）+
/// 经典 P-256/P-384；无独立 X25519（SP 800-52r2 口径）。
pub static FIPS_KX_GROUPS: &[&'static dyn SupportedKxGroup] =
    &[&X25519Mlkem768, &SecP256R1, &SecP384R1];
