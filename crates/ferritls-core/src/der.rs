//! 最小 DER 解析：PKCS#8 / SEC1 / PKCS#1 私钥与 SPKI 公钥的拆包。
//!
//! 只为 [`crate::sign`] 的密钥加载与 rustls `KeyProvider` 服务，
//! **不是**通用 ASN.1 库。X.509 证书解析由 rustls-webpki 负责，在边界外。
//!
//! 里程碑：M4。测试：`tests/der.rs`（畸形输入 fuzz 式样例 + 合法样例；
//! 攻击者可控，任何畸形输入必须返回 [`Error::InvalidInput`](crate::Error)，
//! 不得 panic、不得越界——配合 cargo-fuzz 持续回归）。

/// 解析后的私钥内容（按算法分派给 [`crate::sign`] 各类型）。
#[derive(Debug)]
pub enum ParsedPrivateKey {
    /// P-256：SEC1 OCTET STRING 内的 32 字节标量。
    P256 {
        /// 未压缩 SEC1 公钥点（0x04||X||Y），SEC1 结构中可选携带。
        public_sec1: Option<[u8; 65]>,
    },
    /// P-384：SEC1 内的 48 字节标量。
    P384 {
        /// 未压缩 SEC1 公钥点。
        public_sec1: Option<[u8; 97]>,
    },
    /// RSA PKCS#1 私钥（n、e、d、p、q、…的 DER 表示，M4 细化字段）。
    RsaPkcs1,
    /// Ed25519：32 字节种子。
    Ed25519,
}

/// 解析 PKCS#8 PrivateKeyInfo DER，识别算法并校验结构。
///
/// 不做语义校验（标量是否在阶内、RSA 是否素数），语义校验由
/// [`crate::sign`] 的构造函数完成。
pub fn parse_pkcs8_private_key(der: &[u8]) -> Result<ParsedPrivateKey, crate::Error> {
    let _ = der;
    todo!("M4")
}

/// 解析 SEC1 ECPrivateKey DER（PKCS#8 内层或裸 SEC1）。
pub fn parse_sec1_private_key(der: &[u8]) -> Result<ParsedPrivateKey, crate::Error> {
    let _ = der;
    todo!("M4")
}

/// 从 SPKI（SubjectPublicKeyInfo）DER 中提取算法 OID 与主体位串。
///
/// 返回 `(oid, 主体字节)`；供 rustls `KeyProvider` 判断密钥类型。
pub fn parse_spki(der: &[u8]) -> Result<(&[u8], &[u8]), crate::Error> {
    let _ = der;
    todo!("M4")
}
