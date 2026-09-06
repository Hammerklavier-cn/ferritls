//! 数字签名：ECDSA（P-256/P-384）、RSA（PKCS#1 v1.5 / PSS）、Ed25519。
//!
//! 批准状态：ECDSA P-256/384 与 RSA-PSS/PKCS#1 为 FIPS 批准；
//! **Ed25519 非批准**（FIPS 186-5 不含 EdDSA）。
//!
//! 里程碑：M4。向量：RFC 6979（确定性 ECDSA）、Wycheproof
//! ECDSA/RSA/EdDSA 全量 JSON、RFC 8032 §7.1（`tests/{p256,ed25519}.rs`
//! 已预置样例；Wycheproof JSON 在 M4 引入 `tests/vectors/`）。
//!
//! 签名 API 约定：`sign` 接收**未哈希**的消息，内部先做哈希（与 rustls
//! `Signer::sign` 的输入约定一致）。
//!
//! 安全注意：
//! - ECDSA nonce 用 RFC 6979 确定性生成（FIPS 186-5 允许），杜绝
//!   nonce 重用/偏差类灾难（Sony/PS3、Android Bitcoin 钱包教训）；
//! - RSA 解码必须严格：长度/Padding 逐项检查、全部错误归一化为同一
//!   `Error`、比较常数时间（防 Bleichenbacher/Manger 类选择密文攻击）；
//!   签名私钥运算加盲化；
//! - RSA 密钥最短 2048 位，低于此返回 [`Error::Unsupported`]；
//! - 私钥材料全部 `ZeroizeOnDrop`。

/// ECDSA 签名/验证（NIST 曲线）。
pub mod ecdsa {
    /// P-256 签名私钥（`ZeroizeOnDrop`）。签名输出 DER 编码的 `(r, s)`。
    #[derive(Clone, Debug)]
    pub struct P256SigningKey;

    /// P-384 签名私钥（`ZeroizeOnDrop`）。
    #[derive(Clone, Debug)]
    pub struct P384SigningKey;

    impl P256SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::Approved;

        /// 生成新密钥对（M3 起依赖边界内随机源）。
        pub fn generate() -> Result<Self, crate::Error> {
            todo!("M4")
        }

        /// 从 PKCS#8 DER（或 SEC1 DER）解析私钥。攻击者可控输入，
        /// 一切格式错误返回 [`Error::InvalidInput`](crate::Error)，不得 panic。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            let _ = der;
            todo!("M4")
        }

        /// 对消息签名（内部 SHA-256；RFC 6979 确定性 nonce）。
        /// 返回 DER 编码的 ECDSA-Sig-Value。
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
            let _ = message;
            todo!("M4")
        }

        /// 未压缩 SEC1 公钥（`0x04 || X || Y`）。
        pub fn public_key_sec1(&self) -> [u8; 65] {
            todo!("M4")
        }
    }

    impl P384SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::Approved;

        /// 生成新密钥对。
        pub fn generate() -> Result<Self, crate::Error> {
            todo!("M4")
        }

        /// 从 PKCS#8/SEC1 DER 解析私钥。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            let _ = der;
            todo!("M4")
        }

        /// 对消息签名（内部 SHA-384；RFC 6979）。返回 DER 编码签名。
        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
            let _ = message;
            todo!("M4")
        }

        /// 未压缩 SEC1 公钥。
        pub fn public_key_sec1(&self) -> [u8; 97] {
            todo!("M4")
        }
    }

    /// 验证 P-256/SHA-256 的 DER 签名。公钥为未压缩 SEC1（65 字节）或
    /// 压缩/裁剪形式；验证失败一律 [`Error::VerificationFailed`](crate::Error)。
    pub fn verify_p256_sha256(
        public_key: &[u8],
        message: &[u8],
        signature_der: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (public_key, message, signature_der);
        todo!("M4")
    }

    /// 验证 P-384/SHA-384 的 DER 签名。
    pub fn verify_p384_sha384(
        public_key: &[u8],
        message: &[u8],
        signature_der: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (public_key, message, signature_der);
        todo!("M4")
    }
}

/// RSA 签名/验证（PKCS#1 v1.5 与 PSS，RFC 8017）。
pub mod rsa {
    /// RSA 签名私钥（`ZeroizeOnDrop`；内部含 CRT 参数，运算加盲化）。
    #[derive(Clone, Debug)]
    pub struct SigningKey;

    /// 最短允许的模长字节数（2048 位）。
    pub const MIN_MODULUS_LEN: usize = 256;

    impl SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::Approved;

        /// 从 PKCS#8 DER（PKCS#1 RSA 私钥）解析。模长 < 2048 位返回
        /// [`Error::Unsupported`](crate::Error)。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            let _ = der;
            todo!("M4")
        }

        /// RSA-PSS 签名（salt 长度 = 哈希长度；TLS 1.3 使用）。
        /// `hash` ∈ {256, 384, 512}（位宽）。
        pub fn sign_pss(&self, hash_bits: u16, message: &[u8]) -> Result<Vec<u8>, crate::Error> {
            let _ = (hash_bits, message);
            todo!("M4")
        }

        /// RSA PKCS#1 v1.5 签名（TLS 1.2 遗留套件与证书链验证使用）。
        pub fn sign_pkcs1v15(
            &self,
            hash_bits: u16,
            message: &[u8],
        ) -> Result<Vec<u8>, crate::Error> {
            let _ = (hash_bits, message);
            todo!("M4")
        }
    }

    /// 验证 RSA-PSS 签名。公钥为 DER RSAPublicKey（SPKI 主体）。
    pub fn verify_pss(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (hash_bits, public_key_der, message, signature);
        todo!("M4")
    }

    /// 验证 RSA PKCS#1 v1.5 签名（严格 padding 检查，防 Bleichenbacher）。
    pub fn verify_pkcs1v15(
        hash_bits: u16,
        public_key_der: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), crate::Error> {
        let _ = (hash_bits, public_key_der, message, signature);
        todo!("M4")
    }
}

/// Ed25519 签名/验证（RFC 8032）。
pub mod ed25519 {
    /// Ed25519 签名私钥（种子，`ZeroizeOnDrop`）。
    #[derive(Clone, Debug)]
    pub struct SigningKey;

    impl SigningKey {
        /// 本算法在 FIPS 140-3 下的批准状态。
        pub const APPROVAL: crate::Approval = crate::Approval::NonApproved;

        /// 由 32 字节种子构造（测试/向量入口）。
        pub fn from_seed(seed: [u8; 32]) -> Self {
            let _ = seed;
            todo!("M4")
        }

        /// 从 PKCS#8 DER 解析私钥。
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::Error> {
            let _ = der;
            todo!("M4")
        }

        /// 生成新密钥对。
        pub fn generate() -> Result<Self, crate::Error> {
            todo!("M4")
        }

        /// 对消息签名（PureEdDSA，内部 SHA-512）。
        pub fn sign(&self, message: &[u8]) -> [u8; 64] {
            let _ = message;
            todo!("M4")
        }

        /// 公钥（32 字节）。
        pub fn public_key(&self) -> [u8; 32] {
            todo!("M4")
        }
    }

    /// 验证 Ed25519 签名。
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), crate::Error> {
        let _ = (public_key, message, signature);
        todo!("M4")
    }
}
