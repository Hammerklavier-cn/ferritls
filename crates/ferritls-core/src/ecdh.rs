//! 椭圆曲线 Diffie-Hellman 密钥交换：X25519（RFC 7748）与
//! NIST P-256/P-384（SP 800-56A）。
//!
//! 批准状态：P-256/P-384 为 FIPS 批准；**X25519 独立使用为非批准**
//! （未来仅可作为 ML-KEM 混合组件进入批准模式，M8+ 预研）。
//!
//! 里程碑：M3。向量：RFC 7748 §6.1、Wycheproof ECDH（`tests/x25519.rs`
//! 已预置 RFC 向量；P-256/384 的 Wycheproof JSON 在 M3 引入）。
//!
//! 安全注意（实现期逐条对照 AGENTS.md“安全注意事项”）：
//! - 全部标量乘常数时间：X25519 用按位 Montgomery 阶梯；P-256/384 用
//!   固定窗口 + 雅可比坐标，窗口预表只依赖基点，秘密标量加盲化；
//! - 私钥、共享秘密实现 `Zeroize + ZeroizeOnDrop`；
//! - X25519 按 RFC 7748 忽略对端公钥的钳制位与低有效位；全零输出
//!   （小阶点攻击）按 RFC 规定由调用方策略处理——本层返回
//!   [`Error::VerificationFailed`](crate::Error)（TLS 场景必须终止握手）；
//! - P-256/384 必须验证对端公钥在曲线上（不含无穷远点），拒绝非法点。

macro_rules! ecdh_impl {
    ($modname:ident, $secret:ident, $shared:ident, $slen:literal, $plen:literal, $approval:expr, $milestone:expr) => {
        /// 单条曲线的 ECDH 命名空间。
        pub mod $modname {
            /// 私钥字节数。
            pub const SECRET_KEY_LEN: usize = $slen;
            /// 公钥字节数（NIST 曲线为未压缩 SEC1 格式）。
            pub const PUBLIC_KEY_LEN: usize = $plen;
            /// 共享秘密字节数。
            pub const SHARED_LEN: usize = $slen;

            /// ECDH 私钥（内部持有标量，`ZeroizeOnDrop`）。
            #[derive(Clone, Debug)]
            pub struct $secret;

            /// 共享秘密（`ZeroizeOnDrop`； [`as_bytes`](SharedSecret::as_bytes)
            /// 借出切片供 HKDF 使用）。
            #[derive(Debug)]
            pub struct $shared;

            impl $secret {
                /// 本曲线在 FIPS 140-3 下的批准状态。
                pub const APPROVAL: crate::Approval = $approval;

                /// 生成新私钥。
                ///
                /// M3：`getrandom` 直读 + 钳制/NIST 标量处理；
                /// M5 起：批准模式下必须改走边界内 CTR-DRBG。
                pub fn generate() -> Result<Self, crate::Error> {
                    todo!($milestone)
                }

                /// 由种子确定性构造（测试/向量入口；生产代码不得使用）。
                pub fn from_seed(seed: [u8; $slen]) -> Self {
                    let _ = seed;
                    todo!($milestone)
                }

                /// 导出对应公钥（X25519：u 坐标小端 32 字节；
                /// NIST 曲线：`0x04 || X || Y`）。
                pub fn public_key(&self) -> [u8; $plen] {
                    todo!($milestone)
                }

                /// 计算共享秘密。对端公钥非法或结果为全零时返回
                /// [`Error::VerificationFailed`](crate::Error)。
                pub fn diffie_hellman(&self, peer_public: &[u8]) -> Result<$shared, crate::Error> {
                    let _ = peer_public;
                    todo!($milestone)
                }
            }

            impl $shared {
                /// 共享秘密字节（在 TLS 1.3 中作为 HKDF-Extract 的 IKM）。
                pub fn as_bytes(&self) -> &[u8] {
                    todo!($milestone)
                }
            }
        }
    };
}

ecdh_impl!(
    x25519,
    SecretKey,
    SharedSecret,
    32,
    32,
    crate::Approval::NonApproved,
    "M3"
);
ecdh_impl!(
    p256,
    SecretKey,
    SharedSecret,
    32,
    65,
    crate::Approval::Approved,
    "M3"
);
ecdh_impl!(
    p384,
    SecretKey,
    SharedSecret,
    48,
    97,
    crate::Approval::Approved,
    "M3"
);
