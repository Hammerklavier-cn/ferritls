//! CTR-DRBG（NIST SP 800-90A Rev.1 §10.2.1），AES-256-CTR 为基。
//!
//! FIPS 批准的随机数发生器：FIPS 模式下所有密钥生成与随机数消费都
//! 必须经由它（OS 熵源直读不构成批准的 RBG）。设计参照 Go 标准库
//! FIPS 模块：**每次读取都用 128 位内核熵重播种**（熵作为未记入的
//! additional input），同时保持 2^48 重播种间隔的规范上限。
//!
//! 里程碑：M5。向量：NIST CAVP DRBGVS（`tests/drbg.rs` 定义了结构化
//! 测试入口，向量文件在 M5 引入 `tests/vectors/`）。
//!
//! 安全注意：状态 V/Key `ZeroizeOnDrop`；实例化与每次生成执行
//! SP 800-90A 4.3 健康测试（重复计数测试、适应性比例测试）。

/// SP 800-90A CTR-DRBG（无推导函数/with df 按 CAVP 向量选择，M5 定型）。
#[derive(Debug)]
pub struct CtrDrbg;

impl CtrDrbg {
    /// 实例化：`entropy_input` 48 字节（安全强度 256 位：熵 32 + nonce 16），
    /// `personalization` 可为空。
    pub fn new(entropy_input: &[u8], personalization: &[u8]) -> Result<Self, crate::Error> {
        let _ = (entropy_input, personalization);
        todo!("M5")
    }

    /// 生成随机字节（内部先按健康测试检查熵需求；单次 ≤ 2^19 位即
    /// 65536 字节，超出返回 [`Error::RngError`](crate::Error)）。
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), crate::Error> {
        let _ = out;
        todo!("M5")
    }

    /// 显式重播种（每次 `generate` 的内部重播种策略见模块文档）。
    pub fn reseed(&mut self, entropy_input: &[u8]) -> Result<(), crate::Error> {
        let _ = entropy_input;
        todo!("M5")
    }
}
