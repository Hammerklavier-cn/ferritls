//! `SecureRandom` 适配：rustls 的握手随机数需求桥接到 ferritls-core。
//!
//! M5 前：`getrandom` 直读（非批准模式的过渡状态）。
//! M5 起：批准模式下走边界内 CTR-DRBG（每次读取以 128 位 OS 熵重播种，
//! 参照 Go FIPS 模块策略）。

use rustls::crypto::{GetRandomFailed, SecureRandom};

/// ferritls 的 `SecureRandom` 实现。
#[derive(Debug)]
pub struct SystemRandom;

impl SecureRandom for SystemRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let _ = buf;
        todo!("M5/M6")
    }

    fn fips(&self) -> bool {
        // 认证前恒 false（lib.rs“fips() 语义”）。
        false
    }
}

/// 单例引用（填入 `CryptoProvider::secure_random`）。
pub static SYSTEM_RANDOM: &dyn SecureRandom = &SystemRandom;
