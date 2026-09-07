//! `SecureRandom` 适配：rustls 的握手随机数需求桥接到 ferritls-core。
//!
//! - [`SYSTEM_RANDOM`]：OS 熵直读（getrandom），默认模式使用；
//! - [`FIPS_RANDOM`]：边界内 CTR-DRBG（懒实例化 + 上电自检守卫），每次
//!   读取以 128 位 OS 熵作 additional input（Go FIPS 模块策略），批准
//!   模式 provider 使用。

use std::sync::Mutex;

use rustls::crypto::{GetRandomFailed, SecureRandom};

/// ferritls 的 `SecureRandom` 实现（OS 熵直读）。
#[derive(Debug)]
pub struct SystemRandom;

impl SecureRandom for SystemRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        ferritls_core::entropy::fill(buf).map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        // 认证前恒 false（lib.rs“fips() 语义”）。
        false
    }
}

/// 单例引用（填入 `CryptoProvider::secure_random`）。
pub static SYSTEM_RANDOM: &dyn SecureRandom = &SystemRandom;

/// 批准模式随机源：进程级 CTR-DRBG（懒实例化）。
#[derive(Debug)]
pub struct FipsRandom;

static FIPS_DRBG: Mutex<Option<ferritls_core::drbg::CtrDrbg>> = Mutex::new(None);

impl SecureRandom for FipsRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut guard = FIPS_DRBG.lock().map_err(|_| GetRandomFailed)?;
        let drbg = match guard.as_mut() {
            Some(d) => d,
            None => {
                let d = ferritls_core::drbg::CtrDrbg::instantiate_from_os(b"ferritls-tls-random")
                    .map_err(|_| GetRandomFailed)?;
                guard.insert(d)
            }
        };
        drbg.generate_mixed(buf).map_err(|_| GetRandomFailed)
    }

    fn fips(&self) -> bool {
        // 认证前恒 false（lib.rs“fips() 语义”）。
        false
    }
}

/// 批准模式单例引用。
pub static FIPS_RANDOM: &dyn SecureRandom = &FipsRandom;
