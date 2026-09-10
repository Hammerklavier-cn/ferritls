//! # ferritls-backend-aesni
//!
//! [`ferritls-core`] 的 AES-NI + CLMUL 硬件执行核心。**FIPS 边界外**
//! crate（docs/FIPS.md §1），仅 x86_64——其余目标编译为空 crate。
//!
//! ## 用法
//!
//! ```no_run
//! # fn main() -> Result<(), ferritls_core::Error> {
//! // 进程初始化阶段（构造任何密钥之前）一次性安装：
//! ferritls_backend_aesni::install()?;
//! // 此后 ferritls_core::gcm::{Aes128Gcm, Aes256Gcm} 的新实例走
//! // AES-NI/CLMUL 路径；已构造的实例与未安装的环境不受影响。
//! # Ok(())
//! # }
//! ```
//!
//! 安装语义（详见 [`ferritls_core::ops`] 模块文档）：
//!
//! - 探测 `aes` + `pclmulqdq`，任一缺失返回
//!   [`Unsupported`](ferritls_core::Error::Unsupported)（不降级、不安装）；
//! - 安装前在本 crate 的执行核心上跑 McGrew–Viega TC5/TC16 已知答案
//!   自检，失败返回 [`SelfTestFailed`](ferritls_core::Error::SelfTestFailed)
//!   并拒绝安装；
//! - 批准模式（`ferritls-core` 以 `fips` feature 构建）下 core 拒绝一切
//!   安装，软件路径固定；
//! - 进程级一次，重复安装由 core 拒绝。
//!
//! ## unsafe 纪律（借鉴 fearless_simd 的模式，零依赖自建）
//!
//! crate 根 `#![deny(unsafe_code)]`；全部 unsafe 集中在唯一叶子模块
//! [`raw`](self)（每个 intrinsic 一个单行安全包装）。CPU 能力以
//! [`AesNi`] token 进入类型系统：token 只能经运行时探测构造（其 clone
//! 同样源自一次成功探测），是调用全部 intrinsics 包装的语法前置条件。
//! kernel 与本文件的全部代码均为安全代码。
//!
//! 常数时间：AES/GCM 指令为固定延迟、数据无关；kernel 内无以秘密为
//! 条件的分支或访存（轮密钥按公开轮号索引）；标签比较统一由 core 的
//! 公开类型完成（本 crate 只计算、不比较）。
//!
//! [`ferritls-core`]: https://docs.rs/ferritls-core

#![cfg(target_arch = "x86_64")]
#![deny(unsafe_code)]

mod gcm;
mod raw;
mod token;

use std::sync::OnceLock;

use ferritls_core::ops;

pub use token::AesNi;

/// 后端单例（唯一向 core 注册的对象）。
struct Backend {
    /// 探测成功后由 [`install`] 写入；注册引用只会在写入之后交给 core，
    /// 工厂方法读取时的 [`None`] 属内部不变式破坏。
    tok: OnceLock<AesNi>,
}

static BACKEND: Backend = Backend {
    tok: OnceLock::new(),
};

impl ops::AeadOps for Backend {
    fn name(&self) -> &'static str {
        "aesni-clmul"
    }

    fn aes128_gcm(&self, key: &[u8; 16]) -> Box<dyn ops::AeadGcm> {
        let tok = self
            .tok
            .get()
            .expect("backend token set before registration");
        Box::new(gcm::NiGcm::<11>::new(tok, key))
    }

    fn aes256_gcm(&self, key: &[u8; 32]) -> Box<dyn ops::AeadGcm> {
        let tok = self
            .tok
            .get()
            .expect("backend token set before registration");
        Box::new(gcm::NiGcm::<15>::new(tok, key))
    }
}

/// 探测 AES-NI + CLMUL（不安装）。
///
/// 供需要自定义装配/诊断的调用方使用；常规路径直接 [`install`]。
pub fn detect() -> Option<AesNi> {
    AesNi::detect()
}

/// 探测 → 上电 KAT 自检 → 安装到 ferritls-core（进程级一次）。
///
/// CPU 不支持返回 [`Unsupported`](ferritls_core::Error::Unsupported)；
/// KAT 失败返回 [`SelfTestFailed`](ferritls_core::Error::SelfTestFailed)；
/// 批准模式或重复安装由 core 拒绝（同样表现为
/// [`Unsupported`](ferritls_core::Error::Unsupported)）。
pub fn install() -> Result<(), ferritls_core::Error> {
    let tok = AesNi::detect().ok_or(ferritls_core::Error::Unsupported)?;
    gcm::power_up_kat(&tok)?;
    let _ = BACKEND.tok.set(tok);
    ops::install(&BACKEND)
}
