//! # ferritls-backend-aesni
//!
//! [`ferritls-core`] 的 AES-NI + CLMUL 硬件执行核心。**FIPS 边界外**
//! crate（docs/FIPS.md §1），仅 x86_64——其余目标编译为空 crate。
//!
//! ## 用法
//!
//! ```no_run
//! # fn main() -> Result<(), ferritls_core::Error> {
//! #[cfg(target_arch = "x86_64")]
//! {
//!     // 进程初始化阶段（构造任何密钥之前）一次性安装。本 crate 仅
//!     // x86_64 有内容，其他目标上此块被裁掉、示例仍然可编译。
//!     ferritls_backend_aesni::install()?;
//! }
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
//! crate 根 `#![deny(unsafe_code)]`；unsafe 只存在于唯一叶子模块
//! [`raw`](self)（仅内存读写包装）与各 kernel 的进入点 trampoline
//! （`new`/`seal`/`open` 与 SHA 的压缩函数注册点）。kernel 本体标注
//! `#[target_feature(enable = ...)]` 并在上下文内直调 intrinsic（安全、
//! 编译为裸指令）——从无 feature 上下文包装调用会因 feature 不匹配
//! 被禁止内联，每个调用退化为真实函数调用（见 ARCHITECTURE.md §4）。
//! CPU 能力以 [`AesNi`] token 进入类型系统：token 只能经运行时探测
//! 构造（其 clone 同样源自一次成功探测），是进入 trampoline 的安全
//! 论证。除 trampoline 外的全部代码均为安全代码。
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
mod sha;
mod token;

use std::sync::OnceLock;

use ferritls_core::ops;

pub use token::{AesNi, ShaNi};

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

/// SHA-256 后端单例（函数分发形态：唯一状态是能力证明）。
struct ShaBackend {
    tok: OnceLock<ShaNi>,
}

static SHA_BACKEND: ShaBackend = ShaBackend {
    tok: OnceLock::new(),
};

impl ferritls_core::ops::HashOps for ShaBackend {
    fn name(&self) -> &'static str {
        "sha-ni"
    }

    fn sha256_compress(&self) -> ferritls_core::ops::Sha256Compress {
        let tok = self
            .tok
            .get()
            .expect("sha-ni token set before registration");
        tok.sha256_compress()
    }
}

/// 探测 SHA 扩展 → KAT 自检 → 安装 SHA-256 压缩后端（进程级一次）。
///
/// 语义同 [`install`]：CPU 不支持 / KAT 失败 / 批准模式 / 重复安装
/// 分别以对应错误拒绝。与 [`install`] 相互独立（CPU 可能只具备其一）。
pub fn install_hash() -> Result<(), ferritls_core::Error> {
    let tok = ShaNi::detect().ok_or(ferritls_core::Error::Unsupported)?;
    sha::power_up_kat(&tok)?;
    let _ = SHA_BACKEND.tok.set(tok);
    ferritls_core::ops::install_hash(&SHA_BACKEND)
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
