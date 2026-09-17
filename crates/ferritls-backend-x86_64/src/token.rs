//! CPU 能力 token（借鉴 fearless_simd 的 marker 思想）。
//!
//! [`AesNi`] 是"AES-NI 与 PCLMULQDQ 已在本机确认可用"的**类型级证明**：
//! 它没有公开构造器，唯一来源是 [`AesNi::detect`] 的运行时探测。全部
//! `#[target_feature]` kernel 的 unsafe 进入点（[`crate::gcm`] 的
//! `new`/`seal`/`open` trampoline）都以持有 token 为前置——CPU 能力
//! 因此进入类型系统而非留在注释里；kernel 内部直调 intrinsic，无需
//! 逐调用传递 token（见 [`crate::raw`] 模块文档）。

use ferritls_core::ops::AeadGcm;

/// AES-NI + PCLMULQDQ 可用性证明（零大小）。
///
/// `Clone`/`Copy` 只复制证明本身——任何 `AesNi` 值（含克隆）都必然
/// 源自一次成功的 [`AesNi::detect`]，不变式不被稀释。
#[derive(Clone, Copy)]
pub struct AesNi {
    /// 阻止绕过 [`AesNi::detect`] 的字面量构造（模块外不可见）。
    _priv: (),
}

impl AesNi {
    /// 运行时探测两条扩展；任一缺失返回 [`None`]。
    ///
    /// 探测结果在进程生命周期内视为不变（CPU 特性不热插拔）。
    pub fn detect() -> Option<Self> {
        if std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
        {
            Some(Self { _priv: () })
        } else {
            None
        }
    }

    /// 直接构造 AES-128-GCM 执行核心（不经全局安装）。
    ///
    /// 供差分测试/诊断/自定义装配使用；常规路径用 [`crate::install`]。
    pub fn gcm128(&self, key: &[u8; 16]) -> Box<dyn AeadGcm> {
        Box::new(crate::gcm::NiGcm::<11>::new(self, key))
    }

    /// 直接构造 AES-256-GCM 执行核心（语义同 [`AesNi::gcm128`]）。
    pub fn gcm256(&self, key: &[u8; 32]) -> Box<dyn AeadGcm> {
        Box::new(crate::gcm::NiGcm::<15>::new(self, key))
    }
}

impl std::fmt::Debug for AesNi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AesNi")
    }
}

/// SHA 扩展可用性证明（零大小；语义同 [`AesNi`]）。
#[derive(Clone, Copy)]
pub struct ShaNi {
    _priv: (),
}

impl ShaNi {
    /// 运行时探测 SHA 扩展；缺失返回 [`None`]。
    pub fn detect() -> Option<Self> {
        if std::arch::is_x86_feature_detected!("sha") {
            Some(Self { _priv: () })
        } else {
            None
        }
    }

    /// 交出 SHA-256 块压缩函数（不经全局安装；KAT 由 [`crate::install_hash`]
    /// 负责，差分测试/诊断可直接使用）。
    pub fn sha256_compress(&self) -> ferritls_core::ops::Sha256Compress {
        crate::sha::bind_token(*self);
        crate::sha::compress_fn()
    }
}

impl std::fmt::Debug for ShaNi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShaNi")
    }
}
