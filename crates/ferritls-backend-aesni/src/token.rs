//! CPU 能力 token（借鉴 fearless_simd 的 marker 思想）。
//!
//! [`AesNi`] 是"AES-NI 与 PCLMULQDQ 已在本机确认可用"的**类型级证明**：
//! 它没有公开构造器，唯一来源是 [`AesNi::detect`] 的运行时探测。全部
//! intrinsics 包装（[`crate::raw`]）以 `&AesNi` 为第一参数——持有 token
//! 是调用 intrinsics 的语法前置条件，CPU 能力因此进入类型系统而非
//! 留在注释里。

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
