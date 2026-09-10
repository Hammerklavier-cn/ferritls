//! 后端分发入口（性能优化的唯一挂接点）。
//!
//! 公开类型（如 [`crate::gcm::Aes128Gcm`]）是薄壳，但**默认路径零分发
//! 开销**：未安装任何后端时，公开类型内部直连软件实现（`enum { Soft,
//! Ext }` 的 `Soft` 分支，不经 trait 对象）。安装后端后，新构造的实例
//! 取得 trait 对象执行核心（`Ext` 分支），每消息一次 dyn 分发，
//! µs–ms 级操作下分发开销不可见。
//!
//! 硬件后端（AES-NI/CLMUL/SHA-ext）是边界外的独立 crate（如
//! `ferritls-backend-aesni`，需要 `unsafe`/intrinsics，不得进入本 crate
//! 的 `#![forbid(unsafe_code)]` 边界），经 [`install`]
//! **应用侧显式注册**——适配层与 provider 构造不隐式安装。约定：
//!
//! 1. 进程内一次安装、运行期不切换；重复安装（含同一后端）返回
//!    [`Error::Unsupported`](crate::Error::Unsupported)。已构造的实例
//!    保持其构造时的执行核心，安装应在进程初始化阶段、构造任何密钥
//!    之前完成；
//! 2. 后端安装前必须通过自身 KAT（见后端 crate 的安装文档）；
//! 3. **FIPS 约束**：批准模式（`fips` feature 构建）固定软件路径，
//!    [`install`] 直接拒绝；认证边界按软件实现申报，引入硬件后端
//!    入边界 = 阶段 C 的实验室重审（AGENTS.md 硬性规则 1）。
//! 4. 常数时间纪律分工：后端只**计算**，标签/摘要的**比较**统一由
//!    core 公开类型经 [`crate::ct::verify_tag`] 完成；
//! 5. 执行核心合同为**不可失败**：nonce 长度等前置条件由公开类型的
//!    类型系统保证（`&[u8; 12]`），缓冲长度任意；后端不得因输入内容
//!    返回错误（未来若出现可失败后端，以破坏性版本演进 trait）；
//! 6. 未接后端的原语（SHA-2/CCM/ChaCha20-Poly1305/ECDH/签名）保持
//!    软件直通。SHA-256 的分发**刻意推迟**到 SHA-NI kernel 落地时
//!    一起接线：试接线（M8.1 期间）曾因 HKDF 链中短生命周期实例的
//!    逐实例分发检查造成 +2.3% 回归，不满足默认路径零开销门；其
//!    Ops trait 届时随 kernel 同步定义（不预写无用 trait）。
//!
//! 完整模式说明见 docs/ARCHITECTURE.md §4。

use std::sync::OnceLock;

/// AES-GCM 单密钥执行核心（由后端提供实现）。
///
/// 一个实例持有一把密钥的全部展开材料；`Send + Sync`（rustls 在多连接
/// 间共享套件表）。密钥材料由实现负责 Drop 零化。
pub trait AeadGcm: Send + Sync {
    /// 就地加密：`buf` 为明文输入、密文输出；返回标签。
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16];

    /// 就地解密 `buf`（密文输入、明文输出）并返回**计算出的**标签。
    ///
    /// 不做比较——比较由 core 公开类型以 [`crate::ct::verify_tag`]
    /// 完成（常数时间纪律集中在边界内）。失败路径（比较不过）由
    /// 公开类型负责零化明文缓冲。
    fn open_compute_tag(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16];

    /// 克隆执行核心（公开类型的 `Clone` 经此实现）。
    fn clone_box(&self) -> Box<dyn AeadGcm>;
}

/// AEAD（AES-GCM 族）后端工厂。
pub trait AeadOps: Send + Sync {
    /// 后端名（诊断/基准报告用）。
    fn name(&self) -> &'static str;

    /// 以 `key` 构造 AES-128-GCM 执行核心。
    fn aes128_gcm(&self, key: &[u8; 16]) -> Box<dyn AeadGcm>;

    /// 以 `key` 构造 AES-256-GCM 执行核心。
    fn aes256_gcm(&self, key: &[u8; 32]) -> Box<dyn AeadGcm>;
}

static AEAD_BACKEND: OnceLock<&'static dyn AeadOps> = OnceLock::new();

/// 安装 AEAD 后端（进程级一次）。
///
/// 批准模式（`fips` feature）下拒绝安装；已安装后再次调用（含同一
/// 后端）返回 [`Error::Unsupported`](crate::Error::Unsupported)。
pub fn install(backend: &'static dyn AeadOps) -> Result<(), crate::Error> {
    if crate::policy::fips_mode_enabled() {
        return Err(crate::Error::Unsupported);
    }
    AEAD_BACKEND
        .set(backend)
        .map_err(|_| crate::Error::Unsupported)
}

/// 已安装的 AEAD 后端（未安装 → [`None`]，公开类型直连软件实现）。
pub fn installed_aead() -> Option<&'static dyn AeadOps> {
    AEAD_BACKEND.get().copied()
}
