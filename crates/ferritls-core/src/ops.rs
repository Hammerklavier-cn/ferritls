//! 后端分发入口（性能优化的唯一挂接点）。
//!
//! 两种分发粒度，按"后端需要携带的状态"选择（OpenSSL 模式的对应物）：
//!
//! - **对象分发（AES-GCM）**：硬件后端必须持有展开的轮密钥——执行核心
//!   是每密钥一个的 trait 对象（[`AeadGcm`]），经工厂（[`AeadOps`]）在
//!   公开类型构造时取得，每消息一次 dyn 分发。默认路径零开销：公开
//!   类型内部 `enum { Soft, Ext }`，未安装时直连软件实现。
//! - **函数分发（SHA-256）**：SHA-NI 后端**不携带任何实例状态**——它
//!   只替换块压缩这一个纯函数（[`Sha256Compress`]）。上下文结构保持
//!   哑形态（无 enum、无 Box、`new()` 不查任何全局），分发开销 =
//!   每次 `update`/`finalize` 一次注册表读取（摊给其中全部数据块）+
//!   每块一次目标不变的间接调用。这是 OpenSSL「init 时选定全局函数
//!   指针、上下文纯数据」模式的对应物。
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
//! 6. 未接后端的原语（CCM/ChaCha20-Poly1305/ECDH/签名）保持软件
//!    直通，其 Ops trait 随对应硬件后端排期同步定义，不预写无用
//!    trait。（SHA-256 曾试过对象分发形态，因 HKDF 短命实例的逐
//!    实例检查 +2.3% 被零回归门否决；函数分发形态使其归零。）
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

/// SHA-256 块压缩函数签名（软件与硬件后端共用）。
///
/// `h` 为 8 个 32 位工作变量，`block` 为 64 字节数据块。这是 SHA-256
/// 的全部热点：缓冲/填充等廉价逻辑留在 core 的 [`crate::sha2::Sha256`]
/// 中，后端只替换本函数。
pub type Sha256Compress = fn(h: &mut [u32; 8], block: &[u8; 64]);

/// 哈希后端（函数分发形态）。
///
/// 后端**不携带任何实例状态**——实现只负责交出选定的压缩函数（通常
/// 是一个经 `#[target_feature]` 包装的私有函数），能力探测在安装流程
/// 中完成一次。
pub trait HashOps: Send + Sync {
    /// 后端名（诊断/基准报告用）。
    fn name(&self) -> &'static str;

    /// 交出 SHA-256 块压缩函数。
    fn sha256_compress(&self) -> Sha256Compress;
}

static AEAD_BACKEND: OnceLock<&'static dyn AeadOps> = OnceLock::new();
static HASH_BACKEND: OnceLock<&'static dyn HashOps> = OnceLock::new();

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

/// 安装哈希后端（进程级一次；语义同 [`install`]）。
pub fn install_hash(backend: &'static dyn HashOps) -> Result<(), crate::Error> {
    if crate::policy::fips_mode_enabled() {
        return Err(crate::Error::Unsupported);
    }
    HASH_BACKEND
        .set(backend)
        .map_err(|_| crate::Error::Unsupported)
}

/// 已安装的哈希后端（未安装 → [`None`]，公开类型直连软件实现）。
pub fn installed_hash() -> Option<&'static dyn HashOps> {
    HASH_BACKEND.get().copied()
}

/// 当前 SHA-256 压缩函数（未安装 → 软件）。
///
/// 每次 `update`/`finalize` 调用一次，摊给其中全部数据块。
pub(crate) fn current_sha256_compress() -> Sha256Compress {
    match HASH_BACKEND.get() {
        Some(backend) => backend.sha256_compress(),
        None => crate::sha2::compress256,
    }
}
