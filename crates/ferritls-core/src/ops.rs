//! 后端分发入口（**边界外硬件后端**的挂接点，M8+ 落地）。
//!
//! 本 crate 当前只有纯软件后端；AES-NI / SHA 扩展 / AVX 等硬件后端
//! 在 M8+ 落地。约定（详见 docs/ARCHITECTURE.md）：
//!
//! 1. 每个原语定义一个 `Ops` trait（如 [`AeadOps`]），公开 API 只依赖
//!    trait，不依赖具体后端；
//! 2. 软件实现即默认后端（直接实现于各模块内，本模块下不设注册
//!    结构）；硬件后端以**独立 crate** 形式存在（它们需要
//!    `unsafe`/intrinsics，不得进入本 crate 的
//!    `#![forbid(unsafe_code)]` 边界），经 `linkme`/显式注册挂入；
//! 3. 后端选择在进程初始化时一次性确定（`is_x86_feature_detected!` 等
//!    运行时探测），运行期不变，避免 per-call 分派开销与状态复杂化；
//! 4. **FIPS 约束**：认证边界以软件后端申报；引入硬件后端并纳入边界
//!    需要实验室重新审查——在拿到证书前，批准模式固定软件后端
//!    （性能让位于边界稳定）。
//!
//! 注意（P1 性能轮，AGENTS §5.5）：**软件后端自身**的性能重构
//! （批量 XOR、H 倍数表、位切片、批处理等稳定版改动）不经本模块
//! 分发——它就是对各模块内软件实现的维护。本模块只服务边界外的
//! 硬件后端 crate；在此之前不提供任何实现或注册结构（禁止预写
//! todo 存根，P1 已清除 M0 时代的 `SoftwareBackend` 存根）。

/// AEAD 原语的后端分发 trait（M8 硬件后端 crate 落地时正式启用）。
///
/// 公开 API（如 [`crate::gcm::Aes256Gcm`]）届时内部经由本 trait
/// 调用，使硬件后端可替换执行核心而公开 API 不变。
pub trait AeadOps: Send + Sync {
    /// 算法名（诊断/自检报告用）。
    fn name(&self) -> &'static str;

    /// 就地认证加密：`buf` 为明文输入、密文输出；返回标签。
    fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 16], crate::Error>;

    /// 就地认证解密：`buf` 为密文输入、明文输出；`tag` 验证。
    fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), crate::Error>;
}
