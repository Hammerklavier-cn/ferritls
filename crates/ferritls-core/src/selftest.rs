//! 上电自检（FIPS 140-3 ISO/IEC 19790 §7.9.2 强制项）。
//!
//! 模块首次使用前必须执行：
//! 1. **已知答案测试（KAT）**：每个批准算法跑一组内建向量
//!    （AES-GCM 加解密、SHA-256/384/512、HMAC、HKDF、ECDSA 签名验证、
//!    RSA-PSS 验证、CTR-DRBG）；任一失败 → 模块进入错误状态，此后
//!    所有密码操作返回 [`Error::SelfTestFailed`](crate::Error)；
//! 2. **完整性测试**：模块自身代码/数据摘要校验（方式在 M5 定型：
//!    构建期嵌入摘要 or 加载期计算；这是 CMVP 文档的重点审查项）。
//!
//! 非批准算法（X25519、ChaCha20-Poly1305、Ed25519）不参与自检，但也不
//! 得在自检失败的模块里提供服务（整个模块拒绝服务，不做部分降级）。
//!
//! 里程碑：M5。

/// 自检状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestStatus {
    /// 尚未运行（首次调用任一密码 API 时懒触发）。
    NotRun,
    /// 全部通过。
    Passed,
    /// 失败：模块处于错误状态，拒绝服务。
    Failed(&'static str),
}

/// 执行上电自检（幂等：已运行则直接返回当前状态）。
pub fn run_power_on_self_tests() -> SelfTestStatus {
    todo!("M5")
}

/// 查询当前状态（不触发自检）。
pub fn status() -> SelfTestStatus {
    todo!("M5")
}

/// 所有密码 API 的入口守卫：自检未通过则拒绝服务。
// M5 起被各原语入口调用；此前保留签名以锁定自检守卫的形态。
#[allow(dead_code)]
pub(crate) fn ensure_passed() -> Result<(), crate::Error> {
    match status() {
        SelfTestStatus::Passed => Ok(()),
        SelfTestStatus::NotRun => match run_power_on_self_tests() {
            SelfTestStatus::Passed => Ok(()),
            SelfTestStatus::Failed(which) => Err(crate::Error::SelfTestFailed(which)),
            SelfTestStatus::NotRun => Err(crate::Error::SelfTestFailed("self-test did not run")),
        },
        SelfTestStatus::Failed(which) => Err(crate::Error::SelfTestFailed(which)),
    }
}
