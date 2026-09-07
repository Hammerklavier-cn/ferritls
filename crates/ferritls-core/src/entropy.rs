//! OS 熵源接入（getrandom 系统调用）。
//!
//! 定位：**边界外输入**。FIPS 140-3 视角下，OS 内核熵不构成模块内批准的
//! RBG——它只作为 CTR-DRBG 的种子/重播种材料进入边界（见 [`crate::drbg`]）。
//! 非批准模式下私钥生成可直读（M3–M4 的过渡状态），批准模式下强制走 DRBG。

/// 模块声明的安全强度（字节）：256 位。
pub const SECURITY_STRENGTH_BYTES: usize = 32;

/// 从 OS 熵源填充 `dest`（一次性请求；失败返回
/// [`Error::EntropyFailed`](crate::Error)，绝不静默降级）。
pub fn fill(dest: &mut [u8]) -> Result<(), crate::Error> {
    getrandom::getrandom(dest).map_err(|_| crate::Error::EntropyFailed)
}
