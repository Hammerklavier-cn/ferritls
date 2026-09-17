//! 唯一允许 unsafe 的叶子模块（AGENTS.md §5.5、docs/ARCHITECTURE.md §4）。
//!
//! 本 crate 根部 `#![deny(unsafe_code)]`。**寄存器型 intrinsic 没有本
//! 模块包装**（`AESENC`/`AESENCLAST`/`AESKEYGENASSIST`/`PCLMULQDQ` 与
//! SHA 系列）：它们只在 `#[target_feature]` kernel 内部直调——在该
//! 工具链上这是安全调用且编译为裸指令；反之，从无 feature 上下文经
//! 包装调用会因 feature 不匹配被禁止内联，每个包装调用都退化为真实
//! 函数调用（改造前全 crate 103 处，见 `crate::gcm` / `crate::sha` 的
//! kernel 文档与 docs/ARCHITECTURE.md §4）。
//!
//! 本模块只剩**内存读写**包装（裸指针语义集中一处论证；在 feature 与
//! 非 feature 上下文都可调用）。SSE2 为 x86_64 基线，其 intrinsic 的
//! feature 集是任何调用方的子集，LLVM 可自由内联（实测为裸 `movups`）。

#![allow(unsafe_code)]

use core::arch::x86_64::__m128i;

/// 从 16 字节读取向量（无对齐要求；长度恰为 16）。
#[inline]
pub fn loadu(src: &[u8; 16]) -> __m128i {
    // SAFETY: 读取恰 16 字节，引用保证存活与可读；loadu 无对齐要求。
    unsafe { core::arch::x86_64::_mm_loadu_si128(src.as_ptr().cast()) }
}

/// 写出向量到 16 字节数组（返回值形式；就地写入用 [`store_into`]）。
#[inline]
pub fn storeu(src: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: 目标是本地数组，恰 16 字节且可写；storeu 无对齐要求。
    unsafe { core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), src) };
    out
}

/// 就地写出向量到 16 字节块（CTR keystream 覆盖等热路径）。
#[inline]
pub fn store_into(dst: &mut [u8; 16], v: __m128i) {
    // SAFETY: 目标恰 16 字节且可写；storeu 无对齐要求。
    unsafe { core::arch::x86_64::_mm_storeu_si128(dst.as_mut_ptr().cast(), v) };
}
