//! 唯一允许 unsafe 的叶子模块（AGENTS.md §5.5、docs/ARCHITECTURE.md §4）。
//!
//! 本 crate 根部 `#![deny(unsafe_code)]`，全部 unsafe 集中于此：每个
//! intrinsic 一个单行安全包装。安全论证分两层，对所有包装一致：
//!
//! 1. **目标扩展可用**：每个包装的第一参数是 [`AesNi`]——该 token
//!    只能经运行时探测成功构造（见 [`crate::token`]），持有即证明
//!    本机 CPU 支持 `aes` 与 `pclmulqdq`（SSE2/SSSE3 为 x86_64 基线，
//!    恒可用）；
//! 2. **输入无关**：下列 intrinsic 全部是纯寄存器运算（不访问内存、
//!    无越界语义、无数值陷阱），对任意位模式输入都没有内存安全
//!    后果。当前工具链把这些 intrinsic 定义为带 `#[target_feature]`
//!    的安全函数，编译器要求在非 feature 上下文中经 unsafe 块调用
//!    （E0133）——unsafe 块的作用是显式承担“CPU 支持该扩展”的
//!    合同，由 token 保证。
//!
//! 约定：包装一律 `#[inline]`，不做组合逻辑——组合逻辑属于安全代码
//! （[`crate::gcm`]）。

#![allow(unsafe_code)]

use crate::token::AesNi;
use core::arch::x86_64::__m128i;

/// `AESENC`：一轮 AES 轮变换（SubBytes/ShiftRows/MixColumns 与密钥加）。
#[inline]
pub fn aesenc(_p: &AesNi, a: __m128i, round_key: __m128i) -> __m128i {
    // SAFETY: aes 扩展可用（token 证明）；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_aesenc_si128(a, round_key) }
}

/// `AESENCLAST`：末轮 AES 轮变换（无 MixColumns）。
#[inline]
pub fn aesenclast(_p: &AesNi, a: __m128i, round_key: __m128i) -> __m128i {
    // SAFETY: aes 扩展可用（token 证明）；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_aesenclast_si128(a, round_key) }
}

/// `AESKEYGENASSIST`：SubWord/RotWord/Rcon 辅助（密钥扩展专用）。
///
/// 当前工具链的 intrinsic 以 const 泛型接收 Rcon——此处对合法 Rcon
/// 集合做 match 分发（Rcon 由公开的轮号决定，非常数时间无关紧要）。
#[inline]
pub fn aeskeygenassist(_p: &AesNi, a: __m128i, rcon: u8) -> __m128i {
    use core::arch::x86_64::_mm_aeskeygenassist_si128 as kg;
    // SAFETY: aes 扩展可用（token 证明）；纯寄存器运算。
    unsafe {
        match rcon {
            0x01 => kg::<0x01>(a),
            0x02 => kg::<0x02>(a),
            0x04 => kg::<0x04>(a),
            0x08 => kg::<0x08>(a),
            0x10 => kg::<0x10>(a),
            0x20 => kg::<0x20>(a),
            0x40 => kg::<0x40>(a),
            0x80 => kg::<0x80>(a),
            0x1B => kg::<0x1B>(a),
            0x36 => kg::<0x36>(a),
            // RCON 表由本模块调用方控制（expand_128/256 的常量表），
            // 到达此分支即内部 bug：以 0 结尾的值让 KAT 必然失败。
            _ => kg::<0x00>(a),
        }
    }
}

/// `PCLMULQDQ`（imm=0）：两向量的低 64 位无进位乘。
#[inline]
pub fn clmul00(_p: &AesNi, a: __m128i, b: __m128i) -> __m128i {
    // SAFETY: pclmulqdq 扩展可用（token 证明）；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_clmulepi64_si128::<0x00>(a, b) }
}

/// 逐位异或（SSE2 基线）。
#[inline]
pub fn xor(_p: &AesNi, a: __m128i, b: __m128i) -> __m128i {
    // SAFETY: sse2 为 x86_64 基线；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_xor_si128(a, b) }
}

/// 按 `MASK`（每 2 位选一个源字）重排 32 位字（SSE2 基线）。
#[inline]
pub fn shuffle_epi32<const MASK: i32>(_p: &AesNi, a: __m128i) -> __m128i {
    // SAFETY: sse2 为 x86_64 基线；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_shuffle_epi32::<MASK>(a) }
}

/// 向高位移动 `N` 字节（低位补零；SSSE3 基线）。
#[inline]
pub fn slli_bytes<const N: i32>(_p: &AesNi, a: __m128i) -> __m128i {
    // SAFETY: ssse3 为 x86_64 基线（自 v1 起）；纯寄存器运算。
    unsafe { core::arch::x86_64::_mm_slli_si128::<N>(a) }
}

/// 由 `(hi, lo)` 两个 64 位 lane 构造向量（SSE2 基线）。
#[inline]
pub fn from_u64(_p: &AesNi, hi: u64, lo: u64) -> __m128i {
    // SAFETY: sse2 为 x86_64 基线；纯构造。
    unsafe { core::arch::x86_64::_mm_set_epi64x(hi as i64, lo as i64) }
}

/// 从 16 字节读取向量（无对齐要求；长度恰为 16）。
#[inline]
pub fn loadu(_p: &AesNi, src: &[u8; 16]) -> __m128i {
    // SAFETY: 读取恰 16 字节，引用保证存活与可读；loadu 无对齐要求。
    unsafe { core::arch::x86_64::_mm_loadu_si128(src.as_ptr().cast()) }
}

/// 写出向量到 16 字节数组。
#[inline]
pub fn storeu(_p: &AesNi, src: __m128i) -> [u8; 16] {
    let mut out = [0u8; 16];
    // SAFETY: 目标是本地数组，恰 16 字节且可写；storeu 无对齐要求。
    unsafe { core::arch::x86_64::_mm_storeu_si128(out.as_mut_ptr().cast(), src) };
    out
}
