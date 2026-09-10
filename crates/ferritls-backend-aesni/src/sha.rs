//! SHA-256 的 SHA-NI 执行核心（全部安全代码；函数分发形态）。
//!
//! 本模块实现 [`ferritls_core::ops::Sha256Compress`] 签名的块压缩函数：
//! 状态经 ABEF/CDGH 重排装入 XMM 寄存器，64 轮按每 4 轮一组展开，
//! 消息调度用 `SHA256MSG1/MSG2`、轮函数用 `SHA256RNDS2`，字节序转换用
//! `PSHUFB`。展开结构与 RustCrypto `sha2` 0.10 的 x86 后端逐行同源
//! （schedule = MSG1(v0,v1) + ALIGNR(v3,v2,4) → MSG2(·,v3)，12 步滑动
//! 窗口）；K 常量由脚本从 core `sha2.rs` 的锚定 `K256` 表程序化转写。
//! 正确性由差分测试（对软件路径全量一致）与安装 KAT
//! （FIPS 180-4 SHA-256("abc") 向量）双重锚定。
//!
//! **`#[target_feature]` 是性能关键**（见 `compress_kernel` 文档）：
//! 该工具链的 intrinsic 是带 feature 的安全函数，从无 feature 上下文
//! 调用时编译器不得内联——每个包装调用都成为真实函数调用，~200
//! 次/块会吃光 SHA-NI 的全部优势。kernel 进入 feature 上下文后直接
//! 调用 intrinsic（安全、编译为裸指令）；唯一的 unsafe 是
//! `compress_shani` 进入 feature 上下文的调用点（`#[allow(unsafe_code)]`
//! 单点，SAFETY = token 已证明 CPU 支持）。
//!
//! 常数时间：`SHA256RNDS2/MSG1/MSG2` 为数据无关固定延迟指令；本模块
//! 无以秘密为条件的分支或访存。

use std::sync::OnceLock;

use ferritls_core::ops::Sha256Compress;

use crate::raw;

use crate::token::ShaNi;

/// SHA-256 初始散列值（FIPS 180-4 §5.3.3），KAT 与差分参照用。
pub(crate) const IV256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 轮常量 K，按每 4 轮打包为 `(hi, lo)`（组内 K[4g+3..4g] 逆序装填，
/// 对应 `_mm_set_epi64x` 口径）。
const K_PACKED: [(u64, u64); 16] = [
    (0xE9B5DBA5B5C0FBCF, 0x71374491428A2F98),
    (0xAB1C5ED5923F82A4, 0x59F111F13956C25B),
    (0x550C7DC3243185BE, 0x12835B01D807AA98),
    (0xC19BF1749BDC06A7, 0x80DEB1FE72BE5D74),
    (0x240CA1CC0FC19DC6, 0xEFBE4786E49B69C1),
    (0x76F988DA5CB0A9DC, 0x4A7484AA2DE92C6F),
    (0xBF597FC7B00327C8, 0xA831C66D983E5152),
    (0x1429296706CA6351, 0xD5A79147C6E00BF3),
    (0x53380D134D2C6DFC, 0x2E1B213827B70A85),
    (0x92722C8581C2C92E, 0x766A0ABB650A7354),
    (0xC76C51A3C24B8B70, 0xA81A664BA2BFE8A1),
    (0x106AA070F40E3585, 0xD6990624D192E819),
    (0x34B0BCB52748774C, 0x1E376C0819A4C116),
    (0x682E6FF35B9CCA4F, 0x4ED8AA4A391C0CB3),
    (0x8CC7020884C87814, 0x78A5636F748F82EE),
    (0xC67178F2BEF9A3F7, 0xA4506CEB90BEFFFA),
];

/// 本后端的 SHA-NI 能力证明；`install_hash`/token 方法在探测成功后
/// 绑定，压缩函数指针只在绑定之后交出（crate 内不变式，同
/// [`crate::Backend`] 的 token 纪律）。
static SHA_TOKEN: OnceLock<ShaNi> = OnceLock::new();

/// 绑定能力证明（已绑定则忽略；所有 token 等价）。
pub(crate) fn bind_token(tok: ShaNi) {
    let _ = SHA_TOKEN.set(tok);
}

/// SHA-NI 块压缩 kernel。
///
/// **`#[target_feature]` 是本模块的性能关键**：该工具链的 intrinsic 是
/// 带 feature 的安全函数，从无 feature 上下文调用时编译器不得内联
/// （每次调用都是真实函数调用，~200 次调用/块会吃光 SHA-NI 的全部
/// 优势）；在启用了对应 feature 的函数内，intrinsic 调用是**安全**
/// 的（无需 unsafe 块）并编译为裸指令。
///
/// u32 状态与本机字节序的互转用 `to_le_bytes`（x86_64 恒为小端，
/// 等价于 C 实现的裸内存装载）。展开结构与 RustCrypto `sha2` 0.10
/// 的 x86 后端逐行同源。
#[target_feature(enable = "sha,ssse3,sse4.1")]
fn compress_kernel(h: &mut [u32; 8], block: &[u8; 64]) {
    use core::arch::x86_64::{
        _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_set_epi64x, _mm_sha256msg1_epu32,
        _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32, _mm_shuffle_epi8, _mm_shuffle_epi32,
    };

    // 装载状态并重排为 ABEF / CDGH 两半
    let mut bytes0 = [0u8; 16];
    let mut bytes4 = [0u8; 16];
    for i in 0..4 {
        bytes0[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_le_bytes());
        bytes4[i * 4..i * 4 + 4].copy_from_slice(&h[4 + i].to_le_bytes());
    }
    let tmp = _mm_shuffle_epi32::<0xB1>(raw::loadu(&bytes0)); // CDAB
    let mut state1 = _mm_shuffle_epi32::<0x1B>(raw::loadu(&bytes4)); // HGFE
    let mut state0 = _mm_alignr_epi8::<8>(tmp, state1); // ABEF
    state1 = _mm_blend_epi16::<0xF0>(state1, tmp); // CDGH

    let abef_save = state0;
    let cdgh_save = state1;

    // 字节序掩码：块按 4 字节字做大小端转换（PSHUFB）
    let mask = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b_i64, 0x0405_0607_0001_0203_i64);

    let load = |off: usize| {
        _mm_shuffle_epi8(
            raw::loadu(block[off..off + 16].try_into().expect("16 bytes")),
            mask,
        )
    };
    let mut w0 = load(0);
    let mut w1 = load(16);
    let mut w2 = load(32);
    let mut w3 = load(48);
    let mut w4;

    macro_rules! rounds4 {
        ($w:expr, $k:expr) => {{
            let t1 = _mm_add_epi32($w, _mm_set_epi64x($k.0 as i64, $k.1 as i64));
            state1 = _mm_sha256rnds2_epu32(state1, state0, t1);
            let t2 = _mm_shuffle_epi32::<0x0E>(t1);
            state0 = _mm_sha256rnds2_epu32(state0, state1, t2);
        }};
    }
    macro_rules! schedule4 {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
            let t1 = _mm_sha256msg1_epu32($v0, $v1);
            let t2 = _mm_alignr_epi8::<4>($v3, $v2);
            _mm_sha256msg2_epu32(_mm_add_epi32(t1, t2), $v3)
        }};
    }

    rounds4!(w0, K_PACKED[0]);
    rounds4!(w1, K_PACKED[1]);
    rounds4!(w2, K_PACKED[2]);
    rounds4!(w3, K_PACKED[3]);
    w4 = schedule4!(w0, w1, w2, w3);
    rounds4!(w4, K_PACKED[4]);
    w0 = schedule4!(w1, w2, w3, w4);
    rounds4!(w0, K_PACKED[5]);
    w1 = schedule4!(w2, w3, w4, w0);
    rounds4!(w1, K_PACKED[6]);
    w2 = schedule4!(w3, w4, w0, w1);
    rounds4!(w2, K_PACKED[7]);
    w3 = schedule4!(w4, w0, w1, w2);
    rounds4!(w3, K_PACKED[8]);
    w4 = schedule4!(w0, w1, w2, w3);
    rounds4!(w4, K_PACKED[9]);
    w0 = schedule4!(w1, w2, w3, w4);
    rounds4!(w0, K_PACKED[10]);
    w1 = schedule4!(w2, w3, w4, w0);
    rounds4!(w1, K_PACKED[11]);
    w2 = schedule4!(w3, w4, w0, w1);
    rounds4!(w2, K_PACKED[12]);
    w3 = schedule4!(w4, w0, w1, w2);
    rounds4!(w3, K_PACKED[13]);
    w4 = schedule4!(w0, w1, w2, w3);
    rounds4!(w4, K_PACKED[14]);
    w0 = schedule4!(w1, w2, w3, w4);
    rounds4!(w0, K_PACKED[15]);

    // 合并保存的状态并写回
    let state0 = _mm_add_epi32(state0, abef_save);
    let state1 = _mm_add_epi32(state1, cdgh_save);
    let tmp = _mm_shuffle_epi32::<0x1B>(state0); // FEBA
    let state1 = _mm_shuffle_epi32::<0xB1>(state1); // DCHG
    let state0 = _mm_blend_epi16::<0xF0>(tmp, state1); // DCBA
    let state1 = _mm_alignr_epi8::<8>(state1, tmp); // HGFE

    let out0 = raw::storeu(state0);
    let out1 = raw::storeu(state1);
    for i in 0..4 {
        h[i] = u32::from_le_bytes(out0[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        h[4 + i] = u32::from_le_bytes(out1[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
    }
}

/// 注册给 core 的压缩函数：token 检查 + 进入 feature 上下文。
///
/// SAFETY（唯一的 unsafe 调用点）：进入 `compress_kernel` 前已确认
/// 本机支持 `sha`/`ssse3`/`sse4.1`——token 只能经运行时探测构造，
/// 且仅在绑定后交出（crate 内不变式，同 [`crate::Backend`]）。
#[allow(unsafe_code)]
fn compress_shani(h: &mut [u32; 8], block: &[u8; 64]) {
    let tok = SHA_TOKEN
        .get()
        .expect("sha-ni token bound before compress registration");
    unsafe { compress_kernel(h, block) }
    let _ = tok;
}

/// 安装前 KAT：FIPS 180-4 的 SHA-256("abc") 已知答案。
///
/// 3 字节消息的填充（消息 + 0x80 + 零 + 64 位长度 = 12 字节）落在
/// 单块内：从 IV 压缩一次后与官方向量比对。
pub(crate) fn power_up_kat(tok: &ShaNi) -> Result<(), ferritls_core::Error> {
    bind_token(*tok);
    let mut h = IV256;
    let mut b1 = [0u8; 64];
    b1[..3].copy_from_slice(b"abc");
    b1[3] = 0x80;
    b1[56..64].copy_from_slice(&24u64.to_be_bytes());
    compress_shani(&mut h, &b1);
    let digest: Vec<u8> = h.iter().flat_map(|w| w.to_be_bytes()).collect();
    if digest != hexb("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
        return Err(ferritls_core::Error::SelfTestFailed("sha-ni-kat-sha256"));
    }
    Ok(())
}

fn hexb(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// 交出压缩函数（供 token 方法与后端工厂使用）。
pub(crate) fn compress_fn() -> Sha256Compress {
    compress_shani
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "abc" KAT 直接走压缩函数（不安装）。
    #[test]
    fn kat_abc() {
        let Some(tok) = ShaNi::detect() else {
            eprintln!("SHA-NI unavailable; skipping");
            return;
        };
        power_up_kat(&tok).expect("sha-ni KAT");
    }
}
