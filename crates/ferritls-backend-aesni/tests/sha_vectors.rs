//! SHA-NI 安装后的公开 API 向量测试（M8.2）。
//!
//! 独立测试二进制：`install_hash()` 是进程级的。安装后 core 的
//! `Sha256` 公开 API 走 SHA-NI 压缩路径，用著名向量与流式一致性
//! 锚定整条公开链路（缓冲/填充/分发/kernel）。CPU 不支持时跳过。

// 本 crate 仅 x86_64 有内容（aarch64 等目标为空壳，无 API 可引用）。
#![cfg(target_arch = "x86_64")]

mod common;

use common::assert_hex;
use ferritls_core::sha2::Sha256;

fn setup() -> bool {
    match ferritls_backend_aesni::install_hash() {
        Ok(()) => true,
        Err(e) => {
            eprintln!("sha-ni backend unavailable ({e:?}); skipping");
            false
        }
    }
}

/// 著名向量经公开 API（Ni 压缩路径）。
#[test]
fn ni_sha256_known_answers() {
    if !setup() {
        return;
    }
    assert_hex(
        &Sha256::one_shot(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256(empty)",
    );
    assert_hex(
        &Sha256::one_shot(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256(abc)",
    );
    assert_hex(
        &Sha256::one_shot(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256(448-bit msg, FIPS 180-4)",
    );
}

/// 边界长度（单块/双块收尾、整块+填充块）经 Ni 公开 API。锚值由
/// hashlib 2026-09 对 (i%256) 填充逐长度计算（55/56 字节案例与上方
/// FIPS 向量的软件双核对同源）。
#[test]
fn ni_sha256_boundary_lengths() {
    if !setup() {
        return;
    }
    for (len, expect) in [
        (
            55usize,
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
        ),
        (
            56usize,
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
        ),
        (
            63usize,
            "29af2686fd53374a36b0846694cc342177e428d1647515f078784d69cdb9e488",
        ),
        (
            64usize,
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        ),
        (
            65usize,
            "4bfd2c8b6f1eec7a2afeb48b934ee4b2694182027e6d0fc075074f2fabb31781",
        ),
    ] {
        let d: Vec<u8> = (0..len as u8).cycle().take(len).collect();
        assert_hex(&Sha256::one_shot(&d), expect, "boundary {len}");
    }
}

/// 流式（任意分块）与一次性摘要一致，含 Clone 中途分叉。
#[test]
fn ni_streaming_consistency() {
    if !setup() {
        return;
    }
    let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();

    let mut h = Sha256::new();
    h.update(&data);
    let whole = h.finalize();

    // 逐字节分块。
    let mut h = Sha256::new();
    for b in &data {
        h.update(std::slice::from_ref(b));
    }
    assert_eq!(h.finalize(), whole, "byte-wise streaming");

    // 64 字节整块 + 尾部分块（覆盖缓冲边界）。
    let mut h = Sha256::new();
    h.update(&data[..640]);
    h.update(&data[640..]);
    assert_eq!(h.finalize(), whole, "block-boundary streaming");

    // Clone 中途分叉。
    let mut h = Sha256::new();
    h.update(&data[..300]);
    let mut h2 = h.clone();
    h.update(&data[300..]);
    h2.update(&data[300..]);
    assert_eq!(h.finalize(), whole, "clone branch a");
    assert_eq!(h2.finalize(), whole, "clone branch b");

    // 边界长度：55（单块收尾）/ 56（双块收尾）/ 64（整块 + 填充块）。
    for len in [55usize, 56, 63, 64, 65] {
        let d: Vec<u8> = (0..len as u8).cycle().take(len).collect();
        let mut h = Sha256::new();
        h.update(&d);
        assert_eq!(h.finalize(), Sha256::one_shot(&d), "boundary {len}");
    }
}
