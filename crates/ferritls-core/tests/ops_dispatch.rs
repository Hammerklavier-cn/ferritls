//! ops 分发语义测试（M8.1 接线）。
//!
//! 覆盖：软件默认路径锚定（SHA-256 "abc" 官方向量 + GCM 密封性）、
//! 后端安装后公开类型真实分发（可观测的 mock 行为）、二次安装拒绝、
//! 批准模式下安装拒绝。mock 安装是进程级的——本测试二进制**只**含
//! 分发测试，避免污染其他向量测试（它们必须始终运行在软件默认
//! 路径上）。

mod common;

use ferritls_core::gcm::Aes128Gcm;
use ferritls_core::ops::{self, AeadGcm, AeadOps};
use ferritls_core::sha2::Sha256;

// —— mock 后端：行为刻意与任何真密码学不同，使分发路径可观测 ——

struct MockAead;

struct MockGcm;

impl AeadGcm for MockGcm {
    fn seal(&self, _nonce: &[u8; 12], _aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        buf.fill(0xAA);
        [0xBB; 16]
    }

    fn open_compute_tag(&self, _nonce: &[u8; 12], _aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        buf.fill(0xCC);
        [0xDD; 16]
    }

    fn clone_box(&self) -> Box<dyn AeadGcm> {
        Box::new(MockGcm)
    }
}

impl AeadOps for MockAead {
    fn name(&self) -> &'static str {
        "mock-aead"
    }

    fn aes128_gcm(&self, _key: &[u8; 16]) -> Box<dyn AeadGcm> {
        Box::new(MockGcm)
    }

    fn aes256_gcm(&self, _key: &[u8; 32]) -> Box<dyn AeadGcm> {
        Box::new(MockGcm)
    }
}

static MOCK_AEAD: MockAead = MockAead;

/// 软件默认路径 + 分发生效 + 安装语义（非批准构建）。
///
/// 顺序敏感：mock 安装是进程级且不可撤销，所有软件路径断言必须在
/// 安装之前完成。
#[cfg(not(feature = "fips"))]
#[test]
fn dispatch_and_install_semantics() {
    // 1) 默认软件路径不受接线影响：SHA-256("abc")，FIPS 180-4 官方向量锚
    //    （SHA-2 分发接线推迟到 SHA-NI 阶段，此处仍是纯软件直连）。
    let d = Sha256::one_shot(b"abc");
    common::assert_hex(
        &d,
        "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
        "sha256(abc)",
    );

    // GCM 软件默认路径：往返 + 密封性 + Clone 一致（完整向量在
    // aes_gcm.rs）。
    let g = Aes128Gcm::new(&[0x07; 16]);
    let sealed = g.seal(&[0x01; 12], b"aad", b"secret");
    assert_eq!(
        g.open(&[0x01; 12], b"aad", &sealed).unwrap(),
        b"secret".to_vec()
    );
    let mut tampered = sealed.clone();
    tampered[0] ^= 1;
    assert_eq!(
        g.open(&[0x01; 12], b"aad", &tampered),
        Err(ferritls_core::Error::VerificationFailed)
    );
    let g2 = g.clone();
    assert_eq!(
        g2.open(&[0x01; 12], b"aad", &sealed).unwrap(),
        b"secret".to_vec()
    );

    // 2) 安装 mock 后端 → 新实例分发可观测。
    ops::install(&MOCK_AEAD).expect("first install succeeds");
    let mock_g = Aes128Gcm::new(&[0x07; 16]);
    let mock_sealed = mock_g.seal(&[0x01; 12], b"aad", b"xy");
    assert_eq!(
        mock_sealed,
        [vec![0xAA, 0xAA], vec![0xBB; 16]].concat(),
        "seal must route through the mock backend"
    );
    // open：mock 计算标签 0xDD.. 与 seal 的 0xBB.. 不匹配 → 统一失败。
    assert_eq!(
        mock_g.open(&[0x01; 12], b"aad", &mock_sealed),
        Err(ferritls_core::Error::VerificationFailed)
    );

    // 3) 二次安装（含同一后端）拒绝。
    assert_eq!(
        ops::install(&MOCK_AEAD),
        Err(ferritls_core::Error::Unsupported)
    );
}

/// 批准模式（`fips` feature 构建）：一切安装被拒绝，软件路径固定。
#[cfg(feature = "fips")]
#[test]
fn fips_refuses_install() {
    assert_eq!(
        ops::install(&MOCK_AEAD),
        Err(ferritls_core::Error::Unsupported)
    );
    // 软件路径仍然可用。
    let d = Sha256::one_shot(b"abc");
    common::assert_hex(
        &d,
        "ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad",
        "sha256(abc) under fips build",
    );
    let g = Aes128Gcm::new(&[0x07; 16]);
    let sealed = g.seal(&[0x01; 12], b"aad", b"secret");
    assert_eq!(
        g.open(&[0x01; 12], b"aad", &sealed).unwrap(),
        b"secret".to_vec()
    );
}
