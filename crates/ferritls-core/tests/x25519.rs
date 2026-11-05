//! X25519 向量测试（M3）。
//!
//! 来源：RFC 7748 §6.1。向量为人工录入——启用前必须与 RFC 原文核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::ecdh::x25519;

#[test]
fn x25519_rfc7748_diffie_hellman() {
    let alice_seed = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob_seed = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    let alice = x25519::SecretKey::from_seed(alice_seed.as_slice().try_into().unwrap());
    let bob = x25519::SecretKey::from_seed(bob_seed.as_slice().try_into().unwrap());

    assert_hex(
        &alice.public_key(),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "Alice public key",
    );
    assert_hex(
        &bob.public_key(),
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "Bob public key",
    );

    let ss_a = alice
        .diffie_hellman(&bob.public_key())
        .expect("Alice completes");
    let ss_b = bob
        .diffie_hellman(&alice.public_key())
        .expect("Bob completes");
    let shared_hex = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    assert_hex(ss_a.as_bytes(), shared_hex, "shared secret (Alice)");
    assert_hex(ss_b.as_bytes(), shared_hex, "shared secret (Bob)");
}

/// RFC 7748 §5.2 迭代测试（1000 轮，实现正确性金标准）。
///
/// debug 构建 ~1.6 s（2026-11 实测），直接常跑——曾因耗时长被
/// `#[ignore]` 并交由 CI 慢测试 job 按需运行，该 job 随之取消。
#[test]
fn x25519_rfc7748_iterated() {
    // k、u 初始均为 9（32 字节 LE 编码）；每轮 k ← X25519(k, u)，
    // u ← 旧 k；最终结果为 k（RFC 7748 §5.2 原文核对 2026-09-07）。
    let mut k = [0u8; 32];
    let mut u = [0u8; 32];
    k[0] = 9;
    u[0] = 9;
    for round in 0..1000 {
        let sk = x25519::SecretKey::from_seed(k);
        let out = sk.diffie_hellman(&u).expect("valid point");
        u = k;
        k.copy_from_slice(out.as_bytes());
        if round == 0 {
            // RFC 7748 §5.2 给出的单轮锚值
            assert_hex(
                &k,
                "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                "after one iteration",
            );
        }
    }
    assert_hex(
        &k,
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
        "after 1000 iterations",
    );
}

/// 小阶点直接拒绝：全零 u（无穷远）与 u=1（阶 1）的输出为全零，
/// 必须返回 `VerificationFailed`（AGENTS §5.2：TLS 层必须终止握手）。
/// Wycheproof 的 LowOrderPublic 组以对拍形式覆盖同一路径；此处直接
/// 断言错误值，防止契约被无意放宽。
#[test]
fn x25519_low_order_points_rejected() {
    let sk = x25519::SecretKey::from_seed([9u8; 32]);
    for (what, u) in [
        ("u = 0 (infinity)", [0u8; 32]),
        ("u = 1 (order 1)", {
            let mut u = [0u8; 32];
            u[0] = 1;
            u
        }),
    ] {
        let got = sk.diffie_hellman(&u).err();
        assert!(
            matches!(got, Some(ferritls_core::Error::VerificationFailed)),
            "{what} must be rejected with VerificationFailed, got {got:?}"
        );
    }
}

/// 对端公钥长度非法（0/31/33 字节）必须返回 `InvalidInput`（ecdh.rs
/// 的 `try_into::<[u8; 32]>` 守护）：错误变体钉死——既不得放宽为
/// `VerificationFailed`，也不得 panic（AGENTS §5.2：TLS 层两种非法
/// 编码都要终止握手）。
#[test]
fn x25519_peer_key_wrong_length_rejected() {
    let alice_seed = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice = x25519::SecretKey::from_seed(alice_seed.as_slice().try_into().unwrap());

    for len in [0usize, 31, 33] {
        let peer = vec![0x09u8; len];
        assert_eq!(
            alice.diffie_hellman(&peer).map(|_| ()),
            Err(ferritls_core::Error::InvalidInput),
            "peer key len {len} must be InvalidInput"
        );
    }
}

/// RFC 7748 §5 钳制钉子：`from_seed` 必须清除字节 0 的低 3 位与
/// 字节 31 的最高位、置位字节 31 的 bit 6——同一标量在脏位/清位两
/// 种种子形态下必须导出同一公钥，并与手工钳制结果一致。公钥同时
/// 锚定 RFC 7748 §6.1 的 Alice 官方值（钳制语义被绕过时立即暴露）。
#[test]
fn x25519_from_seed_clamps_dirty_bits() {
    let alice_seed = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");

    // 脏位种子：字节 0 低 3 位、字节 31 最高位置 1（均属钳制清除域）；
    // 清位种子：同两处清 0。
    let mut dirty = alice_seed.clone();
    dirty[0] |= 0x07;
    dirty[31] |= 0x80;
    let mut clean = alice_seed.clone();
    clean[0] &= !0x07;
    clean[31] &= !0x80;

    // 手工钳制（RFC 7748 §5 的逐位定义）
    let mut manual = dirty.clone();
    manual[0] &= 248;
    manual[31] &= 127;
    manual[31] |= 64;

    let via_dirty = x25519::SecretKey::from_seed(dirty.as_slice().try_into().unwrap()).public_key();
    let via_clean = x25519::SecretKey::from_seed(clean.as_slice().try_into().unwrap()).public_key();
    let via_manual =
        x25519::SecretKey::from_seed(manual.as_slice().try_into().unwrap()).public_key();

    assert_eq!(
        via_dirty, via_manual,
        "dirty seed must clamp to the same scalar"
    );
    assert_eq!(
        via_clean, via_manual,
        "clean seed must clamp to the same scalar"
    );
    assert_hex(
        &via_dirty,
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "clamped RFC 7748 §6.1 Alice public key",
    );
}
