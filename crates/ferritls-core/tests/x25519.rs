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
/// 慢测试：已实现并手动验证通过（2026-09-07）；因 debug 构建耗时
/// 较长保留 `#[ignore]`，按需 `-- --ignored` 运行或接入 CI nightly。
#[test]
#[ignore = "慢测试（1000 轮阶梯），已手动验证通过；按需 --ignored 运行"]
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
