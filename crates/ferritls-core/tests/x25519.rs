//! X25519 向量测试（M3）。
//!
//! 来源：RFC 7748 §6.1。向量为人工录入——启用前必须与 RFC 原文核对。

mod common;

use common::{assert_hex, hex};
use ferritls_core::ecdh::x25519;

#[test]
#[ignore = "M3: 待实现后启用（对照 RFC 7748 原文核对）"]
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

#[test]
#[ignore = "M3: RFC 7748 §5.2 迭代测试（1000 轮，实现正确性金标准）"]
fn x25519_rfc7748_iterated() {
    // k := u₀ = 9；重复 1000 次：u ← X25519(k, u)；k ← 旧 u。
    // 最终 u = 684cf59ba83309552800ef566f2f4d3c1c3887c49660241a9c99cea7e
    //          8ed52c3c90c106b6f74d95e9e46d2a1b00f5f1c1c (M3 时对照原文核对)
    // 慢测试，启用后建议 #[ignore] 保留为手动运行或 CI nightly job。
}
