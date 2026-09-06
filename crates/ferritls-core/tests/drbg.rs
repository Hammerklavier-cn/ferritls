//! CTR-DRBG 测试（M5）。
//!
//! 向量来源：NIST CAVP DRBGVS（CTR_DRBG AES-256 no-derf 分组）。
//! 向量文件在 M5 引入 `tests/vectors/drbg/`（路径约定见 AGENTS.md），
//! 本文件先固化测试的调用形态。

mod common;

use ferritls_core::drbg::CtrDrbg;

#[test]
#[ignore = "M5: 待实现 + DRBGVS 向量引入后启用"]
fn ctr_drbg_known_answer() {
    // 形态：entropy + personalization → 首 generate 的输出与 CAVP 期望一致。
    // 具体向量取自 CAVP `CTR_DRBG.rsp`（AES-256, no derivation function），
    // M5 时随向量文件一并填充。
    let entropy = common::hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f");
    let mut drbg = CtrDrbg::new(&entropy, b"").expect("instantiate");
    let mut out = [0u8; 32];
    drbg.generate(&mut out).expect("generate");
    // assert_hex(&out, "<CAVP expected>", "CTR-DRBG first generate");
    let _ = out;
}

#[test]
#[ignore = "M5"]
fn ctr_drbg_reseed_determinism() {
    // 相同熵 + 相同个性化串 → 相同输出序列；换熵 → 序列改变。
    let e1 = [0x11u8; 48];
    let e2 = [0x22u8; 48];
    let mut a = CtrDrbg::new(&e1, b"").unwrap();
    let mut b = CtrDrbg::new(&e1, b"").unwrap();
    let mut c = CtrDrbg::new(&e2, b"").unwrap();
    let (mut oa, mut ob, mut oc) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    a.generate(&mut oa).unwrap();
    b.generate(&mut ob).unwrap();
    c.generate(&mut oc).unwrap();
    assert_eq!(oa, ob, "same entropy ⇒ same output");
    assert_ne!(oa, oc, "different entropy ⇒ different output");
}

#[test]
#[ignore = "M5: 超过单次生成上限必须报 RngError 而非静默提供"]
fn ctr_drbg_generate_limit() {
    let entropy = [0x33u8; 48];
    let mut drbg = CtrDrbg::new(&entropy, b"").unwrap();
    let mut too_big = vec![0u8; 65537];
    assert_eq!(
        drbg.generate(&mut too_big),
        Err(ferritls_core::Error::RngError)
    );
}
