//! CTR-DRBG 测试（M5）。
//!
//! 向量来源：NIST CAVP DRBGVS `CTR_DRBG.rsp`（AES-256 no df，
//! PredictionResistance = False），2026-09-07 取自 NIST
//! drbgtestvectors.zip（drbgvectors_pr_false）。官方流程：
//! Instantiate → Reseed → Generate（丢弃）→ Generate → 比对
//! ReturnedBits；(ei, ps, eir, air, ai1, ai2, rb) 内嵌于本文件。
//! no-df 语义要点（与 CAVP 中间值核对得出）：seed_material 按
//! seedlen 异或折叠；Generate 末次 Update 无条件执行（AI 空则
//! provided_data = 0^seedlen）。

mod common;

use ferritls_core::drbg::CtrDrbg;

fn run_vector(ei: &str, ps: &str, eir: &str, air: &str, ai1: &str, ai2: &str, rb: &str) {
    let mut d = CtrDrbg::new(&common::hex(ei), &common::hex(ps)).expect("instantiate");
    d.reseed(&common::hex(eir), &common::hex(air))
        .expect("reseed");
    let mut discard = [0u8; 64];
    if ai1.is_empty() {
        d.generate(&mut discard).expect("generate 1");
    } else {
        d.generate_with_ai(&mut discard, Some(&common::hex(ai1)))
            .expect("generate 1");
    }
    let mut out = [0u8; 64];
    if ai2.is_empty() {
        d.generate(&mut out).expect("generate 2");
    } else {
        d.generate_with_ai(&mut out, Some(&common::hex(ai2)))
            .expect("generate 2");
    }
    common::assert_hex(&out, rb, "ReturnedBits");
}

#[test]
fn ctr_drbg_cavp_no_df_plain_c0() {
    run_vector(
        "f52b9e211605277c7720c9a6e252846e54d9f1ce442ed891c58dba70c58a8a3b59bbac22fa78dc2683be964a7b3349f3",
        "",
        "a16ae58c900fd2c89445d6b1775b4ed879b918a577622687e5e76685f05d04265058286a1a42794abe44ca798e32eda1",
        "",
        "",
        "",
        "5d2544951b74e09b8601c19c99301784938c595b4db3b2df474b10caad9e4930e1f0107662408ec374ddee05d84521e3e9ea7d2114f03f9a9a92ada6253cc3e5",
    );
}
#[test]
fn ctr_drbg_cavp_no_df_plain_c1() {
    run_vector(
        "cf1de61cffd8ed4e6ebe7246ef185557039792ebcb75081ba3f47fe4ee442b733274f42024d24d2e19940d88abcffe40",
        "",
        "a54d64421dab046606e167c862e557a4d4a8d5b4e86f2b269f8336af20d33d5ac531229279049e404c74956b753747b0",
        "",
        "",
        "",
        "692165d99365ee683b7148f7050a0abf2c3693b77725d2babea71fb7165bf7498e03ea8200e5c50fbc6bbcdc77499f5421385a09bbc6923827a328ee491431e6",
    );
}
#[test]
fn ctr_drbg_cavp_no_df_ai_c0() {
    run_vector(
        "20a8e7e47108cd4f283e5b169855bda83899516e51825bb52248ba8c405da44964502c9fc74da0e2ad4ca1f493134243",
        "",
        "98ba67c7e057a5a328bc9b223796b36947b1fca1ab6b20c1dd25142e949df27e8122c8a6792d8a1156a60b1170a3b5c4",
        "648fa229f5ea25ee6c7453ed577c70f755a2cb90f852b72b282d30bedebaf74af461a2a8a3456e653e7de9ef3740bc44",
        "daf5b64ba409b524c211a300465c631bd900453221023a41927b3d144da0131d89f74c0f18b029994ce84ec9b3684293",
        "6138156ccc58e759d762fb5db2c0926ade760ff531582f1bd8ef430f7f7ab623f82082ad58c2d629340945546bf94e2d",
        "db51c68e5dc6dc500dafa4d07836749df4fc54d0c8e78a3a01ad3162c2438d8aa1698c4ab6b448c3ebd37d23fae3c9ba6aad0912cd15475e9478d4793617a3ce",
    );
}
#[test]
fn ctr_drbg_cavp_no_df_ai_c1() {
    run_vector(
        "a781015e066eaee18f30135e518b87cebbb79c5f0afaa4ab21bb5ab808f09ffd8ccd2ad02606f8cdab95bf897e2bbb1b",
        "",
        "287e14ff5446a2eefd023f208bc8f583c80ddf84fa88e0a55c5a41414ffd1a7297d41017b3a37ef1290aed629e74376e",
        "a7a3d011fb2d7494e023d5de0c32642e0ebb765e0ce5e79dab2dcb7637480ba6110d7a07a3ad7c130139048f80a1c16b",
        "1786eb125d51cfff9164449ba2bacf9a216f4c45a685c07502bf074ce4a61a6ac640e2c1836f2e204598d51428839269",
        "d2fee3f2e3a00ee4bc3dbcd19c313cf74d5d34ab6219407efa16db64f726cdaa68692f8edd2abc871b08a33d2a9c922d",
        "94b2f16610cb7e300bd1bea6b4c3a8d671f2b87ef419d758dfd0217a3d3e462b5e3f5ec054d0934d701748d70fc891c487f715c881416a87240371e9532848fe",
    );
}
#[test]
fn ctr_drbg_cavp_no_df_pers_c0() {
    run_vector(
        "b5e2af38591a9743e5d3e458848a3998536d3b625e1694be847f95c3bfbda267f08624be4bb6aa496e1b596be523e7c4",
        "0a9a59e7605c0e12fae317bb004aecf1427bda4dca7718801895c38179fd36cd922634c3789a99b9d9c556fe50a41de4",
        "942ee972a599f346be15299d347823028469fc883c5e45479e9243df8710d1dc5c3073031e62f605f297479c5bcff993",
        "",
        "",
        "",
        "1f818218f06c9833f084c2b0ecd058d377b2d08c2943f4d24d2b5d7cad2ba49697dc3ad8d6c5c5af6372f02c1868756ca7b39b548cbf0d2bc5da2d11ed5c8f7f",
    );
}
#[test]
fn ctr_drbg_cavp_no_df_pers_c1() {
    run_vector(
        "60e9823004e29524138c8f8661657d1f04ccc418c5e2c677d26078bee024e7169063b147b7e09946468f4b9e34819748",
        "13aa6b6ca5e94d0f2a5b3f505f8eb3aac22fc393715cde101963ec87206912607d74a11f3c09a55afa18c5cc8ae11917",
        "4a16f67d280b34628597c6953ab5af3902b91b05c2c0c7c95366b99c7e6a9c30e876d1e3c634bd0377dc969ea119247d",
        "",
        "",
        "",
        "1b809bde832e7ab5f37273d7f1ccb4d7bbb1a11053cc72271c44f4d21a3efb9a06a54813911dc99ed01611f75757677ba892719cb6ce9dde262290453e4f00c3",
    );
}

#[test]
fn ctr_drbg_reseed_determinism() {
    // 相同熵（模式化、无 3 连重复）+ 空个性化 → 相同输出序列；
    // 换熵 → 序列改变。确定性路径 = generate（无 additional input）。
    let e1: Vec<u8> = (0..48u8).collect();
    let e2: Vec<u8> = (0..48u8).map(|b| b ^ 0x55).collect();
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
fn ctr_drbg_generate_limit() {
    // 超过单次生成上限（65536 字节）必须报 RngError 而非静默提供
    let e: Vec<u8> = (0..48u8).collect();
    let mut drbg = CtrDrbg::new(&e, b"").unwrap();
    let mut too_big = vec![0u8; 65537];
    assert_eq!(
        drbg.generate(&mut too_big),
        Err(ferritls_core::Error::RngError)
    );
    // 上限之内正常
    let mut ok = vec![0u8; 65536];
    assert!(drbg.generate(&mut ok).is_ok());
}

#[test]
fn ctr_drbg_mixed_path_differs_from_plain() {
    // 生产路径（每次生成混入 128 位 OS 熵）输出必须与确定性路径不同
    let e: Vec<u8> = (0..48u8).collect();
    let mut a = CtrDrbg::new(&e, b"").unwrap();
    let mut b = CtrDrbg::new(&e, b"").unwrap();
    let (mut oa, mut ob) = ([0u8; 32], [0u8; 32]);
    a.generate(&mut oa).unwrap();
    b.generate_mixed(&mut ob).unwrap();
    assert_ne!(oa, ob);
    // 生产实例化（OS 熵 + 健康测试）可用
    let _ = CtrDrbg::instantiate_from_os(b"tls13").unwrap();
}
