//! SHA3-224/256/384/512 与 SHAKE-128/256 向量测试（M8.3；224/384 补全）。
//!
//! 来源：
//! - FIPS 202 官方示例（"abc"、空串、448/896 位填充边界与两块消息）；
//! - FIPS 203 附录 A 的 ML-KEM 域分隔示例（见 `sha3.rs` 内联测试）。
//!
//! 向量为人工录入——**启用前必须与官方文档逐字节核对**（AGENTS.md
//! 硬性规则 7/8）：上述全部值经 python hashlib（OpenSSL 后端）独立
//! 复算一致，并与 RustCrypto `ml-kem`（ACVP 全绿实现）测试常量交叉
//! 核对（2026-09-13）；SHA3-224/384 四组同日生成，其中 "abc"/空串
//! 两组另与 Keccak 团队公布的 FIPS 202 示例向量逐字节比对一致
//! （2026-09-17）。

mod common;

use common::assert_hex;
use ferritls_core::sha3::{Shake128, Shake256, sha3_224, sha3_256, sha3_384, sha3_512};

const M56: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const M100: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

#[test]
fn sha3_224_known_answers() {
    assert_hex(
        &sha3_224(b"abc"),
        "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        "SHA3-224(\"abc\")",
    );
    assert_hex(
        &sha3_224(b""),
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
        "SHA3-224(\"\")",
    );
    // 56 字节：144 字节率之内（单块，rate−1 填充转折）。
    assert_hex(
        &sha3_224(M56),
        "8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
        "SHA3-224(448-bit message)",
    );
    // 100 字节：两块消息。
    assert_hex(
        &sha3_224(M100),
        "543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
        "SHA3-224(896-bit message)",
    );
}

#[test]
fn sha3_256_known_answers() {
    assert_hex(
        &sha3_256(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3-256(\"abc\")",
    );
    assert_hex(
        &sha3_256(b""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        "SHA3-256(\"\")",
    );
    // 56 字节：恰好 136 字节率之内的填充转折（rate−1 全零填充段起点）。
    assert_hex(
        &sha3_256(M56),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        "SHA3-256(448-bit message)",
    );
    // 100 字节：两块消息。
    assert_hex(
        &sha3_256(M100),
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
        "SHA3-256(896-bit message)",
    );
}

#[test]
fn sha3_512_known_answers() {
    assert_hex(
        &sha3_512(b"abc"),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
         10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
        "SHA3-512(\"abc\")",
    );
    assert_hex(
        &sha3_512(b""),
        "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
         15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        "SHA3-512(\"\")",
    );
    assert_hex(
        &sha3_512(M56),
        "04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636d\
         ee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
        "SHA3-512(448-bit message)",
    );
    assert_hex(
        &sha3_512(M100),
        "afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa\
         73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185",
        "SHA3-512(896-bit message)",
    );
}

#[test]
fn sha3_384_known_answers() {
    assert_hex(
        &sha3_384(b"abc"),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b2\
         98d88cea927ac7f539f1edf228376d25",
        "SHA3-384(\"abc\")",
    );
    assert_hex(
        &sha3_384(b""),
        "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2a\
         c3713831264adb47fb6bd1e058d5f004",
        "SHA3-384(\"\")",
    );
    assert_hex(
        &sha3_384(M56),
        "991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5a\
         a04a1f076e62fea19eef51acd0657c22",
        "SHA3-384(448-bit message)",
    );
    assert_hex(
        &sha3_384(M100),
        "79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc\
         8c709b98b43b3852b337216179aa7fc7",
        "SHA3-384(896-bit message)",
    );
}

#[test]
fn shake_known_answers() {
    let mut s = Shake128::new();
    s.update(b"abc");
    let mut x = s.finalize_xof();
    let mut out = [0u8; 32];
    x.fill(&mut out);
    assert_hex(
        &out,
        "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8",
        "SHAKE128(\"abc\", 32)",
    );

    let mut s = Shake256::new();
    s.update(b"abc");
    let mut x = s.finalize_xof();
    let mut out = [0u8; 32];
    x.fill(&mut out);
    assert_hex(
        &out,
        "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
        "SHAKE256(\"abc\", 32)",
    );

    // 空输入 + 超过单个 rate（136）的挤出长度：跨块挤出路径。
    let s = Shake128::new();
    let mut x = s.finalize_xof();
    let mut out = [0u8; 64];
    x.fill(&mut out);
    assert_hex(
        &out,
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\
         3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
        "SHAKE128(\"\", 64)",
    );

    let s = Shake256::new();
    let mut x = s.finalize_xof();
    let mut out = [0u8; 64];
    x.fill(&mut out);
    assert_hex(
        &out,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
        "SHAKE256(\"\", 64)",
    );
}

/// 多块消息 + 分块吸收与一次性吸收一致（参照值经 python hashlib
/// 独立复算，2026-09-13）。
#[test]
fn shake_multiblock_and_split_equivalence() {
    let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
    for split in [0usize, 1, 63, 64, 65, 299] {
        let (a, b) = data.split_at(split);
        let mut s = Shake256::new();
        s.update(a);
        s.update(b);
        let mut x = s.finalize_xof();
        let mut out = [0u8; 64];
        x.fill(&mut out);
        assert_hex(
            &out,
            "bced6f4208dce0e6bc155ae057d0589bbfa798b46c7866d107e8d14aee3a46e9\
             a292d82d60f77802cadfa9a46c8142a7268863fbb6f64007d6e9fd44334f0ece",
            "SHAKE256(pattern, 64) split at {split}",
        );

        let mut s = Shake128::new();
        s.update(a);
        s.update(b);
        let mut x = s.finalize_xof();
        let mut out = [0u8; 48];
        x.fill(&mut out);
        assert_hex(
            &out,
            "acbf138b9ceb3b4f0b2a78bf886f2f2b286af964f200f8784af97e6db5885558\
             5e2832c19fa70bc490450ac14326f76a",
            "SHAKE128(pattern, 48) split at {split}",
        );
    }
}

/// 零长度挤出切片：`fill(&mut [])` 必须为空操作——不 panic、不消耗
/// 挤出流（随后挤出的字节与一次性直接挤出完全一致）。两个 SHAKE
/// 实例全部覆盖。
#[test]
fn shake_fill_empty_slice_is_noop() {
    let mut x = Shake128::new().finalize_xof();
    x.fill(&mut []);
    let mut after_empty = [0u8; 32];
    x.fill(&mut after_empty);

    let mut direct = Shake128::new().finalize_xof();
    let mut whole = [0u8; 32];
    direct.fill(&mut whole);
    assert_eq!(
        after_empty, whole,
        "SHAKE128: empty fill must not consume the stream"
    );

    let mut x = Shake256::new().finalize_xof();
    x.fill(&mut []);
    let mut after_empty = [0u8; 32];
    x.fill(&mut after_empty);

    let mut direct = Shake256::new().finalize_xof();
    let mut whole = [0u8; 32];
    direct.fill(&mut whole);
    assert_eq!(
        after_empty, whole,
        "SHAKE256: empty fill must not consume the stream"
    );
}

/// 挤出跨越 rate 边界的精确切分等价：先挤出恰 rate 字节（SHAKE-128
/// = 168、SHAKE-256 = 136）再继续挤出，与一次性挤出 2×rate 逐字节
/// 一致——第一段恰好在 `pos == rate` 处触发置换后归零的路径回归门
/// （fill 拆分若使内部位置/计数漂移立即暴露）。
#[test]
fn shake_fill_splits_equivalent_at_exact_rate_boundary() {
    const RATE128: usize = 168;
    const RATE256: usize = 136;

    let mut x = Shake128::new().finalize_xof();
    let mut split = vec![0u8; 2 * RATE128];
    x.fill(&mut split[..RATE128]);
    x.fill(&mut split[RATE128..]);
    let mut direct = Shake128::new().finalize_xof();
    let mut whole = vec![0u8; 2 * RATE128];
    direct.fill(&mut whole);
    assert_eq!(
        split, whole,
        "SHAKE128: split at exact rate must equal one-shot"
    );

    let mut x = Shake256::new().finalize_xof();
    let mut split = vec![0u8; 2 * RATE256];
    x.fill(&mut split[..RATE256]);
    x.fill(&mut split[RATE256..]);
    let mut direct = Shake256::new().finalize_xof();
    let mut whole = vec![0u8; 2 * RATE256];
    direct.fill(&mut whole);
    assert_eq!(
        split, whole,
        "SHAKE256: split at exact rate must equal one-shot"
    );
}

/// 空段吸收：`update(b"")` 后 finalize 与不 update 直接 finalize 的
/// 挤出流逐字节一致（海绵状态不得被空段扰动；SHAKE-128/256 双实例）。
/// SHA3-256 的空消息 KAT 已由 `sha3_256_known_answers` 覆盖，不重复。
#[test]
fn shake_empty_update_matches_no_update() {
    let mut with_empty = Shake128::new();
    with_empty.update(b"");
    let mut a = with_empty.finalize_xof();
    let mut out_a = [0u8; 64];
    a.fill(&mut out_a);
    let mut b = Shake128::new().finalize_xof();
    let mut out_b = [0u8; 64];
    b.fill(&mut out_b);
    assert_eq!(out_a, out_b, "SHAKE128: update(\"\") must be a no-op");

    let mut with_empty = Shake256::new();
    with_empty.update(b"");
    let mut a = with_empty.finalize_xof();
    let mut out_a = [0u8; 64];
    a.fill(&mut out_a);
    let mut b = Shake256::new().finalize_xof();
    let mut out_b = [0u8; 64];
    b.fill(&mut out_b);
    assert_eq!(out_a, out_b, "SHAKE256: update(\"\") must be a no-op");
}

// ---------------------------------------------------------------------------
// NIST CAVP SHA3VS 完整导入：长消息 + 蒙特卡洛 + SHAKE 变长输出
// （2026-11 测试完备性轮）。JSON 在 tests/vectors/shs/，由
// tools/extract_shavs.py 从官方 .rsp 提取——脚本内以 hashlib 逐字节
// 复算全部用例核对后才落盘。SHA-3 Monte 按 SHA3VS Figure 1：
// Msg = 单个前序 MD 链式哈希（与 SHA-2 的三摘要拼接不同），每检查
// 点 1000 次迭代、共 100 检查点。
// ---------------------------------------------------------------------------

fn load_shs(name: &str) -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/shs/").to_string() + name;
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("parse {path}: {e}"))
}

fn shavs_str<'a>(v: &'a serde_json::Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} not a string"))
}

macro_rules! shavs_sha3_long {
    ($test:ident, $file:literal, $hash:ident) => {
        #[test]
        fn $test() {
            let doc = load_shs($file);
            let cases = doc["cases"].as_array().expect("cases array");
            assert!(!cases.is_empty(), "no cases loaded");
            for c in cases.iter() {
                let msg = common::hex(shavs_str(c, "msg"));
                assert_eq!(msg.len() * 8, c["len"].as_u64().unwrap_or(0) as usize);
                assert_hex(&$hash(&msg), shavs_str(c, "md"), "SHAVS LongMsg case");
            }
        }
    };
}

/// SHAKE LongMsg：Outputlen 节头指定变长输出（位长），XOF fill 锚定。
macro_rules! shavs_shake_long {
    ($test:ident, $file:literal, $shake:ident) => {
        #[test]
        fn $test() {
            let doc = load_shs($file);
            let cases = doc["cases"].as_array().expect("cases array");
            assert!(!cases.is_empty(), "no cases loaded");
            for c in cases.iter() {
                let msg = common::hex(shavs_str(c, "msg"));
                let outlen = c["outputlen"].as_u64().expect("outputlen") as usize;
                assert_eq!(msg.len() * 8, c["len"].as_u64().unwrap_or(0) as usize);
                let mut out = vec![0u8; outlen / 8];
                let mut xof = $shake::new();
                xof.update(&msg);
                xof.finalize_xof().fill(&mut out);
                assert_hex(&out, shavs_str(c, "md"), "SHAVS SHAKE case");
            }
        }
    };
}

macro_rules! shavs_sha3_monte {
    ($test:ident, $file:literal, $hash:ident, $md_len:literal) => {
        #[test]
        fn $test() {
            let doc = load_shs($file);
            let seed = common::hex(shavs_str(&doc, "seed"));
            let mds = doc["mds"].as_array().expect("mds array");
            assert_eq!(mds.len(), 100, "100 checkpoints");
            let mut s = seed;
            for (j, want) in mds.iter().enumerate() {
                let mut md = [0u8; $md_len];
                for _ in 0..1000 {
                    md = $hash(&s);
                    s = md.to_vec();
                }
                let want = want
                    .as_str()
                    .unwrap_or_else(|| panic!("checkpoint {j} not a string"));
                assert_hex(&md, want, "SHAVS Monte checkpoint {j}");
            }
        }
    };
}

shavs_sha3_long!(
    shavs_sha3_256_long_messages,
    "SHA3_256LongMsg.json",
    sha3_256
);
shavs_sha3_long!(
    shavs_sha3_384_long_messages,
    "SHA3_384LongMsg.json",
    sha3_384
);
shavs_sha3_long!(
    shavs_sha3_512_long_messages,
    "SHA3_512LongMsg.json",
    sha3_512
);
shavs_sha3_monte!(
    shavs_sha3_256_monte_carlo,
    "SHA3_256Monte.json",
    sha3_256,
    32
);
shavs_sha3_monte!(
    shavs_sha3_384_monte_carlo,
    "SHA3_384Monte.json",
    sha3_384,
    48
);
shavs_sha3_monte!(
    shavs_sha3_512_monte_carlo,
    "SHA3_512Monte.json",
    sha3_512,
    64
);
shavs_shake_long!(
    shavs_shake128_long_messages,
    "SHAKE128LongMsg.json",
    Shake128
);
shavs_shake_long!(
    shavs_shake256_long_messages,
    "SHAKE256LongMsg.json",
    Shake256
);
