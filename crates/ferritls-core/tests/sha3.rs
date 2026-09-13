//! SHA3-256/512 与 SHAKE-128/256 向量测试（M8.3）。
//!
//! 来源：
//! - FIPS 202 官方示例（"abc"、空串、448/896 位填充边界与两块消息）；
//! - FIPS 203 附录 A 的 ML-KEM 域分隔示例（见 `sha3.rs` 内联测试）。
//!
//! 向量为人工录入——**启用前必须与官方文档逐字节核对**（AGENTS.md
//! 硬性规则 7/8）：上述全部值经 python hashlib（OpenSSL 后端）独立
//! 复算一致，并与 RustCrypto `ml-kem`（ACVP 全绿实现）测试常量交叉
//! 核对（2026-09-13）。

mod common;

use common::assert_hex;
use ferritls_core::sha3::{Shake128, Shake256, sha3_256, sha3_512};

const M56: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const M100: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

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
