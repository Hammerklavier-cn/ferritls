//! SHA-256/384/512 向量测试（M1）。
//!
//! 来源：NIST CAVP "SHAVS" 短消息样例（"abc"、空串、两块消息）。
//! 向量为人工录入——**启用前必须与官方文档逐字节核对**
//! （AGENTS.md 硬性规则 8）。

mod common;

use common::assert_hex;
use ferritls_core::sha2::{Sha256, Sha384, Sha512};

#[test]
fn sha256_known_answers() {
    assert_hex(
        &Sha256::one_shot(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256(\"abc\")",
    );
    assert_hex(
        &Sha256::one_shot(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "SHA-256(\"\")",
    );
    // 56 字节消息：跨块边界（块长 64）。
    assert_hex(
        &Sha256::one_shot(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "SHA-256(two-block message)",
    );
}

#[test]
fn sha384_known_answers() {
    assert_hex(
        &Sha384::one_shot(b"abc"),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
         8086072ba1e7cc2358baeca134c825a7",
        "SHA-384(\"abc\")",
    );
    assert_hex(
        &Sha384::one_shot(b""),
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
         274edebfe76f65fbd51ad2f14898b95b",
        "SHA-384(\"\")",
    );
}

#[test]
fn sha512_known_answers() {
    assert_hex(
        &Sha512::one_shot(b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
         2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA-512(\"abc\")",
    );
    assert_hex(
        &Sha512::one_shot(b""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
         47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "SHA-512(\"\")",
    );
}

#[test]
fn sha2_streaming_consistency() {
    let data: Vec<u8> = (0u8..200).collect();
    let mut h = Sha256::new();
    for chunk in data.chunks(7) {
        h.update(chunk);
    }
    assert_eq!(
        common::to_hex(&h.finalize()),
        common::to_hex(&Sha256::one_shot(&data)),
        "streaming == one_shot"
    );
}

// M1 扩展：引入完整 CAVP SHAVS 长消息/蒙特卡洛向量文件到
// tests/vectors/（路径约定见 AGENTS.md“测试体系”）。
