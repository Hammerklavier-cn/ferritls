//! AES-128-CCM 向量测试（M=16 参数集）。
//!
//! 来源：RFC 3610 §8 官方分组向量**没有** M=16 的用例（只有 M=8/M=10），
//! 而本实现按 TLS 1.3（RFC 8446 §B.5）固定 M=16。向量生成链：
//! python-cryptography（OpenSSL 后端）的 AESCCM 先与 RFC 3610 §8
//! Packet Vector #1（M=8/L=2/含 AAD，官方原文）逐字节核对通过后，
//! 用它生成 M=16 的期望值——生成器与官方文件逐字节锚定，满足
//! AGENTS.md 硬性规则 8。核对日期 2026-09-07。
//!
//! 覆盖：两种长度域（L=2 nonce13 / L=3 nonce12）、跨块边界
//! （15/16/17 字节）、空明文、空 AAD（Adata 位翻转路径）、篡改/
//! 错误 AAD/错误 nonce 拒绝、RFC 3610 §2.2 长度域拒绝。

mod common;

use common::assert_hex;
use ferritls_core::Error;
use ferritls_core::ccm::{Aes128Ccm, Aes128CcmTls};

const KEY: [u8; 16] = [
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
];
const AAD: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];

/// 与生成器一致的明文模式（byte(i) = (7i + 3) mod 256）。
fn pt(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 + 3) as u8).collect()
}

/// L=2（nonce 13 字节，RFC 3610 风格）M=16 期望值。
#[test]
fn ccm_m16_l2_official_derived_vectors() {
    let ccm = Aes128Ccm::new(&KEY);
    let nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    ];

    let cases: [(usize, &str); 6] = [
        (0, "6703297FA4923930C3A67804F1378C0C"),
        (1, "4A905CBF2E85D1953C174CBBB79FC54FF6"),
        (
            15,
            "4ABA6E962587CD247903A1ED053EE0ED276D5EB2E6B0E38946AE8E3F155F10",
        ),
        (
            16,
            "4ABA6E962587CD247903A1ED053EE022E066E5FFF9C00E9E9A14D6DE793FF1DA",
        ),
        (
            17,
            "4ABA6E962587CD247903A1ED053EE02219394EF73B527B94190A9BF5A9B7CBF840",
        ),
        (
            32,
            "4ABA6E962587CD247903A1ED053EE02219AB4EA41567E757170906D2BDCF2491D\
             467E3A858C2E04C464CA3056C86D883",
        ),
    ];
    for (len, expect) in cases {
        let out = ccm
            .seal(&nonce, AAD, &pt(len))
            .expect("within length domain");
        assert_hex(&out, expect, &format!("CCM M=16 L=2 pt={len}"));
        assert_eq!(
            ccm.open(&nonce, AAD, &out).expect("round trip"),
            pt(len),
            "L=2 pt={len} round trip"
        );
    }

    // 空 AAD：B0 的 Adata 位必须翻转为 0（独立期望值覆盖该分支）；
    // 且密文须与带 AAD 的 pt=16 用例完全一致（CTR 密钥流不依赖 AAD）。
    let out = ccm
        .seal(&nonce, b"", &pt(16))
        .expect("within length domain");
    assert_hex(
        &out,
        "4ABA6E962587CD247903A1ED053EE0228BC5E9A73F30E9ECD691EE503E98DEE9",
        "CCM M=16 L=2 pt=16 no-AAD",
    );
    assert_eq!(ccm.open(&nonce, b"", &out).expect("round trip"), pt(16));
}

/// L=3（nonce 12 字节，RFC 8446 §B.5 TLS 1.3 参数集）M=16 期望值。
#[test]
fn ccm_m16_l3_tls_official_derived_vectors() {
    let ccm = Aes128CcmTls::new(&KEY);
    let nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];

    let cases: [(usize, &str); 6] = [
        (0, "3AB6DDB101093DB8716B73038E19B255"),
        (1, "C0E489C84C544E5496DB58EEF90ECE03B7"),
        (
            15,
            "C0993292CEB4116988778997B6E4ACE01B3D3B838F99CDF202ECA2F6AC3904",
        ),
        (
            16,
            "C0993292CEB4116988778997B6E4AC48C92512B12B36A27A2106F93D9342061D",
        ),
        (
            17,
            "C0993292CEB4116988778997B6E4AC4822ED48C6052BC4F9A822616A37D1ECBC59",
        ),
        (
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E700\
             9F60B8FF8F81971ABF842A536DD73FB3",
        ),
    ];
    for (len, expect) in cases {
        let out = ccm
            .seal(&nonce, AAD, &pt(len))
            .expect("within length domain");
        assert_hex(&out, expect, &format!("CCM M=16 L=3 pt={len}"));
        assert_eq!(
            ccm.open(&nonce, AAD, &out).expect("round trip"),
            pt(len),
            "L=3 pt={len} round trip"
        );
    }
}

/// 认证失败面：篡改密文/标签、错误 AAD、错误 nonce、输入过短——
/// 全部统一返回 `VerificationFailed`，绝不 panic。
#[test]
fn ccm_rejects_tampered_and_mismatched_inputs() {
    let ccm = Aes128Ccm::new(&KEY);
    let nonce = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    ];
    let sealed = ccm
        .seal(&nonce, AAD, &pt(32))
        .expect("within length domain");

    // 逐字节篡改（密文区 + 标签区）都必须被拒绝
    for pos in [0, 1, 15, 16, 31, 32, 40, 47] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x01;
        assert_eq!(
            ccm.open(&nonce, AAD, &bad),
            Err(Error::VerificationFailed),
            "bit flip at byte {pos} must fail"
        );
    }
    // 错误 AAD / 空 AAD / 错误 nonce
    assert_eq!(
        ccm.open(&nonce, b"", &sealed),
        Err(Error::VerificationFailed)
    );
    assert_eq!(
        ccm.open(&nonce, b"other aad!", &sealed),
        Err(Error::VerificationFailed)
    );
    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 0x01;
    assert_eq!(
        ccm.open(&wrong_nonce, AAD, &sealed),
        Err(Error::VerificationFailed)
    );
    // 过短输入（0/8/15 字节）
    for n in [0usize, 8, 15] {
        assert_eq!(
            ccm.open(&nonce, AAD, &vec![0u8; n]),
            Err(Error::VerificationFailed)
        );
    }
}

/// RFC 3610 §2.2 长度域：明文 < 2^(8L)、AAD < 2^16 − 2^8。
/// 超限必须显式报错——此前实现会按位截断长度域继续运算
/// （静默产出不可互操作的密文），此处为回归门。
#[test]
fn ccm_length_domain_rejected() {
    let ccm = Aes128Ccm::new(&KEY);
    let nonce = [0u8; 13];
    let big = vec![0u8; 1 << 16]; // L=2 上限 65535
    assert_eq!(ccm.seal(&nonce, b"", &big), Err(Error::InvalidInput));
    // AAD 两字节编码上限 0xff00
    assert_eq!(
        ccm.seal(&nonce, &[0u8; 0xff00], &[0u8; 16]),
        Err(Error::InvalidInput)
    );

    let tls = Aes128CcmTls::new(&KEY);
    // L=3 上限 2^24：open 侧以超长输入覆盖同一检查（校验先于 AES 运算）
    assert_eq!(
        tls.open(&[0u8; 12], b"", &vec![0u8; 16 + (1 << 24)]),
        Err(Error::VerificationFailed)
    );
}
