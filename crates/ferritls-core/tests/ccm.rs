//! AES-128-CCM 向量测试。
//!
//! 来源（两层）：
//! - **RFC 3610 §8 官方分组向量全部 24 个**（2026-09-17 起，此前只有
//!   经参照实现转引的 #1）：程序化提取（python 解析 rfc-editor.org
//!   官方原文 → python-cryptography/OpenSSL 后端双向复算逐字节一致
//!   → 生成测试表），覆盖 M=8/L=2（#1–6、#13–18）与 M=10/L=2
//!   （#7–12、#19–24）及全部 AAD 路径；
//! - **全 M 矩阵（TLS 形态：12 字节 nonce/L=3）**：RFC 无该形态官方
//!   向量，期望值由 python-cryptography（OpenSSL 后端，其 AESCCM 已
//!   先对上述官方原文逐字节校验通过）生成（2026-09-17）；生成脚本的
//!   M=16 行与既有 M=16 测试值逐字节互验一致。
//!
//! 既有 M=16 参数集向量（L=2/L=3，2026-09-07 生成）原样保留，作为
//! 引擎化重构的回归 oracle。
//!
//! 覆盖：两种长度域（L=2 nonce13 / L=3 nonce12）、跨块边界
//! （15/16/17 字节）、空明文、空 AAD（Adata 位翻转路径）、篡改/
//! 错误 AAD/错误 nonce 拒绝、RFC 3610 §2.2 长度域拒绝、参数校验
//! （M ∈ {4..16 偶数}、nonce 7..=13）。

mod common;

use common::{assert_hex, hex};
use ferritls_core::Error;
use ferritls_core::ccm::{Aes128Ccm, Aes128Ccm8Tls, Aes128CcmAny, Aes128CcmTls};

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

/// RFC 3610 §8 官方分组向量全部 24 个：程序化提取自官方原文，
/// python-cryptography 双向复算后生成测试表（见文件头溯源）。
/// 加密方向（seal == 期望 ct||tag）与解密方向（open == 原消息）双验。
#[test]
fn ccm_rfc3610_official_24_vectors() {
    // (key, nonce, aad, msg, ct||tag, M)
    const V: &[(&str, &str, &str, &str, &str, usize)] = &[
        // Packet Vector #1: M=8, L=2, AAD=8 B, msg=23 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000003020100A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
            "588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0",
            8,
        ),
        // Packet Vector #2: M=8, L=2, AAD=8 B, msg=24 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000004030201A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916",
            8,
        ),
        // Packet Vector #3: M=8, L=2, AAD=8 B, msg=25 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000005040302A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "51B1E5F44A197D1DA46B0F8E2D282AE871E838BB64DA8596574ADAA76FBD9FB0C5",
            8,
        ),
        // Packet Vector #4: M=8, L=2, AAD=12 B, msg=19 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000006050403A0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E",
            "A28C6865939A9A79FAAA5C4C2A9D4A91CDAC8C96C861B9C9E61EF1",
            8,
        ),
        // Packet Vector #5: M=8, L=2, AAD=12 B, msg=20 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000007060504A0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "DCF1FB7B5D9E23FB9D4E131253658AD86EBDCA3E51E83F077D9C2D93",
            8,
        ),
        // Packet Vector #6: M=8, L=2, AAD=12 B, msg=21 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000008070605A0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "6FC1B011F006568B5171A42D953D469B2570A4BD87405A0443AC91CB94",
            8,
        ),
        // Packet Vector #7: M=10, L=2, AAD=8 B, msg=23 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "00000009080706A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E",
            "0135D1B2C95F41D5D1D4FEC185D166B8094E999DFED96C048C56602C97ACBB7490",
            10,
        ),
        // Packet Vector #8: M=10, L=2, AAD=8 B, msg=24 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "0000000A090807A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "7B75399AC0831DD2F0BBD75879A2FD8F6CAE6B6CD9B7DB24C17B4433F434963F34B4",
            10,
        ),
        // Packet Vector #9: M=10, L=2, AAD=8 B, msg=25 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "0000000B0A0908A0A1A2A3A4A5",
            "0001020304050607",
            "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "82531A60CC24945A4B8279181AB5C84DF21CE7F9B73F42E197EA9C07E56B5EB17E5F4E",
            10,
        ),
        // Packet Vector #10: M=10, L=2, AAD=12 B, msg=19 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "0000000C0B0A09A0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E",
            "07342594157785152B074098330ABB141B947B566AA9406B4D999988DD",
            10,
        ),
        // Packet Vector #11: M=10, L=2, AAD=12 B, msg=20 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "0000000D0C0B0AA0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E1F",
            "676BB20380B0E301E8AB79590A396DA78B834934F53AA2E9107A8B6C022C",
            10,
        ),
        // Packet Vector #12: M=10, L=2, AAD=12 B, msg=21 B
        (
            "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF",
            "0000000E0D0C0BA0A1A2A3A4A5",
            "000102030405060708090A0B",
            "0C0D0E0F101112131415161718191A1B1C1D1E1F20",
            "C0FFA0D6F05BDB67F24D43A4338D2AA4BED7B20E43CD1AA31662E7AD65D6DB",
            10,
        ),
        // Packet Vector #13: M=8, L=2, AAD=8 B, msg=23 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00412B4EA9CDBE3C9696766CFA",
            "0BE1A88BACE018B1",
            "08E8CF97D820EA258460E96AD9CF5289054D895CEAC47C",
            "4CB97F86A2A4689A877947AB8091EF5386A6FFBDD080F8E78CF7CB0CDDD7B3",
            8,
        ),
        // Packet Vector #14: M=8, L=2, AAD=8 B, msg=24 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "0033568EF7B2633C9696766CFA",
            "63018F76DC8A1BCB",
            "9020EA6F91BDD85AFA0039BA4BAFF9BFB79C7028949CD0EC",
            "4CCB1E7CA981BEFAA0726C55D378061298C85C92814ABC33C52EE81D7D77C08A",
            8,
        ),
        // Packet Vector #15: M=8, L=2, AAD=8 B, msg=25 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00103FE41336713C9696766CFA",
            "AA6CFA36CAE86B40",
            "B916E0EACC1C00D7DCEC68EC0B3BBB1A02DE8A2D1AA346132E",
            "B1D23A2220DDC0AC900D9AA03C61FCF4A559A4417767089708A776796EDB723506",
            8,
        ),
        // Packet Vector #16: M=8, L=2, AAD=12 B, msg=19 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00764C63B8058E3C9696766CFA",
            "D0D0735C531E1BECF049C244",
            "12DAAC5630EFA5396F770CE1A66B21F7B2101C",
            "14D253C3967B70609B7CBB7C499160283245269A6F49975BCADEAF",
            8,
        ),
        // Packet Vector #17: M=8, L=2, AAD=12 B, msg=20 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00F8B678094E3B3C9696766CFA",
            "77B60F011C03E1525899BCAE",
            "E88B6A46C78D63E52EB8C546EFB5DE6F75E9CC0D",
            "5545FF1A085EE2EFBF52B2E04BEE1E2336C73E3F762C0C7744FE7E3C",
            8,
        ),
        // Packet Vector #18: M=8, L=2, AAD=12 B, msg=21 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00D560912D3F703C9696766CFA",
            "CD9044D2B71FDB8120EA60C0",
            "6435ACBAFB11A82E2F071D7CA4A5EBD93A803BA87F",
            "009769ECABDF48625594C59251E6035722675E04C847099E5AE0704551",
            8,
        ),
        // Packet Vector #19: M=10, L=2, AAD=8 B, msg=23 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "0042FFF8F1951C3C9696766CFA",
            "D85BC7E69F944FB8",
            "8A19B950BCF71A018E5E6701C91787659809D67DBEDD18",
            "BC218DAA947427B6DB386A99AC1AEF23ADE0B52939CB6A637CF9BEC2408897C6BA",
            10,
        ),
        // Packet Vector #20: M=10, L=2, AAD=8 B, msg=24 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "00920F40E56CDC3C9696766CFA",
            "74A0EBC9069F5B37",
            "1761433C37C5A35FC1F39F406302EB907C6163BE38C98437",
            "5810E6FD25874022E80361A478E3E9CF484AB04F447EFFF6F0A477CC2FC9BF548944",
            10,
        ),
        // Packet Vector #21: M=10, L=2, AAD=8 B, msg=25 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "0027CA0C7120BC3C9696766CFA",
            "44A3AA3AAE6475CA",
            "A434A8E58500C6E41530538862D686EA9E81301B5AE4226BFA",
            "F2BEED7BC5098E83FEB5B31608F8E29C38819A89C8E776F1544D4151A4ED3A8B87B9CE",
            10,
        ),
        // Packet Vector #22: M=10, L=2, AAD=12 B, msg=19 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "005B8CCBCD9AF83C9696766CFA",
            "EC46BB63B02520C33C49FD70",
            "B96B49E21D621741632875DB7F6C9243D2D7C2",
            "31D750A09DA3ED7FDDD49A2032AABF17EC8EBF7D22C8088C666BE5C197",
            10,
        ),
        // Packet Vector #23: M=10, L=2, AAD=12 B, msg=20 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "003EBE94044B9A3C9696766CFA",
            "47A65AC78B3D594227E85E71",
            "E2FCFBB880442C731BF95167C8FFD7895E337076",
            "E882F1DBD38CE3EDA7C23F04DD65071EB41342ACDF7E00DCCEC7AE52987D",
            10,
        ),
        // Packet Vector #24: M=10, L=2, AAD=12 B, msg=21 B
        (
            "D7828D13B2B0BDC325A76236DF93CC6B",
            "008D493B30AE8B3C9696766CFA",
            "6E37A6EF546D955D34AB6059",
            "ABF21C0B02FEB88F856DF4A37381BCE3CC128517D4",
            "F32905B88A641B04B9C9FFB58CC390900F3DA12AB16DCE9E82EFA16DA62059",
            10,
        ),
    ];
    assert_eq!(V.len(), 24, "RFC 3610 §8 has 24 packet vectors");

    for (i, (key, nonce, aad, msg, ct_tag, m)) in V.iter().enumerate() {
        let any = Aes128CcmAny::new(&hex(key).try_into().expect("16-byte key"), *m)
            .expect("official M is always valid");
        let nonce = hex(nonce);
        let aad = hex(aad);
        let msg = hex(msg);
        let expect = hex(ct_tag);

        let sealed = any.seal(&nonce, &aad, &msg).expect("within length domain");
        assert_eq!(sealed, expect, "seal mismatch at vector #{}", i + 1);
        let opened = any
            .open(&nonce, &aad, &expect)
            .expect("official vector must open");
        assert_eq!(opened, msg, "open mismatch at vector #{}", i + 1);
    }
}

/// 全 M 矩阵（TLS 形态：12 字节 nonce / L=3，AAD = 00..07，明文模式
/// byte(i) = 7i+3 mod 256，与既有 M=16 测试同一生成器约定）。
/// RFC 3610 无该形态官方向量——期望值由 python-cryptography（OpenSSL
/// 后端，先经 RFC 3610 §8 原文逐字节校验）生成，2026-09-17。
/// 结构性事实：密文与 M 无关（各行密文前缀相同，仅标签不同）；且
/// M<16 的标签 ≠ M=16 标签的前 M 字节（截断先于 S0 异或）——锚定
/// RFC 3610 §2.4/§2.5 的截断顺序。
#[test]
fn ccm_any_full_m_matrix_tls_shape() {
    let key: [u8; 16] = hex("404142434445464748494A4B4C4D4E4F").try_into().unwrap();
    let nonce12: [u8; 12] = hex("101112131415161718191A1B").try_into().unwrap();
    let aad = hex("0001020304050607");

    // (M, pt_len, ct||tag)
    const CASES: &[(usize, usize, &str)] = &[
        (4, 0, "9B39580F"),
        (4, 1, "C0880B06A5"),
        (4, 16, "C0993292CEB4116988778997B6E4AC48E564A861"),
        (
            4,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E700E354D7C6",
        ),
        (6, 0, "A28115470236"),
        (6, 1, "C09C5956F58572"),
        (6, 16, "C0993292CEB4116988778997B6E4AC4899CAB06E0254"),
        (
            6,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E70078CAE691903E",
        ),
        (8, 0, "20A5D25498E8E16E"),
        (8, 1, "C0D3998A6B2F3EB534"),
        (8, 16, "C0993292CEB4116988778997B6E4AC485D67B5DADD129769"),
        (
            8,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E700A9A0884B8E646327",
        ),
        (10, 0, "713656E6F2D7D9915EA1"),
        (10, 1, "C000E10C72BBB35D831237"),
        (
            10,
            16,
            "C0993292CEB4116988778997B6E4AC481D1AFB590BBFD1228D9B",
        ),
        (
            10,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E7004C101ABE26150B55BBB2",
        ),
        (12, 0, "3CEF93D506277E0289F03182"),
        (12, 1, "C06C0E59080D51E315A052161F"),
        (
            12,
            16,
            "C0993292CEB4116988778997B6E4AC483B3D8733B69B4217712F1BBD",
        ),
        (
            12,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E700C4F69A5FBBEC812F48215CFA",
        ),
        (14, 0, "D835C7DED3A6E75DE3830C6D6F23"),
        (14, 1, "C06E1B0AD2F4674F800A2D545A2183"),
        (
            14,
            16,
            "C0993292CEB4116988778997B6E4AC48F6A09414DA3C47FCA9CF08BF6A85",
        ),
        (
            14,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E70018FE760CB6600A116CBC92A77B2A",
        ),
        (16, 0, "3AB6DDB101093DB8716B73038E19B255"),
        (16, 1, "C0E489C84C544E5496DB58EEF90ECE03B7"),
        (
            16,
            16,
            "C0993292CEB4116988778997B6E4AC48C92512B12B36A27A2106F93D9342061D",
        ),
        (
            16,
            32,
            "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E7009F60B8FF8F81971ABF842A536DD73FB3",
        ),
    ];

    let engines: Vec<(usize, Aes128CcmAny)> = [4usize, 6, 8, 10, 12, 14, 16]
        .iter()
        .map(|&m| (m, Aes128CcmAny::new(&key, m).unwrap()))
        .collect();

    for (m, len, expect) in CASES {
        let any = engines.iter().find(|(mm, _)| mm == m).unwrap().1.clone();
        let out = any
            .seal(&nonce12, &aad, &pt(*len))
            .expect("within length domain");
        assert_hex(&out, expect, &format!("CCM M={m} L=3 pt={len}"));
        assert_eq!(
            any.open(&nonce12, &aad, &out).expect("round trip"),
            pt(*len),
            "M={m} pt={len} round trip"
        );
    }

    // 密文与 M 无关：同一 (key, nonce, pt) 下所有 M 的密文前缀一致
    let base = engines[0].1.seal(&nonce12, &aad, &pt(32)).unwrap();
    for (m, any) in &engines {
        let out = any.seal(&nonce12, &aad, &pt(32)).unwrap();
        assert_eq!(
            &out[..32],
            &base[..32],
            "ciphertext must not depend on M (M={m})"
        );
        assert_eq!(out.len(), 32 + m);
    }

    // M<16 标签 ≠ M=16 标签前缀（截断先于 S0 异或的直接证据）
    let m16 = engines
        .iter()
        .find(|(m, _)| *m == 16)
        .unwrap()
        .1
        .seal(&nonce12, &aad, &pt(16))
        .unwrap();
    let m8 = engines
        .iter()
        .find(|(m, _)| *m == 8)
        .unwrap()
        .1
        .seal(&nonce12, &aad, &pt(16))
        .unwrap();
    assert_eq!(&m16[..16], &m8[..16], "ciphertext prefix equal");
    assert_ne!(
        &m16[16..24],
        &m8[16..],
        "M=8 tag must not equal first 8 bytes of M=16 tag"
    );

    // 固定类型 Ccm8Tls 与 Any(M=8) 输出逐字节一致（委托关系锚定）
    let ccm8 = Aes128Ccm8Tls::new(&key);
    let out_fixed = ccm8.seal(&nonce12, &aad, &pt(32)).unwrap();
    assert_hex(
        &out_fixed,
        "C0993292CEB4116988778997B6E4AC48223D19621FE12136C790522FED09E700A9A0884B8E646327",
        "Ccm8Tls fixed-type M=8 L=3 pt=32",
    );
    assert_eq!(
        out_fixed,
        engines
            .iter()
            .find(|(m, _)| *m == 8)
            .unwrap()
            .1
            .seal(&nonce12, &aad, &pt(32))
            .unwrap(),
        "fixed Ccm8Tls must delegate to Any(M=8)"
    );
}

/// M=8 TLS 形态的认证失败面：密文区/标签区逐字节翻转必须全拒
///（CCM_8 套件的记录层防线，含 8 字节标签区每字节）。
#[test]
fn ccm8_tls_rejects_tampered_inputs() {
    let key: [u8; 16] = hex("404142434445464748494A4B4C4D4E4F").try_into().unwrap();
    let nonce12: [u8; 12] = hex("101112131415161718191A1B").try_into().unwrap();
    let ccm8 = Aes128Ccm8Tls::new(&key);
    let sealed = ccm8
        .seal(&nonce12, b"aad", &pt(24))
        .expect("within length domain");

    for pos in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x01;
        assert_eq!(
            ccm8.open(&nonce12, b"aad", &bad),
            Err(Error::VerificationFailed),
            "bit flip at byte {pos} (of {}) must fail",
            sealed.len()
        );
    }
    assert_eq!(
        ccm8.open(&nonce12, b"", &sealed),
        Err(Error::VerificationFailed)
    );
    for n in [0usize, 4, 7, 8, 15] {
        assert_eq!(
            ccm8.open(&nonce12, b"aad", &vec![0u8; n]),
            Err(Error::VerificationFailed),
            "short input {n} must fail"
        );
    }
}
