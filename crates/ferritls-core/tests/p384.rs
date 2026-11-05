//! P-384 测试：ECDH 外部锚值 + ECDSA RFC 6979 A.2.6 向量（M3/M4）。
//!
//! ECDSA 向量为人工录入——已与 RFC 6979 原文核对（2026-09-07）；
//! ECDH 锚值由独立参考实现（Python 大整数椭圆曲线）计算。

mod common;

use common::hex;
use ferritls_core::der;
use ferritls_core::ecdh::p384;
use ferritls_core::sign::ecdsa;

/// ECDH 外部锚值：d1 取 RFC 6979 A.2.6 私钥；d2/Q2/共享秘密由独立
/// 参考实现计算，锚定 parse_public/阶梯/仿射转换的外部正确性。
#[test]
fn p384_ecdh_external_anchor() {
    let d1 = hex(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8\
         96D5724E4C70A825F872C9EA60D2EDF5",
    );
    let sk = p384::SecretKey::from_seed(d1.as_slice().try_into().unwrap());
    let q2 = hex(
        "047BDE719CF67203F8AF31690A91836D40618C5BAAB0A2C63AAF38A40B8AFE8AE\
         07E43BE47793846010BA52E45B1A7350AD1B6173FA9BA5642A036D184D23B5B87\
         30ABAA2EFD5AC69F4A0E9172C2B39BD52B198C6943CE5AFA65C34BD3755E4BA2",
    );
    let ss = sk.diffie_hellman(&q2).expect("dh");
    assert_eq!(
        ss.as_bytes(),
        hex(
            "BA7A80ABF7C386063DBECD9D30C45FF1F700D465704DEEB047C4A2AE6F8B494E\
             270A7B44D3D678500FCC8C661283298D"
        )
        .as_slice(),
        "shared secret"
    );
}

/// RFC 6979 A.2.6（P-384，SHA-384，消息 "sample"）。
#[test]
fn p384_ecdsa_rfc6979_sample() {
    let d = hex(
        "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8\
         96D5724E4C70A825F872C9EA60D2EDF5",
    );
    let sk = ecdsa::p384::SigningKey::from_seed(d.as_slice().try_into().unwrap());

    // 公钥锚点（RFC 6979 A.2.6 的 U）
    let q_expected = hex(
        "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
         DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C6218967\
         08A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
    );
    assert_eq!(
        sk.public_key_sec1().expect("public key"),
        q_expected.as_slice(),
        "public key"
    );

    let sig = sk.sign(b"sample").expect("sign");
    let (body, rest) = der::sequence(&sig).expect("der");
    assert!(rest.is_empty());
    let (r_bytes, rest) = der::integer(body).expect("r");
    let (s_bytes, rest2) = der::integer(rest).expect("s");
    assert!(rest2.is_empty());
    assert_eq!(
        r_bytes,
        hex(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
             81A648152E44ACF96E36DD1E80FABE46"
        ),
        "r"
    );
    assert_eq!(
        s_bytes,
        hex(
            "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA\
             329C145786E679E7B82C71A38628AC8"
        ),
        "s"
    );

    // 验证路径
    let vk = ecdsa::p384::VerifyKey::from_sec1_point(&q_expected).expect("pubkey");
    vk.verify(b"sample", &sig).expect("verify");

    // 篡改消息必须失败
    assert_eq!(
        vk.verify(b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

/// 对端公钥解析负面矩阵（经 `diffie_hellman` → `parse_public`，错误
/// 契约按 sw_curve! 宏钉死）：长度非法（95/96/98）、前缀非 0x04、
/// 域越界（X ≥ p / Y ≥ p）一律 `InvalidInput`；格式合法但点不在
/// 曲线上（坐标互换 / y+1）一律 `VerificationFailed`。不得 panic。
#[test]
fn p384_ecdh_peer_key_error_matrix() {
    let sk = p384::SecretKey::from_seed([2u8; 48]);
    // RFC 6979 A.2.6 的 U 与基点 G（坐标取自既有锚值与官方参数）
    let q = hex(
        "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
         DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C6218967\
         08A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
    );
    let gx = hex(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38\
         5502F25DBF55296C3A545E3872760AB7",
    );
    let gy = hex(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0\
         0A60B1CE1D7E819D7A431D7C90EA0E5F",
    );
    // P-384 基域素数 p 的 BE 字节
    let p = hex(
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
         ffffffff0000000000000000ffffffff",
    );

    // 长度非法（97 = 1 + 2×48 为唯一合法长度）
    for len in [0usize, 31, 95, 96, 98, 145] {
        assert_eq!(
            sk.diffie_hellman(&vec![0x04u8; len]).map(|_| ()),
            Err(ferritls_core::Error::InvalidInput),
            "peer key len {len} must be InvalidInput"
        );
    }

    // 前缀非 0x04（长度正确）：压缩/错误前缀拒绝
    for prefix in [0x02u8, 0x03, 0x00, 0x05] {
        let mut bad = q.clone();
        bad[0] = prefix;
        assert_eq!(
            sk.diffie_hellman(&bad).map(|_| ()),
            Err(ferritls_core::Error::InvalidInput),
            "prefix {prefix:#04x} must be InvalidInput"
        );
    }

    // 域越界：X = p / Y = p —— 必须 InvalidInput 而非宽容归约后继续
    let mut x_ge_p = Vec::with_capacity(97);
    x_ge_p.push(0x04);
    x_ge_p.extend_from_slice(&p);
    x_ge_p.extend_from_slice(&gy);
    assert_eq!(
        sk.diffie_hellman(&x_ge_p).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "X >= p must be InvalidInput"
    );
    let mut y_ge_p = Vec::with_capacity(97);
    y_ge_p.push(0x04);
    y_ge_p.extend_from_slice(&gx);
    y_ge_p.extend_from_slice(&p);
    assert_eq!(
        sk.diffie_hellman(&y_ge_p).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "Y >= p must be InvalidInput"
    );

    // 格式合法但不在曲线：坐标互换（G 的 (y,x)）与 y+1——均已被
    // 独立实现确认不在 P-384 上
    let mut swapped = Vec::with_capacity(97);
    swapped.push(0x04);
    swapped.extend_from_slice(&gy);
    swapped.extend_from_slice(&gx);
    assert_eq!(
        sk.diffie_hellman(&swapped).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "swapped coords must be VerificationFailed"
    );
    let mut y_plus_one = Vec::with_capacity(97);
    y_plus_one.push(0x04);
    y_plus_one.extend_from_slice(&gx);
    y_plus_one.extend_from_slice(&hex(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0\
         0A60B1CE1D7E819D7A431D7C90EA0E60",
    ));
    assert_eq!(
        sk.diffie_hellman(&y_plus_one).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "y+1 off-curve must be VerificationFailed"
    );
    // 阳性对照：合法点必须通过（证明矩阵骨架本身无误）
    assert!(sk.diffie_hellman(&q).is_ok(), "valid peer point must parse");
}

/// 零标量退化编码钉子：seed = 群阶 n 的 BE 字节（mod n 精确归约为
/// 0）→ 阶梯输出无穷远，`public_key()` 导出 "04" + 全零坐标的
/// **文档化退化编码**——钉死该行为以防静默变更；`diffie_hellman`
/// 对任意合法对端公钥的结果为无穷远，必须返回 `VerificationFailed`。
#[test]
fn p384_zero_scalar_degenerate_encoding_pinned() {
    let n = hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52973",
    );
    let sk = p384::SecretKey::from_seed(n.as_slice().try_into().unwrap());

    let mut expect = vec![0x04u8];
    expect.extend_from_slice(&[0u8; 96]);
    assert_eq!(
        sk.public_key().expect("public_key").as_slice(),
        expect.as_slice(),
        "zero scalar → 04 || all-zero coords (documented degenerate encoding)"
    );

    let q = hex(
        "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
         DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C6218967\
         08A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
    );
    assert_eq!(
        sk.diffie_hellman(&q).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "0·Q = infinity must be rejected"
    );
}

/// ECDSA 验证 DER 负面矩阵（经公开入口 `verify`，错误契约按
/// parse_sig 钉死）：非 SEQUENCE 首字节、缺 s、s 后拖尾 INTEGER、
/// r 多一个长度字节 → 结构性拒绝；r = 0 / s = 0 / r ≥ n / s ≥ n
/// → 数值性拒绝；BER 不定长 `30 80` → `InvalidInput` 而非 panic。
#[test]
fn p384_ecdsa_verify_rejects_malformed_der_and_degenerate_sig() {
    let q = hex(
        "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64\
         DEF8F0EA9055866064A254515480BC138015D9B72D7D57244EA8EF9AC0C6218967\
         08A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
    );
    let vk = ecdsa::p384::VerifyKey::from_sec1_point(&q).expect("pubkey");
    let msg = b"sample";

    // 阳性对照：RFC 6979 A.2.6 的 (r, s) 经公开编码器重组必须通过
    let r = hex(
        "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C\
         81A648152E44ACF96E36DD1E80FABE46",
    );
    let s = hex(
        "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA\
         329C145786E679E7B82C71A38628AC8",
    );
    let good = ferritls_core::sign::encode_der_sig(&r, &s);
    assert_eq!(
        vk.verify(msg, &good).map(|_| ()),
        Ok(()),
        "positive control must verify"
    );

    // 结构性：非 SEQUENCE 首字节
    for bad_first in [
        vec![0x04u8, 0x02, 0x01, 0x02],
        vec![0x31u8, 0x02, 0x01, 0x02],
    ] {
        assert_eq!(
            vk.verify(msg, &bad_first).map(|_| ()),
            Err(ferritls_core::Error::InvalidInput),
            "non-SEQUENCE first byte {:#04x} must be InvalidInput",
            bad_first[0]
        );
    }
    // 缺 s：SEQUENCE 内只有单个 INTEGER
    let missing_s: Vec<u8> = vec![0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03];
    assert_eq!(
        vk.verify(msg, &missing_s).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "missing s must be InvalidInput"
    );
    // s 后拖尾多余 INTEGER
    let trailing: Vec<u8> = vec![
        0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03,
    ];
    assert_eq!(
        vk.verify(msg, &trailing).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "trailing INTEGER must be rejected"
    );
    // r 多一个长度字节（0x31 = 49 字节内容，超出定长上限 48）
    let mut r_extra = vec![0x30u8, 0x36, 0x02, 0x31];
    r_extra.extend_from_slice(&[0x01u8; 49]);
    r_extra.extend_from_slice(&[0x02, 0x01, 0x02]);
    assert_eq!(
        vk.verify(msg, &r_extra).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "r with extra length byte must be rejected"
    );

    // 数值性：r = 0 / s = 0
    let r_zero: Vec<u8> = vec![0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x02];
    let s_zero: Vec<u8> = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
    for (what, bad) in [("r = 0", r_zero), ("s = 0", s_zero)] {
        assert_eq!(
            vk.verify(msg, &bad).map(|_| ()),
            Err(ferritls_core::Error::VerificationFailed),
            "{what} must be rejected"
        );
    }

    // r/s ≥ n（群阶 n 的 BE 字节；n+1 为解析期直接拒绝，n 经标量
    // 归约走无穷远路径——两者都必须 VerificationFailed）
    let n = hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52973",
    );
    let n_plus_1 = hex(
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
         581a0db248b0a77aecec196accc52974",
    );
    for (what, v) in [("r = n", &n), ("r = n+1", &n_plus_1)] {
        let mut der = vec![0x30u8, 0x36, 0x02, 0x31, 0x00];
        der.extend_from_slice(v);
        der.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert_eq!(
            vk.verify(msg, &der).map(|_| ()),
            Err(ferritls_core::Error::VerificationFailed),
            "{what} must be rejected"
        );
    }
    for (what, v) in [("s = n", &n), ("s = n+1", &n_plus_1)] {
        let mut der = vec![0x30u8, 0x36, 0x02, 0x01, 0x01, 0x02, 0x31, 0x00];
        der.extend_from_slice(v);
        assert_eq!(
            vk.verify(msg, &der).map(|_| ()),
            Err(ferritls_core::Error::VerificationFailed),
            "{what} must be rejected"
        );
    }

    // BER 不定长长度（0x80）：DER 解析必须显式拒绝而非 panic
    let ber_indefinite: Vec<u8> = vec![0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x00, 0x00];
    assert_eq!(
        vk.verify(msg, &ber_indefinite).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "BER indefinite length must be InvalidInput"
    );
}
