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
    assert_eq!(sk.public_key_sec1(), q_expected.as_slice(), "public key");

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
    ecdsa::p384::verify(&q_expected, b"sample", &sig).expect("verify");

    // 篡改消息必须失败
    assert_eq!(
        ecdsa::p384::verify(&q_expected, b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}
