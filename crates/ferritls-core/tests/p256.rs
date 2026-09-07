//! P-256 测试：ECDH 往返 + ECDSA RFC 6979 A.2.5 向量（M3/M4）。
//!
//! ECDSA 向量为人工录入——启用前已与 RFC 6979 原文核对。

mod common;

use common::hex;
use ferritls_core::der;
use ferritls_core::ecdh::p256;
use ferritls_core::sign::ecdsa;

#[test]
fn p256_ecdh_round_trip() {
    let a = p256::SecretKey::generate().expect("generate A");
    let b = p256::SecretKey::generate().expect("generate B");
    let ss_a = a.diffie_hellman(&b.public_key()).expect("A completes");
    let ss_b = b.diffie_hellman(&a.public_key()).expect("B completes");
    assert_eq!(ss_a.as_bytes(), ss_b.as_bytes());
    // 非法对端公钥（点不在曲线上）必须被拒绝——具体向量 M3 从
    // Wycheproof “invalid” 分组引入。
}

/// ECDH 外部锚值：d1 取 RFC 6979 A.2.5 私钥，d2/Q2/共享秘密由独立
/// 参考实现（Python 大整数椭圆曲线）计算，锚定 parse_public/阶梯/
/// 仿射转换的外部正确性（round-trip 对常数因子类错误不敏感）。
#[test]
fn p256_ecdh_external_anchor() {
    let d1 = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let sk = p256::SecretKey::from_seed(d1.as_slice().try_into().unwrap());
    let q2 = hex(
        "04950A1DEE7E23AB706D81D092553CBA8BED90249C586F501F34F7EA06EE86DE26\
         638F2640373222F79F2BC9AD699A932F72B595E395A1FF4A4DC90816D44EC4A9",
    );
    let ss = sk.diffie_hellman(&q2).expect("dh");
    assert_eq!(
        ss.as_bytes(),
        hex("806958C49499F161666BCEE12D09448FD06BF33C7A89378965CB14C23F786517").as_slice(),
        "shared secret"
    );
}

/// RFC 6979 A.2.5（P-256，SHA-256，消息 "sample"）。
#[test]
fn p256_ecdsa_rfc6979_sample() {
    let d = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let sk = ecdsa::p256::SigningKey::from_seed(d.as_slice().try_into().unwrap());

    // 公钥锚点（RFC 6979 A.2.5 的 Q）
    let q_expected = hex(
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
         7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    );
    assert_eq!(sk.public_key_sec1(), q_expected.as_slice(), "public key");

    let sig = sk.sign(b"sample").expect("sign");
    // 解析 DER 中的 (r, s)
    let (body, rest) = der::sequence(&sig).expect("der");
    assert!(rest.is_empty());
    let (r_bytes, rest) = der::integer(body).expect("r");
    let (s_bytes, rest2) = der::integer(rest).expect("s");
    assert!(rest2.is_empty());
    assert_eq!(
        r_bytes,
        hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
        "r"
    );
    assert_eq!(
        s_bytes,
        hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        "s"
    );

    // 验证路径
    ecdsa::p256::verify(&q_expected, b"sample", &sig).expect("verify");

    // 篡改消息必须失败
    assert_eq!(
        ecdsa::p256::verify(&q_expected, b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

/// RFC 6979 A.2.5（P-256，SHA-256，消息 "test"）。
#[test]
fn p256_ecdsa_rfc6979_test() {
    let d = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let sk = ecdsa::p256::SigningKey::from_seed(d.as_slice().try_into().unwrap());
    let q = sk.public_key_sec1();
    let sig = sk.sign(b"test").expect("sign");
    let (body, _) = der::sequence(&sig).expect("der");
    let (r_bytes, rest) = der::integer(body).expect("r");
    let (s_bytes, _) = der::integer(rest).expect("s");
    assert_eq!(
        r_bytes,
        hex("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
        "r"
    );
    assert_eq!(
        s_bytes,
        hex("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        "s"
    );
    ecdsa::p256::verify(&q, b"test", &sig).expect("verify");
}
