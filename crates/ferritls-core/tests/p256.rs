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
    let ss_a = a
        .diffie_hellman(&b.public_key().expect("pubkey B"))
        .expect("A completes");
    let ss_b = b
        .diffie_hellman(&a.public_key().expect("pubkey A"))
        .expect("B completes");
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
    assert_eq!(
        sk.public_key_sec1().expect("public key"),
        q_expected.as_slice(),
        "public key"
    );

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
    let vk = ecdsa::p256::VerifyKey::from_sec1_point(&q_expected).expect("pubkey");
    vk.verify(b"sample", &sig).expect("verify");

    // 篡改消息必须失败
    assert_eq!(
        vk.verify(b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

/// RFC 6979 A.2.5（P-256，SHA-256，消息 "test"）。
#[test]
fn p256_ecdsa_rfc6979_test() {
    let d = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    let sk = ecdsa::p256::SigningKey::from_seed(d.as_slice().try_into().unwrap());
    let q = sk.public_key_sec1().expect("public key");
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
    ecdsa::p256::VerifyKey::from_sec1_point(&q)
        .expect("pubkey")
        .verify(b"test", &sig)
        .expect("verify");
}

/// 对端公钥解析负面矩阵（经 `diffie_hellman` → `parse_public`，错误
/// 契约按 sw_curve! 宏钉死）：长度非法（63/64/66/97）、前缀非 0x04
/// （0x02/0x03 压缩形态不支持）、域越界（X ≥ p / Y ≥ p）一律
/// `InvalidInput`；格式合法但点不在曲线上（坐标互换 / y+1 / x=y）
/// 一律 `VerificationFailed`。全部输入为攻击者可控形态——不得 panic。
#[test]
fn p256_ecdh_peer_key_error_matrix() {
    let sk = p256::SecretKey::from_seed([2u8; 32]);
    // RFC 6979 A.2.5 的 Q 与基点 G（坐标取自既有锚值测试）
    let q = hex(
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
         7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    );
    let gx = hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    let gy = hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    // P-256 基域素数 p 的 BE 字节
    let p = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");

    // 长度非法（65 = 1 + 2×32 为唯一合法长度）
    for len in [0usize, 31, 63, 64, 66, 97] {
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

    // 域越界：X = p（≥ p）、Y = p（≥ p）——必须 InvalidInput 而非
    // 宽容归约后继续
    let mut x_ge_p = Vec::with_capacity(65);
    x_ge_p.push(0x04);
    x_ge_p.extend_from_slice(&p);
    x_ge_p.extend_from_slice(&gy);
    assert_eq!(
        sk.diffie_hellman(&x_ge_p).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "X >= p must be InvalidInput"
    );
    let mut y_ge_p = Vec::with_capacity(65);
    y_ge_p.push(0x04);
    y_ge_p.extend_from_slice(&gx);
    y_ge_p.extend_from_slice(&p);
    assert_eq!(
        sk.diffie_hellman(&y_ge_p).map(|_| ()),
        Err(ferritls_core::Error::InvalidInput),
        "Y >= p must be InvalidInput"
    );

    // 格式合法但不在曲线：坐标互换（G 的 (y,x)）、y+1、x=y——
    // 三者均已被独立实现确认不在 P-256 上
    let mut swapped = Vec::with_capacity(65);
    swapped.push(0x04);
    swapped.extend_from_slice(&gy);
    swapped.extend_from_slice(&gx);
    assert_eq!(
        sk.diffie_hellman(&swapped).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "swapped coords must be VerificationFailed"
    );
    let mut y_plus_one = Vec::with_capacity(65);
    y_plus_one.push(0x04);
    y_plus_one.extend_from_slice(&gx);
    y_plus_one.extend_from_slice(&hex(
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F6",
    ));
    assert_eq!(
        sk.diffie_hellman(&y_plus_one).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "y+1 off-curve must be VerificationFailed"
    );
    let mut x_equals_y = Vec::with_capacity(65);
    x_equals_y.push(0x04);
    x_equals_y.extend_from_slice(&gx);
    x_equals_y.extend_from_slice(&gx);
    assert_eq!(
        sk.diffie_hellman(&x_equals_y).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "x=y off-curve must be VerificationFailed"
    );
    // 阳性对照：合法点必须通过（证明矩阵骨架本身无误）
    assert!(sk.diffie_hellman(&q).is_ok(), "valid peer point must parse");
}

/// 零标量退化编码钉子：seed = 群阶 n 的 BE 字节（mod n 精确归约为
/// 0；注意 2^256−1 mod n ≠ 0，故不能取 [0xff; 32]）→ 阶梯输出无穷
/// 远，`public_key()` 导出 "04" + 全零坐标的**文档化退化编码**——
/// 此处钉死该行为以防静默变更；`diffie_hellman` 对任意合法对端
/// 公钥的结果为无穷远，必须返回 `VerificationFailed`。
#[test]
fn p256_zero_scalar_degenerate_encoding_pinned() {
    let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let sk = p256::SecretKey::from_seed(n.as_slice().try_into().unwrap());

    let mut expect = vec![0x04u8];
    expect.extend_from_slice(&[0u8; 64]);
    assert_eq!(
        sk.public_key().expect("public_key").as_slice(),
        expect.as_slice(),
        "zero scalar → 04 || all-zero coords (documented degenerate encoding)"
    );

    let q = hex(
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
         7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
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
fn p256_ecdsa_verify_rejects_malformed_der_and_degenerate_sig() {
    let q = hex(
        "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
         7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
    );
    let vk = ecdsa::p256::VerifyKey::from_sec1_point(&q).expect("pubkey");
    let msg = b"sample";

    // 阳性对照：RFC 6979 A.2.5 的 (r, s) 经公开编码器重组必须通过
    let r = hex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716");
    let s = hex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8");
    let good = ferritls_core::sign::encode_der_sig(&r, &s);
    assert_eq!(
        vk.verify(msg, &good).map(|_| ()),
        Ok(()),
        "positive control must verify"
    );

    // 结构性：非 SEQUENCE 首字节（BIT STRING / SET OF）
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
    // s 后拖尾多余 INTEGER（外层 SEQUENCE 覆盖三个元素）
    let trailing: Vec<u8> = vec![
        0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03,
    ];
    assert_eq!(
        vk.verify(msg, &trailing).map(|_| ()),
        Err(ferritls_core::Error::VerificationFailed),
        "trailing INTEGER must be rejected"
    );
    // r 多一个长度字节（0x21 = 33 字节内容，超出定长上限）
    let mut r_extra = vec![0x30u8, 0x26, 0x02, 0x21];
    r_extra.extend_from_slice(&[0x01u8; 33]);
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

    // r/s ≥ n（群阶 n 的 BE 字节；n+1 为解析期直接拒绝，n 经
    // 标量归约走无穷远路径——两者都必须 VerificationFailed）
    let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let n_plus_1 = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552");
    for (what, v) in [("r = n", &n), ("r = n+1", &n_plus_1)] {
        let mut der = vec![0x30u8, 0x26, 0x02, 0x21, 0x00];
        der.extend_from_slice(v);
        der.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert_eq!(
            vk.verify(msg, &der).map(|_| ()),
            Err(ferritls_core::Error::VerificationFailed),
            "{what} must be rejected"
        );
    }
    for (what, v) in [("s = n", &n), ("s = n+1", &n_plus_1)] {
        let mut der = vec![0x30u8, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00];
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
