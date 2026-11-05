//! RSA 与 DER 解析测试（M4b/M4c）。
//!
//! RSA 向量：本地 OpenSSL 3.2.4 生成的 2048 位测试密钥与签名
//! （PKCS#1 v1.5 确定性签名逐字节锚定；PSS 为随机化签名，验证
//! 方向锚定 openssl 产物 + 自洽往返）。私钥运算含乘法盲化
//! （M4c）：每次签名盲化因子全新随机，PKCS#1 v1.5 结果必须
//! 逐字节不变——盲化稳定性测试直接锚定该性质。Wycheproof
//! `rsa_signature_test.json` / `rsa_pss_signature_test.json` 全量
//! 向量在 M6/M7 引入 `tests/vectors/`。DER 畸形输入：性质测试，
//! cargo-fuzz 全覆盖在 M6 建立。

mod common;

use common::hex;
use ferritls_core::der;
use ferritls_core::sign::rsa;

/// 测试密钥（PKCS#8，2048 位，openssl genrsa 生成）。
const KEY_PKCS8: &str = "\
308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100a87db87c2fb7d2f212e4c4f652a281faaf37988a960648a0611e2bd65b0c3b75e3f31b0e3b7720c5637b54439419c131e4dadd2956c2d2c79aac60fcfa49136d4ad88110cb3760259987088ff01791b280e6d359cec4e7974d6934057e517a059c90d344b1315abc5335cc8f356fce4a711806668acb497f46fb467025eea30f8568688e1e3b52b3d29c4b619198707de86e5858e91831bea9011d6b79538fb2e1b8112ac575c04a0343c4e2edf7dc9d74cf91e68a5ad6f99ec4cff27ce76f35953b36090c99b558a00333c76258ceb5d6687a669ea9774375dfb837748a30109a1f0f994f5b3eb5890627e06ad1421a88a1b6c100ad2c0dc2865bc90b8c2c0102030100010281ff1578f029e36ae9d72fd137c8ac7f495149432c8d7cd1103060301826193455df904d4b05654ea93e7e8f190e03b1c48d373d2d32377c5ca05375e46658ff371a968f40e383026b9e5f127664e1941f5d40502a5f279ab068f7d4906ca2cc7f6077b37d3923dbc65479c6416b7ec3e0e65bc3540d7d62aadb2d909849728c16fb8e70df511e73d4e1039804e087c21721b38f088b0b1b0f83db85da53e79c72d0c6d4f9a466d8fe0899789797ad0d3b9b2e152b5c9247b114cde350eb58b87f9374192e7b7bdfdf8f92d58b31e910db3f0afc253bf5f43766732db6fc052d79781fd722e966cf498be380c16f876198cee5716872576c56b43884ab907d575902818100d5143393bfcd35cc3ae597eb2706cea971f636a98f6401fff5afc330581c79f7bdeeb16e697562c36b6febec528961861df0da52073e4f60d6f881aed9dd9fa6f9fedb03fcefc90019002e77e0dc8b99240e50567f04ff7b1fbe4a723b5db6c1bed95facdc0f2606c88b22279b9fef95daae8fb3044306a029140edaf5826fa902818100ca6e449c46bcf7f97a807eb9b50859219f26d7528c85455b4c0819afca66560fafdef01f68d50f02708eaa5d740c21939c023a7823d6c96bb17aeeac4aa50523176a60457ab7cb8128b1abd34c6f6107e8723030a38f75fbff32c5bf74b6d06e72d5c968b82e2b776cb8aa011f18cba323a442673f27040ff3e6e54afe41f09902818100b437dfdfc94bc182b915d3461abe113113a851575c6613a2efa3f70cfe992737b8b717eef0d74def470164a37eb39f7e95f84e4f2ebd2eda133820474911bfa4b4b12f80d1ffe51b6609d743a13628042090d2b635bc7e711eca0da14c40d90049710510e9170eec91d5cbcf803ae7a2f150cf4d73ff54ad45d127375e8b31f10281810092cc60490c2b6190b3bb972ac913a2bf7510cfb97759f62ffcf52adb8665ac27781cadf9b92638da4611cf8e31e7d2399f3b26779555df7f8f975c99e90fbea7f2051c878634df096d1f5b41c1fe4b5956c1e81c7da03da95f29cca9c8d40256f643fee948178341f9bff8d9135a01e2eea7e1d7c9be5b7dce1c354fab0eda9102818075a97df71e1077a6200c074d413d7f0d258c19108f1a6cd5556895f29a4e6832615531e1e550e8be211004a13f7e4e04ee74287d36810fd1ec3c98c56c17db36f90bae102b2ed8e8d6fe5a7d31008ec6ad5bfdbaae90cd258d2362e7809edcfa6b323b1c4b8a77a2e7669cfb7c6ee6a51d078c8d7306673dd06572b8b0a1f72a";

/// 对应 SPKI 公钥。
const PUB_SPKI: &str = "\
30820122300d06092a864886f70d01010105000382010f003082010a0282010100a87db87c2fb7d2f212e4c4f652a281faaf37988a960648a0611e2bd65b0c3b75e3f31b0e3b7720c5637b54439419c131e4dadd2956c2d2c79aac60fcfa49136d4ad88110cb3760259987088ff01791b280e6d359cec4e7974d6934057e517a059c90d344b1315abc5335cc8f356fce4a711806668acb497f46fb467025eea30f8568688e1e3b52b3d29c4b619198707de86e5858e91831bea9011d6b79538fb2e1b8112ac575c04a0343c4e2edf7dc9d74cf91e68a5ad6f99ec4cff27ce76f35953b36090c99b558a00333c76258ceb5d6687a669ea9774375dfb837748a30109a1f0f994f5b3eb5890627e06ad1421a88a1b6c100ad2c0dc2865bc90b8c2c010203010001";

/// openssl dgst -sha256 -sign（PKCS#1 v1.5，消息 "sample"）。
const SIG_V15_SHA256: &str = "\
86a0cd7b191639cb2b78a6f050f6b8bca99bc1d2a2545fcc9ab3cb70c909ea631389574555f901c03e08f2fc599aa5787fcfbbe02beed1a486d6f3659fa2d431e1f6d68687052d45d2275844a3415bd48f675b4b030cf24eaaebc02e8c64fa98d01d3e2f5dc1ce33140ec30cc1c517f53d281c9e2560ca07b2d058ded631161da6cc4e68ab6275af564091f62d832d4b3d87d8415684c457700cd726b2dc1e550bd95a6fe37b3919eb05732fd9e1f7c864272b37c86e46302b6b5a8ad6b5833d280dc653a7978787bec289be48b6d8d7f0cecc2fbaae00a9fae7dfe2881c71c63f0bba1ac578c6c3a9500ea417837c8fddfac8fcc12958399782876513598d7a";

/// openssl dgst -sha384 -sign（PKCS#1 v1.5，消息 "sample"）。
const SIG_V15_SHA384: &str = "\
65862db3a237735699e873a5c5c1e795b9d4b085899f5b0eb03e70f0ba5eb0f2e8c43e2e26e7af05c78d768ed4c60d9ad16f76a99cf05e51b9193f83dbd78b54a347df409554c29ffaafa98f53739800f4926c68041a77a574104793adbf6bd95e461378b5620870c9458d84fefc249419278ae10316caf8d92106a11013afecf175e5854e4237e230eae48827558b72d56de8f79112b74ac2ac754ac5401c396b32c8ee3c03660776f695024aa74840d54914594f7d54df758f86ec95d5b4ed19801b9c0df3c6c59e2a811bf89c3368999133f343e113c9c17eb3f240825346763a70b02e42890971cd78dd8068f7c9ead5821be745b3377dc8b648a5c05383";

/// openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32
const SIG_PSS_SHA256: &str = "\
43ca8c69b09413803e138650c027b71c8bbd6db1f9b47a05930c525633aae2392008d3ceee80cc7a182b98ac6a7315592b463960b4dc9a44e8c6788e8c0a88b8bd5797fc692e436cd5a4938541026a49aaccf381d0e935af7b115e31fd61a1c94469ff6c4eb8918e5f10685537c26db9c3bad661e9a0a3aaca4ab514f73e94bba3976851477da641e9d90714df1d68e9b0b77da8184d799d8785e03ce999de0c1b4d35624615802cd8e1a0e6f046cccdefd0a4a051e7ce6e55ee0feb9994016ed8090a089d76ac8e20fe6eb6228d7249ca88d91a83a511e5245c2acaca602d9a630f137c03f3aa7bc43c25fc627139189294bf37ad87431f4b69c6083fe70df8";

/// openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
const SIG_PSS_SHA512: &str = "\
36999a89c9642289981b032c45d105660987e6e9d5228fdcb3906fab31cd583382252df16215b4015a21849f0725d95dcdd491c3f9376f5b089662c84d42cc68f5406998417f89c55223a3fe2dbe3ac625edd47e04fcb9f60e005c1421bfa0912cf63d2df11d16af3da6bb8abee6fc7b47afeb7bd31920870601e7aff0cb1ae5839732f6f8ee808806059bed7a1e5c659ee42819d1e6cbb32b951a0b1208f3c998266faa02f9aa180452af7b9e69aca5d0bf18670f14ae4466a482b6ff5e053c7588322a60722a1e14ef7d3946eb9b45f94198e1470fb28762c694abbadc292b5f64c9c7b4c68f98909602bd976cbc946ce79be14a10f7977c86050d790ad6a3";

/// 512 位密钥（PKCS#8）：模长 < 2048 位必须被拒绝。
const KEY_SMALL: &str = "\
30820155020100300d06092a864886f70d01010105000482013f3082013b020100024100bed2dfae37da30c97b9bfd0e5af6fbd0774d7d0d2b0f562513e22d9aed6ed1c52d98db492bd0493549a9b90a6e085a9fb283cb211baaeb80c91779c84638c633020301000102400d9601eaeb7b136224f4d42d837876313f6d3aec0716ce71515b171822b37327d125b12baadbf1942d7da7882369e3d17bdc0929d97d8efa1077de88c7949161022100efbb6c532ac4227e321253bab6486579f167efda7c782579d33ab3e708368059022100cbc5d2f5c872b986f8c4381d30abb31fd8ba24087a94bc9c716c0679a69e096b022100e4ea5f41fb30568f925895c3509448f1ec66874e665483d494b3155ea32507e10220693bc77fa0be06abfa8ab303f81fa3c8dd8efb8ed96738a47e3ab079609f9af3022100819330744642757f9645020754a9d5b8414d7ab13c0b691de6e455432b4d4fed";

const MSG: &[u8] = b"sample";

#[test]
fn rsa_sign_pkcs1v15_sha256_openssl_anchor() {
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    let sig = sk.sign_pkcs1v15(256, MSG).expect("sign");
    common::assert_hex(&sig, SIG_V15_SHA256, "v1.5 sha256 signature");
    // openssl 产物的验证方向
    let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
    pk.verify_pkcs1v15(256, MSG, &sig).expect("verify self");
    // 篡改签名 → 失败
    let mut bad = sig.clone();
    bad[128] ^= 1;
    assert_eq!(
        pk.verify_pkcs1v15(256, MSG, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

#[test]
fn rsa_verify_pkcs1v15_sha384_openssl_anchor() {
    let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
    let sig = hex(SIG_V15_SHA384);
    pk.verify_pkcs1v15(384, MSG, &sig).expect("verify sha384");
    // 篡改消息 → 失败
    assert_eq!(
        pk.verify_pkcs1v15(384, b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

#[test]
fn rsa_pss_openssl_verify_and_round_trip() {
    let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
    // openssl 生成的 PSS 签名（salt = 哈希长度）验证方向锚定
    pk.verify_pss(256, MSG, &hex(SIG_PSS_SHA256))
        .expect("pss sha256");
    pk.verify_pss(512, MSG, &hex(SIG_PSS_SHA512))
        .expect("pss sha512");
    // 自洽往返（PSS 签名含随机 salt，不做逐字节比较）
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    let sig = sk.sign_pss(256, MSG).expect("sign pss");
    pk.verify_pss(256, MSG, &sig).expect("verify self pss");
    // 篡改消息 → 失败
    assert_eq!(
        pk.verify_pss(256, b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
    // 篡改签名首字节 → 失败
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert_eq!(
        pk.verify_pss(256, MSG, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

/// 盲化正确性（M4c）：每次签名盲化因子 r 全新随机，PKCS#1 v1.5
/// 结果必须逐字节不变（盲化在数学上精确抵消）且与 openssl 锚一致。
#[test]
fn rsa_blinded_pkcs1v15_stable_across_random_blinds() {
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    for _ in 0..8 {
        let sig = sk.sign_pkcs1v15(256, MSG).expect("sign");
        common::assert_hex(&sig, SIG_V15_SHA256, "blinded v1.5 sha256 signature");
    }
}

/// PSS 全随机路径（随机 salt + 随机盲化因子）多次自洽往返。
#[test]
fn rsa_blinded_pss_round_trips() {
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    for _ in 0..8 {
        let sig = sk.sign_pss(384, MSG).expect("sign pss");
        let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
        pk.verify_pss(384, MSG, &sig).expect("verify self pss");
    }
}

#[test]
fn rsa_small_modulus_rejected() {
    match rsa::SigningKey::from_pkcs8_der(&hex(KEY_SMALL)) {
        Err(ferritls_core::Error::Unsupported) => {}
        other => panic!(
            "small modulus must be Unsupported, got {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn der_malformed_inputs_return_error_not_panic() {
    // 性质测试：任意截断/变长的 DER 输入必须返回 Err，绝不 panic。
    // 这里是一组代表性畸形样例；fuzz 目标建立后做全覆盖。
    let malformed: &[&[u8]] = &[
        b"",
        b"\x30",
        b"\x30\x03\x02\x01",         // 截断的 SEQUENCE
        b"\xff\xff\xff\xff",         // 非法 tag
        b"\x30\x80\x00\x00",         // indefinite length（不允许）
        &[0x30, 0x7f, 0x00],         // 声称长度远超输入
        b"\x30\x00\x30\x00\x30\x00", // 空嵌套结构
    ];
    for input in malformed {
        assert!(
            der::parse_pkcs8_private_key(input).is_err(),
            "malformed input must be rejected: {:?}",
            common::to_hex(input)
        );
    }
}

#[test]
fn rsa_key_der_truncations_return_error_not_panic() {
    let full = hex(KEY_PKCS8);
    // 全部前缀截断：外层 TLV 长度必然超界，只能 Err，不能 panic
    for cut in 0..full.len() {
        let out = rsa::SigningKey::from_pkcs8_der(&full[..cut]);
        assert!(out.is_err(), "truncated key at {cut} must be rejected");
    }
    // PKCS#8 version 0 → 1（确定性位置：外层 SEQUENCE 头后的版本整数）
    let mut ver = full.clone();
    ver[6] = 0x01;
    assert!(rsa::SigningKey::from_pkcs8_der(&ver).is_err());
    // 内层 PKCS#1 version 0 → 1 同样拒绝
    // （布局：[0..4] 外层头，[4..7] 版本，[7..22] AlgId，[22..26] OCTET STRING
    //   头，[26..30] 内层 SEQUENCE 头，[30..33] 内层版本）
    let mut ver2 = full.clone();
    ver2[32] = 0x01;
    assert!(rsa::SigningKey::from_pkcs8_der(&ver2).is_err());
}

// ---------------------------------------------------------------------------
// PKCS#8 AlgorithmIdentifier parameters 按算法强制（回归矩阵）：
//   Ed25519 必须省略（RFC 8410 §7）、EC 必须为 namedCurve（RFC 5480）、
//   RSA 必须为 NULL（RFC 8017 §A.1）。此前实现无条件要求 params TLV
//   存在，把全部标准 Ed25519 PKCS#8 密钥（openssl genpkey 产物）
//   误拒——真实加载路径（rustls KeyProvider::load_private_key）。
// ---------------------------------------------------------------------------

/// RFC 8032 §7.1 TEST 1 的种子与公钥（官方向量）。
const ED25519_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const ED25519_PUB: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// RFC 6979 A.2.5 的 P-256 私钥标量（官方向量），供 EC 编码构造。
const P256_SCALAR: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";

/// Ed25519 PKCS#8 的规范 16 字节头（RFC 8410 §7 的固定编码：
/// SEQUENCE{version 0, SEQ{OID 1.3.101.112}, OCTET STRING{OCTET STRING(32)}}，
/// parameters 缺席）。
const ED25519_PKCS8_PREFIX: &str = "302e020100300506032b657004220420";

#[test]
fn der_pkcs8_ed25519_params_absent_accepted() {
    let mut der_bytes = hex(ED25519_PKCS8_PREFIX);
    der_bytes.extend_from_slice(&hex(ED25519_SEED));
    match der::parse_pkcs8_private_key(&der_bytes) {
        Ok(der::ParsedPrivateKey::Ed25519(seed)) => {
            assert_eq!(seed, hex(ED25519_SEED), "seed round trip");
            // 解析出的种子即 RFC 8032 TEST 1 密钥：公钥逐字节核对
            let sk = ferritls_core::sign::ed25519::SigningKey::from_seed(
                seed.as_slice().try_into().expect("32-byte seed"),
            );
            assert_eq!(sk.public_key(), hex(ED25519_PUB).as_slice());
        }
        other => panic!("Ed25519 PKCS#8 (params absent) must parse, got {other:?}"),
    }
}

#[test]
fn der_pkcs8_ed25519_params_present_rejected() {
    // RFC 8410 §7 要求 parameters MUST be absent——携带 NULL 一并拒绝
    // （02 01 00 ‖ 30 07{06 03 2b6570, 05 00} ‖ 04 22 04 20 seed）
    let mut der_bytes = hex("3030020100300706032b6570050004220420");
    der_bytes.extend_from_slice(&hex(ED25519_SEED));
    match der::parse_pkcs8_private_key(&der_bytes) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("Ed25519 PKCS#8 with NULL params must be rejected, got {other:?}"),
    }
}

/// 构造 P-256 PKCS#8（SEC1 内层：version 1 + 32 字节标量，无 [1] 公钥）。
fn p256_pkcs8(with_curve_params: bool) -> Vec<u8> {
    // SEC1 ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING(32) }
    let mut sec1 = Vec::new();
    sec1.extend_from_slice(&hex("020101")); // SEC1 version 1
    let mut priv_tlv = vec![0x04, 0x20];
    priv_tlv.extend_from_slice(&hex(P256_SCALAR));
    sec1.extend_from_slice(&priv_tlv);
    let mut sec1_tlv = vec![0x30, sec1.len() as u8];
    sec1_tlv.extend_from_slice(&sec1);

    // AlgorithmIdentifier：OID id-ecPublicKey（+ 可选 namedCurve prime256v1）
    let mut alg = Vec::new();
    alg.extend_from_slice(&hex("06072a8648ce3d0201"));
    if with_curve_params {
        alg.extend_from_slice(&hex("06082a8648ce3d030107"));
    }
    let mut alg_tlv = vec![0x30, alg.len() as u8];
    alg_tlv.extend_from_slice(&alg);

    // privateKey OCTET STRING 包裹 SEC1
    let mut key_tlv = vec![0x04, sec1_tlv.len() as u8];
    key_tlv.extend_from_slice(&sec1_tlv);

    let mut content = hex("020100"); // PKCS#8 version 0
    content.extend_from_slice(&alg_tlv);
    content.extend_from_slice(&key_tlv);
    let mut out = vec![0x30, content.len() as u8];
    out.extend_from_slice(&content);
    out
}

#[test]
fn der_pkcs8_ec_named_curve_required() {
    // 带 namedCurve：解析为 P256 标量，逐字节等于 RFC 6979 A.2.5 的 d
    let der_bytes = p256_pkcs8(true);
    match der::parse_pkcs8_private_key(&der_bytes) {
        Ok(der::ParsedPrivateKey::P256 { scalar, .. }) => {
            assert_eq!(scalar.as_slice(), hex(P256_SCALAR).as_slice());
        }
        other => panic!("EC PKCS#8 with namedCurve must parse, got {other:?}"),
    }
    // 无 namedCurve（RFC 5480 要求必须存在）：拒绝
    match der::parse_pkcs8_private_key(&p256_pkcs8(false)) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("EC PKCS#8 without namedCurve must be rejected, got {other:?}"),
    }
}

#[test]
fn der_pkcs8_rsa_params_must_be_null() {
    // rsaEncryption 的 parameters 按 RFC 8017 §A.1 必须为 NULL。
    // 内层 PKCS#1 用 4 字节占位（parse_pkcs8 不验证 RSA 内层结构，
    // 返回原样字节）；NULL 的合规形态由 KEY_PKCS8（openssl 产物，
    // 上方 RSA 测试）锚定。
    const OID: &str = "06092a864886f70d010101";
    let build = |params: &[u8]| {
        let mut alg = hex(OID);
        alg.extend_from_slice(params);
        let mut content = hex("020100");
        content.extend_from_slice(&[0x30, alg.len() as u8]);
        content.extend_from_slice(&alg);
        content.extend_from_slice(&[0x04, 0x04, 0xde, 0xad, 0xbe, 0xef]);
        let mut out = vec![0x30, content.len() as u8];
        out.extend_from_slice(&content);
        out
    };
    // NULL（05 00）：通过，返回 PKCS#1 原样字节
    match der::parse_pkcs8_private_key(&build(&hex("0500"))) {
        Ok(der::ParsedPrivateKey::RsaPkcs1(pkcs1)) => {
            assert_eq!(pkcs1, hex("deadbeef"));
        }
        other => panic!("RSA PKCS#8 with NULL params must parse, got {other:?}"),
    }
    // 无 parameters：拒绝
    match der::parse_pkcs8_private_key(&build(&[])) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("RSA PKCS#8 without params must be rejected, got {other:?}"),
    }
    // 非 NULL 垃圾 params（OCTET STRING）：拒绝
    match der::parse_pkcs8_private_key(&build(&hex("04020102"))) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("RSA PKCS#8 with garbage params must be rejected, got {other:?}"),
    }
}

#[test]
fn der_pkcs8_attributes_must_be_single_element() {
    // Ed25519 PKCS#8 + 空 [0] attributes + 尾随垃圾：垃圾必须拒绝
    //（此前仅检查首字节是否 0xa0，其后的任意字节被静默接受）。
    // ED25519_PKCS8_PREFIX 含外层 SEQUENCE 头（长度字节在 out[1]），
    // 追加 attributes/垃圾时须同步改写外层长度。
    let build = |trailing: &[u8]| {
        let mut out = hex(ED25519_PKCS8_PREFIX);
        out.extend_from_slice(&hex(ED25519_SEED));
        out[1] += (2 + trailing.len()) as u8; // 空 [0] TLV 占 2 字节
        out.extend_from_slice(&hex("a000"));
        out.extend_from_slice(trailing);
        out
    };
    match der::parse_pkcs8_private_key(&build(&[])) {
        Ok(der::ParsedPrivateKey::Ed25519(_)) => {}
        other => panic!("empty [0] attributes must be accepted, got {other:?}"),
    }
    match der::parse_pkcs8_private_key(&build(&[0x2a])) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("trailing garbage after [0] must be rejected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// 对抗性矩阵（扩展）：A. der 原语边界 / B. PKCS#8 分支矩阵 /
// C. RSA 结构校验矩阵（R3 装载期校验的外科手术式变异）。
// 全部输入为构造的畸形编码，只断言 Err/Ok 与已知错误变体；实现侧语义
// 以 src/der.rs 与 src/sign.rs（rsa）当前代码为准，注释里逐点对应。
// ---------------------------------------------------------------------------

/// 最短 DER 长度编码（测试构造用）。字段最长 257 字节，两字节长形式
///（0x82）足够。
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        assert!(len < 0x1_00_00, "test fields never exceed two length bytes");
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// 组装单个 TLV（tag + 最短长度头 + 内容）。
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 5);
    out.push(tag);
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// 从 PKCS#8 剥出内层 PKCS#1 RSAPrivateKey 的**完整 DER**（含 SEQUENCE
/// 头）——即 `der::octet_string` 返回的 privateKey 内容。
fn extract_pkcs1(pkcs8: &[u8]) -> Vec<u8> {
    let (content, rest) = der::sequence(pkcs8).expect("pkcs8 sequence");
    assert!(rest.is_empty());
    let (_version, rest) = der::integer(content).expect("pkcs8 version");
    let (_alg, rest) = der::sequence(rest).expect("algorithm identifier");
    let (pkcs1, rest) = der::octet_string(rest).expect("privateKey octet string");
    assert!(rest.is_empty());
    pkcs1.to_vec()
}

/// 将 PKCS#1 DER 重新包裹为 PKCS#8（version 0 + rsaEncryption/NULL），
/// 供 from_pkcs8_der 路径的对照断言。
fn wrap_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    let alg = tlv(0x30, &hex("06092a864886f70d0101010500"));
    let mut content = hex("020100");
    content.extend_from_slice(&alg);
    content.extend_from_slice(&tlv(0x04, pkcs1));
    tlv(0x30, &content)
}

/// 定位内层 PKCS#1 RSAPrivateKey 各字段 TLV 的字节区间（相对完整
/// PKCS#1 DER 的 [start, end)）。字段序：0=version 1=n 2=e 3=d 4=p
/// 5=q 6=dp 7=dq 8=qInv。仅测试基建：调用方对区间做外科手术式变异。
fn pkcs1_field_ranges(pkcs1: &[u8]) -> Vec<(usize, usize)> {
    let (content, rest) = der::sequence(pkcs1).expect("pkcs1 outer sequence");
    assert!(rest.is_empty(), "pkcs1 must not have trailing bytes");
    let mut ranges = Vec::new();
    let mut cur = content;
    let mut base = pkcs1.len() - content.len(); // SEQUENCE 头长度
    while !cur.is_empty() {
        let before = cur.len();
        let (_tag, _val, tail) = der::read_tlv(cur).expect("field TLV");
        let consumed = before - tail.len();
        ranges.push((base, base + consumed));
        base += consumed;
        cur = tail;
    }
    ranges
}

/// 取第 idx 个字段的**原始** INTEGER 内容字节（未去前导零的 DER 内容，
/// 与 `der::integer` 的去零语义不同——变异时须知悉）。
fn pkcs1_field_content<'a>(pkcs1: &'a [u8], ranges: &[(usize, usize)], idx: usize) -> &'a [u8] {
    let (start, end) = ranges[idx];
    let (tag, content, tail) = der::read_tlv(&pkcs1[start..end]).expect("field TLV");
    assert_eq!(tag, 0x02, "field {idx} must be INTEGER");
    assert!(tail.is_empty());
    content
}

/// 将第 idx 个字段替换为内容为 new_content 的 INTEGER TLV 后重组
/// PKCS#1（外层 SEQUENCE 长度头按新总长重编码；其余字段原样保留）。
fn pkcs1_replace_field(
    pkcs1: &[u8],
    ranges: &[(usize, usize)],
    idx: usize,
    new_content: &[u8],
) -> Vec<u8> {
    let hdr = ranges[0].0; // 外层 SEQUENCE 头长度 = 首个字段 TLV 起点
    let (start, end) = ranges[idx];
    let mut content = pkcs1[hdr..start].to_vec();
    content.extend_from_slice(&tlv(0x02, new_content));
    content.extend_from_slice(&pkcs1[end..]);
    tlv(0x30, &content)
}

/// 字段末字节的进位安全 ±2（能加则加 2，否则减 2）。对"乘积/同余"
/// 类校验，任何非零 ±k（k < p−1）都必然破坏等式，方向只为避开字节
/// 进位（实测末字节：dp=0xf1、dq=0x91、q=0x99，均走 +2）。
fn bump_last_by_2(content: &[u8]) -> Vec<u8> {
    let mut v = content.to_vec();
    let last = v.len() - 1;
    if v[last] <= 0xfd {
        v[last] += 2;
    } else {
        v[last] -= 2;
    }
    v
}

// ---------------------------------------------------------------------------
// A. der 原语边界矩阵（直接调用 ferritls_core::der 各 pub fn）
// ---------------------------------------------------------------------------

/// read_tlv 长形式长度矩阵：最短合法长形式（128 = 0x80）通过；
/// 前导零、长度字节数 > 4、声明超界、内容短于声明一律 Err，绝不 panic。
#[test]
fn der_read_tlv_long_form_length_matrix() {
    // `30 81 80` + 128 字节：128 恰为长形式下限，合法
    let mut input = vec![0x30, 0x81, 0x80];
    input.extend_from_slice(&[0xab; 128]);
    let (tag, content, rest) = der::read_tlv(&input).expect("minimal long form");
    assert_eq!(tag, 0x30);
    assert_eq!(content.len(), 128);
    assert!(rest.is_empty());

    // `30 82 00 80`：长形式长度字节带前导零（非最短编码）→ Err
    let mut input = vec![0x30, 0x82, 0x00, 0x80];
    input.extend_from_slice(&[0xab; 128]);
    assert!(der::read_tlv(&input).is_err());

    // `30 85`：长形式长度字节数 n = 5 > 4 → Err（无论后续内容）
    assert!(der::read_tlv(&[0x30, 0x85, 1, 2, 3, 4, 5, 6, 7]).is_err());

    // `30 84 ff ff ff ff`：4 字节长度 0xffffffff 声明超界 → Err。
    // 64 位 usize 下这是普通的"声明超界"拒绝；32 位 usize 下
    // `rest_off + len` 会回绕、随后切片越界（潜在 panic，仅 32 位
    // 目标受影响，见任务报告）——本仓库目标平台全为 64 位。
    assert!(der::read_tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());

    // 声明长度 > 实际内容：`30 81 90`（144）只给 128 字节 → Err
    let mut input = vec![0x30, 0x81, 0x90];
    input.extend_from_slice(&[0xcd; 128]);
    assert!(der::read_tlv(&input).is_err());

    // 高位 tag 号形态 `1f 81 02 00`：read_tlv 不解析多字节 tag——
    // 0x1f 视为单字节 tag，0x81 02 是"长形式但 len=2 < 0x80"的非最短
    // 编码 → Err。钉住非 panic + Err（攻击者可控输入）。
    assert!(der::read_tlv(&[0x1f, 0x81, 0x02, 0x00]).is_err());
}

/// der::integer 最短编码矩阵：负数（首字节高位）、非最短前导零、空
/// 内容拒绝；零 / 一 / 多字节正数接受且去唯一合法前导零。
#[test]
fn der_integer_minimal_encoding_matrix() {
    // 02 01 80：首字节高位为 1（负数）→ Err
    assert!(der::integer(&hex("020180")).is_err());
    // 02 02 00 01：前导 0x00 但次字节高位为 0（非最短编码）→ Err
    assert!(der::integer(&hex("02020001")).is_err());
    // 02 00：空内容 → Err
    assert!(der::integer(&hex("0200")).is_err());
    // 02 01 00：零（单字节 0x00 合法）→ Ok，内容 [0x00]
    let zero = hex("020100");
    let (v, rest) = der::integer(&zero).expect("zero");
    assert_eq!(v, &[0x00]);
    assert!(rest.is_empty());
    // 02 01 01：一 → Ok
    let one = hex("020101");
    let (v, _) = der::integer(&one).expect("one");
    assert_eq!(v, &[0x01]);
    // 02 02 01 00：256（首字节 0x01，无前导零）→ Ok
    let b256 = hex("02020100");
    let (v, _) = der::integer(&b256).expect("256");
    assert_eq!(v, &[0x01, 0x00]);
}

/// der::bit_string 未使用位数矩阵：首位 octet 必须为 0；连未使用位
/// octet 都没有（03 00）拒绝；空位串 + 0 未使用位接受。
#[test]
fn der_bit_string_unused_bits_matrix() {
    // 03 02 01 00：未使用位数 = 1 ≠ 0 → Err
    assert!(der::bit_string(&hex("03020100")).is_err());
    // 03 00：内容为空 → Err
    assert!(der::bit_string(&hex("0300")).is_err());
    // 03 01 00：空位串、0 未使用位 → Ok，载荷为空
    let empty = hex("030100");
    let (bits, rest) = der::bit_string(&empty).expect("empty bitstring");
    assert!(bits.is_empty());
    assert!(rest.is_empty());
}

/// der::object_identifier 对空内容 `06 00` 的原语语义：只做 tag 检查、
/// 返回原始内容字节（无空内容校验）；未知/空 OID 由上层分派表
///（parse_pkcs8_private_key 的算法分支）拒绝——钉住原语行为。
#[test]
fn der_object_identifier_empty_content_pinned() {
    let empty = hex("0600");
    let (oid, rest) = der::object_identifier(&empty).expect("empty OID accepted at primitive");
    assert!(oid.is_empty());
    assert!(rest.is_empty());
}

// ---------------------------------------------------------------------------
// B. PKCS#8 分支矩阵（手拼 DER：EC / Ed25519 / 未知 OID / [0] 分派）
// ---------------------------------------------------------------------------

/// P-256 基点 G（SEC 2 prime256v1，未压缩编码）。parse_pkcs8 不验证
/// 标量↔点对应关系，结构测试只需合法形态；常量本身由
/// der_pkcs8_ec_public_key_both_forms_accepted 与 crate 曲线算术交叉核对。
const P256_GENERATOR: &str = "\
046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

/// 组装 EC PKCS#8（RFC 5480），负例旋钮即参数：
/// - curve_oid_tlv：namedCurve 的完整 OID TLV hex（可注入未知曲线）；
/// - sec1_version：SEC1 内层版本整数值（合法 = 1）；
/// - scalar_len：SEC1 privateKey OCTET STRING 字节数（合法 = 32）；
/// - pub1：完整 [1] TLV 字节（None = 不携带公钥）。
fn ec_pkcs8(
    curve_oid_tlv: &str,
    sec1_version: u8,
    scalar_len: usize,
    pub1: Option<&[u8]>,
) -> Vec<u8> {
    let mut scalar = hex(P256_SCALAR); // 32 字节
    scalar.resize(scalar_len, 0x5a);
    let mut sec1 = tlv(0x02, &[sec1_version]);
    sec1.extend_from_slice(&tlv(0x04, &scalar));
    if let Some(p1) = pub1 {
        sec1.extend_from_slice(p1);
    }
    let alg = tlv(
        0x30,
        &[hex("06072a8648ce3d0201"), hex(curve_oid_tlv)].concat(),
    );
    let mut content = hex("020100");
    content.extend_from_slice(&alg);
    // SEC1 ECPrivateKey 整体（SEQUENCE TLV）包进 privateKey OCTET STRING
    content.extend_from_slice(&tlv(0x04, &tlv(0x30, &sec1)));
    tlv(0x30, &content)
}

/// [1] 公钥的两种现实编码都接受：[1] EXPLICIT（内容 = 内层 BIT STRING
/// TLV，openssl 产物形态）与 [1] IMPLICIT（内容 = 0x00 + 未压缩点），
/// 解析出的点逐字节等于 SEC 2 基点 G（G 常量与 crate 曲线算术交叉核对）。
#[test]
fn der_pkcs8_ec_public_key_both_forms_accepted() {
    // 标量 1 → 公钥 = G：把测试常量锚定到 crate 自身的曲线实现
    let mut seed = [0u8; 32];
    seed[31] = 1;
    let g = ferritls_core::ecdh::p256::SecretKey::from_seed(seed)
        .public_key()
        .expect("derive G");
    assert_eq!(
        g.as_slice(),
        hex(P256_GENERATOR).as_slice(),
        "SEC2 G constant"
    );

    let point = hex(P256_GENERATOR);
    // EXPLICIT：[1] 内容 = BIT STRING TLV（03 42 00 || point）
    let explicit = tlv(0xa1, &tlv(0x03, &[&[0x00], point.as_slice()].concat()));
    // IMPLICIT：[1] 内容 = 0x00（未使用位数）+ 未压缩点
    let implicit = tlv(0xa1, &[&[0x00], point.as_slice()].concat());
    for (form, pub1) in [
        ("explicit", explicit.as_slice()),
        ("implicit", implicit.as_slice()),
    ] {
        let der_bytes = ec_pkcs8("06082a8648ce3d030107", 1, 32, Some(pub1));
        match der::parse_pkcs8_private_key(&der_bytes) {
            Ok(der::ParsedPrivateKey::P256 {
                scalar,
                public_sec1,
            }) => {
                assert_eq!(scalar.as_slice(), hex(P256_SCALAR).as_slice());
                assert_eq!(public_sec1.as_deref(), Some(point.as_slice()), "{form}");
            }
            other => panic!("EC PKCS#8 {form} [1] form must parse, got {other:?}"),
        }
    }
}

/// SEC1 内层负例矩阵：版本 ≠ 1、标量长度 31/33、[1] 标签 a2、压缩点
/// 形态、点长度 64、内层非 BIT STRING、未使用位数 ≠ 0、空 [1]、[1]
/// 后尾随——全部 Err(InvalidInput)，绝不 panic。
#[test]
fn der_pkcs8_ec_sec1_negative_matrix() {
    let point = hex(P256_GENERATOR);
    let explicit_content = tlv(0x03, &[&[0x00], point.as_slice()].concat());
    let curve = "06082a8648ce3d030107";
    let expect_reject = |der_bytes: &[u8], what: &str| match der::parse_pkcs8_private_key(der_bytes)
    {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("{what} must be rejected, got {other:?}"),
    };
    // SEC1 内层版本 1 → 2
    expect_reject(&ec_pkcs8(curve, 2, 32, None), "SEC1 version 2");
    // 标量 31 / 33 字节（P-256 必须 32）
    expect_reject(&ec_pkcs8(curve, 1, 31, None), "scalar 31 bytes");
    expect_reject(&ec_pkcs8(curve, 1, 33, None), "scalar 33 bytes");
    // [1] 用 a2 标签（context tag 2 非法）
    expect_reject(
        &ec_pkcs8(curve, 1, 32, Some(&tlv(0xa2, &explicit_content))),
        "[1] with a2 tag",
    );
    // [1] IMPLICIT 形态携带压缩点前缀（0x02）：形态不符
    expect_reject(
        &ec_pkcs8(
            curve,
            1,
            32,
            Some(&tlv(0xa1, &[&[0x00, 0x02], &point[1..33]].concat())),
        ),
        "[1] implicit compressed point",
    );
    // [1] 点长度 64（未压缩点少一字节）
    expect_reject(
        &ec_pkcs8(
            curve,
            1,
            32,
            Some(&tlv(0xa1, &tlv(0x03, &[&[0x00], &point[..64]].concat()))),
        ),
        "[1] point 64 bytes",
    );
    // [1] EXPLICIT 内层不是 BIT STRING（OCTET STRING 顶替）
    expect_reject(
        &ec_pkcs8(
            curve,
            1,
            32,
            Some(&tlv(
                0xa1,
                &tlv(0x04, &[&[0x00], point.as_slice()].concat()),
            )),
        ),
        "[1] inner OCTET STRING",
    );
    // [1] EXPLICIT BIT STRING 未使用位数 ≠ 0
    expect_reject(
        &ec_pkcs8(
            curve,
            1,
            32,
            Some(&tlv(
                0xa1,
                &tlv(0x03, &[&[0x01], point.as_slice()].concat()),
            )),
        ),
        "[1] BIT STRING unused bits",
    );
    // [1] 空内容
    expect_reject(&ec_pkcs8(curve, 1, 32, Some(&tlv(0xa1, &[]))), "[1] empty");
    // [1] 之后尾随 TLV（SEC1 内多一个元素）
    let mut pub1_trailing = tlv(0xa1, &explicit_content);
    pub1_trailing.extend_from_slice(&hex("0500"));
    expect_reject(
        &ec_pkcs8(curve, 1, 32, Some(&pub1_trailing)),
        "trailing after [1]",
    );
}

/// EC AlgId 携带未知 namedCurve（P-521，1.3.132.0.35 = 2b 81 04 00 23）：
/// RFC 5480 分派只认 prime256v1 / secp384r1 → Err(InvalidInput)。
#[test]
fn der_pkcs8_ec_p521_curve_oid_rejected() {
    let der_bytes = ec_pkcs8("06052b81040023", 1, 32, None);
    match der::parse_pkcs8_private_key(&der_bytes) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("P-521 namedCurve must be rejected, got {other:?}"),
    }
}

/// 组装 Ed25519 PKCS#8（RFC 8410 §7：parameters 缺席），负例旋钮：
/// - seed_len：内层 OCTET STRING 字节数（合法 = 32）；
/// - inner_tag：内层 TLV 标签（合法 = 0x04 OCTET STRING）；
/// - inner_tail：内层 TLV 之后的尾随 TLV（外层 OCTET STRING 内容内）；
/// - trailing：privateKey OCTET STRING 之后的尾随 TLV（PKCS#8 层）。
fn ed25519_pkcs8(seed_len: usize, inner_tag: u8, inner_tail: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut inner = tlv(inner_tag, &vec![0x5a; seed_len]);
    inner.extend_from_slice(inner_tail);
    let alg = tlv(0x30, &hex("06032b6570"));
    let mut content = hex("020100");
    content.extend_from_slice(&alg);
    content.extend_from_slice(&tlv(0x04, &inner));
    content.extend_from_slice(trailing);
    tlv(0x30, &content)
}

/// Ed25519 分支负例矩阵：种子 31/33 字节、内层非 OCTET STRING、内层
/// OCTET STRING 之后尾随 TLV——全部 Err(InvalidInput)；合法基线解析出
/// 的种子逐字节往返。
#[test]
fn der_pkcs8_ed25519_negative_matrix() {
    // 合法基线：32 字节种子
    match der::parse_pkcs8_private_key(&ed25519_pkcs8(32, 0x04, &[], &[])) {
        Ok(der::ParsedPrivateKey::Ed25519(seed)) => assert_eq!(seed, vec![0x5a; 32]),
        other => panic!("baseline Ed25519 PKCS#8 must parse, got {other:?}"),
    }
    let expect_reject = |der_bytes: &[u8], what: &str| match der::parse_pkcs8_private_key(der_bytes)
    {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("{what} must be rejected, got {other:?}"),
    };
    // 种子 31 / 33 字节
    expect_reject(&ed25519_pkcs8(31, 0x04, &[], &[]), "seed 31 bytes");
    expect_reject(&ed25519_pkcs8(33, 0x04, &[], &[]), "seed 33 bytes");
    // 内层不是 OCTET STRING（BIT STRING 顶替）
    expect_reject(&ed25519_pkcs8(32, 0x03, &[], &[]), "inner BIT STRING");
    // 内层 OCTET STRING 之后尾随 TLV（外层 OCTET STRING 内容内）
    expect_reject(
        &ed25519_pkcs8(32, 0x04, &hex("0500"), &[]),
        "tail inside inner",
    );
}

/// Ed448（1.3.101.113 = 2b 65 71）不在分派表（Ed25519/RSA/EC）内：
/// parse_pkcs8_private_key 落到末尾的统一 Err(InvalidInput)。
#[test]
fn der_pkcs8_ed448_oid_rejected() {
    let alg = tlv(0x30, &hex("06032b6571"));
    let mut content = hex("020100");
    content.extend_from_slice(&alg);
    // Ed448 种子 57 字节；分派在内容检查前完成，形态无关紧要
    content.extend_from_slice(&tlv(0x04, &tlv(0x04, &[0x11u8; 57])));
    let der_bytes = tlv(0x30, &content);
    match der::parse_pkcs8_private_key(&der_bytes) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("Ed448 OID must be rejected, got {other:?}"),
    }
}

/// privateKey 之后直接跟垃圾（无 [0] 标签字节）：rest[0] != 0xa0 →
/// Err(InvalidInput)（[0] attributes 分派分支）。
#[test]
fn der_pkcs8_garbage_after_private_key_without_attributes() {
    // 05 00（NULL TLV）顶替 [0]：首字节 0x05 ≠ 0xa0
    match der::parse_pkcs8_private_key(&ed25519_pkcs8(32, 0x04, &[], &hex("0500"))) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("garbage without [0] tag must be rejected, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// C. RSA 结构校验矩阵（R3 装载期校验：CRT 分量范围与下界、d ↔ CRT
//    一致、e·d ≡ 1 mod (p−1)/(q−1)、d 尺寸上界、p·q = n、奇偶与
//    指数合同）。变异 = 外科手术式替换内层 PKCS#1 的单个字段。
// ---------------------------------------------------------------------------

/// 字段 walker 往返锚：剥出的内层 PKCS#1 可直接装载；重新包裹的
/// PKCS#8 亦可装载；九个字段的原始内容长度逐一钉死（变异的手术前提，
/// 由上方解码核对：qInv 无前导零 128 字节，其余秘密分量 00 || 128）。
#[test]
fn rsa_pkcs1_field_walker_round_trip_anchor() {
    let pkcs8 = hex(KEY_PKCS8);
    let pkcs1 = extract_pkcs1(&pkcs8);
    assert!(
        rsa::SigningKey::from_pkcs1_der(&pkcs1).is_ok(),
        "extracted PKCS#1 must load"
    );
    assert!(
        rsa::SigningKey::from_pkcs8_der(&wrap_pkcs8(&pkcs1)).is_ok(),
        "rewrapped PKCS#8 must load"
    );

    let ranges = pkcs1_field_ranges(&pkcs1);
    assert_eq!(ranges.len(), 9, "version + n/e/d/p/q/dp/dq/qInv");
    let lens: Vec<usize> = (0..9)
        .map(|i| pkcs1_field_content(&pkcs1, &ranges, i).len())
        .collect();
    assert_eq!(lens, [1, 257, 3, 255, 129, 129, 129, 129, 128]);
    // 语义锚：version = 0、e = 65537、n 内容 0x00 前导（2048 位正整数）
    assert_eq!(pkcs1_field_content(&pkcs1, &ranges, 0), &[0x00]);
    assert_eq!(pkcs1_field_content(&pkcs1, &ranges, 2), &[0x01, 0x00, 0x01]);
    assert_eq!(pkcs1_field_content(&pkcs1, &ranges, 1)[0], 0x00);
}

/// d 篡改矩阵：d ± 1 破坏 d mod (p−1) == dp 的完全约简等式（R3）；
/// 同长全零 d 在 der::integer 的非最短编码检查即被拒；单字节 0x00 的
/// d = 0 通过解析、走算术层（d mod (p−1) = 0 ≠ dp）被拒。
#[test]
fn rsa_pkcs1_d_tampering_rejected() {
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let expect_reject =
        |mutated: Vec<u8>, what: &str| match rsa::SigningKey::from_pkcs1_der(&mutated) {
            Err(ferritls_core::Error::InvalidInput) => {}
            other => panic!("{what} must be InvalidInput, got {other:?}"),
        };

    // d 最低位翻转（d ± 1）
    let mut d = pkcs1_field_content(&pkcs1, &ranges, 3).to_vec();
    let last = d.len() - 1;
    d[last] ^= 1;
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 3, &d), "d ± 1");

    // 同长全零 d（多字节全零 = 非最短编码，der::integer 层拒绝）
    let zero = vec![0u8; pkcs1_field_content(&pkcs1, &ranges, 3).len()];
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 3, &zero), "d all-zero");

    // d = 0（单字节 0x00：过解析层，撞 d mod (p−1) == dp 等式）
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 3, &[0x00]), "d = 0");

    // PKCS#8 路径同拒（重新包裹后走 from_pkcs8_der）
    let mut d2 = pkcs1_field_content(&pkcs1, &ranges, 3).to_vec();
    let last2 = d2.len() - 1;
    d2[last2] ^= 1;
    let wrapped = wrap_pkcs8(&pkcs1_replace_field(&pkcs1, &ranges, 3, &d2));
    assert!(
        rsa::SigningKey::from_pkcs8_der(&wrapped).is_err(),
        "tampered d via PKCS#8 must be rejected"
    );
}

/// CRT 分量篡改矩阵（R3 新增校验）：dp/dq ± 2 破坏 d mod (p−1)/(q−1)
/// == dp/dq 完全约简等式；dp/dq/qInv = 1 与 dp = 0 撞下界 ≥ 2
///（下界检查先于同余合同与 q·qInv ≡ 1 mod p 的 Montgomery 复核）。
#[test]
fn rsa_pkcs1_crt_component_tampering_rejected() {
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let expect_reject =
        |mutated: Vec<u8>, what: &str| match rsa::SigningKey::from_pkcs1_der(&mutated) {
            Err(ferritls_core::Error::InvalidInput) => {}
            other => panic!("{what} must be InvalidInput, got {other:?}"),
        };

    // dp ± 2 / dq ± 2
    let dp = bump_last_by_2(pkcs1_field_content(&pkcs1, &ranges, 6));
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 6, &dp), "dp ± 2");
    let dq = bump_last_by_2(pkcs1_field_content(&pkcs1, &ranges, 7));
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 7, &dq), "dq ± 2");

    // dp / dq / qInv = 1（下界 ≥ 2）
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 6, &[0x01]), "dp = 1");
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 7, &[0x01]), "dq = 1");
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 8, &[0x01]), "qInv = 1");
    // dp = 0（02 01 00 单字节，过 der::integer，撞下界）
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 6, &[0x00]), "dp = 0");
}

/// 模数与公指数篡改矩阵：n 变偶、负数模数（符号位 INTEGER 在解析层
/// 拒绝）、e < 3 / e 偶、p/q 置零、q ± 2 破坏 p·q = n——全部
/// Err(InvalidInput)。
#[test]
fn rsa_pkcs1_modulus_and_exponent_tampering_rejected() {
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let expect_reject =
        |mutated: Vec<u8>, what: &str| match rsa::SigningKey::from_pkcs1_der(&mutated) {
            Err(ferritls_core::Error::InvalidInput) => {}
            other => panic!("{what} must be InvalidInput, got {other:?}"),
        };

    // n 最低位翻转（末字节 0x01 → 0x00：n 变偶）
    let mut n = pkcs1_field_content(&pkcs1, &ranges, 1).to_vec();
    let last = n.len() - 1;
    n[last] ^= 1;
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 1, &n), "even n");

    // 负数模数：n 内容前加 0xff（首字节符号位为 1 的 INTEGER）——
    // der::integer 在解析层直接拒绝，任何 os2ip/奇偶检查之前
    let mut neg = vec![0xffu8];
    neg.extend_from_slice(pkcs1_field_content(&pkcs1, &ranges, 1));
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 1, &neg), "negative n");

    // e = 1（< 3）、e = 4（偶数）
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 2, &[0x01]), "e = 1");
    expect_reject(
        pkcs1_replace_field(&pkcs1, &ranges, 2, &[0x04]),
        "e = 4 (even)",
    );

    // p / q 置零（单字节 0x00 过解析层，撞奇偶/零检查）
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 4, &[0x00]), "p = 0");
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 5, &[0x00]), "q = 0");

    // q ± 2：p·q ≠ n（q 仍为奇，乘积错位）
    let q = bump_last_by_2(pkcs1_field_content(&pkcs1, &ranges, 5));
    expect_reject(pkcs1_replace_field(&pkcs1, &ranges, 5, &q), "p·q ≠ n");
}

/// d 尺寸上界（R3）：d 去前导零后超过 n_bytes + 8 = 264 字节必然是
/// 垃圾或放大输入 → Err(InvalidInput)。266 字节原始内容（0x00 ‖ 0x80
/// ‖ 0×264，合法最短编码正整数）去零后恰 265 字节 > 264。
#[test]
fn rsa_pkcs1_oversized_d_rejected() {
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let mut d = vec![0x00u8, 0x80];
    d.extend_from_slice(&[0u8; 264]);
    assert_eq!(d.len(), 266);
    let mutated = pkcs1_replace_field(&pkcs1, &ranges, 3, &d);
    match rsa::SigningKey::from_pkcs1_der(&mutated) {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("oversized d must be InvalidInput, got {other:?}"),
    }
    // PKCS#8 路径同拒（重新包裹）
    let wrapped = wrap_pkcs8(&mutated);
    assert!(
        rsa::SigningKey::from_pkcs8_der(&wrapped).is_err(),
        "oversized d via PKCS#8 must be rejected"
    );
}

/// 公钥路径负例矩阵：缺 e、e 超宽（9 字节）、2040 位模数（低于 2048
/// 位下限 → Unsupported）、SPKI 换 OID、SPKI BIT STRING 未使用位数
/// ≠ 0、SPKI 尾随垃圾。
#[test]
fn rsa_public_key_parse_negative_matrix() {
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let n_content = pkcs1_field_content(&pkcs1, &ranges, 1).to_vec();
    let e_content = pkcs1_field_content(&pkcs1, &ranges, 2).to_vec();
    let rsapub = |n_c: &[u8], e_c: &[u8]| {
        let mut seq = tlv(0x02, n_c);
        seq.extend_from_slice(&tlv(0x02, e_c));
        tlv(0x30, &seq)
    };
    let expect_invalid = |out: Result<rsa::VerifyKey, ferritls_core::Error>, what: &str| match out {
        Err(ferritls_core::Error::InvalidInput) => {}
        other => panic!("{what} must be InvalidInput, got {other:?}"),
    };

    // 缺 e：n 之后 integer 落在空输入（read_tlv 要求 ≥ 2 字节）
    expect_invalid(
        rsa::VerifyKey::from_rsapublickey_der(&rsapub(&n_content, &[])),
        "missing e",
    );
    // e 9 字节（> 8 字节上限）
    let e9 = [0x01u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    expect_invalid(
        rsa::VerifyKey::from_rsapublickey_der(&rsapub(&n_content, &e9)),
        "e wider than 8 bytes",
    );
    // 2040 位模数（去掉 0x00 前导与最高字节 0xa8）：低于 2048 位下限
    match rsa::VerifyKey::from_rsapublickey_der(&rsapub(&n_content[2..], &e_content)) {
        Err(ferritls_core::Error::Unsupported) => {}
        other => panic!("2040-bit modulus must be Unsupported, got {other:?}"),
    }

    // SPKI：AlgId 换成 id-ecPublicKey（OID 分派失败）
    let alg_rsa = tlv(0x30, &hex("06092a864886f70d0101010500"));
    let alg_ec = tlv(0x30, &hex("06072a8648ce3d0201"));
    let keybits = tlv(
        0x03,
        &[&[0x00], rsapub(&n_content, &e_content).as_slice()].concat(),
    );
    let spki_with = |alg: &[u8], bitstr: &[u8], trailing: &[u8]| {
        let mut content = alg.to_vec();
        content.extend_from_slice(bitstr);
        content.extend_from_slice(trailing);
        tlv(0x30, &content)
    };
    expect_invalid(
        rsa::VerifyKey::from_spki_der(&spki_with(&alg_ec, &keybits, &[])),
        "SPKI with EC OID",
    );
    // SPKI BIT STRING 未使用位数 ≠ 0（bit_string 原语层拒绝）
    let bad_bits = tlv(
        0x03,
        &[&[0x01], rsapub(&n_content, &e_content).as_slice()].concat(),
    );
    expect_invalid(
        rsa::VerifyKey::from_spki_der(&spki_with(&alg_rsa, &bad_bits, &[])),
        "SPKI BIT STRING unused bits",
    );
    // SPKI BIT STRING 之后尾随垃圾
    expect_invalid(
        rsa::VerifyKey::from_spki_der(&spki_with(&alg_rsa, &keybits, &hex("0500"))),
        "SPKI trailing garbage",
    );
}

/// 验证入口负例：签名长度 ≠ n_bytes（255/257，v1.5 与 PSS 共用
/// public_exponentiate 的定长检查）→ InvalidInput；s ≥ n（s = n 本体
/// 256 字节）→ VerificationFailed。
#[test]
fn rsa_verify_signature_length_and_s_bounds() {
    let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
    let sig15 = hex(SIG_V15_SHA256);
    let sigpss = hex(SIG_PSS_SHA256);

    // 长度 255 / 257：两个验证 API 同一入口、同一 InvalidInput
    for (api, sig) in [("pkcs1v15", &sig15), ("pss", &sigpss)] {
        for len in [sig.len() - 1, sig.len() + 1] {
            let mut bad = sig.clone();
            bad.resize(len, 0x00);
            let out = match api {
                "pkcs1v15" => pk.verify_pkcs1v15(256, MSG, &bad),
                _ => pk.verify_pss(256, MSG, &bad),
            };
            match out {
                Err(ferritls_core::Error::InvalidInput) => {}
                other => panic!("{api} sig len {len} must be InvalidInput, got {other:?}"),
            }
        }
    }

    // s = n（内层 n 字段去 0x00 前导的 256 字节 BE 本体）：s < n 不成立
    let pkcs1 = extract_pkcs1(&hex(KEY_PKCS8));
    let ranges = pkcs1_field_ranges(&pkcs1);
    let n_be = pkcs1_field_content(&pkcs1, &ranges, 1)[1..].to_vec();
    assert_eq!(n_be.len(), 256);
    match pk.verify_pss(256, MSG, &n_be) {
        Err(ferritls_core::Error::VerificationFailed) => {}
        other => panic!("s == n (pss) must be VerificationFailed, got {other:?}"),
    }
    match pk.verify_pkcs1v15(256, MSG, &n_be) {
        Err(ferritls_core::Error::VerificationFailed) => {}
        other => panic!("s == n (pkcs1v15) must be VerificationFailed, got {other:?}"),
    }
}

/// 未支持哈希位宽 224：签名与验证两侧均 Err(Unsupported)
///（hash_msg / digestinfo_prefix 的分派表只有 256/384/512）。
#[test]
fn rsa_hash_bits_224_unsupported_both_sides() {
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    let pk = rsa::VerifyKey::from_spki_der(&hex(PUB_SPKI)).expect("parse pubkey");
    let sig15 = hex(SIG_V15_SHA256);
    let sigpss = hex(SIG_PSS_SHA256);
    // 签名侧
    for out in [sk.sign_pkcs1v15(224, MSG), sk.sign_pss(224, MSG)] {
        match out {
            Err(ferritls_core::Error::Unsupported) => {}
            other => panic!("hash_bits 224 must be Unsupported, got {other:?}"),
        }
    }
    // 验证侧：public_exponentiate（合法长度、s < n）先通过，Unsupported
    // 来自其后的 hash_msg / digestinfo_prefix 分派
    for out in [
        pk.verify_pkcs1v15(224, MSG, &sig15),
        pk.verify_pss(224, MSG, &sigpss),
    ] {
        match out {
            Err(ferritls_core::Error::Unsupported) => {}
            other => panic!("hash_bits 224 must be Unsupported, got {other:?}"),
        }
    }
}
