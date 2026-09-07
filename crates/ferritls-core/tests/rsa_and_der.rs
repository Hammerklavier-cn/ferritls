//! RSA 与 DER 解析测试（M4b）。
//!
//! RSA 向量：本地 OpenSSL 3.2.4 生成的 2048 位测试密钥与签名
//! （PKCS#1 v1.5 确定性签名逐字节锚定；PSS 为随机化签名，验证
//! 方向锚定 openssl 产物 + 自洽往返）。Wycheproof
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
    rsa::verify_pkcs1v15(256, &hex(PUB_SPKI), MSG, &sig).expect("verify self");
    // 篡改签名 → 失败
    let mut bad = sig.clone();
    bad[128] ^= 1;
    assert_eq!(
        rsa::verify_pkcs1v15(256, &hex(PUB_SPKI), MSG, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

#[test]
fn rsa_verify_pkcs1v15_sha384_openssl_anchor() {
    let sig = hex(SIG_V15_SHA384);
    rsa::verify_pkcs1v15(384, &hex(PUB_SPKI), MSG, &sig).expect("verify sha384");
    // 篡改消息 → 失败
    assert_eq!(
        rsa::verify_pkcs1v15(384, &hex(PUB_SPKI), b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
}

#[test]
fn rsa_pss_openssl_verify_and_round_trip() {
    // openssl 生成的 PSS 签名（salt = 哈希长度）验证方向锚定
    rsa::verify_pss(256, &hex(PUB_SPKI), MSG, &hex(SIG_PSS_SHA256)).expect("pss sha256");
    rsa::verify_pss(512, &hex(PUB_SPKI), MSG, &hex(SIG_PSS_SHA512)).expect("pss sha512");
    // 自洽往返（PSS 签名含随机 salt，不做逐字节比较）
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(KEY_PKCS8)).expect("parse key");
    let sig = sk.sign_pss(256, MSG).expect("sign pss");
    rsa::verify_pss(256, &hex(PUB_SPKI), MSG, &sig).expect("verify self pss");
    // 篡改消息 → 失败
    assert_eq!(
        rsa::verify_pss(256, &hex(PUB_SPKI), b"sample!", &sig),
        Err(ferritls_core::Error::VerificationFailed)
    );
    // 篡改签名首字节 → 失败
    let mut bad = sig.clone();
    bad[0] ^= 1;
    assert_eq!(
        rsa::verify_pss(256, &hex(PUB_SPKI), MSG, &bad),
        Err(ferritls_core::Error::VerificationFailed)
    );
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
