//! 适配层 API 形状测试（M6/M7）。
//!
//! 清单断言防止套件/组清单与文档漂移；provider smoke 覆盖两个出厂
//! 配置的构成与 `fips()` 语义（认证前恒 false）。
//!
//! RSA 测试私钥夹具（`tests/data/`）溯源：派生自
//! `crates/ferritls-interop/tests/certs/rsa_leaf.key.der`（openssl
//! 生成的本地专用测试链 RSA-2048 leaf 私钥，见该目录 README.md——
//! 无任何真实安全性），PKCS#1 形态由
//! `openssl rsa -inform DER -traditional -outform DER` 转换得到。
//! 跨 crate 不能 `include_bytes!` 互操作 crate 的文件，故复制为
//! 本 crate 的测试夹具。

mod common;

/// RSA-2048 测试私钥（PKCS#8 PrivateKeyInfo DER）。
const RSA_PKCS8_DER: &[u8] = include_bytes!("data/rsa_leaf_pkcs8.der");

/// 同一把 RSA-2048 测试私钥（裸 PKCS#1 RSAPrivateKey DER，供
/// `RsaKey::from_pkcs1_der` / `any_supported_type` PKCS#1 回退路径）。
const RSA_PKCS1_DER: &[u8] = include_bytes!("data/rsa_leaf_pkcs1.der");

#[test]
fn suite_inventory_matches_docs() {
    assert_eq!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.len(), 5);
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_128_GCM_SHA256"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_256_GCM_SHA384"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_CHACHA20_POLY1305_SHA256"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_128_CCM_SHA256"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_128_CCM_8_SHA256"));
}

/// QUIC 接线防漂移（M8.5）：GCM/ChaCha 三套件暴露 `quic::Algorithm`
/// 且密钥长度正确，CCM 不参与 QUIC。
#[test]
fn quic_algorithms_wired_for_three_suites() {
    let cases = [
        (ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(), 16),
        (ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(), 32),
        (
            ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(),
            32,
        ),
    ];
    for (suite, key_len) in cases {
        let quic_alg = suite
            .tls13()
            .expect("tls13")
            .quic
            .expect("GCM/ChaCha 套件必须接线 QUIC");
        assert_eq!(quic_alg.aead_key_len(), key_len);
        // 规则 3：认证前 fips() 恒 false
        assert!(!quic_alg.fips());
    }
    assert!(
        ferritls_rustls::cipher::tls13_aes_128_ccm_sha256()
            .tls13()
            .expect("tls13")
            .quic
            .is_none()
            && ferritls_rustls::cipher::tls13_aes_128_ccm_8_sha256()
                .tls13()
                .expect("tls13")
                .quic
                .is_none(),
        "CCM（含 CCM_8）不参与 QUIC（RFC 9001 §5.1 以 AES-GCM 为强制基准）"
    );
}

/// 套件批准面防漂移：CCM_8 仅默认模式（8 字节标签不在 SP 800-52r2
/// 批准套件面），批准模式清单不含 ChaCha/CCM_8。
#[test]
fn ccm8_suite_excluded_from_fips_inventory() {
    let fips: Vec<_> = ferritls_rustls::cipher::fips_tls13_suites();
    assert_eq!(fips.len(), 3, "批准模式 = GCM×2 + CCM");
    assert!(
        fips.iter()
            .all(|s| s.suite() != rustls::CipherSuite::TLS13_AES_128_CCM_8_SHA256)
    );

    let all: Vec<_> = ferritls_rustls::cipher::all_tls13_suites();
    assert_eq!(all.len(), 5);
    assert!(
        all.iter()
            .any(|s| s.suite() == rustls::CipherSuite::TLS13_AES_128_CCM_8_SHA256)
    );
}

#[test]
fn kx_group_names_are_stable() {
    use rustls::NamedGroup;
    assert_eq!(ferritls_rustls::kx::X25519_GROUP.name(), NamedGroup::X25519);
    assert_eq!(
        ferritls_rustls::kx::SECP256R1_GROUP.name(),
        NamedGroup::secp256r1
    );
    assert_eq!(
        ferritls_rustls::kx::SECP384R1_GROUP.name(),
        NamedGroup::secp384r1
    );
    assert_eq!(
        ferritls_rustls::kx::X25519MLKEM768_GROUP.name(),
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(
        ferritls_rustls::kx::MLKEM512_GROUP.name(),
        NamedGroup::MLKEM512
    );
    assert_eq!(
        ferritls_rustls::kx::MLKEM768_GROUP.name(),
        NamedGroup::MLKEM768
    );
    assert_eq!(
        ferritls_rustls::kx::MLKEM1024_GROUP.name(),
        NamedGroup::MLKEM1024
    );
    assert_eq!(ferritls_rustls::kx::ALL_KX_GROUPS.len(), 7);
    assert_eq!(ferritls_rustls::kx::FIPS_KX_GROUPS.len(), 6);
    // 混合组在两个清单中均为首项（PQ 优先）
    assert_eq!(
        ferritls_rustls::kx::ALL_KX_GROUPS[0].name(),
        NamedGroup::X25519MLKEM768
    );
    assert_eq!(
        ferritls_rustls::kx::FIPS_KX_GROUPS[0].name(),
        NamedGroup::X25519MLKEM768
    );
}

#[test]
fn default_provider_smoke() {
    let p = ferritls_rustls::default_provider();
    assert!(!p.fips(), "认证前 fips() 必须为 false");
    assert_eq!(p.cipher_suites.len(), 5);
    assert_eq!(p.kx_groups.len(), 7);
}

#[test]
fn fips_mode_provider_smoke() {
    let p = ferritls_rustls::fips_mode_provider();
    // 批准模式也必须为 false：批准模式 ≠ 已认证。
    assert!(!p.fips());
    assert_eq!(p.cipher_suites.len(), 3, "批准模式无 ChaCha20-Poly1305");
    assert_eq!(
        p.kx_groups.len(),
        6,
        "批准模式：X25519MLKEM768 混合 + 纯 ML-KEM 三参数集 + P-256/384，无独立 X25519"
    );
}

/// 验证算法表形状防漂移：默认表 9 项（含 Ed25519），批准表 8 项且是
/// 默认表的子集（同一组静态 verifier）；scheme → 算法映射每组恰一
/// 算法、算法都来自本表 `all` 清单（TLS 1.3 只取首项，单元素切片是
/// 该语义的最保守形态）；scheme 差集恰为 ED25519。
#[test]
fn verification_tables_shape_and_fips_subset() {
    use rustls::SignatureScheme;
    use std::ptr;

    let def = ferritls_rustls::verify::SUPPORTED_ALGORITHMS;
    let fips = ferritls_rustls::verify::FIPS_SUPPORTED_ALGORITHMS;

    assert_eq!(def.all.len(), 9, "默认表：ECDSA×2 + Ed25519 + RSA×6");
    assert_eq!(fips.all.len(), 8, "批准表无 Ed25519");
    for a in fips.all {
        assert!(
            def.all.iter().any(|b| ptr::eq(*a, *b)),
            "批准表出现默认表之外的 verifier"
        );
    }

    for (mapping, all, what) in [
        (def.mapping, def.all, "默认表"),
        (fips.mapping, fips.all, "批准表"),
    ] {
        let mut schemes: Vec<u16> = mapping.iter().map(|(s, _)| u16::from(*s)).collect();
        schemes.sort_unstable();
        schemes.dedup();
        assert_eq!(schemes.len(), mapping.len(), "{what} scheme 键不得重复");
        for (scheme, algs) in mapping {
            assert_eq!(
                algs.len(),
                1,
                "{what} {scheme:?} 映射必须单算法（TLS 1.3 首项语义的最保守形态）"
            );
            assert!(
                all.iter().any(|b| ptr::eq(algs[0], *b)),
                "{what} {scheme:?} 映射的 verifier 不在本表 all 中"
            );
        }
    }

    let def_schemes: Vec<u16> = def.mapping.iter().map(|(s, _)| u16::from(*s)).collect();
    let fips_schemes: Vec<u16> = fips.mapping.iter().map(|(s, _)| u16::from(*s)).collect();
    let diff: Vec<u16> = def_schemes
        .iter()
        .copied()
        .filter(|s| !fips_schemes.contains(s))
        .collect();
    assert_eq!(
        diff.as_slice(),
        &[u16::from(SignatureScheme::ED25519)],
        "批准表与默认表的 scheme 差集恰为 Ed25519"
    );
}

/// FIPS 表消费防漂移：两个 provider 的验证算法表必须指针一致地指向
/// 对应静态表，防止装配时误接（批准模式误接默认表会把 Ed25519 放进
/// 批准面，反之会让默认模式丢算法）。
#[test]
fn providers_consume_their_verification_tables() {
    use std::ptr;

    let def = ferritls_rustls::default_provider();
    let fips = ferritls_rustls::fips_mode_provider();

    assert!(ptr::eq(
        def.signature_verification_algorithms.all,
        ferritls_rustls::verify::SUPPORTED_ALGORITHMS.all
    ));
    assert!(ptr::eq(
        def.signature_verification_algorithms.mapping,
        ferritls_rustls::verify::SUPPORTED_ALGORITHMS.mapping
    ));
    assert!(ptr::eq(
        fips.signature_verification_algorithms.all,
        ferritls_rustls::verify::FIPS_SUPPORTED_ALGORITHMS.all
    ));
    assert!(ptr::eq(
        fips.signature_verification_algorithms.mapping,
        ferritls_rustls::verify::FIPS_SUPPORTED_ALGORITHMS.mapping
    ));
}

/// X25519MLKEM768 端到端形状与共享秘密一致性（M8.3）：
/// 客户端 share 1216 B、服务端 share 1120 B、ss 64 B，两侧一致；
/// 篡改 share 必须被拒绝（ek 模校验 / 密文长度）。
#[test]
fn x25519_mlkem768_roundtrip_and_rejects() {
    use rustls::crypto::CompletedKeyExchange;
    let group = ferritls_rustls::kx::X25519MLKEM768_GROUP;

    // 正常往返（complete 消费 Box，负例先行）
    let client = group.start().expect("client start");
    assert_eq!(client.pub_key().len(), 1184 + 32, "客户端 share 形状");
    let server: CompletedKeyExchange = group
        .start_and_complete(client.pub_key())
        .expect("server start_and_complete");
    assert_eq!(server.pub_key.len(), 1088 + 32, "服务端 share 形状");

    // 负例 1：客户端 share 长度错误 → 服务端拒绝
    let mut bad_share = client.pub_key().to_vec();
    bad_share.pop();
    assert!(group.start_and_complete(&bad_share).is_err());

    // 负例 2：服务端 share 长度错误 → 客户端 complete 拒绝
    let client2 = group.start().expect("client start 2");
    let server2 = group
        .start_and_complete(client2.pub_key())
        .expect("server 2");
    let mut short = server2.pub_key.clone();
    short.pop();
    assert!(client2.complete(&short).is_err());

    // 正向 complete（消费 client）
    let ss_client = client.complete(&server.pub_key).expect("client complete");
    assert_eq!(ss_client.secret_bytes().len(), 64, "ss = ML-KEM ‖ X25519");
    assert_eq!(
        ss_client.secret_bytes(),
        server.secret.secret_bytes(),
        "两侧共享秘密一致"
    );
}

/// 纯 ML-KEM 组（0x0200–0x0202）端到端形状与共享秘密一致性（M8.4）：
/// 客户端 share = ek、服务端 share = ct、ss 32 B，三参数集逐一验证；
/// ek/ct 长度不符必须被拒绝（§7.2 封装密钥检查 / 密文长度检查）。
#[test]
fn pure_mlkem_groups_roundtrip_and_rejects() {
    use rustls::crypto::CompletedKeyExchange;

    let cases = [
        (
            ferritls_rustls::kx::MLKEM512_GROUP,
            800, // ek
            768, // ct
        ),
        (ferritls_rustls::kx::MLKEM768_GROUP, 1184, 1088),
        (ferritls_rustls::kx::MLKEM1024_GROUP, 1568, 1568),
    ];
    for (group, ek_bytes, ct_bytes) in cases {
        let client = group.start().expect("client start");
        assert_eq!(client.pub_key().len(), ek_bytes, "客户端 share = ek");

        // 负例 1：客户端 share 长度错误 → 服务端拒绝
        let mut bad_share = client.pub_key().to_vec();
        bad_share.pop();
        assert!(group.start_and_complete(&bad_share).is_err());

        // 负例 2：内容非法（全 0xFF 首系数 ≥ q）→ §7.2 模校验拒绝
        let garbage = vec![0xffu8; ek_bytes];
        assert!(
            group.start_and_complete(&garbage).is_err(),
            "ek 模校验必须拒绝 0xFF 填充"
        );

        // 正常往返
        let server: CompletedKeyExchange = group
            .start_and_complete(client.pub_key())
            .expect("server start_and_complete");
        assert_eq!(server.pub_key.len(), ct_bytes, "服务端 share = ct");
        assert_eq!(server.secret.secret_bytes().len(), 32, "ss = 32 B");

        // 负例 3：服务端 share 长度错误 → 客户端 complete 拒绝
        let client2 = group.start().expect("client start 2");
        let server2 = group
            .start_and_complete(client2.pub_key())
            .expect("server 2");
        let mut short = server2.pub_key.clone();
        short.pop();
        assert!(client2.complete(&short).is_err());

        // 正向 complete（消费 client）
        let ss_client = client.complete(&server.pub_key).expect("client complete");
        assert_eq!(
            ss_client.secret_bytes(),
            server.secret.secret_bytes(),
            "两侧共享秘密一致"
        );
    }
}

// ---------------------------------------------------------------------------
// choose_scheme 负例与 RSA 方案偏好序（sign.rs）
// ---------------------------------------------------------------------------

/// offer 不含本密钥的方案 → `choose_scheme` 返回 None：四类密钥逐一
/// 验证（含「同为 ECDSA 但曲线不符」与「空 offer」两种形态）。
#[test]
fn choose_scheme_rejects_non_matching_offers() {
    use rustls::SignatureScheme as S;
    use rustls::sign::SigningKey;

    let p256 = ferritls_rustls::sign::EcdsaP256Key::new(&[0x11u8; 32]);
    let p384 = ferritls_rustls::sign::EcdsaP384Key::new(&[0x22u8; 48]);
    let ed = ferritls_rustls::sign::Ed25519Key::new(&[0x33u8; 32]);
    let rsa = ferritls_rustls::sign::RsaKey::from_pkcs1_der(RSA_PKCS1_DER)
        .expect("PKCS#1 测试私钥必须可装载");

    // 空 offer：一律 None
    assert!(p256.choose_scheme(&[]).is_none());
    assert!(p384.choose_scheme(&[]).is_none());
    assert!(ed.choose_scheme(&[]).is_none());
    assert!(rsa.choose_scheme(&[]).is_none());

    // 异算法 offer：一律 None
    assert!(
        p256.choose_scheme(&[S::RSA_PSS_SHA256, S::ED25519])
            .is_none(),
        "P-256 密钥不得接受 RSA/Ed25519 offer"
    );
    assert!(
        p384.choose_scheme(&[S::RSA_PKCS1_SHA512, S::ED25519])
            .is_none(),
        "P-384 密钥不得接受 RSA/Ed25519 offer"
    );
    assert!(
        ed.choose_scheme(&[S::ECDSA_NISTP256_SHA256, S::RSA_PSS_SHA256])
            .is_none(),
        "Ed25519 密钥不得接受 ECDSA/RSA offer"
    );
    assert!(
        rsa.choose_scheme(&[S::ECDSA_NISTP256_SHA256, S::ED25519])
            .is_none(),
        "RSA 密钥不得接受 ECDSA/Ed25519 offer"
    );

    // 同为 ECDSA 但曲线不符：None（防「ECDSA 通吃」式误配）
    assert!(
        p256.choose_scheme(&[S::ECDSA_NISTP384_SHA384]).is_none(),
        "P-256 密钥不得接受 P-384 方案"
    );
    assert!(
        p384.choose_scheme(&[S::ECDSA_NISTP256_SHA256]).is_none(),
        "P-384 密钥不得接受 P-256 方案"
    );
}

/// RSA 方案选择按 `sign.rs` 的 PREFERRED 表（PSS SHA-256 > PSS SHA-384
/// > PSS SHA-512 > PKCS#1 SHA-256 > …），与 offer 顺序无关。
#[test]
fn rsa_scheme_selection_follows_preferred_order() {
    use rustls::SignatureScheme as S;
    use rustls::sign::SigningKey;

    let rsa = ferritls_rustls::sign::RsaKey::from_pkcs1_der(RSA_PKCS1_DER)
        .expect("PKCS#1 测试私钥必须可装载");
    let pick = |offered: &[S]| rsa.choose_scheme(offered).map(|signer| signer.scheme());

    // 任务锚定用例：offer 含 PKCS1-SHA256 与 PSS-SHA384 → 选 PSS-SHA384
    assert_eq!(
        pick(&[S::RSA_PKCS1_SHA256, S::RSA_PSS_SHA384]),
        Some(S::RSA_PSS_SHA384),
        "PSS 优先于 PKCS#1（TLS 1.3 首选 RSASSA-PSS）"
    );
    // 仅 PKCS1-SHA512 → 选 PKCS1-SHA512
    assert_eq!(pick(&[S::RSA_PKCS1_SHA512]), Some(S::RSA_PKCS1_SHA512));
    // 同档内 SHA-384 优先于 SHA-512
    assert_eq!(
        pick(&[S::RSA_PKCS1_SHA384, S::RSA_PKCS1_SHA512]),
        Some(S::RSA_PKCS1_SHA384)
    );
    // 全部六种 offer → 最优的 PSS-SHA256；反转 offer 顺序不改变结果
    let all = [
        S::RSA_PSS_SHA256,
        S::RSA_PSS_SHA384,
        S::RSA_PSS_SHA512,
        S::RSA_PKCS1_SHA256,
        S::RSA_PKCS1_SHA384,
        S::RSA_PKCS1_SHA512,
    ];
    assert_eq!(pick(&all), Some(S::RSA_PSS_SHA256));
    let mut rev = all;
    rev.reverse();
    assert_eq!(pick(&rev), Some(S::RSA_PSS_SHA256), "选择与 offer 顺序无关");
}

// ---------------------------------------------------------------------------
// Signer::sign → core VerifyKey 往返（sign.rs）
// ---------------------------------------------------------------------------

/// ECDSA（P-256/P-384）与 Ed25519 的签名往返：适配层 `Signer::sign`
/// 收到未哈希消息，产出 DER（ECDSA）/64 B（Ed25519）签名，由独立构造
/// 的 core `VerifyKey` 验证；消息篡改必须验证失败。
#[test]
fn ecdsa_and_ed25519_signers_roundtrip_via_core_verify() {
    use rustls::sign::SigningKey;

    const MSG: &[u8] = b"ferritls adapter sign->core verify roundtrip";

    // ---- P-256 / SHA-256 ----
    let seed = [0x11u8; 32];
    let key = ferritls_rustls::sign::EcdsaP256Key::new(&seed);
    let signer = key
        .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP256_SHA256])
        .expect("P-256 方案被 offer");
    assert_eq!(
        signer.scheme(),
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256
    );
    let sig = signer.sign(MSG).expect("P-256 签名");
    let core_sk = ferritls_core::sign::ecdsa::p256::SigningKey::from_seed(seed);
    let vk = ferritls_core::sign::ecdsa::p256::VerifyKey::from_sec1_point(
        &core_sk.public_key_sec1().expect("P-256 公钥"),
    )
    .expect("SEC1 公钥");
    vk.verify(MSG, &sig).expect("P-256 签名必须验证通过");
    assert!(vk.verify(b"tampered message", &sig).is_err());

    // ---- P-384 / SHA-384 ----
    let seed = [0x22u8; 48];
    let key = ferritls_rustls::sign::EcdsaP384Key::new(&seed);
    let signer = key
        .choose_scheme(&[rustls::SignatureScheme::ECDSA_NISTP384_SHA384])
        .expect("P-384 方案被 offer");
    assert_eq!(
        signer.scheme(),
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384
    );
    let sig = signer.sign(MSG).expect("P-384 签名");
    let core_sk = ferritls_core::sign::ecdsa::p384::SigningKey::from_seed(seed);
    let vk = ferritls_core::sign::ecdsa::p384::VerifyKey::from_sec1_point(
        &core_sk.public_key_sec1().expect("P-384 公钥"),
    )
    .expect("SEC1 公钥");
    vk.verify(MSG, &sig).expect("P-384 签名必须验证通过");
    assert!(vk.verify(b"tampered message", &sig).is_err());

    // ---- Ed25519 ----
    let seed = [0x33u8; 32];
    let key = ferritls_rustls::sign::Ed25519Key::new(&seed);
    let signer = key
        .choose_scheme(&[rustls::SignatureScheme::ED25519])
        .expect("Ed25519 方案被 offer");
    assert_eq!(signer.scheme(), rustls::SignatureScheme::ED25519);
    let sig = signer.sign(MSG).expect("Ed25519 签名");
    assert_eq!(sig.len(), ferritls_core::sign::ed25519::SIGNATURE_LEN);
    let core_sk = ferritls_core::sign::ed25519::SigningKey::from_seed(seed);
    let vk = ferritls_core::sign::ed25519::VerifyKey::from_raw_bytes(&core_sk.public_key())
        .expect("裸公钥");
    vk.verify(MSG, &sig).expect("Ed25519 签名必须验证通过");
    assert!(vk.verify(b"tampered message", &sig).is_err());
}

/// 从 PKCS#1 RSAPrivateKey DER 提取 n/e 并重组裸 RSAPublicKey DER
///（core `VerifyKey::from_rsapublickey_der` 的输入格式）。
fn rsa_public_key_der_from_private(pkcs1: &[u8]) -> Vec<u8> {
    let (tag, content, rest) = ferritls_core::der::read_tlv(pkcs1).expect("外层 SEQUENCE");
    assert_eq!(tag, 0x30, "RSAPrivateKey 必须为 SEQUENCE");
    assert!(rest.is_empty(), "外层 SEQUENCE 后不得有尾随字节");
    let (_, _, rest) = ferritls_core::der::read_tlv(content).expect("version");
    let (n_tag, n, rest) = ferritls_core::der::read_tlv(rest).expect("n");
    assert_eq!(n_tag, 0x02, "n 必须为 INTEGER");
    let (e_tag, e, _rest) = ferritls_core::der::read_tlv(rest).expect("e");
    assert_eq!(e_tag, 0x02, "e 必须为 INTEGER");

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            let bytes = (content.len() as u64).to_be_bytes();
            let first = bytes.iter().position(|&b| b != 0).expect("长度非零");
            let enc = &bytes[first..];
            out.push(0x80 | enc.len() as u8);
            out.extend_from_slice(enc);
        }
        out.extend_from_slice(content);
        out
    }

    let mut body = tlv(0x02, n);
    body.extend(tlv(0x02, e));
    tlv(0x30, &body)
}

/// RSA 全部六种方案的签名往返：适配层签名由独立重组的裸
/// RSAPublicKey（core `VerifyKey`）验证；签名长度 = 模长（2048 位 →
/// 256 B）；消息篡改必须验证失败。
#[test]
fn rsa_signer_roundtrip_all_schemes_via_core_verify() {
    use rustls::SignatureScheme as S;
    use rustls::sign::SigningKey;

    const MSG: &[u8] = b"rsa pss / pkcs1 adapter roundtrip";
    const MODULUS_BYTES: usize = 256; // 2048 位模数

    let vk = ferritls_core::sign::rsa::VerifyKey::from_rsapublickey_der(
        &rsa_public_key_der_from_private(RSA_PKCS1_DER),
    )
    .expect("重组的 RSAPublicKey");
    let rsa = ferritls_rustls::sign::RsaKey::from_pkcs1_der(RSA_PKCS1_DER)
        .expect("PKCS#1 测试私钥必须可装载");

    let cases = [
        (S::RSA_PSS_SHA256, 256u16, "pss"),
        (S::RSA_PSS_SHA384, 384, "pss"),
        (S::RSA_PSS_SHA512, 512, "pss"),
        (S::RSA_PKCS1_SHA256, 256, "pkcs1"),
        (S::RSA_PKCS1_SHA384, 384, "pkcs1"),
        (S::RSA_PKCS1_SHA512, 512, "pkcs1"),
    ];
    for (scheme, bits, kind) in cases {
        let signer = rsa
            .choose_scheme(&[scheme])
            .unwrap_or_else(|| panic!("{scheme:?} 被 offer"));
        assert_eq!(signer.scheme(), scheme);
        let sig = signer
            .sign(MSG)
            .unwrap_or_else(|e| panic!("{scheme:?} 签名失败: {e}"));
        assert_eq!(sig.len(), MODULUS_BYTES, "{scheme:?} 签名长度 = 模长");
        let verified = match kind {
            "pss" => vk.verify_pss(bits, MSG, &sig),
            _ => vk.verify_pkcs1v15(bits, MSG, &sig),
        };
        verified.unwrap_or_else(|e| panic!("{scheme:?} 验证失败: {e:?}"));
        let tampered = match kind {
            "pss" => vk.verify_pss(bits, b"tampered message", &sig),
            _ => vk.verify_pkcs1v15(bits, b"tampered message", &sig),
        };
        assert!(tampered.is_err(), "{scheme:?} 篡改消息必须验证失败");
    }
}

// ---------------------------------------------------------------------------
// 经典 ECDH 组 complete() 负例（kx.rs；镜像 ML-KEM 组负例）
// ---------------------------------------------------------------------------

/// `complete` 错误必须归一为 `PeerMisbehaved::InvalidKeyShare`
///（`map_dh_err` 的映射契约）。
fn assert_invalid_key_share(e: Result<rustls::crypto::SharedSecret, rustls::Error>) {
    match e {
        Err(rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare)) => {}
        Err(_) => panic!("必须映射为 PeerMisbehaved::InvalidKeyShare"),
        Ok(_) => panic!("非法对端 share 不得产生共享秘密"),
    }
}

/// 经典三组（X25519 / P-256 / P-384）的 complete() 对非法对端 share
/// 必须拒绝且不 panic：空输入、长度错（少 1 字节 / 裸坐标无 0x04
/// 前缀）、全零低阶点（X25519）或 0 前缀无穷远点（P-256/384）。
#[test]
fn classic_kx_groups_complete_rejects_invalid_peer_shares() {
    // ---- X25519（32 B 裸 u 坐标）----
    let a = ferritls_rustls::kx::X25519_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[]));
    let a = ferritls_rustls::kx::X25519_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0x01u8; 31]));
    let a = ferritls_rustls::kx::X25519_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0x01u8; 33]));
    let a = ferritls_rustls::kx::X25519_GROUP.start().expect("start");
    // 全零 u 坐标 = 小阶点 → 全零共享秘密必须被拒绝
    assert_invalid_key_share(a.complete(&[0u8; 32]));

    // ---- P-256（65 B 未压缩 SEC1：0x04 ‖ X ‖ Y）----
    let a = ferritls_rustls::kx::SECP256R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[]));
    let a = ferritls_rustls::kx::SECP256R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0x04u8; 64])); // 裸坐标，缺 0x04 前缀
    let a = ferritls_rustls::kx::SECP256R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0x04u8; 66])); // 长度错
    let a = ferritls_rustls::kx::SECP256R1_GROUP.start().expect("start");
    // 0x00 前缀 = 无穷远点形态，不在曲线 → 拒绝
    assert_invalid_key_share(a.complete(&[0u8; 65]));
    let a = ferritls_rustls::kx::SECP256R1_GROUP.start().expect("start");
    // 坐标 ≥ p（0xFF 填充）→ 规范性检查拒绝
    assert_invalid_key_share(a.complete(&[0xffu8; 65]));

    // ---- P-384（97 B 未压缩 SEC1）----
    let a = ferritls_rustls::kx::SECP384R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[]));
    let a = ferritls_rustls::kx::SECP384R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0x04u8; 96])); // 裸坐标，缺前缀
    let a = ferritls_rustls::kx::SECP384R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0u8; 97]));
    let a = ferritls_rustls::kx::SECP384R1_GROUP.start().expect("start");
    assert_invalid_key_share(a.complete(&[0xffu8; 97]));
}

/// 经典三组正向往返：两侧以对方公钥 complete，共享秘密逐字节一致
///（长度分别为 32/32/48 B）。
#[test]
fn classic_kx_groups_roundtrip_shared_secrets() {
    let cases = [
        (ferritls_rustls::kx::X25519_GROUP, 32usize),
        (ferritls_rustls::kx::SECP256R1_GROUP, 32),
        (ferritls_rustls::kx::SECP384R1_GROUP, 48),
    ];
    for (group, ss_len) in cases {
        let a = group.start().expect("start a");
        let b = group.start().expect("start b");
        assert_eq!(a.pub_key().len(), b.pub_key().len(), "公钥形状一致");
        let a_pk = a.pub_key().to_vec();
        let ss_ab = a.complete(b.pub_key()).expect("a complete");
        let ss_ba = b.complete(&a_pk).expect("b complete");
        assert_eq!(ss_ab.secret_bytes().len(), ss_len, "共享秘密长度");
        assert_eq!(
            ss_ab.secret_bytes(),
            ss_ba.secret_bytes(),
            "{group:?} 两侧共享秘密必须一致"
        );
    }
}

// ---------------------------------------------------------------------------
// any_supported_type / any_ecdsa_type / KeyLoader（sign.rs）
// ---------------------------------------------------------------------------

/// 手工组装的最小 P-256 PKCS#8 PrivateKeyInfo（RFC 5958/5480，无可选
/// [1] 公钥，标量 0x21..0x41）。结构：
/// `SEQUENCE { INTEGER 0, SEQUENCE { OID ecPublicKey, OID prime256v1 },
/// OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING <32 B> } } }`。
fn p256_pkcs8_der() -> Vec<u8> {
    let mut der = vec![
        0x30, 0x41, // SEQUENCE (65 B)
        0x02, 0x01, 0x00, // version 0
        0x30, 0x13, // AlgorithmIdentifier
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        0x04, 0x27, // privateKey OCTET STRING (39 B)
        0x30, 0x25, // SEC1 ECPrivateKey
        0x02, 0x01, 0x01, // version 1
        0x04, 0x20, // 标量 OCTET STRING (32 B)
    ];
    der.extend(0x21u8..0x41);
    assert_eq!(der.len(), 67);
    der
}

/// `any_supported_type`：PKCS#8 入口（RSA）、裸 PKCS#1 回退路径、
/// 非法 DER（随机字节 / 截断）拒绝。
#[test]
fn any_supported_type_pkcs1_fallback_and_rejects() {
    use rustls::SignatureAlgorithm;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};

    // PKCS#8 入口（RSA）
    let key = ferritls_rustls::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(RSA_PKCS8_DER.to_vec()),
    ))
    .expect("PKCS#8 RSA 必须可装载");
    assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);

    // 裸 PKCS#1 RSA 回退路径（sign.rs any_supported_type 第二分支）
    let key = ferritls_rustls::sign::any_supported_type(&PrivateKeyDer::Pkcs1(
        PrivatePkcs1KeyDer::from(RSA_PKCS1_DER.to_vec()),
    ))
    .expect("裸 PKCS#1 RSA 必须经回退路径装载");
    assert_eq!(key.algorithm(), SignatureAlgorithm::RSA);

    // 随机字节 → Err
    assert!(
        ferritls_rustls::sign::any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            vec![0x5au8; 64]
        )))
        .is_err(),
        "随机字节不得被当作私钥"
    );
    // 截断的合法 PKCS#8 → Err
    assert!(
        ferritls_rustls::sign::any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            RSA_PKCS8_DER[..100].to_vec()
        )))
        .is_err(),
        "截断 DER 必须被拒绝"
    );
}

/// `any_ecdsa_type`：P-256 PKCS#8 → Ok；RSA PKCS#8 → Err（"not an
/// ECDSA key"）。
#[test]
fn any_ecdsa_type_accepts_only_ecdsa() {
    use rustls::SignatureAlgorithm;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let key = ferritls_rustls::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(p256_pkcs8_der()),
    ))
    .expect("P-256 PKCS#8 必须可装载");
    assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);

    // 兜底：同一把 P-256 经通用入口也应装载为 ECDSA
    let key = ferritls_rustls::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(p256_pkcs8_der()),
    ))
    .expect("通用入口同样接受 P-256");
    assert_eq!(key.algorithm(), SignatureAlgorithm::ECDSA);

    let err = ferritls_rustls::sign::any_ecdsa_type(&PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(RSA_PKCS8_DER.to_vec()),
    ))
    .expect_err("RSA 私钥不得通过 ECDSA 入口");
    assert!(
        err.to_string().contains("not an ECDSA key"),
        "错误信息必须为 not an ECDSA key，得到 {err}"
    );
}

/// `KeyLoader::from_pkcs8`：手工组装的 Ed25519 PKCS#8 → Ok 且算法为
/// Ed25519（覆盖种子的 `try_into` 成功分支）；种子截断（32 → 31，
/// 手工改写 OCTET STRING 长度）→ Err——core der 层对 Ed25519 种子
/// 强制 32 字节（der.rs `parse_pkcs8_private_key`），适配层的
/// `try_into` 守卫为纵深防御（该校验分支另有显式错误路径）。
#[test]
fn key_loader_ed25519_pkcs8_accepts_and_truncated_seed_rejected() {
    use rustls::SignatureAlgorithm;

    // 32 字节种子：Ok(Ed25519Key)
    let seed: Vec<u8> = (0x40u8..0x60).collect();
    assert_eq!(seed.len(), 32);
    let mut der = vec![
        0x30, 0x2e, // SEQUENCE (46 B)
        0x02, 0x01, 0x00, // version 0
        0x30, 0x05, // AlgorithmIdentifier
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112（无参数，RFC 8410 §7）
        0x04, 0x22, // privateKey OCTET STRING (34 B)
        0x04, 0x20, // 种子 OCTET STRING (32 B)
    ];
    der.extend_from_slice(&seed);
    let key =
        ferritls_rustls::sign::KeyLoader::from_pkcs8(&der).expect("合法 Ed25519 PKCS#8 必须可装载");
    assert_eq!(key.algorithm(), SignatureAlgorithm::ED25519);

    // 种子 32 → 31：Err（der 层长度校验拒绝）
    let mut der31 = vec![
        0x30, 0x2d, // SEQUENCE (45 B)
        0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x21, 0x04,
        0x1f, // 种子 OCTET STRING (31 B)
    ];
    der31.extend(0x40u8..0x5f);
    assert_eq!(der31.len(), 47);
    assert!(
        ferritls_rustls::sign::KeyLoader::from_pkcs8(&der31).is_err(),
        "31 字节种子必须被拒绝"
    );
}

/// `KeyProvider::fips()` 恒 false（规则 3：认证前），且套件清单的
/// 精确顺序 = 偏好序（与 `TLS13_SUITE_NAMES` 逐项一致；批准模式 =
/// GCM×2 + CCM，无 ChaCha/CCM_8）。
#[test]
fn key_provider_fips_and_exact_suite_ordering() {
    assert!(
        !ferritls_rustls::sign::KEY_LOADER.fips(),
        "KeyProvider::fips() 认证前恒 false"
    );

    fn suite_name(s: rustls::SupportedCipherSuite) -> &'static str {
        match s.suite() {
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
            rustls::CipherSuite::TLS13_AES_128_CCM_SHA256 => "TLS_AES_128_CCM_SHA256",
            rustls::CipherSuite::TLS13_AES_128_CCM_8_SHA256 => "TLS_AES_128_CCM_8_SHA256",
            other => panic!("未知套件 {other:?}"),
        }
    }

    let names: Vec<&str> = ferritls_rustls::cipher::all_tls13_suites()
        .into_iter()
        .map(suite_name)
        .collect();
    assert_eq!(
        names,
        ferritls_rustls::cipher::TLS13_SUITE_NAMES,
        "all_tls13_suites() 顺序必须与 TLS13_SUITE_NAMES 逐项一致"
    );

    let fips: Vec<&str> = ferritls_rustls::cipher::fips_tls13_suites()
        .into_iter()
        .map(suite_name)
        .collect();
    assert_eq!(
        fips,
        [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_AES_128_CCM_SHA256"
        ],
        "批准模式清单顺序与构成"
    );
}
