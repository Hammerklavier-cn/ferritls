//! 适配层 API 形状测试（M6/M7）。
//!
//! 清单断言防止套件/组清单与文档漂移；provider smoke 覆盖两个出厂
//! 配置的构成与 `fips()` 语义（认证前恒 false）。

#[test]
fn suite_inventory_matches_docs() {
    assert_eq!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.len(), 4);
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_128_GCM_SHA256"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_256_GCM_SHA384"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_CHACHA20_POLY1305_SHA256"));
    assert!(ferritls_rustls::cipher::TLS13_SUITE_NAMES.contains(&"TLS_AES_128_CCM_SHA256"));
}

/// QUIC 接线防漂移（M8.5）：GCM/ChaCha 三套件暴露 `quic::Algorithm`
/// 且密钥长度正确，CCM 不参与 QUIC。
#[test]
fn quic_algorithms_wired_for_three_suites() {
    use rustls::quic::Algorithm;
    let cases = [
        (ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(), 16),
        (ferritls_rustls::cipher::tls13_aes_256_gcm_sha384(), 32),
        (ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(), 32),
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
            .is_none(),
        "CCM 不参与 QUIC（RFC 9001 §5.1 以 AES-GCM 为强制基准）"
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
    assert_eq!(p.cipher_suites.len(), 4);
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
