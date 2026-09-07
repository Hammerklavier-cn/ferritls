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
    assert_eq!(ferritls_rustls::kx::ALL_KX_GROUPS.len(), 3);
    assert_eq!(ferritls_rustls::kx::FIPS_KX_GROUPS.len(), 2);
}

#[test]
fn default_provider_smoke() {
    let p = ferritls_rustls::default_provider();
    assert!(!p.fips(), "认证前 fips() 必须为 false");
    assert_eq!(p.cipher_suites.len(), 4);
    assert_eq!(p.kx_groups.len(), 3);
}

#[test]
fn fips_mode_provider_smoke() {
    let p = ferritls_rustls::fips_mode_provider();
    // 批准模式也必须为 false：批准模式 ≠ 已认证。
    assert!(!p.fips());
    assert_eq!(p.cipher_suites.len(), 3, "批准模式无 ChaCha20-Poly1305");
    assert_eq!(p.kx_groups.len(), 2, "批准模式无 X25519");
}
