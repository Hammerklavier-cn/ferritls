//! 互操作测试占位（M6 接线后逐步启用）。
//!
//! 骨架期只固化验收形态：每个测试描述“完成时应当断言什么”。

/// ferritls ↔ ferritls：TLS 1.3 全套件 × 全 KX 组握手。
#[test]
#[ignore = "M6"]
fn ping_pong_ferritls_ferritls() {
    // ClientConfig/ServerConfig 均 default_provider()；
    // 断言：握手成功、协商套件 ∈ TLS13_SUITE_NAMES、双向收发一致。
}

/// ferritls ↔ ring provider：跨 provider 握手。
#[test]
#[ignore = "M6: 引入 rustls ring provider dev-dep 后启用"]
fn ping_pong_vs_ring() {}

/// ferritls ↔ OpenSSL：本地 `s_server` 进程互操作。
#[test]
#[ignore = "M6: CI 提供 openssl 二进制后启用（仅 Linux job）"]
fn vs_openssl_s_server() {}

/// RFC 8448 轨迹重放：密钥调度与记录层字节级比对。
#[test]
#[ignore = "M6: RFC 8448 向量文件引入后启用"]
fn rfc8448_key_schedule_trace() {}

/// 批准模式矩阵：仅批准套件/组组合的握手。
#[test]
#[ignore = "M7"]
fn fips_mode_matrix() {}
