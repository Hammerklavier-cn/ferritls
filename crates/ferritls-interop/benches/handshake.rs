//! TLS 1.3 内存全握手基准（软件路径）：ferritls ↔ ferritls（X25519 /
//! P-256，AES-128-GCM）与 ring ↔ ring 同套件基线对照。
//!
//! 用进程内 duplex 管道替代 TCP 回环（排除调度/线程噪声），单线程交替
//! 驱动 client/server 的 `complete_io`；每次迭代 = 一次完整握手（双方
//! 全部密码学计算 + 记录层组帧）。助手见 `support`。
//!
//! 本基准**不安装**硬件后端——ferritls 案例始终走软件默认路径；
//! AES-NI 后端的对照基准见 `handshake_ni`。
//!
//! 运行：`cargo bench -p ferritls-interop --bench handshake`。

mod support;

use std::sync::Arc;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use rustls::NamedGroup;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use support::{client_config, full_handshake, pinned_provider, server_config};

/// 基准用例：(名称, 基础 provider 构造器, 钉扎的密钥交换组)。
type Case = (&'static str, fn() -> CryptoProvider, NamedGroup);

fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake");
    group.throughput(Throughput::Elements(1));

    let name = ServerName::try_from("localhost".to_string()).expect("server name");

    let cases: &[Case] = &[
        (
            "ferritls-x25519",
            ferritls_rustls::default_provider,
            NamedGroup::X25519,
        ),
        (
            "ferritls-p256",
            ferritls_rustls::default_provider,
            NamedGroup::secp256r1,
        ),
        (
            "ring-baseline-x25519",
            rustls::crypto::ring::default_provider,
            NamedGroup::X25519,
        ),
    ];

    for (case_name, provider_fn, kx) in cases {
        let provider = pinned_provider(provider_fn(), *kx);
        let server_cfg = Arc::new(server_config(provider.clone()));
        let client_cfg = Arc::new(client_config(provider));
        full_handshake(&client_cfg, &server_cfg, &name);
        group.bench_function(*case_name, |b| {
            b.iter(|| full_handshake(&client_cfg, &server_cfg, &name))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_handshake);
criterion_main!(benches);
