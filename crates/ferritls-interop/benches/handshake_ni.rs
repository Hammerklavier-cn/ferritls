//! TLS 1.3 内存全握手基准（AES-NI 路径）：与 `handshake.rs` 同一测量
//! 方法，区别仅在基准启动时安装 `ferritls-backend-x86_64`——此后构造的
//! ferritls provider 的 AES-GCM 执行核心为 AES-NI/CLMUL。
//!
//! 进程隔离说明：`install()` 是进程级的，本基准与 `handshake.rs`
//! （不安装，软件路径）分属两个二进制，互不污染。
//!
//! 仅 x86_64 构建（其余目标为空壳 main）；CPU 不支持时案例跳过。
//!
//! 运行：`cargo bench -p ferritls-interop --bench handshake_ni`。

mod support;

#[cfg(target_arch = "x86_64")]
mod bench {
    use std::sync::Arc;

    use criterion::{Criterion, Throughput, criterion_group};
    use rustls::NamedGroup;
    use rustls::crypto::CryptoProvider;
    use rustls::pki_types::ServerName;

    use super::support::{client_config, full_handshake, pinned_provider, server_config};

    /// 基准用例：(名称, 基础 provider 构造器, 钉扎的密钥交换组)。
    type Case = (&'static str, fn() -> CryptoProvider, NamedGroup);

    fn bench_handshake_ni(c: &mut Criterion) {
        // AEAD 与 SHA-256 各自独立安装（CPU 可能只支持其一）。
        match ferritls_backend_x86_64::install() {
            Ok(()) => {}
            Err(e) => eprintln!("aesni unavailable ({e:?}); AEAD stays software"),
        }
        match ferritls_backend_x86_64::install_hash() {
            Ok(()) => {}
            Err(e) => eprintln!("sha-ni unavailable ({e:?}); SHA stays software"),
        }

        let mut group = c.benchmark_group("handshake_ni");
        group.throughput(Throughput::Elements(1));

        let name = ServerName::try_from("localhost".to_string()).expect("server name");

        let cases: &[Case] = &[
            (
                "ferritls-ni-x25519",
                ferritls_rustls::default_provider,
                NamedGroup::X25519,
            ),
            (
                "ferritls-ni-p256",
                ferritls_rustls::default_provider,
                NamedGroup::secp256r1,
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

    criterion_group!(benches, bench_handshake_ni);

    pub fn run() {
        benches();
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn main() {}

#[cfg(target_arch = "x86_64")]
fn main() {
    bench::run();
}
