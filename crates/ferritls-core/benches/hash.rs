//! 哈希 / MAC / KDF 基准：SHA-256/384 流式吞吐、HMAC-SHA256、
//! HKDF-SHA256 extract/expand。
//!
//! 运行：`cargo bench -p ferritls-core --bench hash`。

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ferritls_core::hkdf;
use ferritls_core::hmac::HmacSha256;
use ferritls_core::sha2::{Sha256, Sha384};

const SIZES: [usize; 2] = [1350, 16384];

/// 确定性伪随机填充（bench 内不调 OS 熵）。
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn bench_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash");
    let data = pattern(0x6b, *SIZES.iter().max().unwrap());

    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let data: &[u8] = &data[..size];
        group.bench_with_input(BenchmarkId::new("sha256-stream", size), data, |b, d| {
            b.iter(|| {
                let mut h = Sha256::new();
                h.update(d);
                h.finalize()
            })
        });
        group.bench_with_input(BenchmarkId::new("sha384-stream", size), data, |b, d| {
            b.iter(|| {
                let mut h = Sha384::new();
                h.update(d);
                h.finalize()
            })
        });
    }

    // HMAC：TLS 1.3 Finished/记录层 MAC 场景的典型量级。
    let hmac_key = pattern(0x71, 32);
    let hmac_msg = pattern(0x72, 1350);
    group.throughput(Throughput::Bytes(hmac_msg.len() as u64));
    group.bench_function("hmac-sha256-1350", |b| {
        b.iter(|| HmacSha256::one_shot(&hmac_key, &hmac_msg))
    });

    // HKDF：TLS 1.3 密钥调度实际使用的 extract + expand 形状。
    let salt = pattern(0x73, 32);
    let ikm = pattern(0x74, 32);
    group.bench_function("hkdf-sha256-extract", |b| {
        b.iter(|| hkdf::extract_sha256(&salt, &ikm))
    });
    let prk = hkdf::extract_sha256(&salt, &ikm);
    let info = pattern(0x75, 40);
    let mut okm = [0u8; 64];
    group.bench_function("hkdf-sha256-expand-64", |b| {
        b.iter(|| hkdf::expand_sha256(&prk, &info, &mut okm).expect("okm length ok"))
    });

    group.finish();
}

criterion_group!(benches, bench_hash);
criterion_main!(benches);
