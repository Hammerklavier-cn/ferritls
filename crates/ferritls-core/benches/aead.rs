//! AEAD 基准：AES-128/256-GCM、AES-128-CCM（TLS 参数集）、
//! ChaCha20-Poly1305 的 seal 与 open。
//!
//! 两档输入：1350 B（典型 TLS 记录载荷）与 16 KiB（大记录/吞吐参考）；
//! AAD 固定 5 B（对应 TLS 记录头）。经 criterion 的 release profile
//! （workspace `lto = "thin"`）运行：`cargo bench -p ferritls-core --bench aead`。

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ferritls_core::ccm::Aes128CcmTls;
use ferritls_core::chacha20poly1305::ChaCha20Poly1305;
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

const SIZES: [usize; 2] = [1350, 16384];
const AAD: [u8; 5] = [0x16, 0x03, 0x03, 0x05, 0x3e];
const NONCE: [u8; 12] = [0x42; 12];

/// 确定性伪随机填充（bench 内不调 OS 熵）。
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn bench_aead(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");
    let pt = pattern(0x5a, *SIZES.iter().max().unwrap());

    for size in SIZES {
        group.throughput(Throughput::Bytes(size as u64));
        let pt: &[u8] = &pt[..size];

        let gcm128 = Aes128Gcm::new(&[0x01; 16]);
        let ct128 = gcm128.seal(&NONCE, &AAD, pt);
        group.bench_with_input(BenchmarkId::new("gcm128-seal", size), pt, |b, pt| {
            b.iter(|| gcm128.seal(&NONCE, &AAD, pt))
        });
        group.bench_with_input(BenchmarkId::new("gcm128-open", size), &ct128, |b, ct| {
            b.iter(|| gcm128.open(&NONCE, &AAD, ct).expect("tag valid"))
        });

        let gcm256 = Aes256Gcm::new(&[0x02; 32]);
        let ct256 = gcm256.seal(&NONCE, &AAD, pt);
        group.bench_with_input(BenchmarkId::new("gcm256-seal", size), pt, |b, pt| {
            b.iter(|| gcm256.seal(&NONCE, &AAD, pt))
        });
        group.bench_with_input(BenchmarkId::new("gcm256-open", size), &ct256, |b, ct| {
            b.iter(|| gcm256.open(&NONCE, &AAD, ct).expect("tag valid"))
        });

        let ccm = Aes128CcmTls::new(&[0x03; 16]);
        let ct_ccm = ccm.seal(&NONCE, &AAD, pt).expect("ccm length ok");
        group.bench_with_input(BenchmarkId::new("ccm128-seal", size), pt, |b, pt| {
            b.iter(|| ccm.seal(&NONCE, &AAD, pt).expect("ccm length ok"))
        });
        group.bench_with_input(BenchmarkId::new("ccm128-open", size), &ct_ccm, |b, ct| {
            b.iter(|| ccm.open(&NONCE, &AAD, ct).expect("tag valid"))
        });

        let chacha = ChaCha20Poly1305::new(&[0x04; 32]);
        let ct_chacha = chacha.seal(&NONCE, &AAD, pt);
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305-seal", size),
            pt,
            |b, pt| b.iter(|| chacha.seal(&NONCE, &AAD, pt)),
        );
        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305-open", size),
            &ct_chacha,
            |b, ct| b.iter(|| chacha.open(&NONCE, &AAD, ct).expect("tag valid")),
        );
    }
    group.finish();
}

criterion_group!(benches, bench_aead);
criterion_main!(benches);
