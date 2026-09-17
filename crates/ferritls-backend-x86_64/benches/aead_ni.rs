//! AES-GCM 软/Ni 逐记录 A/B 基准：同一测量方法（尺寸、AAD、确定性
//! 填充）下对比 core 软件公开 API 与 AES-NI 执行核心。
//!
//! 本基准**不安装**后端：软件侧 = `Aes128Gcm/Aes256Gcm::new`（默认
//! 路径），Ni 侧 = token 直接构造的执行核心——两个路径在同一进程内
//! 独立测量，无全局状态切换。测量方法与 `ferritls-core` 的 `aead`
//! 基准保持一致，便于跨基准对照。
//!
//! 运行：`cargo bench -p ferritls-backend-x86_64 --bench aead_ni`
//! （仅 x86_64；CPU 不支持时打印后跳过）。

#[cfg(target_arch = "x86_64")]
mod bench {
    use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
    use ferritls_backend_x86_64::AesNi;
    use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

    /// 与 ferritls-core aead 基准一致的确定性填充。
    fn pattern(seed: u64, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        let mut x = seed | 1;
        (0..len).for_each(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.push(x as u8);
        });
        v
    }

    const SIZES: [usize; 2] = [1350, 16384];
    const AAD: &[u8] = &[0u8; 5];

    fn bench_aead_ni(c: &mut Criterion) {
        let Some(tok) = AesNi::detect() else {
            eprintln!("AES-NI/CLMUL unavailable; skipping aead_ni bench");
            return;
        };

        let mut group = c.benchmark_group("aead_ni");
        let nonce = [0x11u8; 12];

        // AES-128-GCM：软 vs Ni，seal/open。
        let soft128 = Aes128Gcm::new(&[0x01; 16]);
        let ni128 = tok.gcm128(&[0x01; 16]);
        let soft256 = Aes256Gcm::new(&[0x02; 32]);
        let ni256 = tok.gcm256(&[0x02; 32]);

        for size in SIZES {
            let pt = pattern(0xA11CE, size);
            let soft_ct_128 = soft128.seal(&nonce, AAD, &pt);
            soft256.seal(&nonce, AAD, &pt); // 热身/对齐软路径缓存（结果不用于断言）

            group.throughput(Throughput::Bytes(size as u64));
            group.bench_function(BenchmarkId::new("soft-seal", size), |b| {
                b.iter(|| soft128.seal(&nonce, AAD, &pt))
            });
            group.bench_function(BenchmarkId::new("ni-seal", size), |b| {
                b.iter(|| ni128.seal(&nonce, AAD, &mut pt.clone()))
            });
            group.bench_function(BenchmarkId::new("soft-open", size), |b| {
                b.iter(|| soft128.open(&nonce, AAD, &soft_ct_128))
            });
            group.bench_function(BenchmarkId::new("ni-open", size), |b| {
                let ct_128 = soft_ct_128[..soft_ct_128.len() - 16].to_vec();
                let soft_tag = &soft_ct_128[soft_ct_128.len() - 16..];
                b.iter(|| {
                    let mut buf = ct_128.clone();
                    let tag = ni128.open_compute_tag(&nonce, AAD, &mut buf);
                    assert_eq!(tag.as_slice(), soft_tag, "bench rot guard");
                })
            });
            group.bench_function(BenchmarkId::new("soft256-seal", size), |b| {
                b.iter(|| soft256.seal(&nonce, AAD, &pt))
            });
            group.bench_function(BenchmarkId::new("ni256-seal", size), |b| {
                b.iter(|| ni256.seal(&nonce, AAD, &mut pt.clone()))
            });
        }
        group.finish();
    }

    criterion_group!(benches, bench_aead_ni);

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
