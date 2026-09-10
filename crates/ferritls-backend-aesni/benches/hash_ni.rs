//! SHA-256 软/Ni A/B 基准：与 `ferritls-core` 的 `hash` 基准完全相同
//! 的案例构造（尺寸、HMAC/HKDF 形状），在同一进程内分安装前后测量。
//!
//! 进程内顺序：criterion_group 按注册顺序同步执行——`soft` 组先跑
//! （未安装 → 软件路径），`install_bridge` 安装 SHA-NI 后端，`ni` 组
//! 再跑同名案例（公开 API 自动走 Ni 压缩）。两组数据可直接配对。
//!
//! 运行：`cargo bench -p ferritls-backend-aesni --bench hash_ni`
//! （仅 x86_64；CPU 不支持时 ni 组打印后跳过）。

#[cfg(target_arch = "x86_64")]
mod bench {
    use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
    use ferritls_core::hkdf;
    use ferritls_core::hmac::HmacSha256;
    use ferritls_core::sha2::Sha256;

    const SIZES: [usize; 2] = [1350, 16384];

    /// 与 core hash 基准一致的确定性填充。
    fn pattern(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn cases(c: &mut Criterion, prefix: &str) {
        let mut group = c.benchmark_group(prefix);
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
        }

        let hmac_key = pattern(0x71, 32);
        let hmac_msg = pattern(0x72, 1350);
        group.throughput(Throughput::Bytes(hmac_msg.len() as u64));
        group.bench_function("hmac-sha256-1350", |b| {
            b.iter(|| HmacSha256::one_shot(&hmac_key, &hmac_msg))
        });

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

    fn bench_hash_soft(c: &mut Criterion) {
        cases(c, "hash_soft");
    }

    /// 在两组之间安装 SHA-NI 后端（进程级一次；失败时 ni 组自行跳过）。
    fn install_bridge(_c: &mut Criterion) {
        match ferritls_backend_aesni::install_hash() {
            Ok(()) => {}
            Err(e) => eprintln!("sha-ni backend unavailable ({e:?}); ni group will skip"),
        }
    }

    fn bench_hash_ni(c: &mut Criterion) {
        if ferritls_core::ops::installed_hash().is_none() {
            eprintln!("sha-ni not installed; skipping ni group");
            return;
        }
        cases(c, "hash_ni");
    }

    criterion_group!(benches, bench_hash_soft, install_bridge, bench_hash_ni);

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
