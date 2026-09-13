//! ML-KEM-768 基准：KeyGen / Encaps / Decaps（M8.3）。
//!
//! 全部走确定性入口（`keypair_from_seed` / `encapsulate_with_seed`），
//! 与 aead/drbg 基准口径一致——bench 内不调 OS 熵；生产路径
//! （`generate_keypair`/`encapsulate`）额外含一次 32–64 字节 OS 熵
//! 读取，量级为微秒以下、不改变结论。运行：
//! `cargo bench -p ferritls-core --bench kem`。

use criterion::{Criterion, criterion_group, criterion_main};
use ferritls_core::mlkem;

/// 确定性 32 字节种子。
fn seed32(b: u8) -> [u8; 32] {
    [b; 32]
}

fn bench_kem(c: &mut Criterion) {
    let mut group = c.benchmark_group("mlkem768");

    let (ek, dk) = mlkem::keypair_from_seed(&seed32(0x11), &seed32(0x22));
    let m = seed32(0x33);
    let (ct, ss) = mlkem::encapsulate_with_seed(&ek, &m).expect("encaps");
    let _ = ss;

    group.bench_function("keygen", |b| {
        b.iter(|| mlkem::keypair_from_seed(&seed32(0x44), &seed32(0x55)))
    });
    group.bench_function("encaps", |b| {
        b.iter(|| mlkem::encapsulate_with_seed(&ek, &m))
    });
    group.bench_function("decaps", |b| b.iter(|| mlkem::decapsulate(&dk, &ct)));

    group.finish();
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
