//! ML-KEM 三参数集基准：KeyGen / Encaps / Decaps（M8.3 起 768，
//! M8.4 扩展 512/1024）。
//!
//! 全部走确定性入口（`keypair_from_seed` / `encapsulate_with_seed`），
//! 与 aead/drbg 基准口径一致——bench 内不调 OS 熵；生产路径
//! （`generate_keypair`/`encapsulate`）额外含一次 32–64 字节 OS 熵
//! 读取，量级为微秒以下、不改变结论。运行：
//! `cargo bench -p ferritls-core --bench kem`。

use criterion::{Criterion, criterion_group, criterion_main};
use ferritls_core::mlkem::{self, k1024, k512, k768};

/// 确定性 32 字节种子。
fn seed32(b: u8) -> [u8; 32] {
    [b; 32]
}

macro_rules! bench_set {
    ($c:expr, $name:literal, $set:ident) => {{
        let mut group = $c.benchmark_group($name);
        let (ek, dk) = $set::keypair_from_seed(&seed32(0x11), &seed32(0x22));
        let m = seed32(0x33);
        let (ct, ss) = $set::encapsulate_with_seed(&ek, &m).expect("encaps");
        let _ = ss;
        group.bench_function("keygen", |b| {
            b.iter(|| $set::keypair_from_seed(&seed32(0x44), &seed32(0x55)))
        });
        group.bench_function("encaps", |b| {
            b.iter(|| $set::encapsulate_with_seed(&ek, &m))
        });
        group.bench_function("decaps", |b| b.iter(|| $set::decapsulate(&dk, &ct)));
        group.finish();
    }};
}

fn bench_kem(c: &mut Criterion) {
    // mlkem768 组名保留（M8.3 基线 continuity，与 criterion 历史对齐）
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

    bench_set!(c, "mlkem512", k512);
    bench_set!(c, "mlkem1024", k1024);
}

criterion_group!(benches, bench_kem);
criterion_main!(benches);
