//! DRBG 基准：CTR-DRBG（SP 800-90A 无 DF）32 B 生成。
//!
//! generate 路径含每次调用的 128 位 OS 熵重播种（AGENTS.md §5.3 策略），
//! 因此测得的是真实部署成本（含 OS 熵读取）。不 bench 实例化本身：其
//! 成本 ≈ 一次 Update + OS 熵读取，且 criterion 0.8 在 windows-gnu 上的
//! alloca 扩展栈与 getrandom 组合下实例化会间歇返回 EntropyFailed
//! （criterion 外 2 万次循环零失败，属基准环境交互而非库缺陷）。运行：
//! `cargo bench -p ferritls-core --bench drbg`。

use criterion::{Criterion, criterion_group, criterion_main};
use ferritls_core::drbg::CtrDrbg;

fn bench_drbg(c: &mut Criterion) {
    let mut group = c.benchmark_group("drbg");

    let mut rng = CtrDrbg::instantiate_from_os(&[]).expect("instantiate from os");
    let mut out = [0u8; 32];
    group.bench_function("generate-32b", |b| {
        b.iter(|| rng.generate(&mut out).expect("generate"))
    });

    group.finish();
}

criterion_group!(benches, bench_drbg);
criterion_main!(benches);
