//! ECDH 基准：X25519、P-256、P-384 的公钥导出（标量乘）与共享秘密
//! 计算（含公钥解析/在曲线检查/盲化）。
//!
//! 密钥用固定种子确定性构造（from_seed），bench 循环内不调 OS 熵。
//! 运行：`cargo bench -p ferritls-core --bench ecdh`。

use criterion::{Criterion, criterion_group, criterion_main};
use ferritls_core::ecdh::{p256, p384, x25519};

fn bench_ecdh(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdh");

    let seed32 = [0x11u8; 32];
    let sk25519 = x25519::SecretKey::from_seed(seed32);
    let pk25519 = sk25519.public_key();
    group.bench_function("x25519-public-key", |b| b.iter(|| sk25519.public_key()));
    group.bench_function("x25519-dh", |b| {
        b.iter(|| sk25519.diffie_hellman(&pk25519).expect("shared secret"))
    });

    let sk256 = p256::SecretKey::from_seed(seed32);
    let pk256 = sk256.public_key();
    group.bench_function("p256-public-key", |b| b.iter(|| sk256.public_key()));
    group.bench_function("p256-dh", |b| {
        b.iter(|| sk256.diffie_hellman(&pk256).expect("shared secret"))
    });

    let sk384 = p384::SecretKey::from_seed([0x12u8; 48]);
    let pk384 = sk384.public_key();
    group.bench_function("p384-public-key", |b| b.iter(|| sk384.public_key()));
    group.bench_function("p384-dh", |b| {
        b.iter(|| sk384.diffie_hellman(&pk384).expect("shared secret"))
    });

    group.finish();
}

criterion_group!(benches, bench_ecdh);
criterion_main!(benches);
