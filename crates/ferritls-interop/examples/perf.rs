//! ferritls 吞吐基准（P1 性能轮基线/回归工具）。
//!
//! 运行：`cargo run -p ferritls-interop --release --example perf`
//!
//! 输出各原语吞吐（MB/s）。数字受机器/工具链影响，仅用于**同机前后
//! 对比**并记录进 docs/ROADMAP.md P1 表；正确性由向量测试套件保证，
//! 本工具不做正确性判断（仅在 open 失败时 panic 以暴露基准本身失效）。
//! 本 crate publish=false，dev-deps 不受边界白名单约束（AGENTS.md §2）。

use std::time::Instant;

use ferritls_core::aes::{Aes128, Aes256};
use ferritls_core::ccm::Aes128Ccm;
use ferritls_core::chacha20poly1305::ChaCha20Poly1305;
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};
use ferritls_core::sha2::{Sha256, Sha512};

/// xorshift32 填充缓冲（内容无密码学意义，只需非全零、无周期性巧合）。
fn fill_pseudo(buf: &mut [u8]) {
    let mut x = 0x9E37_79B9u32;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
}

/// 自适应校准迭代次数：单次耗时 → 使总测量时长落在 200–400ms 区间，
/// 并夹在 [16, 8192]。预热两轮后正式计时；返回值经 black_box 防止
/// 被优化消除。闭包返回值任意（丢弃即可，本工具不判正确性）。
fn bench<F, T>(label: &str, bytes_per_iter: usize, mut f: F)
where
    F: FnMut() -> T,
{
    let _ = std::hint::black_box(f());
    let _ = std::hint::black_box(f());
    let t0 = Instant::now();
    let _ = std::hint::black_box(f());
    let one = t0.elapsed().max(std::time::Duration::from_nanos(1));
    let target = std::time::Duration::from_millis(300);
    let iters = (target.as_nanos() / one.as_nanos()).clamp(16, 8192).max(1);
    let start = Instant::now();
    for _ in 0..iters {
        let _ = std::hint::black_box(f());
    }
    let dt = start.elapsed();
    let mbs = (bytes_per_iter as f64 * iters as f64) / dt.as_secs_f64() / 1024.0 / 1024.0;
    println!("{label:<34} {mbs:>10.2} MB/s   ({iters} iters)");
}

fn bench_gcm_128() {
    let mut key = [0u8; 16];
    fill_pseudo(&mut key);
    let aead = Aes128Gcm::new(&key);
    let nonce = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad = [0x17u8, 0x03, 0x03, 0x10, 0x00]; // TLS 记录头形状

    for &size in &[1024, 16 * 1024] {
        let mut pt = vec![0u8; size];
        fill_pseudo(&mut pt);
        bench(&format!("AES-128-GCM seal  {size:>6} B"), size, || {
            aead.seal(&nonce, &aad, &pt)
        });
        let ct = aead.seal(&nonce, &aad, &pt);
        bench(&format!("AES-128-GCM open  {size:>6} B"), size, || {
            aead.open(&nonce, &aad, &ct).expect("perf: open failed")
        });
    }
}

fn bench_gcm_256() {
    let mut key = [0u8; 32];
    fill_pseudo(&mut key);
    let aead = Aes256Gcm::new(&key);
    let nonce = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad = [0x17u8, 0x03, 0x03, 0x10, 0x00];

    let mut pt = vec![0u8; 16 * 1024];
    fill_pseudo(&mut pt);
    bench("AES-256-GCM seal  16384 B", 16 * 1024, || {
        aead.seal(&nonce, &aad, &pt)
    });
    let ct = aead.seal(&nonce, &aad, &pt);
    bench("AES-256-GCM open  16384 B", 16 * 1024, || {
        aead.open(&nonce, &aad, &ct).expect("perf: open failed")
    });
}

fn bench_ccm_128() {
    let mut key = [0u8; 16];
    fill_pseudo(&mut key);
    let aead = Aes128Ccm::new(&key);
    let nonce = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let aad = [0x17u8, 0x03, 0x03, 0x10, 0x00];

    let mut pt = vec![0u8; 16 * 1024];
    fill_pseudo(&mut pt);
    bench("AES-128-CCM seal  16384 B", 16 * 1024, || {
        aead.seal(&nonce, &aad, &pt).expect("perf: ccm seal failed")
    });
    let ct = aead.seal(&nonce, &aad, &pt).expect("perf: ccm seal failed");
    bench("AES-128-CCM open  16384 B", 16 * 1024, || {
        aead.open(&nonce, &aad, &ct).expect("perf: open failed")
    });
}

fn bench_chacha() {
    let mut key = [0u8; 32];
    fill_pseudo(&mut key);
    let aead = ChaCha20Poly1305::new(&key);
    let nonce = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    let aad = [0x17u8, 0x03, 0x03, 0x10, 0x00];

    for &size in &[1024, 16 * 1024] {
        let mut pt = vec![0u8; size];
        fill_pseudo(&mut pt);
        bench(&format!("ChaCha20-Poly1305 seal {size:>4} B"), size, || {
            aead.seal(&nonce, &aad, &pt)
        });
        let ct = aead.seal(&nonce, &aad, &pt);
        bench(&format!("ChaCha20-Poly1305 open {size:>4} B"), size, || {
            aead.open(&nonce, &aad, &ct).expect("perf: open failed")
        });
    }
}

fn bench_sha2() {
    let mut buf = vec![0u8; 16 * 1024];
    fill_pseudo(&mut buf);
    bench("SHA-256 16384 B", 16 * 1024, || Sha256::one_shot(&buf));
    bench("SHA-512 16384 B", 16 * 1024, || Sha512::one_shot(&buf));
}

fn bench_aes_block() {
    let mut key = [0u8; 16];
    fill_pseudo(&mut key);
    let aes = Aes128::new(&key);
    let mut block = [0u8; 16];
    fill_pseudo(&mut block);
    bench("AES-128 encrypt_block", 16, || {
        aes.encrypt_block(&mut block)
    });
    let mut key256 = [0u8; 32];
    fill_pseudo(&mut key256);
    let aes256 = Aes256::new(&key256);
    bench("AES-256 encrypt_block", 16, || {
        aes256.encrypt_block(&mut block)
    });
}

fn main() {
    println!("ferritls perf (P1 baseline tool) — numbers are same-machine before/after only\n");
    bench_gcm_128();
    bench_gcm_256();
    bench_ccm_128();
    bench_chacha();
    bench_sha2();
    bench_aes_block();
}
