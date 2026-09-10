//! 软件 vs AES-NI 差分测试（**不安装**后端——core 公开 API 保持软件
//! 默认路径，Ni 侧经 token 直接构造执行核心）。
//!
//! 确定性伪随机（xorshift64）：同机可复现，覆盖边界长度（空/单字节/
//! 块边界前后/多块大缓冲）× 两种密钥长度 × 双向交叉（Ni seal → 软件
//! open，软件 seal → Ni open）。

use ferritls_backend_aesni::AesNi;
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

/// xorshift64*，确定性。
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn fill(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// 边界长度集合：空、子块、块边界前后、多块、大缓冲。
const PT_LENS: [usize; 10] = [0, 1, 15, 16, 17, 31, 32, 33, 1350, 16384];
const AAD_LENS: [usize; 6] = [0, 1, 5, 16, 20, 51];

fn rand_bytes(rng: &mut Rng, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rng.fill(&mut v);
    v
}

/// Ni 与软件在 AES-128-GCM 上逐字节一致（seal 双向 + 交叉 open）。
#[test]
fn differential_aes128() {
    let Some(tok) = AesNi::detect() else {
        eprintln!("AES-NI/CLMUL unavailable; skipping");
        return;
    };
    let mut rng = Rng(0x853c_49e6_748f_ea9b_u64 ^ 0xA128);
    for round in 0..1000u32 {
        let mut key = [0u8; 16];
        rng.fill(&mut key);
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let aad = rand_bytes(&mut rng, AAD_LENS[(round as usize) % AAD_LENS.len()]);
        let pt = rand_bytes(
            &mut rng,
            PT_LENS[(round as usize / AAD_LENS.len()) % PT_LENS.len()],
        );

        let soft = Aes128Gcm::new(&key);
        let ni = tok.gcm128(&key);

        // seal 一致：公开 API（ct||tag）vs 执行核心（就地 + 标签）。
        let soft_sealed = soft.seal(&nonce, &aad, &pt);
        let mut ni_buf = pt.clone();
        let ni_tag = ni.seal(&nonce, &aad, &mut ni_buf);
        assert_eq!(
            ni_buf.as_slice(),
            &soft_sealed[..soft_sealed.len() - 16],
            "128 ct round {round}"
        );
        assert_eq!(
            ni_tag.as_slice(),
            &soft_sealed[soft_sealed.len() - 16..],
            "128 tag round {round}"
        );

        // 交叉 open：Ni 的密文由软件打开，反之亦然。
        assert_eq!(soft.open(&nonce, &aad, &soft_sealed).unwrap(), pt);
        let mut via_ni = soft_sealed[..soft_sealed.len() - 16].to_vec();
        let tag2 = ni.open_compute_tag(&nonce, &aad, &mut via_ni);
        assert_eq!(tag2.as_slice(), &soft_sealed[soft_sealed.len() - 16..]);
        assert_eq!(via_ni, pt);
    }
}

/// Ni 与软件在 AES-256-GCM 上逐字节一致。
#[test]
fn differential_aes256() {
    let Some(tok) = AesNi::detect() else {
        eprintln!("AES-NI/CLMUL unavailable; skipping");
        return;
    };
    let mut rng = Rng(0x243F_6A88_85A3_08D3_u64 ^ 0xB256);
    for round in 0..1000u32 {
        let mut key = [0u8; 32];
        rng.fill(&mut key);
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce);
        let aad = rand_bytes(&mut rng, AAD_LENS[(round as usize + 3) % AAD_LENS.len()]);
        let pt = rand_bytes(
            &mut rng,
            PT_LENS[(round as usize / AAD_LENS.len() + 4) % PT_LENS.len()],
        );

        let soft = Aes256Gcm::new(&key);
        let ni = tok.gcm256(&key);

        let soft_sealed = soft.seal(&nonce, &aad, &pt);
        let mut ni_buf = pt.clone();
        let ni_tag = ni.seal(&nonce, &aad, &mut ni_buf);
        assert_eq!(
            ni_buf.as_slice(),
            &soft_sealed[..soft_sealed.len() - 16],
            "256 ct round {round}"
        );
        assert_eq!(
            ni_tag.as_slice(),
            &soft_sealed[soft_sealed.len() - 16..],
            "256 tag round {round}"
        );

        assert_eq!(soft.open(&nonce, &aad, &soft_sealed).unwrap(), pt);
        let mut via_ni = soft_sealed[..soft_sealed.len() - 16].to_vec();
        let tag2 = ni.open_compute_tag(&nonce, &aad, &mut via_ni);
        assert_eq!(tag2.as_slice(), &soft_sealed[soft_sealed.len() - 16..]);
        assert_eq!(via_ni, pt);
    }
}

/// Clone 的执行核心与原核心输出一致。
#[test]
fn differential_clone_box() {
    let Some(tok) = AesNi::detect() else {
        eprintln!("AES-NI/CLMUL unavailable; skipping");
        return;
    };
    let ni = tok.gcm256(&[0x77; 32]);
    let cloned = ni.clone_box();
    let mut a = b"clone consistency check ...".to_vec();
    let mut b = a.clone();
    let t1 = ni.seal(&[9u8; 12], b"aad", &mut a);
    let t2 = cloned.seal(&[9u8; 12], b"aad", &mut b);
    assert_eq!(a, b);
    assert_eq!(t1, t2);
}
