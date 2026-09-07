//! fuzz：AEAD 解密路径（任意密文/标签，先验后出，不得 panic）。
#![no_main]

use ferritls_core::{ccm, chacha20poly1305::ChaCha20Poly1305, gcm::{Aes128Gcm, Aes256Gcm}};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    // key 从输入取（填充到所需长度），nonce 随后（通用 CCM 参数集需要
    // 13 字节），其余按一半分 aad/ct
    let (key, nonce_len) = match sel % 4 {
        0 => (rest.len().min(16), 12usize),
        1 => (rest.len().min(32), 12),
        2 => (rest.len().min(16), 13),
        _ => (rest.len().min(32), 12),
    };
    let (key_bytes, rest) = rest.split_at(key);
    let (nonce_bytes, rest) = rest.split_at(rest.len().min(nonce_len));
    let (aad, ct) = rest.split_at(rest.len() / 2);

    let mut key = [0u8; 32];
    key[..key_bytes.len()].copy_from_slice(key_bytes);
    let mut nonce = [0u8; 13];
    nonce[..nonce_bytes.len()].copy_from_slice(nonce_bytes);

    match sel % 4 {
        0 => {
            let _ = Aes128Gcm::new(&key[..16].try_into().unwrap()).open(&nonce[..12].try_into().unwrap(), aad, ct);
        }
        1 => {
            let _ = Aes256Gcm::new(&key).open(&nonce[..12].try_into().unwrap(), aad, ct);
        }
        // 两个 CCM 参数集都覆盖（sel bit 2 选择）：TLS 12 字节 nonce/L=3
        // （rustls 适配层在用）与通用 13 字节 nonce/L=2。nonce 类型是
        // 各 open() 签名推断的定长数组，切片长度错一个字节即
        // TryFromSliceError——曾因此让本分支对所有输入必然 panic。
        2 if sel & 4 == 0 => {
            let _ = ccm::Aes128CcmTls::new(&key[..16].try_into().unwrap()).open(&nonce[..12].try_into().unwrap(), aad, ct);
        }
        2 => {
            let _ = ccm::Aes128Ccm::new(&key[..16].try_into().unwrap()).open(&nonce[..13].try_into().unwrap(), aad, ct);
        }
        _ => {
            let _ = ChaCha20Poly1305::new(&key).open(&nonce[..12].try_into().unwrap(), aad, ct);
        }
    }
});
