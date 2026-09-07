//! fuzz：对端公钥解析（X25519/P-256/P-384 任意对端字节，不得 panic；
//! 小阶点/不在曲线上的点必须 Err）。
#![no_main]

use ferritls_core::ecdh;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    match sel % 3 {
        0 => {
            let sk = ecdh::x25519::SecretKey::from_seed([7u8; 32]);
            let _ = sk.diffie_hellman(rest);
        }
        1 => {
            let sk = ecdh::p256::SecretKey::from_seed([7u8; 32]);
            let _ = sk.diffie_hellman(rest);
        }
        _ => {
            let sk = ecdh::p384::SecretKey::from_seed([7u8; 48]);
            let _ = sk.diffie_hellman(rest);
        }
    }
});
