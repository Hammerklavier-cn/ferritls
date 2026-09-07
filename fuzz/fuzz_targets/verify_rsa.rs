//! fuzz：RSA 验证（任意 SPKI DER/消息/签名，解析与 padding 检查不得 panic）。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (spki, rest) = rest.split_at(rest.len().min(512));
    let (msg, sig) = rest.split_at(rest.len() / 2);
    let hash_bits = match sel % 3 {
        0 => 256u16,
        1 => 384,
        _ => 512,
    };
    let _ = if sel & 4 == 0 {
        ferritls_core::sign::rsa::verify_pkcs1v15(hash_bits, spki, msg, sig)
    } else {
        ferritls_core::sign::rsa::verify_pss(hash_bits, spki, msg, sig)
    };
});
