//! fuzz：ECDSA 验证（任意公钥/消息/DER 签名，不得 panic）。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (public, rest) = if sel & 1 == 0 {
        // P-256：正常情况公钥 65 字节，其余长度也必须安全拒绝
        rest.split_at(rest.len().min(65))
    } else {
        // P-384：97 字节公钥
        rest.split_at(rest.len().min(97))
    };
    let (msg, sig) = rest.split_at(rest.len() / 2);
    let _ = if sel & 1 == 0 {
        ferritls_core::sign::ecdsa::p256::verify(public, msg, sig)
    } else {
        ferritls_core::sign::ecdsa::p384::verify(public, msg, sig)
    };
});
