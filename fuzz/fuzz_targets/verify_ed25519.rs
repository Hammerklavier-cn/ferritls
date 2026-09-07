//! fuzz：Ed25519 验证（任意公钥/消息/签名，不得 panic）。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let (public, rest) = data.split_at(32);
    let (msg, sig) = rest.split_at(rest.len() / 2);
    let _ = ferritls_core::sign::ed25519::verify(public, msg, sig);
});
