//! fuzz：PKCS#8 私钥解析（攻击者可控 DER 不得 panic，必须 Result）。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ferritls_core::der::parse_pkcs8_private_key(data);
});
