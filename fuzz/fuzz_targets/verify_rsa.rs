//! fuzz：RSA 验证（任意 SPKI DER/消息/签名，解析与 padding 检查不得 panic）。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let (key_der, rest) = rest.split_at(rest.len().min(512));
    let (msg, sig) = rest.split_at(rest.len() / 2);
    let hash_bits = match sel % 3 {
        0 => 256u16,
        1 => 384,
        _ => 512,
    };
    // 任意 DER 输入按两种格式解析（裸 RSAPublicKey 与完整 SPKI），
    // 解析与 padding 检查均不得 panic。
    let _ = if sel & 4 == 0 {
        ferritls_core::sign::rsa::VerifyKey::from_rsapublickey_der(key_der)
            .or_else(|_| ferritls_core::sign::rsa::VerifyKey::from_spki_der(key_der))
            .and_then(|vk| vk.verify_pkcs1v15(hash_bits, msg, sig))
    } else {
        ferritls_core::sign::rsa::VerifyKey::from_rsapublickey_der(key_der)
            .or_else(|_| ferritls_core::sign::rsa::VerifyKey::from_spki_der(key_der))
            .and_then(|vk| vk.verify_pss(hash_bits, msg, sig))
    };
});
