//! fuzz：ML-KEM 三参数集解封装（任意 dk/ct，隐式拒绝，不得 panic）。
#![no_main]

use ferritls_core::mlkem::{k1024, k512, k768};
use libfuzzer_sys::fuzz_target;

macro_rules! fuzz_set {
    ($set:ident, $rest:expr) => {{
        let rest: &[u8] = $rest;
        let mut dk_bytes = [0u8; $set::DK_BYTES];
        let dk_src = &rest[..rest.len().min($set::DK_BYTES)];
        dk_bytes[..dk_src.len()].copy_from_slice(dk_src);
        let mut ct_bytes = [0u8; $set::CT_BYTES];
        let ct_src = &rest[dk_src.len()..];
        let ct_src = &ct_src[..ct_src.len().min($set::CT_BYTES)];
        ct_bytes[..ct_src.len()].copy_from_slice(ct_src);

        // 解析入口：dk 头部哈希校验 / ek 模校验必须稳定，不得 panic
        let dk = $set::DecapsKey::from_bytes(&dk_bytes);
        let _ = $set::EncapsKey::from_bytes(&dk_bytes[..$set::EK_BYTES]);
        // 解封装：任意 dk/ct 隐式拒绝且确定性（同输入两次一致）
        if let (Ok(dk), Ok(ct)) = (dk, $set::Ciphertext::from_bytes(&ct_bytes)) {
            let ss = $set::decapsulate(&dk, &ct);
            let ss2 = $set::decapsulate(&dk, &ct);
            assert_eq!(
                ss.expose_bytes(),
                ss2.expose_bytes(),
                "decapsulate must be deterministic"
            );
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let sel = data[0];
    let rest = &data[1..];
    match sel % 3 {
        0 => fuzz_set!(k512, rest),
        1 => fuzz_set!(k768, rest),
        _ => fuzz_set!(k1024, rest),
    }
});
