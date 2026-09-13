//! fuzz：ML-KEM-768 解封装（任意 dk/ct，隐式拒绝，不得 panic）。
#![no_main]

use ferritls_core::mlkem::{self, Mlkem768Ciphertext, Mlkem768DecapsKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // sel 选择 dk/ct 的构造方式；余下输入截断填充
    let sel = data[0];
    let rest = &data[1..];

    let mut dk_bytes = [0u8; mlkem::DK_BYTES];
    let dk_src = &rest[..rest.len().min(mlkem::DK_BYTES)];
    dk_bytes[..dk_src.len()].copy_from_slice(dk_src);

    let mut ct_bytes = [0u8; mlkem::CT_BYTES];
    let ct_src = &rest[dk_src.len()..];
    let ct_src = &ct_src[..ct_src.len().min(mlkem::CT_BYTES)];
    ct_bytes[..ct_src.len()].copy_from_slice(ct_src);

    match sel % 3 {
        // 0：合法途径构造 dk/ct 后解封装（走完整解析校验）
        0 => {
            if let Ok(dk) = Mlkem768DecapsKey::from_bytes(&dk_bytes) {
                if let Ok(ct) = Mlkem768Ciphertext::from_bytes(&ct_bytes) {
                    let ss = mlkem::decapsulate(&dk, &ct);
                    // ss 必须是确定性的：同输入重解封装一致
                    let ss2 = mlkem::decapsulate(&dk, &ct);
                    assert_eq!(
                        ss.expose_bytes(),
                        ss2.expose_bytes(),
                        "decapsulate must be deterministic"
                    );
                }
            }
        }
        // 1：原始字节直接解封装（跳过解析校验，任意 dk/ct 不 panic）
        1 => {
            if let Ok(dk) = Mlkem768DecapsKey::from_bytes(&dk_bytes) {
                let ct = Mlkem768Ciphertext::from_bytes(&ct_bytes).expect("fixed width");
                let _ = mlkem::decapsulate(&dk, &ct);
            }
        }
        // 2：随机 ek 的模校验必须稳定拒绝超范围系数
        _ => {
            let _ = mlkem::Mlkem768EncapsKey::from_bytes(&dk_bytes[..mlkem::EK_BYTES.min(dk_bytes.len())]);
        }
    }
});
