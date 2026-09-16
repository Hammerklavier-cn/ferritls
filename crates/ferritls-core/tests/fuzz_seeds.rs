//! fuzz 种子语料冒烟（长期防漂移护栏）。
//!
//! 直接读取 `fuzz/corpus/` 下的种子文件，用与对应 fuzz target **同构**
//! 的逻辑跑一遍：入口不得 panic，解封装必须确定性。种子若与源向量
//! 漂移（如重生成后忘同步），本测试先于 CI fuzz 冒烟拦截。
//!
//! mlkem-decaps 种子由 `tools/gen_mlkem_fuzz_seeds.py` 从
//! `tests/mlkem_acvp.rs` 的 ACVP 解封装用例生成，格式：
//! `byte0 = sel（%3：0→512, 1→768, 2→1024），随后 = dk ‖ ct`。

use ferritls_core::mlkem::{k512, k768, k1024};
use std::path::{Path, PathBuf};

fn corpus_dir(name: &str) -> PathBuf {
    // 测试的 cwd = crate 清单目录（crates/ferritls-core）
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(name)
}

fn read_seeds(name: &str) -> Vec<(String, Vec<u8>)> {
    let dir = corpus_dir(name);
    assert!(dir.is_dir(), "语料目录不存在: {}", dir.display());
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("读 {} 失败: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "bin"))
        .collect();
    entries.sort();
    assert!(!entries.is_empty(), "{} 语料为空", dir.display());
    entries
        .into_iter()
        .map(|p| {
            let data = std::fs::read(&p).unwrap();
            (p.file_name().unwrap().to_string_lossy().into_owned(), data)
        })
        .collect()
}

macro_rules! check_set {
    ($set:ident, $dk:expr, $ct:expr) => {{
        let dk = $set::DecapsKey::from_bytes($dk);
        let ct = $set::Ciphertext::from_bytes($ct);
        if let (Ok(dk), Ok(ct)) = (dk, ct) {
            let ss = $set::decapsulate(&dk, &ct);
            let ss2 = $set::decapsulate(&dk, &ct);
            assert_eq!(
                ss.expose_bytes(),
                ss2.expose_bytes(),
                "decapsulate must be deterministic"
            );
            true
        } else {
            false
        }
    }};
}

#[test]
fn mlkem_decaps_seeds_parse_and_stay_deterministic() {
    for (name, data) in read_seeds("mlkem-decaps") {
        assert!(data.len() >= 2, "{name}: 种子过短");
        let sel = data[0] % 3;
        let rest = &data[1..];
        let parsed = match sel {
            0 => check_set!(
                k512,
                &rest[..rest.len().min(k512::DK_BYTES)],
                &rest[k512::DK_BYTES.min(rest.len())..]
            ),
            1 => check_set!(
                k768,
                &rest[..rest.len().min(k768::DK_BYTES)],
                &rest[k768::DK_BYTES.min(rest.len())..]
            ),
            _ => check_set!(
                k1024,
                &rest[..rest.len().min(k1024::DK_BYTES)],
                &rest[k1024::DK_BYTES.min(rest.len())..]
            ),
        };
        // 种子源自 ACVP valid 用例，dk/ct 必须解析成功（防漂移）
        assert!(parsed, "{name}: dk/ct 未通过解析（种子已漂移？）");
    }
}
