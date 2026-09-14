#!/usr/bin/env python3
"""从 NIST ACVP-Server 的 ML-KEM 官方向量 JSON 程序化提取
ferritls-core 的 ML-KEM 三参数集测试文件（tests/mlkem_acvp.rs）。

用法（官方 JSON 从 ACVP-Server 仓库 gen-val/json-files/ 下载，
internalProjection.json，经 contents API 时需 Accept: vnd.github.raw）：

    python tools/extract_mlkem_acvp.py ML-KEM-keyGen-FIPS203.json \
        ML-KEM-encapDecap-FIPS203.json

官方出处（M8.4，2026-09-15 提取，NIST 原件为源；文件头有 SHA-256
记录）：
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203
（M8.3 曾用 RustCrypto/KEMs ml-kem/tests 镜像快照——NIST 上游
2026-09 重生成了 sample 向量，两代种子不同、语义等价；本脚本现以
NIST 原件为源，重跑输出对所用 JSON 确定性。）

子集策略（每个参数集独立执行）：keyGen 前 3 例 + 封装（AFT）前 3 例
+ 解封装（VAL）前 2 例 valid + 1 例 "modified ciphertext"（官方期望
k 即隐式拒绝值 J(z‖c)）+ KeyCheck 负例组各 1 例 valid 对照 + 1 例
无效（encapsulationKeyCheck 的模校验拒绝 / decapsulationKeyCheck
的 h 校验拒绝）。子集固定，重跑输出稳定。
"""

import hashlib
import json
import sys

KEYGEN_CASES = 3
ENCAP_CASES = 3
DECAP_VALID_CASES = 2
DECAP_MODIFIED_CASES = 1
KEYCHECK_VALID_CASES = 1
KEYCHECK_INVALID_CASES = 1

PARAM_SETS = [
    ("512", "ML-KEM-512"),
    ("768", "ML-KEM-768"),
    ("1024", "ML-KEM-1024"),
]

HEADER = """\
//! ML-KEM 三参数集（512/768/1024）的 NIST ACVP 向量测试（M8.4）
//! ——**程序化生成，勿手改**。
//!
//! 生成：`tools/extract_mlkem_acvp.py`（用法与出处见该脚本头注释）。
//! 来源：NIST ACVP-Server `gen-val/json-files/ML-KEM-keyGen-FIPS203`
//! 与 `ML-KEM-encapDecap-FIPS203` 的 `internalProjection.json` 原件
//! （本文件生成时所用的镜像副本指纹记录于下）。
//!
//! 子集（每参数集独立）：keyGen ×3（d,z → ek,dk，含 dk 解析校验）、
//! 封装 ×3（ek,m → c,ss）、解封装 2×valid + 1×"modified ciphertext"
//! （官方期望 k 即隐式拒绝值 J(z‖c)）、KeyCheck 负例各 1 例 valid
//! 对照 + 1 例无效（模校验 / h 校验必须拒绝）。
//!
//! 另含负例：封装密钥模校验（§7.2）、跨参数集长度拒绝。

#![allow(clippy::similar_names)]

mod common;

use common::{hex, to_hex};
use ferritls_core::mlkem::{self, k1024, k512, k768};

/// 生成时所依据的官方文件指纹（SHA-256，2026-09-15，NIST 原件）。
const SOURCE_HASHES: [(&str, &str); 2] = [
    ("keygen-internalProjection.json", "{keygen_sha}"),
    ("encapdecap-internalProjection.json", "{encapdecap_sha}"),
];

fn seed32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}

fn negative_cases_512() {
    let mut ek = vec![0u8; k512::EK_BYTES];
    ek[0] = 0xff;
    ek[1] = 0xff;
    assert!(k512::EncapsKey::from_bytes(&ek).is_err());
    assert!(k512::DecapsKey::from_bytes(&vec![0u8; k512::DK_BYTES - 1]).is_err());
    assert!(k512::Ciphertext::from_bytes(&[0u8; 1]).is_err());
}

fn negative_cases_768() {
    let mut ek = vec![0u8; k768::EK_BYTES];
    ek[0] = 0xff;
    ek[1] = 0xff;
    assert!(k768::EncapsKey::from_bytes(&ek).is_err());
    assert!(k768::DecapsKey::from_bytes(&vec![0u8; k768::DK_BYTES - 1]).is_err());
    assert!(k768::Ciphertext::from_bytes(&[0u8; 1]).is_err());
    // 跨参数集：768 形状的输入不得被其它参数集类型接受
    assert!(k512::Ciphertext::from_bytes(&vec![0u8; k768::CT_BYTES]).is_err());
    assert!(k1024::EncapsKey::from_bytes(&vec![0u8; k768::EK_BYTES]).is_err());
}

fn negative_cases_1024() {
    let mut ek = vec![0u8; k1024::EK_BYTES];
    ek[0] = 0xff;
    ek[1] = 0xff;
    assert!(k1024::EncapsKey::from_bytes(&ek).is_err());
    assert!(k1024::DecapsKey::from_bytes(&vec![0u8; k1024::DK_BYTES - 1]).is_err());
    assert!(k1024::Ciphertext::from_bytes(&[0u8; 1]).is_err());
}

/// 负例入口（各参数集长度/模校验拒绝 + 跨参数集形状拒绝）。
#[test]
fn negative_cases() {
    negative_cases_512();
    negative_cases_768();
    negative_cases_1024();
    let _ = SOURCE_HASHES;
}

"""


def vs_data(doc):
    return doc.get("vsData", doc)


def pick_group(groups, ps, fn=None):
    for g in groups:
        if g.get("parameterSet") == ps and (fn is None or g.get("function") == fn):
            return g
    raise SystemExit("no group: " + ps + " / " + str(fn))


def emit_set_banner(tag, ps):
    return "// ".join(["", "=" * 30 + " ML-KEM-" + tag + " (" + ps + ") " + "=" * 30]) + "\n\n"


def gen_keygen(ctx, group):
    out = []
    for t in group["tests"][:KEYGEN_CASES]:
        tc = str(t["tcId"])
        out.append(f"    // tcId {tc}\n")
        out.append("    {\n")
        out.append(f'        let d = seed32("{t["d"].lower()}");\n')
        out.append(f'        let z = seed32("{t["z"].lower()}");\n')
        out.append(f"        let (ek, dk) = {ctx['mod']}::keypair_from_seed(&d, &z);\n")
        out.append('        assert_eq!(to_hex(ek.as_bytes()), "' + t["ek"].lower() + f'", "ek {ctx['ps']} ' + tc + '");\n')
        out.append('        assert_eq!(to_hex(dk.expose_bytes()), "' + t["dk"].lower() + f'", "dk {ctx['ps']} ' + tc + '");\n')
        out.append(f"        assert!({ctx['dty']}::from_bytes(dk.expose_bytes()).is_ok());\n")
        out.append("    }\n")
    return "".join(out)


def gen_encap(ctx, group):
    out = []
    for t in group["tests"][:ENCAP_CASES]:
        tc = str(t["tcId"])
        out.append(f"    // tcId {tc}（reason: {t.get('reason', '')}）\n")
        out.append("    {\n")
        out.append(f'        let ek = {ctx['ety']}::from_bytes(&hex("{t["ek"].lower()}")).expect("valid vector");\n')
        out.append(f'        let m = seed32("{t["m"].lower()}");\n')
        out.append(f"        let (c, ss) = {ctx['mod']}::encapsulate_with_seed(&ek, &m).expect(\"encaps\");\n")
        out.append('        assert_eq!(to_hex(c.as_bytes()), "' + t["c"].lower() + f'", "c {ctx['ps']} ' + tc + '");\n')
        out.append('        assert_eq!(to_hex(ss.expose_bytes()), "' + t["k"].lower() + f'", "ss {ctx['ps']} ' + tc + '");\n')
        out.append("    }\n")
    return "".join(out)


def pick_decap_tests(tests):
    valid = [t for t in tests if t.get("reason") == "valid decapsulation"]
    modified = [t for t in tests if t.get("reason") == "modified ciphertext"]
    return valid[:DECAP_VALID_CASES] + modified[:DECAP_MODIFIED_CASES]


def gen_decap(ctx, group):
    out = []
    for t in pick_decap_tests(group["tests"]):
        tc = str(t["tcId"])
        out.append(f"    // tcId {tc}（reason: {t.get('reason', '')}）\n")
        out.append("    {\n")
        out.append(f'        let dk = {ctx['dty']}::from_bytes(&hex("{t["dk"].lower()}")).expect("valid vector");\n')
        out.append(f'        let c = {ctx['cty']}::from_bytes(&hex("{t["c"].lower()}")).expect("valid vector");\n')
        out.append(f"        let ss = {ctx['mod']}::decapsulate(&dk, &c);\n")
        out.append('        assert_eq!(to_hex(ss.expose_bytes()), "' + t["k"].lower() + f'", "ss {ctx['ps']} ' + tc + '");\n')
        out.append("    }\n")
    return "".join(out)


def pick_keycheck_tests(tests):
    valid = [t for t in tests if t.get("testPassed")]
    invalid = [t for t in tests if not t.get("testPassed")]
    return valid[:KEYCHECK_VALID_CASES] + invalid[:KEYCHECK_INVALID_CASES]


def gen_keycheck(ctx, enc_group, dec_group):
    out = []
    for t in pick_keycheck_tests(enc_group["tests"]):
        tc = str(t["tcId"])
        suffix = ".is_ok()" if t["testPassed"] else ".is_err()"
        out.append(f"    // encapsulationKeyCheck tcId {tc}（{t['reason']}）\n")
        out.append(f"    assert!({ctx['ety']}::from_bytes(&hex(\"{t['ek'].lower()}\")){suffix});\n")
    for t in pick_keycheck_tests(dec_group["tests"]):
        tc = str(t["tcId"])
        suffix = ".is_ok()" if t["testPassed"] else ".is_err()"
        out.append(f"    // decapsulationKeyCheck tcId {tc}（{t['reason']}）\n")
        out.append(f"    assert!({ctx['dty']}::from_bytes(&hex(\"{t['dk'].lower()}\")){suffix});\n")
    return "".join(out)


def main():
    keygen_path, encapdecap_path = sys.argv[1], sys.argv[2]
    kg_raw = open(keygen_path, "rb").read()
    ed_raw = open(encapdecap_path, "rb").read()
    kg = json.loads(kg_raw)
    ed = json.loads(ed_raw)
    kg_groups = vs_data(kg)["testGroups"]
    ed_groups = vs_data(ed)["testGroups"]

    out = [HEADER
           .replace("{keygen_sha}", hashlib.sha256(kg_raw).hexdigest())
           .replace("{encapdecap_sha}", hashlib.sha256(ed_raw).hexdigest())]

    for tag, ps_name in PARAM_SETS:
        ctx = {
            "tag": tag,
            "ps": ps_name,
            "mod": "k" + tag,
            "ety": "k" + tag + "::EncapsKey",
            "dty": "k" + tag + "::DecapsKey",
            "cty": "k" + tag + "::Ciphertext",
        }
        out.append(emit_set_banner(tag, ps_name))
        # keyGen
        out.append("#[test]\nfn acvp_keygen_" + tag + "() {\n")
        out.append(gen_keygen(ctx, pick_group(kg_groups, ps_name)))
        out.append("}\n\n")
        # 封装
        out.append("#[test]\nfn acvp_encapsulation_" + tag + "() {\n")
        out.append(gen_encap(ctx, pick_group(ed_groups, ps_name, "encapsulation")))
        out.append("}\n\n")
        # 解封装（VAL，含隐式拒绝）
        out.append("#[test]\nfn acvp_decapsulation_" + tag + "() {\n")
        out.append(gen_decap(ctx, pick_group(ed_groups, ps_name, "decapsulation")))
        out.append("}\n\n")
        # KeyCheck 负例（含官方 valid 对照）
        out.append("/// KeyCheck：官方 valid 对照必须接受、无效例必须拒绝。\n")
        out.append("#[test]\nfn acvp_keycheck_" + tag + "() {\n")
        out.append(gen_keycheck(
            ctx,
            pick_group(ed_groups, ps_name, "encapsulationKeyCheck"),
            pick_group(ed_groups, ps_name, "decapsulationKeyCheck")))
        out.append("}\n\n")

    text = "".join(out)
    dest = "crates/ferritls-core/tests/mlkem_acvp.rs"
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("wrote", dest, len(text), "bytes")


if __name__ == "__main__":
    main()
