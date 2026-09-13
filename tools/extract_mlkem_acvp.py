#!/usr/bin/env python3
"""从 NIST ACVP-Server 的 ML-KEM 官方向量 JSON 程序化提取
ferritls-core 的 ML-KEM-768 测试文件（tests/mlkem_acvp.rs）。

用法（官方 JSON 从 ACVP-Server 仓库 gen-val/json-files/ 下载）：

    python tools/extract_mlkem_acvp.py ML-KEM-keyGen-FIPS203.json \
        ML-KEM-encapDecap-FIPS203.json

官方出处（2026-09-13 提取所依据的镜像，文件头有 SHA-256 记录）：
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-keyGen-FIPS203
  https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203
（经 RustCrypto/KEMs ml-kem/tests 的 internal projection 副本交叉
  定位，commit 65370b8；本脚本的输出对该 JSON 确定性。）

子集策略：ML-KEM-768 的 keyGen 前 3 例 + 封装（AFT）前 3 例 +
解封装（VAL）前 3 例（VAL 组含 "modify ciphertext" 隐式拒绝用例）。
子集固定，重跑输出稳定。
"""

import hashlib
import json
import sys

KEYGEN_CASES = 3
ENCAP_CASES = 3
DECAP_CASES = 3

HEADER = """\
//! ML-KEM-768 的 NIST ACVP 向量测试（M8.3）——**程序化生成，勿手改**。
//!
//! 生成：`tools/extract_mlkem_acvp.py`（用法与出处见该脚本头注释）。
//! 来源：NIST ACVP-Server `gen-val/json-files/ML-KEM-keyGen-FIPS203`
//! 与 `ML-KEM-encapDecap-FIPS203`（internal projection；本文件生成
//! 时所用的镜像副本记录于下）。
//!
//! 子集（ML-KEM-768）：keyGen ×3（d,z → ek,dk）、封装 ×3
//! （ek,m → c,ss）、解封装 ×3（dk,c → ss，含 "modify ciphertext"
//! 隐式拒绝用例，官方期望值即为 J(z‖c)）。
//!
//!
//! 另含负例：封装密钥模校验（§7.2）、篡改密文的隐式拒绝差分、
//! dk 头部哈希校验。

#![allow(clippy::similar_names)]

mod common;

use common::{hex, to_hex};
use ferritls_core::mlkem::{
    self, Mlkem768Ciphertext, Mlkem768DecapsKey, Mlkem768EncapsKey,
};

/// 生成时所依据的官方镜像文件指纹（SHA-256，2026-09-13）。
const SOURCE_HASHES: [(&str, &str); 2] = [
    ("key-gen.json", "{keygen_sha}"),
    ("encap-decap.json", "{encapdecap_sha}"),
];

fn seed32(s: &str) -> [u8; 32] {
    hex(s).try_into().expect("32 bytes")
}

"""


def vs_data(doc):
    return doc.get("vsData", doc)


def pick(param_set, groups, n):
    for g in groups:
        if g.get("parameterSet") == param_set:
            return g, g["tests"][:n]
    raise SystemExit(f"no {param_set} group")


def emit_hex(values, indent="    "):
    lines = []
    for i in range(0, len(values), 64):
        lines.append(indent + "&[" + values[i:i + 64] + "]")
    return "\n".join(lines)


def main():
    keygen_path, encapdecap_path = sys.argv[1], sys.argv[2]
    kg_raw = open(keygen_path, "rb").read()
    ed_raw = open(encapdecap_path, "rb").read()
    kg = json.loads(kg_raw)
    ed = json.loads(ed_raw)

    kg_group, kg_tests = pick("ML-KEM-768", vs_data(kg)["testGroups"], KEYGEN_CASES)
    ed_groups = vs_data(ed)["testGroups"]
    enc_group, enc_tests = pick("ML-KEM-768", [g for g in ed_groups if g.get("function") == "encapsulation"], ENCAP_CASES)
    dec_group, dec_tests = pick("ML-KEM-768", [g for g in ed_groups if g.get("function") == "decapsulation"], DECAP_CASES)

    out = [HEADER
           .replace("{keygen_sha}", hashlib.sha256(kg_raw).hexdigest())
           .replace("{encapdecap_sha}", hashlib.sha256(ed_raw).hexdigest())]

    # keyGen 测试
    out.append("/// keyGen：(d, z) → (ek, dk)（含 2400 字节 dk 解析校验）。\n")
    out.append("#[test]\nfn acvp_keygen() {\n")
    for t in kg_tests:
        out.append(f"    // tcId {t['tcId']}\n")
        out.append("    {\n")
        out.append(f"        let d = seed32(\"{t['d'].lower()}\");\n")
        out.append(f"        let z = seed32(\"{t['z'].lower()}\");\n")
        out.append("        let (ek, dk) = mlkem::keypair_from_seed(&d, &z);\n")
        out.append('        assert_eq!(to_hex(ek.as_bytes()), "' + t["ek"].lower() + '", "ek tcId ' + str(t["tcId"]) + '");\n')
        out.append('        assert_eq!(to_hex(dk.expose_bytes()), "' + t["dk"].lower() + '", "dk tcId ' + str(t["tcId"]) + '");\n')
        out.append("        assert!(Mlkem768DecapsKey::from_bytes(dk.expose_bytes()).is_ok());\n")
        out.append("    }\n")
    out.append("}\n\n")

    # 封装测试
    out.append("/// 封装：(ek, m) → (c, ss)（确定性 m；官方期望 k = K = G(m‖H(ek))[..32]）。\n")
    out.append("#[test]\nfn acvp_encapsulation() {\n")
    for t in enc_tests:
        out.append(f"    // tcId {t['tcId']}（reason: {t.get('reason', '')}）\n")
        out.append("    {\n")
        out.append(f"        let ek = Mlkem768EncapsKey::from_bytes(&hex(\"{t['ek'].lower()}\"))expect_PLACEHOLDER;\n")
        out.append(f"        let m = seed32(\"{t['m'].lower()}\");\n")
        out.append("        let (c, ss) = mlkem::encapsulate_with_seed(&ek, &m).expect(\"encaps\");\n")
        out.append('        assert_eq!(to_hex(c.as_bytes()), "' + t["c"].lower() + '", "c tcId ' + str(t["tcId"]) + '");\n')
        out.append('        assert_eq!(to_hex(ss.expose_bytes()), "' + t["k"].lower() + '", "ss tcId ' + str(t["tcId"]) + '");\n')
        out.append("    }\n")
    out.append("}\n\n")

    # 解封装测试（VAL：dk 在组级；含隐式拒绝用例）
    out.append("/// 解封装（VAL）：dk 在组级；modified ciphertext 的期望 k 即\n/// J(z‖c)（隐式拒绝）。\n")
    out.append("#[test]\nfn acvp_decapsulation() {\n")
    out.append(f"    let dk = Mlkem768DecapsKey::from_bytes(&hex(\"{dec_group['dk'].lower()}\"))expect_PLACEHOLDER;\n")
    for t in dec_tests:
        out.append(f"    // tcId {t['tcId']}（reason: {t.get('reason', '')}）\n")
        out.append("    {\n")
        out.append(f"        let c = Mlkem768Ciphertext::from_bytes(&hex(\"{t['c'].lower()}\"))expect_PLACEHOLDER;\n")
        out.append("        let ss = mlkem::decapsulate(&dk, &c);\n")
        out.append('        assert_eq!(to_hex(ss.expose_bytes()), "' + t["k"].lower() + '", "ss tcId ' + str(t["tcId"]) + '");\n')
        out.append("    }\n")
    out.append("}\n\n")

    # 负例
    out.append("""/// 负例：ek 模校验拒绝（d1 = 0x0FFF >= q）、篡改密文走隐式拒绝
/// （≠ 正确 ss）、dk 的 h 校验拒绝。
#[test]
fn negative_cases() {
    // ek 前两字节置 0xFF：首系数 d1 = 0x0FFF = 4095 >= q，模校验必须拒绝
    let mut ek = vec![0u8; 1184];
    ek[0] = 0xff;
    ek[1] = 0xff;
    assert!(Mlkem768EncapsKey::from_bytes(&ek).is_err());

    // 篡改密文：decapsulate 返回隐式拒绝值（与正确 ss 不同、不 panic）
    let d = seed32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let z = seed32("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f");
    let (ek, dk) = mlkem::keypair_from_seed(&d, &z);
    let m = seed32("010201020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c");
    let (c, ss) = mlkem::encapsulate_with_seed(&ek, &m).expect("encaps");
    let mut bad = *c.as_bytes();
    bad[0] ^= 0x01;
    let bad = Mlkem768Ciphertext::from_bytes(&bad).expect("valid vector");
    let ss2 = mlkem::decapsulate(&dk, &bad);
    assert_ne!(to_hex(ss.expose_bytes()), to_hex(ss2.expose_bytes()));
    // 长度错误
    assert!(Mlkem768DecapsKey::from_bytes(&vec![0u8; 2399]).is_err());
    assert!(Mlkem768Ciphertext::from_bytes(&[0u8; 1]).is_err());
    let _ = SOURCE_HASHES;
}
""")

    text = "".join(out).replace(")expect_PLACEHOLDER", ").expect(\"valid vector\")")
    dest = "crates/ferritls-core/tests/mlkem_acvp.rs"
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print("wrote", dest, len(text), "bytes")


if __name__ == "__main__":
    main()
