#!/usr/bin/env python3
"""生成 fuzz/corpus/mlkem-decaps/ 的种子语料（M8.4 三参数集）。

来源 = crates/ferritls-core/tests/mlkem_acvp.rs 中已全绿的 ACVP 解封装
用例（同一案例的 dk/c 真值对）：每参数集一份 valid 种子 + 一份
modified-ciphertext 种子（ct 末字节翻 1 bit，走隐式拒绝路径）。

fuzz target 输入格式（fuzz_targets/mlkem_decaps.rs）：
    byte0 = sel（sel % 3：0→512, 1→768, 2→1024），随后 = dk ‖ ct。

向量本身已被测试套件逐字节验证过（来源与核对记录见
docs/VECTOR-PROVENANCE.md 的 mlkem.rs 行），因此本脚本只做结构搬运：
拼接、长度断言、写文件。重跑输出确定。
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TESTS = REPO / "crates/ferritls-core/tests/mlkem_acvp.rs"
OUT = REPO / "fuzz/corpus/mlkem-decaps"

# (参数集, sel, DK_BYTES, CT_BYTES) —— 与 core mlkem::{k512,k768,k1024} 一致
SETS = [("k512", 0, 1632, 768), ("k768", 1, 2400, 1088), ("k1024", 2, 3168, 1568)]


def extract_pair(src: str, set_name: str):
    """取该参数集第一个 valid 解封装用例的 (dk_bytes, ct_bytes)。"""
    dk = re.search(
        rf"let dk = {set_name}::DecapsKey::from_bytes\(&hex\(\"([0-9a-fA-F]+)\"\)\)",
        src,
    )
    ct = re.search(
        rf"let c = {set_name}::Ciphertext::from_bytes\(&hex\(\"([0-9a-fA-F]+)\"\)\)",
        src,
    )
    assert dk and ct, f"{set_name}: 未找到 dk/ct 用例"
    return bytes.fromhex(dk.group(1)), bytes.fromhex(ct.group(1))


def main():
    src = TESTS.read_text(encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    written = []
    for set_name, sel, dk_len, ct_len in SETS:
        dk, ct = extract_pair(src, set_name)
        assert len(dk) == dk_len, f"{set_name}: dk 长度 {len(dk)} != {dk_len}"
        assert len(ct) == ct_len, f"{set_name}: ct 长度 {len(ct)} != {ct_len}"
        # valid 种子
        (OUT / f"{set_name}_valid.bin").write_bytes(bytes([sel]) + dk + ct)
        # modified-ct 种子：末字节翻 1 bit → 重加密比较不等 → 隐式拒绝 K̃
        mod = bytearray(ct)
        mod[-1] ^= 0x01
        (OUT / f"{set_name}_modified_ct.bin").write_bytes(bytes([sel]) + dk + bytes(mod))
        written += [f"{set_name}_valid.bin", f"{set_name}_modified_ct.bin"]
    for name in written:
        p = OUT / name
        print(f"wrote {p.relative_to(REPO)} ({p.stat().st_size} B)")


if __name__ == "__main__":
    sys.exit(main())
