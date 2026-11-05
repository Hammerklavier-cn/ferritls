#!/usr/bin/env python3
"""提取 NIST CAVP SHAVS 向量到 tests/vectors/shs/（测试完备性轮，2026-11）。

处理字节导向（byte-oriented）官方 .rsp 文件：
- LongMsg（SHA-256/384/512、SHA3-256/384/512、SHAKE128/256）：逐用例
  以 hashlib 独立复算并比对官方 MD/Output——任何不一致即中止（rule 7
  的逐字节核对在本脚本机械化）；
- Monte（SHA-2/SHA-3 各三族）：按 SHAVS/SHA3VS 官方算法复算全部
  100 个检查点（SHA-2：MD = H(MD_{i-3}‖MD_{i-2}‖MD_{i-1}) 滚动三摘要
  拼接；SHA-3（SHA3VS Figure 1）：Msg = 单个前序 MD 链式哈希），
  任何检查点不一致即中止。

裁剪策略：Monte 全量保留（每族 100 检查点，体积小）；LongMsg
保留 ≤512 字节全部用例 + 其余按确定性 1/4 抽样 + 恒保留最大长度
用例（大文件裁剪约定，AGENTS.md）。

用法: python3 -I tools/extract_shavs.py <文件.rsp> [更多.rsp ...]
输出: crates/ferritls-core/tests/vectors/shs/<同名>.json
"""
import hashlib
import json
import os
import re
import sys

DST = "crates/ferritls-core/tests/vectors/shs"

# 文件名 -> (hashlib 构造器 | None=SHAKE, 输出长度字节 | None)
LONG_FILES = {
    "SHA256LongMsg.rsp": (hashlib.sha256, None),
    "SHA384LongMsg.rsp": (hashlib.sha384, None),
    "SHA512LongMsg.rsp": (hashlib.sha512, None),
    "SHA3_256LongMsg.rsp": (hashlib.sha3_256, None),
    "SHA3_384LongMsg.rsp": (hashlib.sha3_384, None),
    "SHA3_512LongMsg.rsp": (hashlib.sha3_512, None),
    "SHAKE128LongMsg.rsp": (hashlib.shake_128, None),
    "SHAKE256LongMsg.rsp": (hashlib.shake_256, None),
}

# 文件名 -> hashlib 构造器（Monte：SHA-2 三摘要滚动 / SHA-3 单链）
MONTE_FILES = {
    "SHA256Monte.rsp": (hashlib.sha256, "sha2"),
    "SHA384Monte.rsp": (hashlib.sha384, "sha2"),
    "SHA512Monte.rsp": (hashlib.sha512, "sha2"),
    "SHA3_256Monte.rsp": (hashlib.sha3_256, "sha3"),
    "SHA3_384Monte.rsp": (hashlib.sha3_384, "sha3"),
    "SHA3_512Monte.rsp": (hashlib.sha3_512, "sha3"),
}


def parse_long(path):
    """解析 LongMsg .rsp：[(len_bits, msg_hex, md_hex, outputlen_bits|None)]。

    SHAKE 文件带 [Outputlen = N] 节头；MD/Output 均按位长折算字节
    （官方文件保证字节对齐）。"""
    cases = []
    outputlen = None
    cur = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"\[Outputlen = (\d+)\]", line)
            if m:
                outputlen = int(m.group(1))
                continue
            m = re.match(r"\[L = (\d+)\]", line)
            if m:
                continue
            m = re.match(r"(Len|Msg|MD|Output) = ?(.*)", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            if key == "Len":
                cur = {"len": int(val), "msg": "", "md": ""}
            elif key == "Msg":
                cur["msg"] = val
            elif key in ("MD", "Output"):
                cur["md"] = val
                cur["outputlen"] = outputlen
                cases.append(cur)
                cur = {}
    return cases


def parse_monte(path):
    """解析 Monte .rsp：(seed_hex, [md_hex × 100])。"""
    seed = None
    mds = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            m = re.match(r"Seed = ?([0-9a-fA-F]+)$", line)
            if m:
                seed = m.group(1)
                continue
            m = re.match(r"MD = ?([0-9a-fA-F]+)$", line)
            if m:
                mds.append(m.group(1))
    if seed is None or not mds:
        raise ValueError(f"{path}: missing Seed or MD entries")
    return seed, mds


def extract_long(path, name, h, _out):
    cases = parse_long(path)
    if not cases:
        raise ValueError(f"{path}: no cases parsed")
    # rule 7：逐用例以 hashlib 独立复算，官方值必须逐字节一致
    verified = 0
    for c in cases:
        msg = bytes.fromhex(c["msg"])
        assert len(msg) * 8 == c["len"], f"{name}: len {c['len']} != {len(msg)*8}"
        outlen = c["outputlen"]
        if outlen is not None:
            out = h(msg).hexdigest(outlen // 8)
        else:
            out = h(msg).hexdigest()
        assert out == c["md"], f"{name}: MD mismatch on len {c['len']}"
        verified += 1
    # 裁剪：≤512 字节全保留；其余 1/4 抽样；恒保留最大长度用例
    kept, idx, seen_valid = [], 0, 0
    max_i = max(range(len(cases)), key=lambda i: cases[i]["len"])
    for i, c in enumerate(cases):
        keep = i == max_i or (c["len"] // 8) <= 512 or seen_valid % 4 == 0
        if (c["len"] // 8) > 512:
            seen_valid += 1
        if keep:
            kept.append({"len": c["len"], "msg": c["msg"], "md": c["md"],
                         "outputlen": c["outputlen"]})
        idx += 1
    out = {"algorithm": name, "source": os.path.basename(path),
           "casesTotal": len(cases), "verified": verified, "cases": kept}
    return out, len(cases), len(kept)


def extract_monte(path, name, h, style):
    seed, mds = parse_monte(path)
    assert len(mds) == 100, f"{name}: expected 100 checkpoints, got {len(mds)}"
    # 官方算法复算：SHA-2 = 三摘要滚动拼接；SHA-3 = 单摘要链
    s = bytes.fromhex(seed)
    for want in mds:
        if style == "sha2":
            a = b = c = s
            for _ in range(1000):
                md = h(a + b + c).digest()
                a, b, c = b, c, md
            s = md
        else:
            for _ in range(1000):
                s = h(s).digest()
        assert s.hex() == want, f"{name}: checkpoint mismatch (want {want[:16]})"
    out = {"algorithm": name, "source": os.path.basename(path),
           "style": style, "seed": seed, "iterations": 1000, "mds": mds}
    return out, len(mds)


def main():
    os.makedirs(DST, exist_ok=True)
    total_in = total_kept = 0
    for arg in sys.argv[1:]:
        name = os.path.basename(arg)
        if name in LONG_FILES:
            h, _ = LONG_FILES[name]
            out, n_in, n_kept = extract_long(arg, name, h, _)
        elif name in MONTE_FILES:
            h, style = MONTE_FILES[name]
            out, n_in = extract_monte(arg, name, h, style)
            n_kept = n_in
        else:
            print(f"skip unknown {name}", file=sys.stderr)
            continue
        dst = os.path.join(DST, name.replace(".rsp", ".json"))
        with open(dst, "w", encoding="utf-8", newline="\n") as f:
            json.dump(out, f, ensure_ascii=True, separators=(",", ":"))
        total_in += n_in
        total_kept += n_kept
        print(f"{name:28s} {n_in:5d} -> {n_kept:5d}  {os.path.getsize(dst)//1024:5d} KB")
    print(f"{'TOTAL':28s} {total_in:5d} -> {total_kept:5d}")


if __name__ == "__main__":
    main()
