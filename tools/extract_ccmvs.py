#!/usr/bin/env python3
"""提取 NIST SP800-38C CAVS CCM 向量到 tests/vectors/ccm/（测试完备性轮）。

来源：NIST CCM Test Vectors（SP800-38C），经 OpenSSL master
test/recipes/30-test_evp_data/evpciph_aes_ccm_cavs.txt 转载（Apache-2.0
许可头，见 docs/VECTOR-PROVENANCE.md）。仅取 aes-128-ccm（本实现
API 面）；期望值逐块原样搬运（官方文件即真值源）。

裁剪策略：全部 (nonce, tag) 形状组合各保留至多 2 个 ENCRYPT 用例
（官方期望密文逐字节锚定）+ Decryption-Verification 失败用例按 1/4
确定性抽样（篡改标签/密文必须拒绝）。

用法: python3 -I tools/extract_ccmvs.py <evpciph_aes_ccm_cavs.txt>
输出: crates/ferritls-core/tests/vectors/ccm/ccmvs_aes128.json
"""
import collections
import json
import os
import sys

DST = "crates/ferritls-core/tests/vectors/ccm/ccmvs_aes128.json"


def parse_blocks(path):
    """evp_test 格式：注释行/#/Title 行外，KEY = VALUE，空行分块。"""
    import re

    blocks = []
    title = None
    cur = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                if cur:
                    blocks.append((title, cur))
                    cur = {}
                continue
            if line.startswith("Title = "):
                title = line[len("Title = "):]
                continue
            m = re.match(r"(\w+) = ?(.*)", line)
            if m:
                cur[m.group(1)] = m.group(2)
    if cur:
        blocks.append((title, cur))
    return blocks


def main():
    src = sys.argv[1]
    blocks = parse_blocks(src)
    enc_by_shape = collections.defaultdict(list)
    dec_fail = []
    for title, b in blocks:
        if b.get("Cipher", "").lower() != "aes-128-ccm":
            continue
        iv = bytes.fromhex(b.get("IV", ""))
        tag = bytes.fromhex(b.get("Tag", ""))
        case = {
            "title": title,
            "key": b["Key"],
            "iv": b.get("IV", ""),
            "aad": b.get("AAD", ""),
            "pt": b.get("Plaintext", ""),
            "ct": b.get("Ciphertext", ""),
            "tag": b.get("Tag", ""),
            "op": b.get("Operation", "ENCRYPT"),
            "result": b.get("Result", "OK"),
        }
        if case["op"] == "ENCRYPT":
            enc_by_shape[(len(iv), len(tag))].append(case)
        else:
            dec_fail.append(case)
    # 形状覆盖：每个 (nonce_len, tag_len) 至多 2 个 ENCRYPT；
    # 解密失败用例 1/4 抽样。
    kept = []
    for shape in sorted(enc_by_shape):
        kept.extend(enc_by_shape[shape][:2])
    kept.extend(dec_fail[::4])
    out = {
        "algorithm": "AES-128-CCM",
        "source": "NIST SP800-38C CAVS via OpenSSL evpciph_aes_ccm_cavs.txt",
        "encryptShapes": sorted(k for k in enc_by_shape),
        "decryptFailTotal": len(dec_fail),
        "cases": kept,
    }
    os.makedirs(os.path.dirname(DST), exist_ok=True)
    with open(DST, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, ensure_ascii=True, separators=(",", ":"))
    print(f"cases: {len(kept)} ({len(enc_by_shape)} encrypt shapes, "
          f"{len(dec_fail)} decrypt-fail total -> {len(dec_fail[::4])} kept)")
    print(f"{os.path.getsize(DST)//1024} KB -> {DST}")


if __name__ == "__main__":
    main()
