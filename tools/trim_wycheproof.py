#!/usr/bin/env python3
"""下载并裁剪 Wycheproof 测试向量到 tests/vectors/（M7）。

裁剪策略（AGENTS.md：大文件须裁剪，避免仓库膨胀）：
- 保留全部 invalid / acceptable 用例（安全对抗性内容，这是引入它们的目的）；
- valid 用例按确定性抽样保留（默认 1/4，P-384 ECDH 的重复 EdgeCase 组 1/8）；
- 剥离用不到的大字段（PEM/JWK/PKCS8/私钥族等），保留 notes/header 以便
  失败时对照 flags 语义。

来源：C2SP/wycheproof（google/wycheproof 迁移后的维护仓库）testvectors_v1/，
提交哈希见 tests/vectors/README.md（本脚本同目录的 PROVENANCE 记录）。

用法: python tools/trim_wycheproof.py <下载目录> [<文件名过滤>...]
（缺省过滤 = 全量再生成；可只传新文件名做增量。）
"""
import json
import os
import sys

TEST_KEYS = ["tcId", "comment", "flags", "result"]
PUBKEY_KEEP = {"curve", "uncompressed", "pk"}


# 本实现的 GCM API 面只收 96 位 nonce（类型级 [u8; 12]）与 128 位标签、
# 密钥 128/256（无 192）——非此参数空间的组整体裁掉（ivSize≠96 组测的
# 是 GHASH 型 J0 派生，不在 API 面内）。
def gcm_group_filter(g):
    return g.get("ivSize") == 96 and g.get("tagSize") == 128 and g.get("keySize") in (128, 256)


def chacha_group_filter(g):
    return g.get("ivSize") == 96 and g.get("tagSize") == 128 and g.get("keySize") == 256


# 文件名 -> (group 白名单字段, test 数据字段, valid 抽样率, 组过滤器|None)
SPECS = {
    "ecdh_secp256r1_ecpoint_test.json": ({"curve", "encoding"}, ["public", "private", "shared"], 4, None),
    "ecdh_secp384r1_ecpoint_test.json": ({"curve", "encoding"}, ["public", "private", "shared"], 8, None),
    "x25519_test.json": ({"curve"}, ["public", "private", "shared"], 4, None),
    "ecdsa_secp256r1_sha256_test.json": ({"sha", "publicKey"}, ["msg", "sig"], 4, None),
    "ecdsa_secp384r1_sha384_test.json": ({"sha", "publicKey"}, ["msg", "sig"], 4, None),
    "ed25519_test.json": ({"publicKey"}, ["msg", "sig"], 4, None),
    "rsa_signature_2048_sha256_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_signature_2048_sha384_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_signature_2048_sha512_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_pss_2048_sha256_mgf1_32_test.json": (
        {"sha", "mgfSha", "sLen", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "aes_gcm_test.json": ({"ivSize", "keySize", "tagSize"}, ["key", "iv", "aad", "msg", "ct", "tag"], 4, gcm_group_filter),
    "chacha20_poly1305_test.json": ({"ivSize", "keySize", "tagSize"}, ["key", "iv", "aad", "msg", "ct", "tag"], 4, chacha_group_filter),
}


def trim_file(src_dir, name, group_keys, data_keys, valid_ratio, group_filter):
    with open(os.path.join(src_dir, name), encoding="utf-8") as f:
        doc = json.load(f)
    out = {"algorithm": doc.get("algorithm"), "header": doc.get("header"),
           "notes": doc.get("notes", {}), "source": doc.get("source"),
           "testGroups": []}
    total = kept = 0
    for g in doc["testGroups"]:
        if group_filter is not None and not group_filter(g):
            continue
        ng = {k: g[k] for k in group_keys if k in g}
        if "publicKey" in ng and isinstance(ng["publicKey"], dict):
            ng["publicKey"] = {k: v for k, v in ng["publicKey"].items() if k in PUBKEY_KEEP}
        tests = []
        valid_seen = 0
        for t in g["tests"]:
            total += 1
            keep = t["result"] != "valid" or valid_seen % valid_ratio == 0
            if t["result"] == "valid":
                valid_seen += 1
            if not keep:
                continue
            nt = {k: t[k] for k in TEST_KEYS if k in t}
            for dk in data_keys:
                nt[dk] = t[dk]
            tests.append(nt)
            kept += 1
        ng["tests"] = tests
        out["testGroups"].append(ng)
    out["numberOfTests"] = kept
    return out, total, kept


def main():
    src = sys.argv[1]
    # 可选的文件名过滤（只重新生成指定文件）；缺省 = 全量
    only = set(sys.argv[2:])
    dst = "crates/ferritls-core/tests/vectors"
    os.makedirs(dst, exist_ok=True)
    total_in = total_kept = 0
    for name, (gk, dk, ratio, gfilter) in SPECS.items():
        if only and name not in only:
            continue
        out, total, kept = trim_file(src, name, gk, dk, ratio, gfilter)
        path = os.path.join(dst, name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(out, f, ensure_ascii=True, separators=(",", ":"))
        total_in += total
        total_kept += kept
        print(f"{name:42s} {total:4d} -> {kept:4d} cases  {os.path.getsize(path)//1024:4d} KB")
    print(f"{'TOTAL':42s} {total_in:4d} -> {total_kept:4d} cases")


if __name__ == "__main__":
    main()
