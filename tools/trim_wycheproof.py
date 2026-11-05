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


# CCM API 面：仅 AES-128（keySize 128）；nonce/tag 长度是运行时参数，
# 越界组（nonce 非 7..13、tag 非 4..16 偶数）全量保留作参数拒绝负例。
def ccm_group_filter(g):
    return g.get("keySize") == 128


# PSS 参数变体：MGF1 哈希固定同消息哈希（API 面约定），只保留
# SHA-256/384/512 的 mgfSha==sha 组；sLen 任意（0/20/28/32/48/64）。
def pss_misc_group_filter(g):
    return g.get("mgfSha") == g.get("sha") and g.get("sha") in ("SHA-256", "SHA-384", "SHA-512")


# sig_gen：模长 ≥ 2048（本实现装载下限）、SHA-2 族，且 **均衡素数**
# CRT 形状（p、q 字节长 ≤ ⌈n_bytes/8⌉/2·8——core 的 CRT limb 宽度按
# 模长半宽定长分配，非均衡拆分（如 1368/688 位）超出该形状，装载
# 层面拒绝属既定约束）；WeakHash（SHA-1/224）与 SmallPublicKey
# （1024/1536）组的 acceptable = 拒收，留给装载负例路径。
def sig_gen_group_filter(g):
    if g.get("keySize", 0) < 2048 or g.get("sha") not in ("SHA-256", "SHA-384", "SHA-512"):
        return False
    n_len, p_len, q_len = _sig_gen_n_pq_lens(g.get("privateKeyPkcs8", ""))
    # 与 core 一致：n_bytes = DER n 字段实际字节（含正整数 0x00 填充），
    # n_len = ceil(n_bytes/8) limb，pl = ceil(n_len/2)，CRT 分量 ≤ pl·8 字节。
    pl_bytes = (((n_len + 7) // 8) + 1) // 2 * 8
    return p_len <= pl_bytes and q_len <= pl_bytes


def _sig_gen_n_pq_lens(pkcs8_hex):
    """从 PKCS#8 hex 里取 PKCS#1 的 n/p/q 字节长（解析失败返回 (0, 9**9, 9**9) 滤除）。"""
    try:
        b = bytes.fromhex(pkcs8_hex)
        def tlv(b, off):
            tag = b[off]; ln = b[off + 1]; o = off + 2
            if ln & 0x80:
                k = ln & 0x7F
                ln = int.from_bytes(b[off + 2:off + 2 + k], "big")
                o = off + 2 + k
            return tag, b[o:o + ln], o + ln
        _, content, _ = tlv(b, 0)
        _, _ver, off = tlv(content, 0)
        _, _alg, off = tlv(content, off)
        _, priv, _ = tlv(content, off)
        _, inner, _ = tlv(priv, 0)
        fields, io = [], 0
        while io < len(inner):
            t, v, io = tlv(inner, io)
            fields.append(v)
        return len(fields[1]), len(fields[4]), len(fields[5])
    except Exception:
        return 0, 9**9, 9**9


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
    # —— 测试完备性轮新增（2026-11）：HMAC / HKDF / CCM / RSA 扩展面 ——
    # HMAC：小文件全量保留（keySize 128/256/520 × tagSize 半/全，
    # 520 bit = block+1 恰好覆盖超块密钥路径；invalid = 篡改 tag）。
    "hmac_sha256_test.json": ({"keySize", "tagSize"}, ["key", "msg", "tag"], 1, None),
    "hmac_sha384_test.json": ({"keySize", "tagSize"}, ["key", "msg", "tag"], 1, None),
    "hmac_sha512_test.json": ({"keySize", "tagSize"}, ["key", "msg", "tag"], 1, None),
    # HKDF：每用例自带 salt/ikm/info/size/okm；invalid 主要为
    # size > 255·HashLen（Expand 计数器上溢拒绝），全量保留。
    "hkdf_sha256_test.json": (set(), ["salt", "ikm", "info", "size", "okm"], 1, None),
    "hkdf_sha384_test.json": (set(), ["salt", "ikm", "info", "size", "okm"], 1, None),
    "hkdf_sha512_test.json": (set(), ["salt", "ikm", "info", "size", "okm"], 1, None),
    # AES-CCM：保留 keySize=128 的全部组（本实现仅 AES-128）；
    # ivSize 越界组（0..2144）与 tagSize 非 4..16 偶数组的用例恰是
    # 参数拒绝负例，测试侧按参数空间分派断言。
    "aes_ccm_test.json": ({"ivSize", "keySize", "tagSize"}, ["key", "iv", "aad", "msg", "ct", "tag"], 1, ccm_group_filter),
    # RSA 扩展面：3072/4096 模数 × SHA-256/384（2048 族既有）；
    # pss_misc 仅保留 mgfSha == sha 且 SHA-2 族组（MGF1 独立哈希
    # 参数不在 API 面内，见 wycheproof.rs 注释）；sig_gen 为签名侧
    # KAT，需保留 privateKeyPkcs8 以驱动 core 签名。
    "rsa_signature_3072_sha256_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_signature_3072_sha384_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_signature_4096_sha256_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_signature_4096_sha384_test.json": ({"sha", "keySize", "publicKeyDer"}, ["msg", "sig"], 4, None),
    "rsa_pss_misc_test.json": ({"sha", "mgfSha", "sLen", "keySize", "publicKeyDer"}, ["msg", "sig"], 1, pss_misc_group_filter),
    "rsa_pkcs1_2048_sig_gen_test.json": ({"sha", "keySize", "keyDer", "privateKeyPkcs8"}, ["msg", "sig"], 4, sig_gen_group_filter),
    "rsa_pkcs1_3072_sig_gen_test.json": ({"sha", "keySize", "keyDer", "privateKeyPkcs8"}, ["msg", "sig"], 4, sig_gen_group_filter),
    "rsa_pkcs1_4096_sig_gen_test.json": ({"sha", "keySize", "keyDer", "privateKeyPkcs8"}, ["msg", "sig"], 4, sig_gen_group_filter),
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
