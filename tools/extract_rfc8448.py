#!/usr/bin/env python3
"""从 RFC 8448 官方文本提取 §3 Simple 1-RTT 轨迹字节常量并生成 Rust 测试。

1. 解析 rfc-editor.org 官方 txt（AGENTS.md 规则 7：禁止人工转录）。
2. 用 Python 独立复算全部密钥调度中间值并与 RFC 标注比对（第二意见）。
3. 生成 crates/ferritls-core/tests/schedule_rfc8448.rs。

用法: python tools/extract_rfc8448.py <rfc8448.txt> [输出.rs]
"""
import hashlib
import hmac as pyhmac
import re
import sys

HEX2 = re.compile(r"\b[0-9a-fA-F]{2}\b")
OCTETS = re.compile(r"\(\d+ octets?\)")


def flat_section(lines):
    start = next(i for i, l in enumerate(lines) if l.startswith("3.  Simple 1-RTT"))
    end = next(i for i, l in enumerate(lines) if l.startswith("4.  Resumed 0-RTT"))
    text = re.sub(r"\s+", " ", "\n".join(lines[start:end]))
    text = OCTETS.sub("", text)
    return text.replace("(empty)", "")


def extract(flat, label, n, anchor, occurrence=1):
    off = flat.index(anchor)
    idx = -1
    for _ in range(occurrence):
        idx = flat.index(label, off)
        off = idx + 1
    colon = flat.index(":", idx)
    return "".join(HEX2.findall(flat[colon:])[:n]).lower()


def H(b):
    return hashlib.sha256(b).hexdigest()


def Hmac(k, m):
    return pyhmac.new(k, m, hashlib.sha256).hexdigest()


def Extract(salt, ikm):
    return pyhmac.new(salt, ikm, hashlib.sha256).digest()


def Expand(prk, info, n):
    t, okm = b"", b""
    for _ in range(1, -(-n // 32) + 1):
        t = pyhmac.new(prk, t + info + bytes([len(t) // 32 + 1]), hashlib.sha256).digest()
        okm += t
    return okm[:n]


def ExpLabel(prk, label, ctx, n):
    info = build_info(label, ctx, n)
    return Expand(prk, info, n)


def build_info(label, ctx, n):
    # RFC 8446 §7.1 HkdfLabel：label 与 context 都是带 1 字节长度前缀的向量。
    return n.to_bytes(2, "big") + bytes([6 + len(label)]) + b"tls13 " + label.encode() + bytes([len(ctx)]) + ctx


def main():
    rfc_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "crates/ferritls-core/tests/schedule_rfc8448.rs"
    flat = flat_section(open(rfc_path, encoding="utf-8").read().splitlines())

    # ---- 原始消息字节（来自官方文本，非转录）----
    raw = {
        "CLIENT_PRIV": extract(flat, "private key :", 32, "{client} create an ephemeral x25519 key pair:"),
        "CLIENT_PUB": extract(flat, "public key :", 32, "{client} create an ephemeral x25519 key pair:"),
        "SERVER_PRIV": extract(flat, "private key :", 32, "{server} create an ephemeral x25519 key pair:"),
        "SERVER_PUB": extract(flat, "public key :", 32, "{server} create an ephemeral x25519 key pair:"),
        "CLIENT_HELLO": extract(flat, "ClientHello :", 196, "construct a ClientHello handshake message:"),
        "SERVER_HELLO": extract(flat, "ServerHello :", 90, "construct a ServerHello handshake message:"),
        "ENCRYPTED_EXTENSIONS": extract(flat, "EncryptedExtensions :", 40, "construct an EncryptedExtensions handshake message:"),
        "CERTIFICATE": extract(flat, "Certificate :", 445, "construct a Certificate handshake message:"),
        "CERTIFICATE_VERIFY": extract(flat, "CertificateVerify :", 136, "construct a CertificateVerify handshake message:"),
        "SERVER_FINISHED": extract(flat, "Finished :", 36, "{server} construct a Finished handshake message:"),
        "CLIENT_FINISHED": extract(flat, "Finished :", 36, "{client} construct a Finished handshake message:"),
        "DH_SHARED": extract(flat, "IKM :", 32, '{server} extract secret "handshake":'),
    }
    assert raw["CLIENT_HELLO"].startswith("01"), "CH 首字节"
    assert raw["SERVER_HELLO"].startswith("02"), "SH 首字节"
    assert raw["ENCRYPTED_EXTENSIONS"].startswith("08"), "EE 首字节"
    assert raw["CERTIFICATE"].startswith("0b"), "Cert 首字节"
    assert raw["CERTIFICATE_VERIFY"].startswith("0f"), "CV 首字节"
    assert raw["SERVER_FINISHED"].startswith("140000209b"), "第一条 Finished 应为 server 的"
    assert raw["CLIENT_FINISHED"].startswith("14000020a8"), "第二条 Finished 应为 client 的"

    # ---- RFC 标注真值（第二遍独立提取）----
    expected = {
        "EARLY": extract(flat, "secret :", 32, '{server} extract secret "early":'),
        "HANDSHAKE_SECRET": extract(flat, "secret :", 32, '{server} extract secret "handshake":'),
        "DERIVED_HANDSHAKE": extract(flat, "expanded :", 32, 'derive secret for handshake "tls13 derived":'),
        "CLIENT_HS_TRAFFIC": extract(flat, "expanded :", 32, 'derive secret "tls13 c hs traffic":'),
        "SERVER_HS_TRAFFIC": extract(flat, "expanded :", 32, 'derive secret "tls13 s hs traffic":'),
        "DERIVED_MASTER": extract(flat, "expanded :", 32, 'derive secret for master "tls13 derived":'),
        "MASTER_SECRET": extract(flat, "secret :", 32, '{server} extract secret "master":'),
        "SERVER_FINISHED_KEY": extract(flat, "expanded :", 32, '{server} calculate finished "tls13 finished":'),
        "SERVER_VERIFY_DATA": extract(flat, "finished :", 32, '{server} calculate finished "tls13 finished":'),
        "CLIENT_FINISHED_KEY": extract(flat, "expanded :", 32, '{client} calculate finished "tls13 finished":'),
        "CLIENT_VERIFY_DATA": extract(flat, "finished :", 32, '{client} calculate finished "tls13 finished":'),
        "CLIENT_AP_TRAFFIC": extract(flat, "expanded :", 32, 'derive secret "tls13 c ap traffic":'),
        "SERVER_AP_TRAFFIC": extract(flat, "expanded :", 32, 'derive secret "tls13 s ap traffic":'),
        "EXPORTER_MASTER": extract(flat, "expanded :", 32, 'derive secret "tls13 exp master":'),
        "RESUMPTION_MASTER": extract(flat, "expanded :", 32, 'derive secret "tls13 res master":'),
        "RESUMPTION_SECRET": extract(flat, "expanded :", 32, 'generate resumption secret "tls13 resumption":'),
        "SERVER_HS_KEY": extract(flat, "key expanded :", 16, "{server} derive write traffic keys for handshake data:"),
        "SERVER_HS_IV": extract(flat, "iv expanded :", 12, "{server} derive write traffic keys for handshake data:"),
        "SERVER_AP_KEY": extract(flat, "key expanded :", 16, "{server} derive write traffic keys for application data:"),
        "SERVER_AP_IV": extract(flat, "iv expanded :", 12, "{server} derive write traffic keys for application data:"),
        "CLIENT_HS_KEY": extract(flat, "key expanded :", 16, "{server} derive read traffic keys for handshake data:"),
        "CLIENT_HS_IV": extract(flat, "iv expanded :", 12, "{server} derive read traffic keys for handshake data:"),
        "CLIENT_AP_KEY": extract(flat, "key expanded :", 16, "{client} derive write traffic keys for application data:"),
        "CLIENT_AP_IV": extract(flat, "iv expanded :", 12, "{client} derive write traffic keys for application data:"),
    }
    # transcript hash 标注（RFC 在各 derive secret 块中的 hash 行）
    expected["TH_SERVER_HELLO"] = extract(flat, "hash :", 32, 'derive secret "tls13 c hs traffic":')
    expected["TH_APPLICATION"] = extract(flat, "hash :", 32, 'derive secret "tls13 c ap traffic":')
    expected["TH_RESUMPTION"] = extract(flat, "hash :", 32, 'derive secret "tls13 res master":')
    # Expand-Label 的 info 构造校验（用 c hs traffic 的 54 字节 info 标注）
    info_annotated = extract(flat, "info :", 54, 'derive secret "tls13 c hs traffic":')

    # ---- Python 独立复算（第二意见）----
    b = {k: bytes.fromhex(h) for k, h in raw.items()}
    zero32 = bytes(32)
    empty_hash = H(b"")
    m_prefix = (b["CLIENT_HELLO"] + b["SERVER_HELLO"] + b["ENCRYPTED_EXTENSIONS"]
                + b["CERTIFICATE"] + b["CERTIFICATE_VERIFY"])
    th_sh = H(b["CLIENT_HELLO"] + b["SERVER_HELLO"])
    th_cv = H(m_prefix)
    th_sf = H(m_prefix + b["SERVER_FINISHED"])
    th_res = H(m_prefix + b["SERVER_FINISHED"] + b["CLIENT_FINISHED"])

    early = Extract(zero32, zero32)
    derived1 = ExpLabel(early, "derived", bytes.fromhex(empty_hash), 32)
    hs = Extract(derived1, b["DH_SHARED"])
    c_hs = ExpLabel(hs, "c hs traffic", bytes.fromhex(th_sh), 32)
    s_hs = ExpLabel(hs, "s hs traffic", bytes.fromhex(th_sh), 32)
    derived2 = ExpLabel(hs, "derived", bytes.fromhex(empty_hash), 32)
    master = Extract(derived2, zero32)
    fk_s = ExpLabel(s_hs, "finished", b"", 32)
    fk_c = ExpLabel(c_hs, "finished", b"", 32)
    c_ap = ExpLabel(master, "c ap traffic", bytes.fromhex(th_sf), 32)
    s_ap = ExpLabel(master, "s ap traffic", bytes.fromhex(th_sf), 32)
    exp_master = ExpLabel(master, "exp master", bytes.fromhex(th_sf), 32)
    res_master = ExpLabel(master, "res master", bytes.fromhex(th_res), 32)
    resumption = ExpLabel(res_master, "resumption", b"\x00\x00", 32)

    computed = {
        "EARLY": early.hex(),
        "TH_SERVER_HELLO": th_sh,
        "DERIVED_HANDSHAKE": derived1.hex(),
        "HANDSHAKE_SECRET": hs.hex(),
        "CLIENT_HS_TRAFFIC": c_hs.hex(),
        "SERVER_HS_TRAFFIC": s_hs.hex(),
        "DERIVED_MASTER": derived2.hex(),
        "MASTER_SECRET": master.hex(),
        "SERVER_FINISHED_KEY": fk_s.hex(),
        "SERVER_VERIFY_DATA": Hmac(fk_s, bytes.fromhex(th_cv)),
        "CLIENT_FINISHED_KEY": fk_c.hex(),
        "CLIENT_VERIFY_DATA": Hmac(fk_c, bytes.fromhex(th_sf)),
        "TH_APPLICATION": th_sf,
        "CLIENT_AP_TRAFFIC": c_ap.hex(),
        "SERVER_AP_TRAFFIC": s_ap.hex(),
        "EXPORTER_MASTER": exp_master.hex(),
        "TH_RESUMPTION": th_res,
        "RESUMPTION_MASTER": res_master.hex(),
        "RESUMPTION_SECRET": resumption.hex(),
        "SERVER_HS_KEY": ExpLabel(s_hs, "key", b"", 16).hex(),
        "SERVER_HS_IV": ExpLabel(s_hs, "iv", b"", 12).hex(),
        "SERVER_AP_KEY": ExpLabel(s_ap, "key", b"", 16).hex(),
        "SERVER_AP_IV": ExpLabel(s_ap, "iv", b"", 12).hex(),
        "CLIENT_HS_KEY": ExpLabel(c_hs, "key", b"", 16).hex(),
        "CLIENT_HS_IV": ExpLabel(c_hs, "iv", b"", 12).hex(),
        "CLIENT_AP_KEY": ExpLabel(c_ap, "key", b"", 16).hex(),
        "CLIENT_AP_IV": ExpLabel(c_ap, "iv", b"", 12).hex(),
    }

    # Expand-Label info 构造与 RFC info 标注逐字节比对
    my_info = build_info("c hs traffic", bytes.fromhex(th_sh), 32).hex()
    assert my_info == info_annotated, f"info 构造不符\n  mine: {my_info}\n  rfc:  {info_annotated}"

    failed = [(k, computed[k], expected[k]) for k in computed if computed[k] != expected[k]]
    print(f"{'CHECK':22s} python-recomputed vs rfc-annotated")
    for k in computed:
        ok = "OK  " if computed[k] == expected[k] else "FAIL"
        print(f"{ok} {k:22s} {computed[k][:32]}{'...' if len(computed[k]) > 32 else ''}")
    if failed:
        for k, got, exp in failed:
            print(f"\nMISMATCH {k}\n  computed: {got}\n  rfc:      {exp}")
        sys.exit(1)

    # ---- 生成 Rust 测试 ----
    all_hex = dict(raw)
    all_hex.update(computed)
    lines = []
    lines.append('//! RFC 8448 §3「Simple 1-RTT Handshake」密钥调度全链验证（M7）。')
    lines.append('//!')
    lines.append('//! 以 RFC 8448 官方轨迹为外部真值，逐级复算 TLS 1.3 密钥调度：X25519')
    lines.append('//! 共享秘密 → HKDF-Extract / Expand-Label → traffic secrets → Finished')
    lines.append('//! verify_data → record 层 traffic keys → resumption。全部字节常量由')
    lines.append('//! `tools/extract_rfc8448.py` 从 rfc-editor.org 官方文本程序化提取')
    lines.append('//! （AGENTS.md 规则 7，禁止人工转录），生成时脚本用 Python 独立复算了')
    lines.append('//! 全部中间值并与 RFC 标注逐字节比对通过。覆盖 `ecdh::x25519`、')
    lines.append('//! `sha2::Sha256`、`hmac::HmacSha256`、`hkdf::{extract_sha256,')
    lines.append('//! expand_sha256}`。')
    lines.append('//!')
    lines.append('//! 说明：rustls 的 ServerHello random / ClientHello 扩展集无法在')
    lines.append('//! provider 层注入，完整记录级字节重放不可行（ROADMAP M7 注记）；本')
    lines.append('//! 测试把轨迹中 provider 负责的部分（KDF 栈 + ECDH）按外部真值逐字节')
    lines.append('//! 锚定，transcript 编码部分由 ring 交叉互操作测试（interop）锚定。')
    lines.append('')
    lines.append('mod common;')
    lines.append('')
    lines.append('use common::{assert_hex, hex};')
    lines.append('use ferritls_core::{ecdh::x25519, hkdf, hmac, sha2};')
    lines.append('')
    lines.append('#[rustfmt::skip]')
    lines.append('mod rfc8448 {')
    lines.append('    //! 官方轨迹常量：名称 → 小写十六进制（见 tools/extract_rfc8448.py）。')
    lines.append('    pub(super) const _DOC: &str = "generated; do not edit by hand";')
    for k, v in all_hex.items():
        chunks = [v[i:i + 64] for i in range(0, len(v), 64)]
        if len(chunks) == 1:
            lines.append(f'    pub(super) const {k}: &str = "{chunks[0]}";')
        else:
            body = "\n        ".join(f'"{c}",' for c in chunks)
            lines.append(f'    pub(super) const {k}: &str = concat!(')
            lines.append(f'        {body}')
            lines.append('    );')
    lines.append('}')
    lines.append('')
    lines.append('use rfc8448::*;')
    lines.append('')
    lines.append('fn sha256(parts: &[&[u8]]) -> [u8; 32] {')
    lines.append('    let mut h = sha2::Sha256::new();')
    lines.append('    for p in parts {')
    lines.append('        h.update(p);')
    lines.append('    }')
    lines.append('    h.finalize()')
    lines.append('}')
    lines.append('')
    lines.append('/// TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）。label 与 context 都是')
    lines.append('/// 带 1 字节长度前缀的向量：')
    lines.append('/// info = uint16(len) || uint8(len) || "tls13 " || label || uint8(ctx_len) || ctx')
    lines.append('fn expand_label(prk: &[u8], label: &str, context_hash: &[u8], out_len: usize) -> Vec<u8> {')
    lines.append('    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context_hash.len());')
    lines.append('    info.extend_from_slice(&(out_len as u16).to_be_bytes());')
    lines.append('    info.push((6 + label.len()) as u8);')
    lines.append('    info.extend_from_slice(b"tls13 ");')
    lines.append('    info.extend_from_slice(label.as_bytes());')
    lines.append('    info.push(context_hash.len() as u8);')
    lines.append('    info.extend_from_slice(context_hash);')
    lines.append('    let mut okm = vec![0u8; out_len];')
    lines.append('    hkdf::expand_sha256(prk, &info, &mut okm);')
    lines.append('    okm')
    lines.append('}')
    lines.append('')
    lines.append('/// 密钥调度前半段：early → derived → handshake secret（各测试复用）。')
    lines.append('fn handshake_secret() -> [u8; 32] {')
    lines.append('    let zero32 = [0u8; 32];')
    lines.append('    let empty_hash = sha256(&[]);')
    lines.append('    let early = hkdf::extract_sha256(&zero32, &zero32);')
    lines.append('    assert_hex(&early, EARLY, "early secret");')
    lines.append('    let derived = expand_label(&early, "derived", &empty_hash, 32);')
    lines.append('    assert_hex(&derived, DERIVED_HANDSHAKE, "derived (handshake)");')
    lines.append('    let hs = hkdf::extract_sha256(&derived, &hex(DH_SHARED));')
    lines.append('    assert_hex(&hs, HANDSHAKE_SECRET, "handshake secret");')
    lines.append('    hs')
    lines.append('}')
    lines.append('')
    lines.append('#[test]')
    lines.append('fn x25519_shared_secret_matches_rfc8448() {')
    lines.append('    let client = x25519::SecretKey::from_seed(hex(CLIENT_PRIV).try_into().unwrap());')
    lines.append('    let server = x25519::SecretKey::from_seed(hex(SERVER_PRIV).try_into().unwrap());')
    lines.append('    assert_hex(&client.public_key(), CLIENT_PUB, "client public key");')
    lines.append('    assert_hex(&server.public_key(), SERVER_PUB, "server public key");')
    lines.append('    let c2s = client.diffie_hellman(&hex(SERVER_PUB)).expect("client side dh");')
    lines.append('    let s2c = server.diffie_hellman(&hex(CLIENT_PUB)).expect("server side dh");')
    lines.append('    assert_hex(c2s.as_bytes(), DH_SHARED, "dh shared (client view)");')
    lines.append('    assert_hex(s2c.as_bytes(), DH_SHARED, "dh shared (server view)");')
    lines.append('}')
    lines.append('')
    lines.append('#[test]')
    lines.append('fn traffic_secrets_match_rfc8448() {')
    lines.append('    let hs = handshake_secret();')
    lines.append('    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);')
    lines.append('    assert_hex(&th_sh, TH_SERVER_HELLO, "transcript hash CH..SH");')
    lines.append('    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);')
    lines.append('    assert_hex(&c_hs, CLIENT_HS_TRAFFIC, "client hs traffic secret");')
    lines.append('    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);')
    lines.append('    assert_hex(&s_hs, SERVER_HS_TRAFFIC, "server hs traffic secret");')
    lines.append('    let empty_hash = sha256(&[]);')
    lines.append('    let derived_master = expand_label(&hs, "derived", &empty_hash, 32);')
    lines.append('    assert_hex(&derived_master, DERIVED_MASTER, "derived (master)");')
    lines.append('    let zero32 = [0u8; 32];')
    lines.append('    let master = hkdf::extract_sha256(&derived_master, &zero32);')
    lines.append('    assert_hex(&master, MASTER_SECRET, "master secret");')
    lines.append('}')
    lines.append('')
    lines.append('#[test]')
    lines.append('fn finished_verify_data_matches_rfc8448() {')
    lines.append('    let hs = handshake_secret();')
    lines.append('    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);')
    lines.append('    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);')
    lines.append('    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);')
    lines.append('')
    lines.append('    // server Finished：finished_key = Expand-Label(s_hs, "finished", "", 32)，')
    lines.append('    // verify_data = HMAC(finished_key, Transcript-Hash(CH..CV))。')
    lines.append('    let th_cv = sha256(&[')
    lines.append('        &hex(CLIENT_HELLO),')
    lines.append('        &hex(SERVER_HELLO),')
    lines.append('        &hex(ENCRYPTED_EXTENSIONS),')
    lines.append('        &hex(CERTIFICATE),')
    lines.append('        &hex(CERTIFICATE_VERIFY),')
    lines.append('    ]);')
    lines.append('    let fk_s = expand_label(&s_hs, "finished", &[], 32);')
    lines.append('    assert_hex(&fk_s, SERVER_FINISHED_KEY, "server finished_key");')
    lines.append('    let vd_s = hmac::HmacSha256::one_shot(&fk_s, &th_cv);')
    lines.append('    assert_hex(&vd_s, SERVER_VERIFY_DATA, "server verify_data");')
    lines.append('')
    lines.append('    // client Finished：transcript 到 server Finished 为止。')
    lines.append('    let th_sf = sha256(&[')
    lines.append('        &hex(CLIENT_HELLO),')
    lines.append('        &hex(SERVER_HELLO),')
    lines.append('        &hex(ENCRYPTED_EXTENSIONS),')
    lines.append('        &hex(CERTIFICATE),')
    lines.append('        &hex(CERTIFICATE_VERIFY),')
    lines.append('        &hex(SERVER_FINISHED),')
    lines.append('    ]);')
    lines.append('    assert_hex(&th_sf, TH_APPLICATION, "transcript hash CH..SFin");')
    lines.append('    let fk_c = expand_label(&c_hs, "finished", &[], 32);')
    lines.append('    assert_hex(&fk_c, CLIENT_FINISHED_KEY, "client finished_key");')
    lines.append('    let vd_c = hmac::HmacSha256::one_shot(&fk_c, &th_sf);')
    lines.append('    assert_hex(&vd_c, CLIENT_VERIFY_DATA, "client verify_data");')
    lines.append('}')
    lines.append('')
    lines.append('#[test]')
    lines.append('fn application_secrets_and_traffic_keys_match_rfc8448() {')
    lines.append('    let hs = handshake_secret();')
    lines.append('    let empty_hash = sha256(&[]);')
    lines.append('    let zero32 = [0u8; 32];')
    lines.append('    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);')
    lines.append('    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);')
    lines.append('    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);')
    lines.append('    let master = hkdf::extract_sha256(&expand_label(&hs, "derived", &empty_hash, 32), &zero32);')
    lines.append('')
    lines.append('    // 应用流量秘密（transcript 到 server Finished）。')
    lines.append('    let th_app = sha256(&[')
    lines.append('        &hex(CLIENT_HELLO),')
    lines.append('        &hex(SERVER_HELLO),')
    lines.append('        &hex(ENCRYPTED_EXTENSIONS),')
    lines.append('        &hex(CERTIFICATE),')
    lines.append('        &hex(CERTIFICATE_VERIFY),')
    lines.append('        &hex(SERVER_FINISHED),')
    lines.append('    ]);')
    lines.append('    let c_ap = expand_label(&master, "c ap traffic", &th_app, 32);')
    lines.append('    assert_hex(&c_ap, CLIENT_AP_TRAFFIC, "client ap traffic secret");')
    lines.append('    let s_ap = expand_label(&master, "s ap traffic", &th_app, 32);')
    lines.append('    assert_hex(&s_ap, SERVER_AP_TRAFFIC, "server ap traffic secret");')
    lines.append('    let exp_master = expand_label(&master, "exp master", &th_app, 32);')
    lines.append('    assert_hex(&exp_master, EXPORTER_MASTER, "exporter master secret");')
    lines.append('')
    lines.append('    // record 层 traffic keys（key/iv 展开的 transcript 上下文为空）。')
    lines.append('    assert_hex(&expand_label(&s_hs, "key", &[], 16), SERVER_HS_KEY, "server hs write key");')
    lines.append('    assert_hex(&expand_label(&s_hs, "iv", &[], 12), SERVER_HS_IV, "server hs write iv");')
    lines.append('    assert_hex(&expand_label(&c_hs, "key", &[], 16), CLIENT_HS_KEY, "client hs write key");')
    lines.append('    assert_hex(&expand_label(&c_hs, "iv", &[], 12), CLIENT_HS_IV, "client hs write iv");')
    lines.append('    assert_hex(&expand_label(&s_ap, "key", &[], 16), SERVER_AP_KEY, "server ap write key");')
    lines.append('    assert_hex(&expand_label(&s_ap, "iv", &[], 12), SERVER_AP_IV, "server ap write iv");')
    lines.append('    assert_hex(&expand_label(&c_ap, "key", &[], 16), CLIENT_AP_KEY, "client ap write key");')
    lines.append('    assert_hex(&expand_label(&c_ap, "iv", &[], 12), CLIENT_AP_IV, "client ap write iv");')
    lines.append('}')
    lines.append('')
    lines.append('#[test]')
    lines.append('fn resumption_master_matches_rfc8448() {')
    lines.append('    let hs = handshake_secret();')
    lines.append('    let empty_hash = sha256(&[]);')
    lines.append('    let zero32 = [0u8; 32];')
    lines.append('    let master = hkdf::extract_sha256(&expand_label(&hs, "derived", &empty_hash, 32), &zero32);')
    lines.append('')
    lines.append('    // resumption master：transcript 到 client Finished；ticket nonce = 00 00。')
    lines.append('    let th_res = sha256(&[')
    lines.append('        &hex(CLIENT_HELLO),')
    lines.append('        &hex(SERVER_HELLO),')
    lines.append('        &hex(ENCRYPTED_EXTENSIONS),')
    lines.append('        &hex(CERTIFICATE),')
    lines.append('        &hex(CERTIFICATE_VERIFY),')
    lines.append('        &hex(SERVER_FINISHED),')
    lines.append('        &hex(CLIENT_FINISHED),')
    lines.append('    ]);')
    lines.append('    assert_hex(&th_res, TH_RESUMPTION, "transcript hash CH..CFin");')
    lines.append('    let res_master = expand_label(&master, "res master", &th_res, 32);')
    lines.append('    assert_hex(&res_master, RESUMPTION_MASTER, "resumption master secret");')
    lines.append('    let resumption = expand_label(&res_master, "resumption", &[0x00, 0x00], 32);')
    lines.append('    assert_hex(&resumption, RESUMPTION_SECRET, "resumption secret");')
    lines.append('}')
    rs = "\n".join(lines) + "\n"
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(rs)
    print(f"\ninfo construction verified; wrote {out_path} ({len(rs)} bytes)")


if __name__ == "__main__":
    main()
