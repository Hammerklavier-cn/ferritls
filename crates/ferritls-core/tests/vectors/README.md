# tests/vectors — 外部测试向量

本目录存放第三方官方测试向量（裁剪后），供 `tests/wycheproof.rs`、
`tests/sha2.rs` / `tests/sha3.rs`（`shs/`）、`tests/ccm.rs`（`ccm/`）与
`tests/attacker_corpus.rs`（`d2i/`、`corpus/`）消费。

## 来源与版本

- 上游：`C2SP/wycheproof`（`google/wycheproof` 迁移后的官方维护仓库），
  `testvectors_v1/` 目录。
- 引入时上游提交：`3fa63dd0344abb611f1fb1d77e119938603ea230`（main，2026-09 抓取）。
- 2026-11-05 增量：C2SP/wycheproof **master 快照**（tarball SHA-256
  `33f8042214bc36a0133356285c1a44900b4093389609aa6d43ad968a7090bd83`），
  仅新增 hmac/hkdf/ccm/RSA 扩展 15 文件，既有 10 文件未触碰。
- 每个文件内保留 `"header"` / `"notes"` / `"source"`，可对照 flags 语义。

## 裁剪策略（tools/trim_wycheproof.py）

- **保留全部 `invalid` / `acceptable` 用例**——对抗性内容是引入它们的目的
  （攻击者可控输入不 panic、严格编码拒绝的机器化验证）；
- `valid` 用例确定性抽样（默认 1/4；P-384 ECDH 的 EdgeCaseDoubling 重复组 1/8）；
- 剥离用不到的字段（PEM/JWK/PKCS8、RSA 私钥族）；ECDSA 只留未压缩公钥点；
- **例外**：hmac/hkdf/ccm/pss_misc 为小文件按 1:1 全量保留（`ratio = 1`）；
  `rsa_pkcs1_*_sig_gen` 需保留 `privateKeyPkcs8`（签名侧 KAT）并按均衡
  素数 CRT 形状过滤（非均衡拆分超出本实现 CRT limb 形状约束）。

体积 2.8 MB → 1.1 MB（3686 → 2349 用例，2026-09）；2026-11 增量 +2014
用例（见下表）。重新生成：先用 `trim_wycheproof.py` 头部注释中的地址
下载原始 JSON，再运行脚本（裁剪规则确定，输出可复现；**只传新文件名
做增量，勿全量再生成**——既有文件钉住 2026-09 上游快照）。

## 文件清单

| 文件 | 算法 | 用例数 |
|---|---|---|
| `ecdh_secp256r1_ecpoint_test.json` | ECDH P-256（裸 SEC1 点编码） | 108 |
| `ecdh_secp384r1_ecpoint_test.json` | ECDH P-384（裸 SEC1 点编码） | 116 |
| `x25519_test.json` | X25519 | 320 |
| `ecdsa_secp256r1_sha256_test.json` | ECDSA P-256/SHA-256 验证 | 422 |
| `ecdsa_secp384r1_sha384_test.json` | ECDSA P-384/SHA-384 验证 | 422 |
| `ed25519_test.json` | Ed25519 验证 | 139 |
| `rsa_signature_2048_sha{256,384,512}_test.json` | RSA PKCS#1 v1.5 验证 | 254/253/254 |
| `rsa_pss_2048_sha256_mgf1_32_test.json` | RSA-PSS 验证 | 61 |
| `aes_gcm_test.json` | AES-128/256-GCM seal/open | 74 |
| `chacha20_poly1305_test.json` | ChaCha20-Poly1305 seal/open | 124 |
| `hmac_sha{256,384,512}_test.json`（2026-11） | HMAC（MacTest；keySize 短/摘要长/520 bit=block+1 × tagSize 半/全） | 174×3 |
| `hkdf_sha{256,384,512}_test.json`（2026-11） | HKDF（invalid = size 恰为 255·HashLen+1） | 86/83/83 |
| `aes_ccm_test.json`（2026-11） | AES-128-CCM（keySize=128 全组；nonce/tag 越界组作参数拒绝负例） | 184 |
| `rsa_signature_{3072,4096}_sha{256,384}_test.json`（2026-11） | RSA PKCS#1 v1.5 验证（大模数） | 254/254/253/254 |
| `rsa_pss_misc_test.json`（2026-11） | RSA-PSS 参数变体（mgfSha==sha × SHA-2 族；盐长 0/20/28/32/48/64 全变体） | 18 |
| `rsa_pkcs1_{2048,3072,4096}_sig_gen_test.json`（2026-11） | RSA PKCS#1 v1.5 **签名侧** KAT | 6/6/6 |

注意：不引入 `rsa_pkcs1_2048_test.json`（那是 RSAES **解密**向量；本项目
不做 RSA 解密）。ECDH 用 `*_ecpoint` 变体（`public` 为 `04‖X‖Y` 裸点，
与本实现的 API 输入一致；`asn` 变体是 SPKI 编码）。两个 AEAD 文件按
参数空间裁组：只保留 nonce-96/tag-128（GCM 另限 AES-128/256）——非此
参数空间的组（非 96 位 IV 的 GHASH 型 J0 派生、AES-192、截断标签）不在
本实现 API 面内，由 `trim_wycheproof.py` 的组过滤器裁掉并在驱动里断言。
AEAD 入库（2026-10）填补了 AEAD 领域此前仅有手写 tamper 用例的空白；
逐字段核对脚本对上游原文全量比对通过（198/198）。
CCM 文件（2026-11）相反地**保留**越界参数组（nonce 非 7..13、tag 非
4..16 偶数）作参数拒绝负例——CCM 的 nonce/tag 是运行时参数，正是
API 面内的拒绝路径。

## 子目录

| 目录 | 来源 | 消费者 |
|---|---|---|
| `shs/`（2026-11） | NIST CAVP SHAVS/SHA3VS 字节导向官方 zip（SHA-2/SHA-3 LongMsg+Monte、SHAKE LongMsg；zip SHA-256 记于 docs/VECTOR-PROVENANCE.md），tools/extract_shavs.py 提取（hashlib 全量复算核对） | `tests/sha2.rs` / `tests/sha3.rs` |
| `ccm/`（2026-11） | NIST SP800-38C CAVS 经 OpenSSL master 转载，tools/extract_ccmvs.py 提取 | `tests/ccm.rs` |
| `d2i/`（2026-11） | OpenSSL master `test/d2i-tests/` 10 文件（Apache-2.0；CVE 回归 + 非最小 INTEGER + 高 tag 号） | `tests/attacker_corpus.rs` |
| `corpus/`（2026-11） | BoringSSL master fuzz corpus 精选 31 文件（ISC/dual；LibFuzzer 演化语料；逐文件钉住解析结果） | `tests/attacker_corpus.rs` |
