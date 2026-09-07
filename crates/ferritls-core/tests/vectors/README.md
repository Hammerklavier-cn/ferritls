# tests/vectors — 外部测试向量

本目录存放第三方官方测试向量（裁剪后），供 `tests/wycheproof.rs` 消费。

## 来源与版本

- 上游：`C2SP/wycheproof`（`google/wycheproof` 迁移后的官方维护仓库），
  `testvectors_v1/` 目录。
- 引入时上游提交：`3fa63dd0344abb611f1fb1d77e119938603ea230`（main，2026-09 抓取）。
- 每个文件内保留 `"header"` / `"notes"` / `"source"`，可对照 flags 语义。

## 裁剪策略（tools/trim_wycheproof.py）

- **保留全部 `invalid` / `acceptable` 用例**——对抗性内容是引入它们的目的
  （攻击者可控输入不 panic、严格编码拒绝的机器化验证）；
- `valid` 用例确定性抽样（默认 1/4；P-384 ECDH 的 EdgeCaseDoubling 重复组 1/8）；
- 剥离用不到的字段（PEM/JWK/PKCS8、RSA 私钥族）；ECDSA 只留未压缩公钥点。

体积 2.8 MB → 1.1 MB（3686 → 2349 用例）。重新生成：先用 `trim_wycheproof.py`
头部注释中的地址下载原始 JSON，再运行脚本（裁剪规则确定，输出可复现）。

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

注意：不引入 `rsa_pkcs1_2048_test.json`（那是 RSAES **解密**向量；本项目
不做 RSA 解密）。ECDH 用 `*_ecpoint` 变体（`public` 为 `04‖X‖Y` 裸点，
与本实现的 API 输入一致；`asn` 变体是 SPKI 编码）。
