# 测试向量溯源（AGENTS.md 规则 7 的执行记录）

规则 7：测试向量启用前必须与官方文件逐字节核对；不得静默 unignore。
本文件登记各向量测试的官方来源与核对方式，供实验室审查与重新核对。

`tests/vectors/`（文件级溯源见该目录 README.md）之外，`crates/ferritls-core/tests/`
中的向量均为**人工录入但经官方向量核对**或**程序化提取**：

| 测试文件 | 官方来源 | 核对方式 |
|---|---|---|
| `sha2.rs` | FIPS 180-4 示例（"abc"/双块/百万字节 'a'）+ SHAVS 风格填充边界（55–129 字节 13 个转折长度） | 官方示例值逐字节核对；边界长度摘要经 python hashlib 与 OpenSSL 3.2.4 `dgst` 双工具交叉核对（2026-09-07） |
| `hmac.rs` | RFC 4231 测试用例 1–3 + TC6/TC7（131 字节超块长密钥，SHA-256/384/512 六值） | 逐字节核对（TC6/7 摘要折行片段与计算值精确匹配，另经 `openssl dgst -mac hmac` 独立复算） |
| `hkdf.rs` | RFC 5869 Appendix A（TC1–TC3） | 逐字节核对 |
| `aes_gcm.rs` | NIST GCMVS（原始文件核对后内联）+ McGrew–Viega 附录 B 边界用例（TC2–TC4 全零密钥/明文、54 字节 AAD 空明文） | .rsp 逐字段；TC2 期望值与官方原文一致，其余由经 TC1/TC5/TC16 官方锚值校验的独立参照实现生成（2026-09-07） |
| `chacha20poly1305.rs` | RFC 8439 §2.4.2 / §A.5 | 逐字节核对 |
| `ccm.rs` | RFC 3610 §8 官方分组向量**不含 M=16**：M=16 期望值由 python-cryptography（OpenSSL 后端）AESCCM 生成，该生成器先与 RFC 3610 §8 Packet Vector #1（M=8/L=2/含 AAD）官方原文逐字节核对通过（2026-09-07） | 生成器对官方文件逐字节锚定后派生 |
| `x25519.rs` | RFC 7748 §6.1 + §5.2 迭代测试 | 逐字节核对；迭代轮转方向经独立大整数实现验证 |
| `p256.rs` / `p384.rs`（ECDH） | RFC/标准 KAT + Wycheproof 锚点 | 双来源交叉 |
| `p256.rs` / `p384.rs`（ECDSA） | RFC 6979 A.2.5（P-256/SHA-256）、A.2.6（P-384/SHA-384） | 逐字节核对（含 DER 定长编码细节） |
| `ed25519.rs` | RFC 8032 §7（TEST1–TEST3、SHA(abc)、TEST 1024） | TEST 1024 消息/签名于 2026-09-07 从 RFC 原文提取；签名另经 python-cryptography 与 OpenSSL 3.2.4 两个独立实现复算一致 |
| `rsa_and_der.rs` | openssl CLI 交叉生成的自签材料 + NIST CAVP RSA 子集 | openssl 验证器互验 |
| `drbg.rs` | NIST DRBGVS（AES-256-CTR，无 DF；Instantiate→Reseed→Generate×2 官方流程） | .rsp + .txt 中间值（Key/V）核对 |
| `selftest.rs` | 上表 KAT 的汇编（实现一致性，无独立官方来源） | — |
| `schedule_rfc8448.rs` | RFC 8448 §3 官方轨迹 | **程序化提取**（tools/extract_rfc8448.py，脚本内含 Python 独立复算比对） |
| `wycheproof.rs` | C2SP/wycheproof testvectors_v1（裁剪入库） | 文件级入库，见 tests/vectors/README.md |

## 2026-09-07 修订说明

- CCM 行修正：早前表格声称的 NIST CCMVS 向量并未实际引入（CAVP 公开集
  无 M=16 参数集），本次以"官方向量校验过的独立参照实现"链路补齐，
  并暴露/修复了 CCM 四处规范偏差（B0 Adata 位、AAD 段独立补齐、
  CTR 计数器宽度、长度域静默截断），见 `tests/ccm.rs`。
- 新增 GCM 边界、HMAC 超长密钥、SHA-2 填充边界、Ed25519 TEST 1024、
  HKDF 前缀性质/超长拒绝等测试（非向量类自洽性质测试不入表）。

## 再核对指引

1. RFC 类：从 rfc-editor.org 取原文，比对测试常量。
2. CAVP/SHAVS/GCMVS/CCMVS/DRBGVS：NIST CSRC 官网下载 .rsp（注意部分
   文件仅经实验室通道分发时需 ACVP；公开静态集已足够核对内联值）。
3. RFC 8448：`tools/extract_rfc8448.py <rfc8448.txt>` 一键重提取并
   重新生成测试文件（生成器内含 Python 独立复算，输出确定）。
4. Wycheproof：`tools/trim_wycheproof.py`（策略见 tests/vectors/README.md）。
