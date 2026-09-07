# 测试向量溯源（AGENTS.md 规则 7 的执行记录）

规则 7：测试向量启用前必须与官方文件逐字节核对；不得静默 unignore。
本文件登记各向量测试的官方来源与核对方式，供实验室审查与重新核对。

`tests/vectors/`（文件级溯源见该目录 README.md）之外，`crates/ferritls-core/tests/`
中的向量均为**人工录入但经官方向量核对**或**程序化提取**：

| 测试文件 | 官方来源 | 核对方式 |
|---|---|---|
| `sha2.rs` | FIPS 180-4 示例 + NIST SHAVS（Short/Long/Monte Carlo 子集） | 官方 .rsp 逐字段核对 |
| `hmac.rs` | RFC 4231 测试用例 1–2 | 逐字节核对 |
| `hkdf.rs` | RFC 5869 Appendix A（TC1–TC3） | 逐字节核对 |
| `aes_gcm.rs` | NIST GCMVS（原始文件核对后内联） | .rsp 的 key/iv/pt/aad/ct/tag 逐字段 |
| `chacha20poly1305.rs` | RFC 8439 §2.4.2 / §A.5 | 逐字节核对 |
| `ccm`（aes_gcm.rs 内） | NIST CCMVS（L=2/L=3 参数集） | .rsp 逐字段 |
| `x25519.rs` | RFC 7748 §6.1 + §5.2 迭代测试 | 逐字节核对；迭代轮转方向经独立大整数实现验证 |
| `p256.rs` / `p384.rs`（ECDH） | RFC/标准 KAT + Wycheproof 锚点 | 双来源交叉 |
| `p256.rs` / `p384.rs`（ECDSA） | RFC 6979 A.2.5（P-256/SHA-256）、A.2.6（P-384/SHA-384） | 逐字节核对（含 DER 定长编码细节） |
| `ed25519.rs` | RFC 8032 §7（TEST1–TEST3、SHA(abc)） | 逐字节核对 |
| `rsa_and_der.rs` | openssl CLI 交叉生成的自签材料 + NIST CAVP RSA 子集 | openssl 验证器互验 |
| `drbg.rs` | NIST DRBGVS（AES-256-CTR，无 DF；Instantiate→Reseed→Generate×2 官方流程） | .rsp + .txt 中间值（Key/V）核对 |
| `selftest.rs` | 上表 KAT 的汇编（实现一致性，无独立官方来源） | — |
| `schedule_rfc8448.rs` | RFC 8448 §3 官方轨迹 | **程序化提取**（tools/extract_rfc8448.py，脚本内含 Python 独立复算比对） |
| `wycheproof.rs` | C2SP/wycheproof testvectors_v1（裁剪入库） | 文件级入库，见 tests/vectors/README.md |

## 再核对指引

1. RFC 类：从 rfc-editor.org 取原文，比对测试常量。
2. CAVP/SHAVS/GCMVS/CCMVS/DRBGVS：NIST CSRC 官网下载 .rsp（注意部分
   文件仅经实验室通道分发时需 ACVP；公开静态集已足够核对内联值）。
3. RFC 8448：`tools/extract_rfc8448.py <rfc8448.txt>` 一键重提取并
   重新生成测试文件（生成器内含 Python 独立复算，输出确定）。
4. Wycheproof：`tools/trim_wycheproof.py`（策略见 tests/vectors/README.md）。
