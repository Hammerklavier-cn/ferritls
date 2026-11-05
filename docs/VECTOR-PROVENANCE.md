# 测试向量溯源（AGENTS.md 规则 7 的执行记录）

规则 7：测试向量启用前必须与官方文件逐字节核对；不得静默 unignore。
本文件登记各向量测试的官方来源与核对方式，供实验室审查与重新核对。

`tests/vectors/`（文件级溯源见该目录 README.md）之外，`crates/ferritls-core/tests/`
中的向量均为**人工录入但经官方向量核对**或**程序化提取**：

| 测试文件 | 官方来源 | 核对方式 |
|---|---|---|
| `sha2.rs` | FIPS 180-4 示例（"abc"/双块/百万字节 'a'）+ SHAVS 风格填充边界（55–129 字节 13 个转折长度） | 官方示例值逐字节核对；边界长度摘要经 python hashlib 与 OpenSSL 3.2.4 `dgst` 双工具交叉核对（2026-09-07） |
| `hmac.rs` | RFC 4231 测试用例 1–3 + TC6/TC7（131 字节超块长密钥，SHA-256/384/512 六值） | 逐字节核对（TC6/7 摘要折行片段与计算值精确匹配，另经 `openssl dgst -mac hmac` 独立复算） |
| `hkdf.rs` | RFC 5869 Appendix A（TC1–TC3，SHA-256）；SHA-384/512 无官方用例——期望值由双参照链生成互验 | SHA-256 逐字节核对；SHA-384/512 由纯 python RFC 5869 参照实现与 python-cryptography（OpenSSL 后端）HKDF 两链独立计算并比对一致（2026-09-17） |
| `aes_gcm.rs` | NIST GCMVS（原始文件核对后内联）+ McGrew–Viega 附录 B 边界用例（TC2–TC4 全零密钥/明文、54 字节 AAD 空明文） | .rsp 逐字段；TC2 期望值与官方原文一致，其余由经 TC1/TC5/TC16 官方锚值校验的独立参照实现生成（2026-09-07） |
| `chacha20poly1305.rs` | RFC 8439 §2.4.2 / §A.5 | 逐字节核对 |
| `ccm.rs` | **RFC 3610 §8 官方分组向量全部 24 个**（M=8/L=2 与 M=10/L=2，2026-09-17 程序化提取自 rfc-editor.org 原文，python-cryptography 双向复算后生成测试表直跑）；另全 M 矩阵与既有 M=16 参数集（RFC 无 M=16/L=3 官方向量）：期望值由 python-cryptography（OpenSSL 后端）AESCCM 生成——该生成器先与 RFC 3610 §8 原文逐字节校验通过（2026-09-07 建 M=16，2026-09-17 扩全 M 并与 M=16 旧值互验） | 官方 24 向量程序化提取 + 参照实现双向复算；派生向量经「生成器对官方文件逐字节锚定」链路（见 tests/ccm.rs 文件头） |
| `x25519.rs` | RFC 7748 §6.1 + §5.2 迭代测试 | 逐字节核对；迭代轮转方向经独立大整数实现验证 |
| `p256.rs` / `p384.rs`（ECDH） | RFC/标准 KAT + Wycheproof 锚点 | 双来源交叉 |
| `p256.rs` / `p384.rs`（ECDSA） | RFC 6979 A.2.5（P-256/SHA-256）、A.2.6（P-384/SHA-384） | 逐字节核对（含 DER 定长编码细节） |
| `ed25519.rs` | RFC 8032 §7（TEST1–TEST3、SHA(abc)、TEST 1024） | TEST 1024 消息/签名于 2026-09-07 从 RFC 原文提取；签名另经 python-cryptography 与 OpenSSL 3.2.4 两个独立实现复算一致 |
| `rsa_and_der.rs` | openssl CLI 交叉生成的自签材料 + NIST CAVP RSA 子集 | openssl 验证器互验 |
| `drbg.rs` | NIST DRBGVS（AES-256-CTR，无 DF；Instantiate→Reseed→Generate×2 官方流程） | .rsp + .txt 中间值（Key/V）核对 |
| `sha3.rs` | FIPS 202 示例（空串/"abc"/448·896 位填充边界/多块消息的 SHA3-256/512 与 SHAKE128/256 输出）+ FIPS 203 附录 A 的 G/H/J/PRF/XOF 示例值（"Input to an invocation of …" 固定输入） | 官方示例值逐字节核对（2026-09-13）；附录 A 值另经 RustCrypto `ml-kem`（ACVP 全绿实现）`crypto.rs` 测试常量交叉核对 |
| `sha3.rs`（224/384，2026-09-17 补全） | FIPS 202 全家族的 Keccak 团队公布示例（SHA3-224/384 的空串与 "abc"）+ 同文件 448/896 位标准消息 | "abc"/空串与 Keccak 团队公布值逐字节比对一致；四组均经 python hashlib（OpenSSL 后端）独立复算；selftest 新增 SHA3-224/256/384/512 KAT（"abc"，同源值） |
| `mlkem.rs` | **NIST ACVP-Server** `gen-val/json-files/ML-KEM-keyGen-FIPS203` 与 `ML-KEM-encapDecap-FIPS203` 的 `internalProjection.json` 原件，**三参数集**（M8.4，2026-09-15 提取；NIST 上游 2026-09 重生成了 sample 向量，与 M8.3 所用 RustCrypto/KEMs 镜像快照 commit 65370b8 不同代——768 两代互验一致，算法为确定性锚定）：每集 keyGen 3 例（d,z→ek,dk，含 dk 解析校验）+ 封装 3 例（ek,m→c,ss）+ 解封装 2 valid + 1 "modified ciphertext"（隐式拒绝）+ KeyCheck 负例（encapsulationKeyCheck 模校验 / decapsulationKeyCheck h 校验，各含官方 valid 对照）；另 `mlkem.rs` 内置 KAT 三集（selftest，同源五元组） | **程序化提取**（tools/extract_mlkem_acvp.py，从官方 JSON 逐字段转写；子集选择确定）；文件 SHA-256 与获取日期记录于生成文件头（2026-09-15） |
| `selftest.rs` | 上表 KAT 的汇编（实现一致性，无独立官方来源） | —；2026-10 扩充的四个 KAT 的锚定：AES-256-GCM = GCM 规范 Test Case 14（CT/TAG 经 python-cryptography（OpenSSL 后端）独立复算一致）；HKDF-SHA-384 = `hkdf.rs` 双参照链同源值；ECDSA P-384 = RFC 6979 A.2.6（与 `p384.rs` 同源，DER 由 r/s 经脚本构造）；RSA-PSS = 实现生成一次后经 `openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32` 验证锚定（盐随机，签名方向无法逐字节锚定，故 KAT 走验证方向 + 篡改拒绝 + 自产签名往返） |
| `schedule_rfc8448.rs` | RFC 8448 §3 官方轨迹 | **程序化提取**（tools/extract_rfc8448.py，脚本内含 Python 独立复算比对） |
| `wycheproof.rs` | C2SP/wycheproof testvectors_v1（裁剪入库） | 文件级入库，见 tests/vectors/README.md；AEAD 两文件（aes_gcm/chacha20_poly1305，2026-10 入库）按参数空间裁组后与上游原文逐字段核对 198/198 |
| `ferritls-rustls/src/quic_vectors.rs`（M8.5） | **RFC 9001 附录 A 原文**（rfc-editor.org，2026-09-15 下载）：§A.1 密钥与掩码（client/server hp + sample→mask）、§A.2 客户端 Initial 完整包（AES-128-GCM，1162 B 载荷 = 245 B CRYPTO 帧 + 917 B 零 PADDING，1200 B 受保护包）、§A.3 服务端 Initial 完整包（99 B 载荷，135 B 受保护包）、§A.5 ChaCha20 短头包（key/iv/hp/sample/mask/最终 21 B 包）；另 picoquic `multipath_test.c` 经 rustls 测试转引的 multipath 向量因 rustls `KeyBuilder` 为 `pub(crate)`（第三方无法从 secret 经公开 API 重建 PacketKey）**未采用**，`for_path` 以 rustls 公开 `Nonce::for_path` 同式 + 往返/非碰撞测试覆盖 | **程序化提取 + 派生关系校验**（python 脚本从 RFC 文本按行提取 hex 并验证：nonce = iv⊕pn、掩码位应用后包头、sample 取位 `[pn_offset+4 .. +16]` 全部闭合）；§A.2/A.3 测试经公开 `quic::Suite::keys` 路径运行，覆盖 HKDF/HMAC + "quic key/iv/hp" 派生全链 |
| `sha2.rs` / `sha3.rs`（SHAVS/SHA3VS 完整导入，2026-11-05） | **NIST CAVP 官方字节导向 zip 原件**（csrc.nist.gov CAVP secure-hashing 页，2026-11-05 下载，zip SHA-256：shabytetestvectors `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8`、sha-3bytetestvectors `cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c`、shakebytetestvectors `debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7`）：SHA-256/384/512 LongMsg + Monte、SHA3-256/384/512 LongMsg + Monte、SHAKE128/256 LongMsg；落盘 `tests/vectors/shs/`（长消息 ≤512 B 全保留 + 其余 1/4 确定性抽样 + 恒保留最大长度；Monte 全量 100 检查点） | **程序化提取**（tools/extract_shavs.py）：脚本内以 python hashlib 对**全部** LongMsg 用例独立复算并逐字节比对官方值（不一致即中止）；Monte 按官方算法完整复算 100 检查点核对——SHA-2 = SHAVS §4.3 三摘要滚动拼接 `MD = H(MD_{i-3}‖MD_{i-2}‖MD_{i-1})`、每检查点 1000 次迭代；SHA-3 = SHA3VS Figure 1 单摘要链（与 SHA-2 不同，已核实），两族均 100/100 命中官方检查点 |
| `wycheproof.rs`（新模块，2026-11-05） | C2SP/wycheproof testvectors_v1 **master 快照**（tarball SHA-256 `33f8042214bc36a0133356285c1a44900b4093389609aa6d43ad968a7090bd83`，2026-11-05 经 codeload 下载；与既有 10 文件同上游）：`hmac_sha{256,384,512}`（全量 174×3）、`hkdf_sha{256,384,512}`（全量；invalid = size 恰为 255·HashLen+1）、`aes_ccm`（keySize=128 全组 184）、`rsa_signature_{3072,4096}_sha{256,384}`、`rsa_pss_misc`（mgfSha==sha 且 SHA-2 组 18 例）、`rsa_pkcs1_{2048,3072,4096}_sig_gen`（签名侧 KAT，均衡素数 CRT 形状过滤） | 增量裁剪（tools/trim_wycheproof.py 新增 SPECS，既有 10 文件未触碰）；结果映射与例外见 wycheproof.rs 文件头——HMAC invalid = 同长篡改 tag → 前缀区分断言；pss_misc 全 valid 于**任意盐长语义**（见下方修订说明）；sig_gen 的 WeakHash/SmallPublicKey 组（acceptable）按本实现装载下限排除 |
| `ccm.rs`（CCMVS 补齐，2026-11-05） | **NIST SP800-38C CAVS 官方向量**，经 OpenSSL master `test/recipes/30-test_evp_data/evpciph_aes_ccm_cavs.txt` 转载（文件头注明 "Tests from NIST CCM Test Vectors (SP800-38C)"，Apache-2.0）：aes-128-ccm 955 块——14 个 (nonce 7–13, tag 4–16 偶数) 形状的 Variable Tag/Nonce/Plaintext/AAD 加密用例 + 477 个 Decryption-Verification 失败用例；落盘 `tests/vectors/ccm/ccmvs_aes128.json`（每形状 ≤2 加密 + 失败 1/4 抽样，共 68） | 程序化提取（tools/extract_ccmvs.py）：官方期望值原样搬运为数据文件；ENCRYPT → seal 逐字节 + 往返，DECRYPT(CIPHERUPDATE_ERROR) → open 必须拒绝（tests/ccm.rs `ccmvs_nist_aes128_official_vectors`）。2026-09-07 修订所记 "CCMVS 未实际引入" 至此由官方转载件补齐（直接 URL 已失效，转载链路注明） |
| `attacker_corpus.rs`（2026-11-05） | OpenSSL master `test/d2i-tests/` 10 文件（Apache-2.0；CVE-2016-2108/2109/7053 官方回归 + 非最小 INTEGER 双符号 + 高 tag 号）→ `tests/vectors/d2i/`；BoringSSL master `fuzz/{pkcs8,privkey,spki,cert,der_roundtrip}_corpus` 精选 31 文件（ISC License / OpenSSL dual，LibFuzzer 演化语料）→ `tests/vectors/corpus/` | 一次性全量烟测（2026-11-05）：BoringSSL 7 语料目录 **438 文件**喂全部解析/验证入口（PKCS#8/SPKI/裸 RSA/EC 点/Ed25519/ECDH 对端/三 AEAD open/DER 原语）**零 panic**；入库子集逐文件钉住解析结果（3 个合法 PKCS#8 + 其余 Err），防"静默从拒绝变接受"回归 |

## 2026-09-07 修订说明

- CCM 行修正：早前表格声称的 NIST CCMVS 向量并未实际引入（CAVP 公开集
  无 M=16 参数集），本次以"官方向量校验过的独立参照实现"链路补齐，
  并暴露/修复了 CCM 四处规范偏差（B0 Adata 位、AAD 段独立补齐、
  CTR 计数器宽度、长度域静默截断），见 `tests/ccm.rs`。
- 新增 GCM 边界、HMAC 超长密钥、SHA-2 填充边界、Ed25519 TEST 1024、
  HKDF 前缀性质/超长拒绝等测试（非向量类自洽性质测试不入表）。

## 2026-11-05 修订说明（测试完备性轮）

- **Wycheproof/HMAC 映射**：`valid` + 全长标签 → verify Ok；截断标签
  （tagSize = 半摘要）→ one_shot 截断逐字节一致（本实现 `verify` 按
  长度精确比较，截断验证不在 API 面——与上游 compute-only 先例一致
  而断言更强）。`invalid`（同长篡改）→ 计算前缀必须区分（全长时另
  断言 verify Err）。
- **RSA-PSS 盐长语义变更**：`verify_pss` 由"盐长 = 哈希长度"放宽为
  按 RFC 8017 编码严格解码任意盐长（PS 全零、首个非零字节必须为
  0x01 分隔符，salt 为其后任意长度尾段；MGF1 哈希仍固定与消息哈希
  相同）。`rsa_pss_2048_sha256_mgf1_32_test.json` 的 tcId 67–72
  （"s_len changed to …"，ModifiedSignature）在该语义下是同一消息的
  真实有效签名——Wycheproof 判 invalid 相对的是组声明的 sLen 参数
  （验证方被假定钉死盐长）；本 API 无盐长参数，接受属既定分歧（同
  OpenSSL 默认行为），测试对这一类不做拒绝断言。
- **sha2.rs:78 TODO 完成**：完整 CAVP SHAVS 长消息/蒙特卡洛向量经
  tools/extract_shavs.py 导入（SHA-2/SHA-3/SHAKE 共 14 文件），脚本内
  hashlib 逐字节核对全部用例；SHA-2 与 SHA-3 的 Monte 算法差异
  （三摘要滚动 vs 单摘要链）已分别按 SHAVS §4.3 与 SHA3VS Figure 1
  核实并 100/100 复算命中。
- **与权威实现的校验语义对照**（research 记录，2026-11-05）：
  - RSA 装载校验对齐 BoringSSL 解析期层级：新增 CRT 分量下界
    （dp/dq/qInv ≥ 2）、d ↔ CRT 一致（d mod (p−1) == dp 且
    d mod (q−1) == dq，等式强制完全约简）、e·d ≡ 1 mod (p−1) 与
    mod (q−1)（合成为 e·d ≡ 1 mod λ(n)）；素性、√2 下界、|p−q| 距离
    与 n 小因子检验属 SP 800-56B 生成期层级，不在装载路径（同
    OpenSSL 非认证校验分层）。CRT limb 形状约束（p、q ≤ ⌈n_len/2⌉
    limb）导致非均衡素数密钥（如 Wycheproof sig_gen 的 1368/688 位
    拆分）被拒——既定设计约束，sig_gen 裁剪按形状过滤。
  - EC 点：仅未压缩形态（较 BoringSSL/aws-lc 的"接受压缩点"更严，
    刻意分歧）；X/Y < p 规范性、不在曲线、无穷远点拒绝与权威一致；
    X25519 低阶/全零拒绝（权威实现在代码内强制但缺 KAT，本实现有
    直接测试）。
  - 指数上限：本实现 e < 2^64（BoringSSL 默认 e ≤ 33 bits 为 DoS
    缓解；8 字节上限为本实现的同类缓解，刻意分歧）。
  - GCM nonce 固定 96 位、CCM nonce 7..13/tag 4..16 偶数（类型级/
    运行时参数校验，OpenSSL 的可变 IV 面不在 API 内）。
  - HKDF-Expand 新增 PRK < HashLen → InvalidInput（RFC 5869 §2.3
    强制，此前静默接受）。
  - fields `from_bytes_le_mod` 条件减修复：旧实现漏掉倍增移位出
    carry 的归约分支（BE 版正确、LE 版遗漏；超长导入 oracle 拦截，
    定长 oracle 触发窗口 ~2⁻²⁴/步故此前未暴露）。

## 再核对指引

1. RFC 类：从 rfc-editor.org 取原文，比对测试常量。
2. CAVP/SHAVS/GCMVS/CCMVS/DRBGVS：NIST CSRC 官网下载 .rsp（注意部分
   文件仅经实验室通道分发时需 ACVP；公开静态集已足够核对内联值）。
3. RFC 8448：`tools/extract_rfc8448.py <rfc8448.txt>` 一键重提取并
   重新生成测试文件（生成器内含 Python 独立复算，输出确定）。
4. Wycheproof：`tools/trim_wycheproof.py`（策略见 tests/vectors/README.md）。
5. SHAVS/SHA3VS：`tools/extract_shavs.py <官方.rsp>...`（字节导向 zip
   从 csrc.nist.gov CAVP secure-hashing 页下载，sha256 记于上表；
   脚本内 hashlib 复算全部用例 + Monte 官方算法全检查点复算）。
6. CCMVS：`tools/extract_ccmvs.py <evpciph_aes_ccm_cavs.txt>`（NIST
   SP800-38C 经 OpenSSL 转载；直接 CCMVS URL 已失效）。
7. 语料子集：`tests/vectors/d2i/`（OpenSSL d2i-tests）与
   `tests/vectors/corpus/`（BoringSSL fuzz corpus 精选）按
   `tests/attacker_corpus.rs` 表格核对；全量烟测一次性执行不入库。
5. fuzz 种子（`fuzz/corpus/mlkem-decaps/`）：由
   `tools/gen_mlkem_fuzz_seeds.py` 从上表 `mlkem.rs` 行的 ACVP 解封装
   用例（同一案例的 dk/c 真值对，每参数集 valid + modified-ct 各一）
   生成，格式 `sel ‖ dk ‖ ct`；向量更新后重跑脚本即可，
   `tests/fuzz_seeds.rs` 冒烟守护漂移。
6. fuzz 种子（其余 target，2026-10 补齐）：由 python-cryptography
   生成的真实密钥材料构造（valid/tampered 对），遵循各 target 的
   输入协议（`fuzz/fuzz_targets/*.rs` 的 sel 字节与固定长度切割；
   `ccm_tls` 形状恒预留 13 字节 nonce 字段、CcmTls 取前 12）；
   RSA PKCS#8 解析种子复用 selftest 内建 KAT 密钥。
   `tests/fuzz_seeds.rs` 对全部 target 同构冒烟（valid 必须 Ok、
   tampered/truncated 必须 Err）。
