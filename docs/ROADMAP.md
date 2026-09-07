# ferritls 路线图（M0–M8）

工期为专注投入的粗估（单人全职折算）。每个里程碑的出口条件 =
“实现 + 向量核对 + 测试 unignore 全绿 + CI 绿”，缺一不可
（AGENTS.md §6.2）。

| 里程碑 | 内容 | 粗估 | 状态 |
|---|---|---|---|
| M0 | 脚手架/CI/文档/骨架/向量测试预置 | 1 周 | **完成（2026-09）** |
| M1 | SHA-2 + HMAC + HKDF | 1–2 周 | **完成（2026-09）** |
| M2 | AES + GCM + CCM + ChaCha20-Poly1305 | 2–3 周 | **完成（2026-09）** |
| M3 | X25519 + P-256/384 ECDH | 3–4 周 | **完成（2026-09）** |
| M4 | ECDSA + RSA + Ed25519 + DER 解析 | 3–4 周 | **完成（2026-09，M4a+M4b）** |
| M5 | CTR-DRBG + 上电自检 + 零化审计 | 1–2 周 | **完成（2026-09）** |
| M6 | rustls 集成 + 互操作矩阵 | 2 周 | **完成（2026-09）** |
| M7 | 发布 0.1 + 批准模式打磨 + ACVP 预演 | 持续 | **完成（2026-09，发布动作待定）** |
| P1 | 性能轮：稳定版自动向量化（默认生效） | 1–2 周 | **完成（2026-09）** |
| M8 | TLS 1.2 / QUIC / ML-KEM 混合 / intrinsics 后端 | 发布后 | 规划中 |

## M0 — 脚手架（已完成）

- [x] 双许可（Apache-2.0 OR MIT）
- [x] workspace 三 crate + 依赖白名单落地（workspace Cargo.toml）
- [x] CI：fmt / clippy(-D warnings, 含 fips 矩阵) / 三平台 test / deny
- [x] ferritls-core 16 模块骨架（`todo!("Mx")`，签名即接口契约）
- [x] 向量测试预置：sha2 / hmac / hkdf / aes_gcm / chacha20poly1305 /
      x25519 / p256 / ed25519 / drbg / selftest / rsa_and_der（全部
      `#[ignore = "Mx"]`）
- [x] ferritls-rustls trait 骨架（rustls 0.23.43 接口编译期锁定）
- [x] ferritls-interop 验收矩阵文档 + 占位测试
- [x] AGENTS.md / ARCHITECTURE / FIPS / ROADMAP

## M1 — 哈希与 KDF（一切的地基）

范围：`sha2.rs`、`hmac.rs`、`hkdf.rs` 落地；`tests/{sha2,hmac,hkdf}.rs`
unignore；CAVP SHAVS 长消息/蒙特卡洛子集入 `tests/vectors/`。
同时：定义第一个 Ops trait（Hash 后端模式打样，ARCHITECTURE §4）。

## M2 — AEAD

范围：AES（按位 S-box 软实现）→ GCM（常数时间 GHASH）→ CCM →
ChaCha20-Poly1305；`AeadOps` 分发正式启用。向量：GCMVS/CCMVS 子集 +
RFC 8439 + McGrew-Viega 样例。

## M3 — 密钥交换

范围：X25519（Montgomery 阶梯，纯软常数时间）；P-256/384（域算术、
雅可比坐标、固定窗口 + 盲化、公钥合法性检查）。向量：RFC 7748（含
1000 轮迭代，慢测试单独标记）、Wycheproof ECDH 全量（含 invalid 分组）。
**本里程碑 PR 必须附侧信道设计说明**（AGENTS.md §5.2）。

## M4 — 签名

范围：ECDSA（RFC 6979）、RSA（PSS + PKCS#1，严格编解码 + 盲化）、
Ed25519（RFC 8032）、`der.rs` 最小解析。向量：RFC 6979 A.2.5/A.2.6、
Wycheproof ECDSA/RSA/EdDSA 全量。密钥生成在 M5 前临时用 `getrandom`
直读（`generate()` 的文档已注明）。

## M5 — DRBG + 自检

范围：CTR-DRBG（SP 800-90A + 健康测试 + 每次生成重播种）、上电 KAT
框架 + 完整性测试、零化审计（ARCHITECTURE §6 清单逐项核对）、
`generate()` 切换 DRBG。向量：DRBGVS。

## M6 — rustls 集成

范围：五字段 provider 装配、全部 crypto trait 实装、`extract_keys`、
`ferritls-interop` 矩阵（ferritls↔ferritls/ring/aws-lc-rs/openssl）、
RFC 8448 轨迹重放、cargo-fuzz 目标建立（DER/签名验证/AEAD）。

## M7 — 发布 0.1 与 FIPS 就绪（已完成 2026-09）

- [x] RFC 8448 §3 密钥调度全链向量（X25519 + HKDF 栈外部真值锚定；
      记录级字节重放不可行的原因见 tests/schedule_rfc8448.rs 文档）
- [x] Wycheproof 对抗性向量 2349 用例入库（invalid/acceptable 全保留），
      并暴露修复 der.rs 两处 DER 宽容解析、Ed25519 x=0 符号位缺陷
- [x] rustls-ring 交叉互操作矩阵（3 套件 × 双方向）——打破自握手盲区
- [x] webpki 真实证书链校验（含不可信根/篡改负例）；修正 verify.rs
      AlgorithmIdentifier 编码语义（SEQUENCE 内容，非完整 DER）
- [x] cargo-fuzz 六目标 + 语料 + CI 冒烟（AGENTS §5.4 欠账清偿）
- [x] docs/FIPS.md 升级为 SP 800-140Br1 安全策略底稿（§6）
- [x] M4c：RSA 私钥运算乘法盲化落地（rᵉ 预盲 / r⁻¹ 去盲 + Garner
      回绕修正常数时间化；变量时间 xgcd 论证与中间值零化；openssl
      逐字节锚 + 盲化稳定性测试守护）
- [x] crates.io 0.1.0 元数据齐备，`cargo publish --dry-run` 通过
      （rustls crate 的 dry-run 需 core 实际发布后才能通过——发布顺序
      core → rustls）
- [x] crates.io 发布自动化进 CI：推 tag `v*`（或手动 dispatch 填
      tag）→ 全量门禁 → 单次 `cargo publish`（cargo 1.90 起 workspace
      一次发布，core → rustls 拓扑序，验证用本地 overlay 无需等
      索引传播）；前置：仓库 secrets 配置 CARGO_REGISTRY_TOKEN
- [ ] **实际发布 v0.1.0**：配置 secret 后推 tag v0.1.0 即完成

## P1 — 性能轮（稳定版自动向量化，进行中 2026-09）

背景与决策：`std::simd`（portable_simd）截至 2026-09 仍 nightly-only，
**不能**作为默认 feature（默认启用 = 强迫全部用户与发布 CI 上
nightly）。本轮在 stable 上默认生效：零 `unsafe`、零新依赖、零 feature
开关，全部留在 FIPS 边界内的软件后端上（AGENTS §5.5 修订的两条入口
之①）。位切片/转置/批处理的代码形状为将来 portable_simd 稳定后的
`core::simd` 变体与 M8 intrinsics 后端 crate 复用而设计。

- [x] AEAD 输出路径 bulk-XOR 化：消灭 gcm/ccm/chacha20poly1305 中
      逐字节 `Vec::push` 的内循环（固定块 `zip` 形状，自动向量化）
- [x] GCM 标签比较常数时间化（gcm.rs 的 `!=` u128 比较 → ct 比较，
      与 ccm.rs 对齐；顺手修复的 §5.1 违规）
- [x] GHASH：逐位 gf128_mul → **瞬态** H 倍数 4-bit 表（8 块分组
      前向 Horner，公开索引判据，AGENTS §5.1 修订；旧实现保留为
      测试 oracle + 随机块等价性测试；表用完零化，不常驻实例——
      常驻 64 KiB/实例对多连接服务器不可接受）；顺带修复 h 未
      Drop 零化的 §6 缺口
- [x] ChaCha20：四块批处理转置布局（`[u32; 4]` 通道 × 16 状态字，
      ARX 跨通道自动向量化；尾块标量回退）+ Poly1305 流式吸收
      （消灭每记录一次全长拷贝）
- [x] bitsliced AES 加密方向：64-lane u64 位平面布尔电路（GF(2^8)
      多项式基 x^254 加法链 + 仿射；卷积乘/平面重排平方），供
      GCM/CCM CTR 的批量入口 `encrypt_ctr_batch`；单块路径
      （J0/H/CBC-MAC/密钥展开）保持掩码实现；解密方向不动
- [x] 收尾：前后数字填入下表，AGENTS §9 状态更新

每项独立 PR，出口条件：全向量套件 / Wycheproof 2349 / interop 矩阵
**一行不改且全绿** + 常数时间声明 + 基准前后数字。基准命令：

```bash
cargo run -p ferritls-interop --release --example perf
```

### 基准数字（本地 x86_64 Linux，同机前后对比；2026-09-08 完成）

| 项目 | 基线 | PR1 后 | PR2/3 后 | PR4 后 | 总提升 |
|---|---|---|---|---|---|
| AES-128-GCM seal 1 KiB | 2.68 MB/s | 2.65 | 2.68 | 34.2 | 12.8× |
| AES-128-GCM seal 16 KiB | 2.71 MB/s | 2.69 | 2.80 | 52.1 | **19.2×** |
| AES-256-GCM seal 16 KiB | 1.95 MB/s | 1.95 | 2.00 | 41.0 | **21.0×** |
| AES-128-CCM seal 16 KiB | 1.41 MB/s | 1.41 | 1.39 | 2.74 | 1.9× |
| ChaCha20-Poly1305 seal 16 KiB | 451 MB/s | 504 | 565 | 573 | 1.3× |
| SHA-256 16 KiB | 357 MB/s | 363 | 370 | 370 | —（未动） |
| AES-128 单块加密 | 2.72 MB/s | 2.77 | 2.86 | 2.86 | —（未动） |

### 完成时注记（2026-09）

- 全程零 `unsafe`、零新依赖、零 feature 开关、公开 API 未变；
  位切片/分组/转置代码形状为将来 `core::simd`（稳定后）与 M8
  intrinsics 后端 crate 复用而设计。
- **实测回退记录**：曾尝试以标量代数 S-box（x^254 链）替代掩码
  全扫描，实测更慢（单块 -12%：LLVM 已把 256 项扫描向量化，而
  加法链是长串行依赖），已回退——单块路径维持掩码扫描。
- 已知余留慢点（后续候选）：CCM 的串行 CBC-MAC（单块掩码路径，
  2.74 MB/s）；GCM 小记录的 J0/tag_base 两次单块加密；DRBG 仍逐
  块加密（可平移 `encrypt_ctr_batch`）；Poly1305 串行吸收
  （ChaCha 已不是瓶颈）；SHA-2 单流（M8 一并）。

## 已知问题 / 待开 issue

- windows-gnu 工具链构建 ring 需要 ucrt64 工具链在 PATH 前列
  （mingw64 DLL 与 ucrt64 编译器混载会静默崩溃；CI 不受影响）。

## M8 — 发布后方向（按需排期）

- TLS 1.2：`tls12` feature、PRF（`PrfUsingHmac`）、ECDHE-GCM 套件
  （SP 800-52r2 部署面需要）；
- QUIC packet protection（`quic` 字段 + Header Protection）；
- ML-KEM（FIPS 203）+ X25519MLKEM768 混合（X25519 进批准模式的通道）；
- intrinsics 后端 crate（AES-NI/SHA-ext，边界外，经 ops 挂接）；
- 认证阶段 B/C 启动（见 docs/FIPS.md）。
