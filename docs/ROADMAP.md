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
| M8 | TLS 1.2 / QUIC / ML-KEM 混合 / intrinsics 后端 | 发布后 | 规划中 |

## M0 — 脚手架（已完成）

- [x] 双许可（Apache-2.0 OR MIT）
- [x] workspace 三 crate + 依赖白名单落地（workspace Cargo.toml）
- [x] CI：fmt / clippy(-D warnings, 含 fips 矩阵) / 三平台 test / MSRV / deny
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
- [x] crates.io 0.1.0 元数据齐备，`cargo publish --dry-run` 通过
      （rustls crate 的 dry-run 需 core 实际发布后才能通过——发布顺序
      core → rustls）
- [ ] **crates.io 实际发布 + tag v0.1.0**（外向动作，待维护者执行）

## 已知问题 / 待开 issue

- **TODO(M4c) RSA-CRT 私钥盲化**（AGENTS §5.2 允许后补）：本仓库无
  gh CLI 会话，issue 待维护者在 GitHub 上创建（标题建议：
  "RSA private-key blinding (M4c)"，正文引用 AGENTS.md §5.2 与
  docs/FIPS.md §6.11）；在 issue 开立前此条目即为跟踪载体。
- windows-gnu 工具链构建 ring 需要 ucrt64 工具链在 PATH 前列
  （mingw64 DLL 与 ucrt64 编译器混载会静默崩溃；CI 不受影响）。

## M8 — 发布后方向（按需排期）

- TLS 1.2：`tls12` feature、PRF（`PrfUsingHmac`）、ECDHE-GCM 套件
  （SP 800-52r2 部署面需要）；
- QUIC packet protection（`quic` 字段 + Header Protection）；
- ML-KEM（FIPS 203）+ X25519MLKEM768 混合（X25519 进批准模式的通道）；
- intrinsics 后端 crate（AES-NI/SHA-ext，边界外，经 ops 挂接）；
- 认证阶段 B/C 启动（见 docs/FIPS.md）。
