# AGENTS.md — ferritls 工作指南（面向人类贡献者与 AI 编码代理）

本文件是仓库的**权威工作规范**：设计思路、硬性规则、安全注意事项、
rustls 对接细节与测试约定。修改设计先改这里和相关 `docs/`，再动代码。
任何代理（人或 AI）在本仓库工作前必须读完本文件。

文档地图：

| 文档 | 内容 |
|---|---|
| 本文件 | 规则、速查、注意事项 |
| `docs/ARCHITECTURE.md` | 模块分层、数据流、Ops 后端模式、rustls 接口映射 |
| `docs/FIPS.md` | FIPS 边界定义、依赖白名单、认证三阶段路线、安全策略底稿 |
| `docs/ROADMAP.md` | 里程碑 M0–M8 的范围/出口条件/当前状态 |
| `docs/VECTOR-PROVENANCE.md` | 全部测试向量的官方来源与核对记录 |

---

## 1. 项目是什么、为什么

**ferritls** = 纯 Rust（无 C、无汇编、无 `unsafe`）的 rustls 0.23
`CryptoProvider`，目标是：

1. **替代 rustls-rustcrypto**（已停更：2024-04 最后发版，README 挂
   "禁止生产使用"横幅，仓库只剩 dependabot 提交）；
2. **提供免 aws-lc-rs 的构建路径**（无 C 工具链、无漫长 cmake/asm 编译）；
3. **按 FIPS 140-3 的工程要求组织**，为将来的 CMVP 认证保留完整路径。

### 为什么密码原语要自研，而不是包装 RustCrypto 生态？

因为 CMVP 认证的对象是一个**边界固定的密码模块**：模块内的每一行
代码、每一个依赖都要被实验室审查并纳入安全策略。包装十几个各自发版
的第三方 crate 无法构成可申报、可按快照重验证的稳定边界。Go 标准库的
FIPS 模块（纯 Go、边界内自包含，2025-05 进入 CMVP 审理）是这一路线
的先例——目前**没有任何纯 Rust 模块通过 CMVP**，ferritls 力争成为
第一批。

### 关键背景事实（2026-09 调研结论，决策依据）

- rustls 0.24 起将取消隐式默认 provider（用户必须显式传 provider），
  对第三方 provider 是利好；0.23 仍是当前稳定线（0.23.43）。
- NIST SP 800-52r2 的 FIPS TLS 配置：仅 AES-GCM/CCM 套件 + P-256/384
  + ECDSA/RSA-PSS/RSA-PKCS1 签名；**X25519 独立使用、ChaCha20-Poly1305、
  Ed25519 均为非批准**；X25519 只能经 ML-KEM 混合（X25519MLKEM768）
  进入批准模式（AWS-LC FIPS 3.x 与 Go 已如此实践）。
- CMVP 认证按**锁定源码快照**发证，此后任何边界内改动都需要重验证
  （或走更新流程）；Go 的节奏是约每年重验证一次。

---

## 2. 仓库布局与 crate 职责

```
ferritls/
├── crates/
│   ├── ferritls-core/       # 密码学核心 = FIPS 模块边界（#![forbid(unsafe_code)]）
│   ├── ferritls-rustls/     # rustls CryptoProvider 适配层（边界外，无密码学）
│   └── ferritls-interop/    # 互操作/E2E 测试宿主（publish=false，依赖不受白名单约束）
├── docs/                    # ARCHITECTURE / FIPS / ROADMAP
├── .github/workflows/ci.yml # fmt / clippy(-D warnings) / 三平台 test / cargo-deny
│                            #   / fuzz 冒烟 / tag 触发的 crates.io 自动发布
└── deny.toml                # 许可 + 供应链约束
```

分层（详见 `docs/ARCHITECTURE.md`）：

```
rustls（应用层）
  └── ferritls-rustls   trait 适配/套件装配（无密码学）
        └── ferritls-core   密码学实现（FIPS 边界）
              ├─ L0: ct / policy / der / entropy
              ├─ L1: sha2 / aes / chacha20poly1305
              ├─ L2: hmac / hkdf / gcm / ccm
              └─ L3: ecdh / sign / drbg / selftest
```

依赖方向单向向下；`ferritls-core` 不得依赖 rustls 任何构件。

---

## 3. 硬性规则（违反即拒绝合并）

1. **`ferritls-core` 内绝对禁止 `unsafe`**（crate 级
   `#![forbid(unsafe_code)]`）。未来的 AES-NI/SHA 扩展后端需要 unsafe
   与 intrinsics——它们放入**独立的边界外后端 crate**（如
   `ferritls-backend-aesni`），经 `ferritls-core::ops` 的 trait 挂接；
   是否将其纳入 FIPS 边界属阶段 C 的决策，不是默认权利。
2. **边界内依赖白名单只有 `subtle`、`zeroize`、`getrandom`**。新增
   依赖 = 先在 `docs/FIPS.md` 更新白名单与审计依据 + 在 PR 描述中
   说明理由，否则拒绝。`tests/` 的 dev-dependencies 不受此限。
3. **认证（阶段 C）落地前，一切 rustls `fips()` 钩子恒返回 `false`**。
   “按 FIPS 模式运行”（`fips` feature / `fips_mode_provider()`）与
   “已通过 CMVP 认证”是两个概念，代码、文档、README 任何地方不得
   混淆。
4. **攻击者可控输入不得触发 panic**：网络字节、证书、密钥文件的
   解析与验证失败必须返回 `Err`。数组下标、`unwrap`、`expect`、
   除法（除数为变量）出现在处理不可信输入的路径上等同 bug。
   （`todo!()` 骨架与 `tests/` 内部断言除外。）
5. **常数时间纪律**：秘密（密钥、私钥标量、共享秘密、MAC/标签）不得
   影响控制流、内存访问模式或提前返回。比较用 `subtle`；选择用
   `subtle::Choice`；禁止“优化”掉这些模式。见 §5。
6. **密钥材料零化**：边界内所有持有秘密的类型实现
   `Zeroize + ZeroizeOnDrop`（或等价 Drop 逻辑）。
7. **测试向量启用前必须与官方文件逐字节核对**：`tests/` 中的向量是
   人工录入的，可能抄错；unignore 某测试前，用 RFC/CAVP 原文核对
   `key/iv/pt/ct/tag` 每一个字段。
8. **不得静默 unignore 测试**：里程碑完成 → 实现落地 → 向量核对 →
   移除 `#[ignore]` → 本地 + CI 全绿，五步缺一不可。
9. **公开 API 变更先改文档**：模块地图（`ferritls-core/src/lib.rs`）、
   `docs/ARCHITECTURE.md` 的映射表与本文件保持同步。

---

## 4. rustls 对接层速查（0.23.43 实测，防坑清单）

以下事实均已核实，写代码时直接查表，不要再猜：

- `CryptoProvider` 有 **5 个字段**：`cipher_suites`、`kx_groups`、
  `signature_verification_algorithms`、`secure_random`、**`key_provider`**
  （容易漏最后一个；它是 `&'static dyn KeyProvider`）。
- 签名 trait `SigningKey`/`Signer` 在 **`rustls::sign`**（不在
  `rustls::crypto` 下）。`Signer::sign(message)` 收到的是**未哈希**
  消息，哈希由 Signer 内部完成。`choose_scheme(offered)` 返回
  `Option<Box<dyn Signer>>`。
- `rustls::Tls13CipherSuite` 字段：`common: CipherSuiteCommon`、
  `hkdf_provider: &'static dyn crypto::tls13::Hkdf`、
  `aead_alg: &'static dyn crypto::cipher::Tls13AeadAlgorithm`、
  `quic: Option<&'static dyn quic::Algorithm>`。**`quic: None` 表示
  该套件不参与 QUIC 握手**（我们的现状；QUIC 是 M8+）。
- **复用 rustls 内建辅助器**：`crypto::tls13::HkdfUsingHmac`（把
  `crypto::hmac::Hmac` 实现包装成完整 TLS 1.3 密钥调度）与
  `crypto::tls12::PrfUsingHmac`（M8 用）。我们只需实现薄薄的
  `crypto::hmac::Hmac`（hash/factory/update/finish/sign/verify），
  **不要**在 core 或 adapter 里手写密钥调度。
- `SupportedKxGroup::start_and_complete()` 有默认实现（start+complete），
  经典 ECDH 不必覆写；KEM（M8+）才需要。
- `ActiveKeyExchange::complete(self: Box<Self>, ...)` **消费 self**；
  `pub_key()` 是方法名（不是 `public_key()`）。
- `Tls13AeadAlgorithm::extract_keys()` 被 rustls 用于导出
  traffic secrets（key exporter / TLS 1.2 resumption 等），
  不支持时返回 `Err(UnsupportedOperationError)`——但 QUIC 与
  key log 需要 `Ok`，M6 按能力实现。
- `WebPkiSupportedAlgorithms.mapping`：TLS 1.3 对每个 scheme 只用
  **第一个**算法；TLS 1.2 会尝试全部。
- `SignatureVerificationAlgorithm`（pki-types 1.15，**本地实测**，docs.rs
  旧快照有出入）：必需方法为 `verify_signature(&self, public_key,
  message, signature)`（注意参数没有 `public_key_alg`，哈希自己做）+
  `public_key_alg_id()` + `signature_alg_id()`；`fips()` 是提供默认
  `false` 的钩子（我们显式覆写为 `false` 以留注释）。`SignatureScheme`
  从 `rustls` 根导入，**不在** `rustls::pki_types` 的再导出里。
  **算法 ID 字节语义（M7 实测修正）**：两个 `*_alg_id()` 返回
  **AlgorithmIdentifier 的 SEQUENCE 内容**（内层 TLV 序列，**不带**外层
  `30 xx` 头）——webpki 用 `der::expect_tag` 剥外层后逐字节比对；RSA
  的 NULL 参数属于内容必须保留，PSS 则为 PSS OID + 参数。权威参照 =
  pki-types `src/data/alg-*.der`（此前“完整 DER”的记录是误读，曾导致
  verify.rs 全部 9 个算法无法通过 webpki 链校验，见 M7 webpki 测试）。
  另：`with_single_cert` 会做密钥/证书 SPKI 匹配检查，仅当 key provider
  的 `SigningKey::public_key()` 返回 `Some` 时触发（ring 会查、我们的
  返回 None 跳过）。
- `CryptoProvider::fips()` 是所有子 `fips()` 的合取；`ClientConfig::
  fips()`/`ServerConfig::fips()` 还会叠加协议配置。
- rustls 0.24 预警：workspace 化（rustls-aws-lc-rs / rustls-ring 独立
  crate）、无隐式默认 provider、trait 字段可能调整。**适配层是唯一
  允许 import rustls 的地方**，升级冲击被限制在 `ferritls-rustls`。
- 没有可复用的已发布 provider 测试套件（crates.io 的
  `rustls-provider-test` 是空占位）；互操作测试自建于
  `ferritls-interop`，必要时 git-dependency rustls monorepo 的未发布
  harness（`rustls/rustls-provider-test`）。

---

## 5. 安全注意事项（实现每个里程碑前重读对应条目）

### 5.1 常数时间

- 适用面：MAC/标签比较（`ct.rs`）、AEAD 打开路径、GHASH/Poly1305 内
  部算术、标量乘的位处理、RSA 幂运算的窗口访问、DER 解析中**不**适用
  （解析对象是公开数据，可正常短路）。
- 禁止：以秘密为索引查表（AES T 表实现因此被禁，只许按位 S-box）；
  以秘密为条件的分支/提前返回；`if a == b` 式比较秘密。
- subtle 的 `Choice` 是黑盒：不要 `unwrap_bool()` 后分支（debug 断言
  除外）。
- 查表按索引的来源分两类判：**以秘密为索引**的查表绝对禁止（AES T 表
  实现因此被禁，只许按位/掩码 S-box）；**索引只依赖公开数据、表内容
  派生自秘密**的预计算表允许（GHASH 的 H 倍数 4-bit 表属此类：索引
  是公开的 AAD/密文/长度字节，访存模式与秘密无关）。采用后一类表的
  PR 必须在描述中给出"索引仅公开数据"的论证。
  （P1 性能轮修订 2026-09：旧条目"GHASH 拒绝 4/8 位查表加速"把两类
  混为一谈，按本条执行。）

### 5.2 各算法要点

- **AES**：软实现按位 S-box + MixColumns；轮密钥与密钥材料
  `ZeroizeOnDrop`。
- **GCM**：nonce 唯一性由协议层（rustls 记录序号）保证，本层不重复
  检查；标签验证在解密数据返回之前完成（先验后出）。
- **X25519**：按 RFC 7748 钳制输入；对端公钥非法编码（长度错）返回
  `InvalidInput`，结果全零（小阶点）返回 `VerificationFailed`——TLS
  层两种都要终止握手。
- **P-256/384**：域算术自研；标量乘固定窗口 + 雅可比坐标 + 标量盲化；
  窗口预表只依赖基点（可预计算公开）；对端公钥必须做在曲线检查。
  这是全项目侧信道风险最高的部分，实现 PR 必须附设计说明。
- **ECDSA**：nonce 一律 RFC 6979 确定性（FIPS 186-5 允许）；签名验证
  中 `r`/`s` 为零或超阶必须拒绝。
- **RSA**：解密/验证的 padding 检查严格且全部错误归一化为同一错误；
  私钥运算乘法盲化（M4c 已落地：rᵉ 预盲 + r⁻¹ 去盲，r 单次随机、
  中间值零化；r⁻¹ 的变量时间 xgcd 仅限单次随机输入）；模长 <2048
  拒绝。
- **ChaCha20-Poly1305**：注意 32 位计数器与 96 位 nonce 的 IETF 拼接；
  Poly1305 字组转整数的小端序。
- **Ed25519**：RFC 8032 逐条实现，包括 SHA-512 两段式与 cofactor
  处理（verify 不接受非规范 s —— 决定跟踪 dalek 严格模式）。

### 5.3 DRBG 与熵

- CTR-DRBG（SP 800-90A）：实例化用 48 字节熵材料（32 熵 + 16 nonce）；
  **每次 generate 前用 128 位 OS 熵重播种**（Go 模块策略：内核熵作为
  未记入强度的 additional input，防御熵源退化/回滚）；健康测试
  （重复计数 + 适应性比例）实例化时执行。
- `getrandom` 失败必须显式失败（`Error::EntropyFailed`），禁止降级到
  时间戳/弱源。

### 5.4 panic 面审计

每个里程碑的验收项之一：对解析/验证入口跑 fuzz 语料（cargo-fuzz
targets 在 M6 建立，语料进 `fuzz/`），零 panic。

### 5.5 优化纪律

- **先正确，后快**：向量全绿 + 常数时间审查通过之前，禁止任何
  “性能优化”提交（包括看似无害的循环展开）。
- 优化有两条入口：① **软件后端自身的重构**（stable 工具链、零
  unsafe、边界内——如 P1 性能轮的批量 XOR / H 倍数表 / 位切片 /
  批处理形状重排，P2 起含默认 feature `simd` 的显式 `core::simd`
  路径，约束集见下条）属常规维护，不经 ops 分发，公开 API 与
  rustls 适配层不动；② **新增硬件后端**的唯一入口是
  `ferritls-core::ops` 的 trait 分发（模式见 `docs/ARCHITECTURE.md`
  §4），以边界外独立 crate 存在。
- **`simd` feature（P2 起，默认启用）**：显式 `core::simd`
  （portable_simd）代码经 `#![cfg_attr(feature = "simd",
  feature(portable_simd))]` 启用，在 stable 工具链上依赖
  `RUSTC_BOOTSTRAP=1` 编译（仓内由 `.cargo/config.toml` 的 `[env]`
  提供，CI 由 workflow env 提供；下游 stable 用户需自带该 env 或以
  `default-features = false` 退出）。约束集：safe-only
  （`#![forbid(unsafe_code)]` 不变）、零新依赖（portable_simd 属
  std，白名单不变）、通道宽度按编译期信息选择（AES 批量按请求
  块数在已实例化档位中取最小浪费；ChaCha20 按
  `cfg(target_feature)` 三档 AVX-512/AVX2/基线，档位选择不依赖
  任何秘密）、**不做运行时分发**（调用 `#[target_feature]` 函数
  需要 unsafe，被 forbid）、标量路径原样保留为永久回退与 oracle
  基线。portable_simd 稳定后：拆除 RUSTC_BOOTSTRAP 依赖，代码
  不变。
- 任何优化不得引入以秘密为条件的分支/访存（§5.1），PR 里要说明。
- 性能 PR 三要件：全向量套件一行不改且绿（simd feature 存在时须
  **默认（simd）与 no-default-features（标量回退）双配置**都绿）+
  常数时间声明 + 基准前后数字（`cargo run -p ferritls-interop
  --release --example perf`；宽 ISA 评估加跑
  `RUSTFLAGS="-C target-feature=+avx2"`（及 +avx512f,+avx512vl）
  变体——自动向量化在宽 ISA 下常常不加宽，效率判定以同 ISA 对照
  为准，不以 x86-64 默认 SSE2 宽度为唯一标尺）。
- 批准模式下后端固定为软件后端（边界稳定优先，见 `ops.rs` 文档）。

---

## 6. 测试体系

### 6.1 布局

- `crates/ferritls-core/tests/common/mod.rs`：hex 工具（唯一允许的
  测试基础设施代码）。
- `crates/ferritls-core/tests/<算法>.rs`：向量测试（M1 起逐步 unignore，
  当前全部启用；来源与核对方式见 `docs/VECTOR-PROVENANCE.md`）。
- `crates/ferritls-core/tests/schedule_rfc8448.rs`：TLS 1.3 密钥调度
  全链外部真值（**由 tools/extract_rfc8448.py 生成，勿手改**）。
- `crates/ferritls-core/tests/wycheproof.rs` + `tests/vectors/`：
  Wycheproof 对抗性向量（裁剪入库，策略见 vectors/README.md）。
- `crates/ferritls-rustls/tests/api.rs`：清单断言 + provider 冒烟。
- `crates/ferritls-interop/tests/`：互操作矩阵（M6）、ring 交叉互操作
  与 webpki 真实证书链校验（M7）；`tests/certs/` 为 openssl 生成的
  测试专用链（root→intermediate→leaf + 无关根）。

### 6.2 里程碑的“测试完成”定义

| 里程碑 | 必须绿的内容 |
|---|---|
| M1 | `sha2.rs`、`hmac.rs`、`hkdf.rs` unignore 且绿 + CAVP SHAVS 长消息/蒙特卡洛子集 |
| M2 | `aes_gcm.rs`、`chacha20poly1305.rs` 绿 + GCMVS/CCMVS 向量子集 |
| M3 | `x25519.rs`、`p256.rs`(ECDH 部分) 绿 + Wycheproof ECDH（含 invalid 分组） |
| M4 | `p256.rs`(ECDSA)、`ed25519.rs`、`rsa_and_der.rs` 绿 + Wycheproof 全量 + RFC 6979 |
| M5 | `drbg.rs`、`selftest.rs` 绿 + DRBGVS 向量 |
| M6 | interop 矩阵 + RFC 8448 轨迹 |
| M7 | 批准模式矩阵 + ACVP demo 向量 |

### 6.3 本地命令

默认 feature `simd`（P2 起）经 `#![feature(portable_simd)]` 启用，
**stable 工具链上需 `RUSTC_BOOTSTRAP=1`**——仓内 `.cargo/config.toml`
的 `[env]` 已提供，以下命令可直接跑；仓外/CI 由环境变量提供。

```bash
cargo build --workspace
cargo test --workspace                 # ignored 默认跳过（simd 路径）
cargo test -p ferritls-core --no-default-features   # 标量回退路径
cargo test -p ferritls-core --features fips
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo deny check                       # 需已安装 cargo-deny
cargo run -p ferritls-interop --release --example perf # 性能基准（同机前后对比用）
RUSTFLAGS="-C target-feature=+avx2" cargo test --workspace          # AVX2 档
RUSTFLAGS="-C target-cpu=native" cargo run -p ferritls-interop \
    --release --example perf           # 宽 ISA 性能（本机 CPU 支持 AVX2/512 时）
cargo test -p ferritls-core --test sha2 -- --ignored   # 手动跑单个 ignored 测试
```

---

## 7. 编码与提交规范

- rustfmt 默认配置；clippy `--all-targets -D warnings`；公共项必须有
  `///` 文档（骨架的 `todo!()` 也要写清楚属于哪个里程碑、向量来源）。
- 骨架约定：未实现的函数体为 `todo!("Mx")`，参数先 `let _ = ...;`
  消耗掉避免 unused 警告；实现落地时删除。
- 提交信息 conventional 风格（`feat:`/`fix:`/`docs:`/`ci:`/`test:`），
  一个提交一个主题。里程碑完成时提交信息引用里程碑号
  （如 `feat(core): implement SHA-2 family (M1)`）。
- 分支：`main` 保持随时可发布；功能分支 `feat/m1-sha2` 样式。
- CI 是硬门：本地过不了的 PR 不提交。

---

## 8. FIPS 相关红线（详细路线在 docs/FIPS.md）

- **边界 = `ferritls-core` 的特定版本快照**。这决定了：边界内代码
  动一发就要重验证；所以边界内只放密码学必需品（`der` 解析已属边缘，
  因为它在边界内服务密钥加载——实验室申报为“非安全相关的支撑功能”）。
- 认证三阶段：**A** 工程就绪（M0–M7 内完成，零外部依赖）→ **B**
  算法证书（ACVP production，需 NVLAP 实验室，费用数万至十几万美元级）
  → **C** 模块验证（12–24+ 个月，按快照，年度重验证）。
- 阶段 B/C 不阻塞 M6/M7 的功能发布；provider 的可用性与认证状态
  解耦。
- README / crate 描述中关于 FIPS 的措辞模板：“organized as a FIPS
  140-3 cryptographic module boundary; **not yet CMVP-validated**”。

---

## 9. 当前状态（2026-09，M0–M7 完成）

- [x] 双许可（Apache-2.0 OR MIT）、workspace、CI、cargo-deny
- [x] ferritls-core 全模块实现（无 `todo!()` 残留）
- [x] M1：SHA-2 + HMAC + HKDF（RFC/官方向量绿）
- [x] M2：AES-GCM / CCM（含 TLS nonce-12/L-3 参数集）/ ChaCha20-Poly1305
- [x] M3：X25519（RFC 7748 §5.2/§6.1）+ P-256/384 ECDH（外部锚值）
- [x] M4a：ECDSA P-256/384（RFC 6979 A.2.5/A.2.6）+ Ed25519
      （RFC 8032 TEST 1/2/3 + SHA(abc)）+ DER/PKCS#8/SEC1 解析
- [x] M4b：RSA（CRT + Garner，固定宽度 Montgomery 模幂），
      PKCS#1 v1.5 逐字节锚定 openssl、PSS 验证方向锚定
- [x] M4c：RSA 私钥运算乘法盲化（rᵉ 预盲 / r⁻¹ 去盲 + Garner
      回绕修正常数时间化；openssl 锚与盲化稳定性测试守护）
- [x] M5：CTR-DRBG（SP 800-90A 无 DF，CAVP DRBGVS 向量）+
      上电自检 KAT 全集 + 失败注入测试
- [x] M6：rustls 适配层全量实装（4 套件 × 3 KX 组 × 全验证算法），
      interop 内存握手矩阵（含 fips_mode_provider 矩阵）绿
- [x] M7：RFC 8448 §3 密钥调度向量（程序化提取 + Python 复算双核对）、
      Wycheproof 2349 用例（暴露并修复 DER 宽容解析/Ed25519 符号位
      缺陷）、rustls-ring 交叉互操作矩阵、webpki 真实证书链校验
      （修正 verify.rs 算法 ID 编码）、cargo-fuzz 六目标 + CI 冒烟、
      FIPS.md 升级 SP 800-140Br1 底稿、发布元数据 + dry-run 通过；
      crates.io 发布已自动化：推 tag `v*`（或手动 dispatch 填 tag）
      触发全量门禁后单次 `cargo publish`（cargo 1.90 起 workspace
      一次发布 core → rustls；需仓库 secrets 配置
      CARGO_REGISTRY_TOKEN）
- [x] P1 性能轮 + P1.5 余留慢点轮（完成 2026-09）：稳定版自动向量化
      重构——AEAD 输出路径 bulk-XOR 化、GHASH 瞬态 H 倍数表（公开
      索引）、ChaCha20 四块批处理、64-lane 位切片 AES 批量加密、
      16 宽单次扫描 SubBytes（单块路径）、DRBG 批量 CTR、Poly1305
      4 块分组吸收、GCM 标签比较常数时间化；零 unsafe / 零新依赖 /
      零 feature 开关。AES-128-GCM 2.7 → 56 MB/s（20×）、
      AES-256-GCM 2.0 → 44 MB/s（23×）、AES-128-CCM 1.4 → 14 MB/s
      （10×）、单块 AES 2.9 → 18 MB/s（6×）、ChaCha20-Poly1305
      451 → 620 MB/s；数字、两次实测回退记录与余留慢点见
      `docs/ROADMAP.md` P1/P1.5 节
- [x] P2 portable_simd 轮（完成 2026-09-08）：`simd` 默认 feature +
      stable 工具链 RUSTC_BOOTSTRAP 编译 `core::simd` 显式向量化
      ——AES 位切片平面泛型化（`Plane` trait：`u64` 与
      `Simd<u64,L>` 同一份电路源码，批量档 64/128/256/512 按公开
      请求块数选档）、ChaCha20 通道按 `cfg(target_feature)` 三档
      （AVX-512 16 块 / AVX2 8 块 / 基线 4 块）；单块 SubBytes 的
      显式 `u8x16` 尝试实测回退 2.5×（select 降级）已撤销。同 ISA
      对照（Zen 4）：+avx512 AES-128-GCM 2.55×（57.6→146.7）、
      AES-256-GCM 3.11×（44.6→138.7）；+avx2 ChaCha 2.17×
      （584→1266）；基线 GCM +28~32%、ChaCha 1.62×（旧数组版连
      SSE2 都未向量化满）。设计、约束、完整矩阵与回退记录见
      `docs/ROADMAP.md` P2 节
- [ ] M8：TLS 1.2 / QUIC / ML-KEM 混合 / intrinsics 后端

**已知的实现级注记**（修订实现前必读）：

- `aes.rs`（位切片平面，P2）：电路函数（`bs_mul/bs_sq/bs_sbox/
  bs_rounds`）按 `Plane` trait 泛型——`u64` 实例即标量回退路径
  （no-default-features），`Simd<u64,L>` 实例即 simd 档位（64/128/
  256/512 块按公开 n 分发，n≤64 恒走 u64 档）。改动电路必须同时
  跑双 oracle（`bitslice_circuits_match_scalar_exhaustive` +
  `encrypt_ctr_batch_matches_scalar` 的档位边界组）；本 rustc 的
  `Simd<T,N>` 对 N 无 trait bound（无需 LaneCount），若未来 rustc
  要求需补 where 子句；计数器装载/提取按 64-lane 组进行后经
  `from_lane_groups`/`to_lane_group` 装配，组数上限 8（512 块）；
- `chacha20poly1305.rs`（Simd 通道，P2）：`rotl` 的右移量必须是
  `32 − r` 而非 `r`——`(v<<r)|(v>>r)` 仅在 r=16 自对偶时凑巧正确
  （曾实际产出错误密钥流、由标量 oracle 立即拦截，12/8/7 全错）；
  通道数按 `cfg(target_feature)` 三档（16/8/4），改通道数后必须重跑
  `blocks4_matches_scalar_and_rfc_anchor`（自动覆盖当前档）与
  `keystream_xor_matches_scalar_all_shapes`（整批/填充批/标量尾
  三种路径）；填充批只消耗 `ceil(rem/64)` 块，counter 按实际消耗
  推进（计数器为公开量）；
- `aes.rs`（单块 SubBytes，P2 实测回退第三例）：显式 `u8x16` 的
  `simd_eq`+`select` 掩码扫描在 crate 内联上下文实测慢 2.5×
  （`Mask::select` 的掩码↔向量往返未被消除；独立编译时代码生成
  理想也不作数）——单块保持标量掩码扫描形态（LLVM 自动向量化），
  改动前先实测；portable_simd 的 `select` 不可假设折叠为 AND；
- `aes.rs`（位切片，P1）：GF(2^8) 折叠约减严禁混入 GF(2^4) 的关系
  （x⁴=x+1 属 GF(16)，在 AES 的 f 下 x⁴ 是规范表示）；乘法折叠必须
  覆盖 x^9/x^11/x^13 全部奇次项——两类错误都实际踩过、由穷举测试
  （65536 对 + 256 S-box 值）拦截；
- `aes.rs`（性能路径选择，P1.5）：位切片电路的平面操作数按"批"
  固定（64 lane 共享），收益来自 lane 填充率——单块走该电路实测
  慢 2×，已回退；单块热点（CCM CBC-MAC、GCM J0/tag_base）用
  `sub_bytes` 16 宽单次掩码扫描（LLVM 向量化内层 16 字节选择）。
  改动任一路径后必须跑 `encrypt_ctr_batch_matches_scalar` /
  `sub_bytes_matches_scalar` 双 oracle；
- `chacha20poly1305.rs`（Poly1305 分组吸收，P1.5）：
  `absorb_zeropadded` 的 4 块分组循环余 0 时不得再补零填充块
  （曾实际产出多余块、由边界长度等价测试拦截）；`fold_mod_p` 的
  掩码选择要求被丢弃的高位均已进位传播到下一字（donna 不变式），
  改动字组顺序前先重推值保持论证；
- `fields.rs::from_bytes_be_mod`：条件减 p 的"还原"分支是空操作
  （acc 从未被替换），曾被误写为 acc += p 造成全量污染；
- `ecdh.rs::x25519_ladder`：u 坐标导入后必须 `from_raw` 进
  Montgomery 域（曾漏掉 → 全错一个 R 因子）；
- `sign.rs`（Ed25519）：`compress()` 仿射转换是 X/Z、Y/Z
  （非 Jacobian 的 Z²/Z³），符号位取 `to_raw()` 后的规范奇偶；
- `sign.rs`（ECDSA）：RFC 6979 步骤 d–g 共两次 K 重构（0x00 与
  0x01 分隔符各一次，第二次必须用更新后的 V）；候选 k 与 n 比较
  而非取模；模数 n 的 BE 字节直接取 `S::P`（严禁 from_raw——
  模数 mod 自身为 0）；
- `sign.rs`（RSA Garner）：`h = (sp − sq)·qInv mod p` 需先将 diff
  转入 Montgomery 域再乘 raw qInv；`diff + p` 的回绕进位恰出现
  一次且必须丢弃；
- `drbg.rs`（无 DF）：seed_material 按 seedlen 异或折叠（非截断）；
  Generate 末次 Update 无条件执行（AI 空则 0^seedlen）；
  官方流程 = Instantiate → Reseed → Generate → Generate。

下一步实现者（人或代理）请从 M7 开始（RFC 8448 / Wycheproof /
发布准备），动手前重读 §5 与上述注记。
