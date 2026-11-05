# AGENTS.md — ferritls 工作指南（面向人类贡献者与 AI 编码代理）

本文件是仓库的**权威工作规范**：硬性规则、安全纪律、rustls 对接事实
与测试约定。修改设计先改这里和相关 `docs/`，再动代码。任何代理
（人或 AI）在本仓库工作前必须读完本文件。

文档地图：

| 文档 | 内容 |
|---|---|
| 本文件 | 规则、速查、安全纪律、实现陷阱注记 |
| `README.md` / `README.zh.md` | 对外简介与用法（英文默认；详细用法在 Rust docs） |
| `docs/ARCHITECTURE.md` | 模块分层、数据流、Ops 后端模式、rustls 接口映射 |
| `docs/FIPS.md` | FIPS 边界、依赖白名单、认证三阶段、安全策略底稿 |
| `docs/ROADMAP.md` | 里程碑 M0–M8 状态、性能轮结论与数字 |
| `docs/VECTOR-PROVENANCE.md` | 全部测试向量的官方来源与核对记录 |
| `docs/BENCHMARKS.md` | 基准体系：运行方式、基线工作流、历史 A/B 记录 |

---

## 1. 项目是什么、为什么

**ferritls** = 纯 Rust（无 C、无汇编）的 rustls 0.23
`CryptoProvider`——密码学核心 crate 全程 `#![forbid(unsafe_code)]`；
可选的 AES-NI 硬件后端 crate 在边界外，把 `unsafe` 限制在唯一的
叶子模块（§5.5、docs/ARCHITECTURE.md §4）。目标：

1. **替代 rustls-rustcrypto**（已停更，README 挂"禁止生产使用"横幅）；
2. **提供免 aws-lc-rs 的构建路径**（无 C 工具链、无 cmake/asm 编译）；
3. **按 FIPS 140-3 的工程要求组织**，为将来的 CMVP 认证保留完整路径。

**为什么密码原语自研而非包装 RustCrypto 生态**：CMVP 认证的对象是
一个边界固定的密码模块——边界内每一行代码、每一个依赖都要被实验室
审查并纳入安全策略；包装十几个各自发版的第三方 crate 无法构成可按
快照重验证的稳定边界。Go 标准库 FIPS 模块（纯 Go、边界内自包含，
2025-05 进入 CMVP 审理）是先例；目前**没有任何纯 Rust 模块通过
CMVP**，ferritls 力争成为第一批。

**关键背景事实（2026-09 调研，决策依据）**：

- rustls 0.24 起取消隐式默认 provider（利好第三方 provider）；
  0.23 仍是当前稳定线。
- SP 800-52r2 的 FIPS TLS 配置：仅 AES-GCM/CCM 套件 + P-256/384 +
  ECDSA/RSA-PSS/RSA-PKCS1；X25519 独立使用、ChaCha20-Poly1305、
  Ed25519 均非批准；X25519 只能经 X25519MLKEM768 混合进入批准模式。
- CMVP 按锁定源码快照发证，此后边界内任何改动需重验证（Go 节奏：
  约每年一次）。

---

## 2. 仓库布局与 crate 职责

```
ferritls/
├── crates/
│   ├── ferritls-core/       # 密码学核心 = FIPS 模块边界（#![forbid(unsafe_code)]）
│   ├── ferritls-rustls/     # rustls CryptoProvider 适配层（边界外，无密码学）
│   ├── ferritls-interop/    # 互操作/E2E 测试宿主（publish=false，依赖不受白名单约束）
│   └── ferritls-backend-x86_64/ # AES-NI + CLMUL GHASH + SHA-NI 硬件后端
│                            #   （边界外、仅 x86_64；unsafe 限于叶子模块
│                            #   与 kernel trampoline，经 core::ops 注册）
├── docs/                    # ARCHITECTURE / FIPS / ROADMAP / VECTOR-PROVENANCE / BENCHMARKS
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
              ├─ L1: sha2 / sha3 / aes / chacha20poly1305
              ├─ L2: hmac / hkdf / gcm / ccm
              └─ L3: ecdh / mlkem / sign / drbg / selftest
```

依赖方向单向向下；`ferritls-core` 不得依赖 rustls 任何构件。

---

## 3. 硬性规则（违反即拒绝合并）

1. **`ferritls-core` 内绝对禁止 `unsafe`**（crate 级
   `#![forbid(unsafe_code)]`）。硬件后端放入**独立的边界外 crate**，
   经 `ferritls-core::ops` 的 trait 挂接；是否纳入 FIPS 边界属阶段 C
   决策，不是默认权利。
2. **边界内依赖白名单只有 `subtle`、`zeroize`、`getrandom`**。新增
   依赖 = 先更新 `docs/FIPS.md` 白名单与审计依据 + PR 描述说明理由，
   否则拒绝。`tests/` 的 dev-dependencies 不受此限。
3. **认证（阶段 C）落地前，一切 rustls `fips()` 钩子恒返回 `false`**。
   “按 FIPS 模式运行”（`fips` feature / `fips_mode_provider()`）与
   “已通过 CMVP 认证”是两个概念，代码、文档、README 任何地方不得混淆。
4. **攻击者可控输入不得触发 panic**：网络字节、证书、密钥文件的解析
   与验证失败必须返回 `Err`。数组下标、`unwrap`、`expect`、除法
   （除数为变量）出现在不可信输入路径上等同 bug。（`todo!()` 骨架与
   `tests/` 内部断言除外。）
5. **常数时间纪律**：秘密不得影响控制流、内存访问模式或提前返回。
   比较用 `subtle`；选择用 `subtle::Choice`；禁止“优化”掉这些模式（§5）。
6. **密钥材料零化**：边界内所有持有秘密的类型实现
   `Zeroize + ZeroizeOnDrop`（或等价 Drop 逻辑）。
7. **测试向量启用前必须与官方文件逐字节核对**：`tests/` 中的向量是
   人工录入的，可能抄错；unignore 某测试前，用 RFC/CAVP 原文核对
   每一个字段。来源登记入 `docs/VECTOR-PROVENANCE.md`。
8. **不得静默 unignore 测试**：里程碑完成 → 实现落地 → 向量核对 →
   移除 `#[ignore]` → 本地 + CI 全绿，五步缺一不可。
9. **公开 API 变更先改文档**：模块地图（`ferritls-core/src/lib.rs`）、
   `docs/ARCHITECTURE.md` 映射表与本文件保持同步。

---

## 4. rustls 对接层速查（0.23.46 实测，防坑清单）

以下事实均已核实，写代码时直接查表，不要再猜：

- `CryptoProvider` 有 **5 个字段**：`cipher_suites`、`kx_groups`、
  `signature_verification_algorithms`、`secure_random`、**`key_provider`**
  （容易漏最后一个；`&'static dyn KeyProvider`）。
- 签名 trait `SigningKey`/`Signer` 在 **`rustls::sign`**（不在
  `rustls::crypto` 下）。`Signer::sign(message)` 收到**未哈希**消息，
  哈希由 Signer 内部完成；`choose_scheme(offered)` 返回
  `Option<Box<dyn Signer>>`。
- `Tls13CipherSuite` 字段：`common`、`hkdf_provider`、`aead_alg`、
  `quic: Option<&'static dyn quic::Algorithm>`。GCM/ChaCha 三套件
  `Some`，**CCM 恒 `None`**（RFC 9001 §5.1 以 AES-GCM 为强制基准，
  ring 同；`ConnectionTrafficSecrets` 亦无 CCM 变体）。
- **QUIC 适配事实**：rustls 已无 `quic` cargo feature（模块无条件
  可用，Connection 类型需 `std`）；`quic::Algorithm` =
  `packet_key(AeadKey, Iv)` + `header_protection_key(AeadKey)` +
  `aead_key_len()` + `fips()`；`PacketKey`/`HeaderProtectionKey` 是
  `*_in_place` 形态（seal 返回独立 `Tag`；open 返回明文切片，须先验
  后出）。QUIC 密钥派生由 rustls 内部 `KeyBuilder` 经 `hkdf_provider`
  完成（label "quic key/iv/hp"），**不经过 `extract_keys`**——后者只
  服务 key log/secrets 导出。`AeadKey` 构造是 `pub(crate)`：第三方
  **无法**构造，测试要用裸字节请让自家类型的构造函数直接收
  `&[u8; N]`。`write_hs` 的 KeyChange 语义 =「buf 按切换前层级保护，
  KeyChange 只影响后续调用」（quinn-proto `write_crypto` 逐行同构）。
  `HeaderProtectionKey::decrypt_in_place` 依赖掩码后的首字节推包号
  长度（掩码方向传 `masked=true`），照 RFC 9001 §5.4.1；sample =
  包[pn_offset+4 .. +16]。
- **复用 rustls 内建辅助器**：`crypto::tls13::HkdfUsingHmac` 与
  `crypto::tls12::PrfUsingHmac`（TLS 1.2 用）。我们只实现薄薄的
  `crypto::hmac::Hmac`，**不要**手写密钥调度。
- `SupportedKxGroup::start_and_complete()` 有默认实现（start+complete），
  经典 ECDH 不必覆写；KEM/混合组才需要。
- `ActiveKeyExchange::complete(self: Box<Self>, ...)` **消费 self**；
  `pub_key()` 是方法名（不是 `public_key()`）。
- `Tls13AeadAlgorithm::extract_keys()` 只服务 `dangerous_extract_secrets`
  与 `refresh_traffic_keys`——**key log 不经过它**（rustls 0.23.46
  实测：`KeyLog::log` 由 key_schedule 的原始 traffic secret 直供，
  CCM 连接同样产生 key log；`session.rs` 的 ccm keylog 测试钉住此
  事实）；不支持时返回 `Err(UnsupportedOperationError)`
  ——GCM/ChaCha 按能力实现，CCM 无变体恒 `Err`（推论：CCM 连接的
  secret 提取与 key update 必 Err）；QUIC 不走此路径。
- `WebPkiSupportedAlgorithms.mapping`：TLS 1.3 对每个 scheme 只用
  **第一个**算法；TLS 1.2 会尝试全部。
- `SignatureVerificationAlgorithm`（pki-types 1.15 **本地实测**，
  docs.rs 旧快照有出入）：必需方法 `verify_signature(&self,
  public_key, message, signature)`（无 `public_key_alg` 参数，哈希
  自己做）+ `public_key_alg_id()` + `signature_alg_id()`；`fips()` 有
  默认 `false`（我们显式覆写以留注释）。`SignatureScheme` 从 `rustls`
  根导入，不在 `rustls::pki_types` 再导出里。
  **算法 ID 字节语义**：两个 `*_alg_id()` 返回 AlgorithmIdentifier 的
  **SEQUENCE 内容**（内层 TLV，不带外层 `30 xx` 头）——webpki 用
  `der::expect_tag` 剥外层后逐字节比对；RSA 的 NULL 参数必须保留，
  PSS 为 PSS OID + 参数。权威参照 = pki-types `src/data/alg-*.der`。
  **公钥字节语义**：webpki 传入的 `public_key` 是 subjectPublicKey 的
  BIT STRING 内容——裸密钥本体（RSA = 裸 `RSAPublicKey` DER、EC =
  未压缩 SEC1 点、Ed25519 = 32 字节），**不含** SPKI 包装。core 的
  验证 API 全部类型化为 `VerifyKey`（构造器按格式命名），适配层直接
  透传。历史坑：RSA 按 SPKI 解析曾导致全部 RSA 链校验失败，P-256
  本地测试链掩盖了缺陷——interop 的 `webpki_rsa_*` 是回归防线。
  另：`with_single_cert` 的密钥/证书 SPKI 匹配检查仅当 key provider 的
  `SigningKey::public_key()` 返回 `Some` 时触发（我们返回 None 跳过）。
- `CryptoProvider::fips()` 是所有子 `fips()` 的合取；`ClientConfig::
  fips()`/`ServerConfig::fips()` 还叠加协议配置。
- rustls 0.24 预警：workspace 化、无隐式默认 provider、trait 字段
  可能调整。**适配层是唯一允许 import rustls 的地方**，升级冲击被
  限制在 `ferritls-rustls`。
- 没有可复用的已发布 provider 测试套件（crates.io 的
  `rustls-provider-test` 是空占位）；互操作测试自建于
  `ferritls-interop`。

---

## 5. 安全注意事项（实现每个里程碑前重读对应条目）

### 5.1 常数时间

- 适用面：MAC/标签比较（`ct.rs`）、AEAD 打开路径、GHASH/Poly1305
  内部算术、标量乘位处理、RSA 幂运算窗口访问；DER 解析**不适用**
  （对象是公开数据，可正常短路）。
- 禁止：以秘密为索引查表（AES T 表实现因此被禁，只许按位/掩码
  S-box）；以秘密为条件的分支/提前返回；`if a == b` 式比较秘密。
- subtle 的 `Choice` 是黑盒：不要 `unwrap_bool()` 后分支（debug 断言
  除外）。
- 查表按索引来源二分判：**以秘密为索引**绝对禁止；**索引只依赖公开
  数据、表内容派生自秘密**的预计算表允许（GHASH 的 H 倍数 4-bit 表
  属此类：索引是公开的 AAD/密文/长度字节）。采用后一类表的 PR 必须
  给出"索引仅公开数据"的论证。（2026-09 修订：旧条目把两类混为一谈。）

### 5.2 各算法要点

- **AES**：软实现按位 S-box + MixColumns；轮密钥 `ZeroizeOnDrop`。
- **GCM**：nonce 唯一性由协议层保证，本层不重复检查；先验后出。
- **CCM**：标签长 M 与 nonce 长度为运行时参数（M ∈ {4..16 偶数}、
  nonce 7..=13，引擎见 `ccm.rs`）；**截断先于 S0 异或**；先验后出；
  TLS 批准套件面仅 M=16（CCM_8 仅默认模式）。
- **SHA-3**：SHA3 与 SHAKE 共用海绵核、仅域分隔字节不同（0x06/0x1F）；
  rate 数值勿凭记忆（易混，见 §9 注记）。
- **X25519**：按 RFC 7748 钳制输入；对端公钥非法编码（长度错）返回
  `InvalidInput`，结果全零（小阶点）返回 `VerificationFailed`——TLS
  层两种都要终止握手。
- **P-256/384**：域算术自研；标量乘固定窗口 + 雅可比坐标 + 标量盲化；
  窗口预表只依赖基点（公开可预计算）；对端公钥必须做在曲线检查。
  全项目侧信道风险最高，实现 PR 必须附设计说明。
- **ECDSA**：nonce 一律 RFC 6979 确定性；验证中 `r`/`s` 为零或超阶
  必须拒绝。
- **RSA**：padding 检查严格且全部错误归一化为同一错误；私钥运算乘法
  盲化（M4c：rᵉ 预盲 + r⁻¹ 去盲；r⁻¹ 的变量时间 xgcd 仅限单次随机
  输入）；模长 <2048 拒绝。装载期校验对齐 BoringSSL 解析期层级
  （p·q = n、qInv 同余、CRT 分量范围含下界 ≥2、d ↔ CRT 一致、
  e·d ≡ 1 mod (p−1)/(q−1)——详见 §9 sign.rs 注记）；PSS 验证按
  RFC 8017 严格解码**任意盐长**（MGF1 哈希固定同消息哈希）。CRT
  limb 形状按模长半宽定长分配，非均衡素数拆分（p 显著大于 q）在
  装载层拒绝——既定约束。
- **ChaCha20-Poly1305**：32 位计数器与 96 位 nonce 的 IETF 拼接；
  Poly1305 字组转整数的小端序。
- **Ed25519**：RFC 8032 逐条实现，含 SHA-512 两段式与 cofactor 处理；
  verify 不接受非规范 s（跟踪 dalek 严格模式）。
- **ML-KEM（FIPS 203）**：`Decaps` 的重加密密文比较必须常数时间
  （`subtle` 得 `Choice` 后 ct-select K'/K̃，禁止 `if` 分支）；封装前
  必须做 §7.2 封装密钥检查（长度 + 系数模校验，实质是解码系数全部
  < q，**不能写成编码往返**），失败返回 `InvalidInput` 不 panic；
  2400 字节 dk 解析时校验 `h = H(ek)`；SampleNTT 拒绝循环与 CBD 位
  运算只依赖公开 XOF/PRF 输出；zeta/γ 表索引为公开循环计数；秘密
  （dk、ss、K'、K̃、ŝ、种子）`ZeroizeOnDrop`；Â[i][j] =
  SampleNTT(XOF(ρ‖j‖i))（Encrypt 用转置 XOF(ρ‖i‖j)）——与 Kyber R3
  不兼容的根源，一切以 ACVP 向量为最终仲裁；参数差异集中在
  `fips203_params` 单一来源（k=2 ↔ η₁=3，k=4 ↔ (du,dv)=(11,5)）。

### 5.3 DRBG 与熵

- CTR-DRBG（SP 800-90A）：实例化用 48 字节熵材料（32 熵 + 16 nonce）；
  **每次 generate 前用 128 位 OS 熵重播种**（Go 模块策略：内核熵作为
  未记入强度的 additional input）；健康测试（重复计数 + 适应性比例）
  实例化时执行。
- `getrandom` 失败必须显式失败（`Error::EntropyFailed`），禁止降级到
  时间戳/弱源。

### 5.4 panic 面审计

每个里程碑的验收项之一：对解析/验证入口跑 fuzz 语料（cargo-fuzz
targets 在 `fuzz/`），零 panic。

### 5.5 优化纪律

- **先正确，后快**：向量全绿 + 常数时间审查通过之前，禁止任何
  “性能优化”提交（包括看似无害的循环展开）。
- 优化两条入口：① **软件后端自身的重构**（stable、零 unsafe、边界内
  ——批量 XOR / H 倍数表 / 位切片 / `core::simd` 等）属常规维护，
  不经 ops 分发，公开 API 与适配层不动；② **新增硬件后端**的唯一
  入口是 `ferritls-core::ops` 的 trait 分发（模式见 ARCHITECTURE §4），
  以边界外独立 crate 存在。
- **硬件后端 crate 的 unsafe 纪律**：crate 根 `#![deny(unsafe_code)]`，
  unsafe 只在唯一 `#[allow(unsafe_code)]` 私有叶子模块与各 kernel 的
  单点 trampoline；CPU 能力 token 只能经运行时探测构造；**kernel 必须
  标 `#[target_feature]` 并在上下文内直调 intrinsic**——从无 feature
  上下文调用不得内联，硬件收益会被调用开销吃光（借鉴 fearless_simd，
  零依赖自建）。安装前后端须通过自身 KAT。
- **`simd` feature（默认启用）**：显式 `core::simd`（portable_simd）
  经 `#![cfg_attr(feature = "simd", feature(portable_simd))]` 启用，
  stable 上依赖 `RUSTC_BOOTSTRAP=1`（仓内 `.cargo/config.toml [env]`
  / CI env 提供；下游自带 env 或 `default-features = false` 退出）。
  约束集：safe-only、零新依赖（portable_simd 属 std）、通道宽度按
  编译期信息选择（不依赖任何秘密）、**不做运行时分发**（调
  `#[target_feature]` 函数需要 unsafe）、标量路径原样保留为永久回退
  与 oracle 基线。portable_simd 稳定后拆 RUSTC_BOOTSTRAP、代码不变。
- 任何优化不得引入以秘密为条件的分支/访存（§5.1），PR 里要说明。
- 性能 PR 三要件：全向量套件一行不改且绿（**默认（simd）与
  no-default-features（标量）双配置**）+ 常数时间声明 + 基准前后数字
  （`cargo run -p ferritls-interop --release --example perf`；宽 ISA
  评估加跑 `RUSTFLAGS="-C target-feature=+avx2"`（及 +avx512f,
  +avx512vl）变体——效率判定以同 ISA 对照为准）。
- 批准模式下后端固定为软件后端（`ops::install()` 在 `fips` 构建下
  拒绝，见 `ops.rs` 文档）。

---

## 6. 测试体系

### 6.1 布局

- `crates/ferritls-core/tests/common/mod.rs`：hex 工具（唯一允许的
  测试基础设施代码）。
- `crates/ferritls-core/tests/<算法>.rs`：向量测试（全部启用；来源与
  核对方式见 `docs/VECTOR-PROVENANCE.md`）。
- `tests/schedule_rfc8448.rs`：TLS 1.3 密钥调度全链外部真值（由
  tools/extract_rfc8448.py 生成，**勿手改**）。
- `tests/wycheproof.rs` + `tests/vectors/`：Wycheproof 对抗性向量
  （裁剪入库，策略见 vectors/README.md；2026-11 扩至 25 文件——
  新增 HMAC/HKDF/CCM/RSA 扩展/签名侧 sig_gen；子目录 `shs/` =
  NIST SHAVS/SHA3VS 长消息+蒙特卡洛、`ccm/` = NIST SP800-38C CAVS、
  `d2i/` + `corpus/` = 攻击者语料回归，溯源见
  docs/VECTOR-PROVENANCE.md）。
- `tests/attacker_corpus.rs`：d2i/语料逐文件结果钉住 + 全解析面
  no-panic（438 文件一次性烟测零 panic 后入库精选子集）。
- `tests/ops_default.rs`：ops 注册表默认态观测（独立测试二进制，
  不安装后端——与 ops_dispatch.rs 的 mock 安装二进制分离）。
- `tests/fuzz_seeds.rs`：按**全部** fuzz target 同构逻辑跑
  `fuzz/corpus/` 种子（valid 必须成功、tampered/truncated 必须失败；
  种子生成脚本与溯源见 VECTOR-PROVENANCE.md「再核对指引」）。
- `crates/ferritls-rustls/tests/api.rs`：清单断言 + provider 冒烟。
- `crates/ferritls-interop/tests/`：互操作矩阵、ring 交叉互操作与
  webpki 真实链校验、内存 QUIC 回环（`quic.rs`）、Ni 后端 A/B 握手
  （`interop_ni.rs`）、mTLS（`mtls.rs`）、会话恢复 + KeyLog
  （`session.rs`）、记录层边界（`records.rs`）、套件协商顺序含 fips
  协商面拒绝（`negotiation.rs`）、reqwest 应用层集成（`reqwest.rs`，
  0.12 线回环，覆盖 install_default 与 use_preconfigured_tls 双路径）、
  损坏/截断记录失败路径 + TLS 1.2-only 拒绝（`failures.rs`，驱动
  适配层 MessageDecrypter 短记录 guard 并钉住 DecryptError→
  bad_record_mac 映射）。
  `tests/certs/` 为 openssl 生成的测试专用链（root→intermediate→leaf
  + 无关根；P-256/RSA-2048/Ed25519/P-384 + mTLS 客户端链；再生成命令
  见该目录 README.md——EC leaf 私钥必须显式 `pkcs8 -topk8` 转 DER，
  P-384 签发必须 `-sha384`）。

### 6.2 里程碑的“测试完成”定义

| 里程碑 | 必须绿的内容 |
|---|---|
| M1 | `sha2.rs`、`hmac.rs`、`hkdf.rs` unignore 且绿 + CAVP SHAVS 子集 |
| M2 | `aes_gcm.rs`、`chacha20poly1305.rs` 绿 + GCMVS/CCMVS 向量子集 |
| M3 | `x25519.rs`、`p256.rs`(ECDH) 绿 + Wycheproof ECDH（含 invalid 分组） |
| M4 | `p256.rs`(ECDSA)、`ed25519.rs`、`rsa_and_der.rs` 绿 + Wycheproof 全量 + RFC 6979 |
| M5 | `drbg.rs`、`selftest.rs` 绿 + DRBGVS 向量 |
| M6 | interop 矩阵 + RFC 8448 轨迹 |
| M7 | 批准模式矩阵 + ACVP demo 向量 |

### 6.3 本地命令

默认 feature `simd` 在 stable 上需 `RUSTC_BOOTSTRAP=1`——仓内
`.cargo/config.toml [env]` 已提供，以下命令可直接跑：

```bash
cargo build --workspace
cargo test --workspace                 # 全量（当前无 ignored 测试）
cargo test -p ferritls-core --no-default-features   # 标量回退路径
cargo test -p ferritls-core --features fips
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo deny check                       # 需已安装 cargo-deny
cargo run -p ferritls-interop --release --example perf # 基准（同机前后对比）
RUSTFLAGS="-C target-feature=+avx2" cargo test --workspace          # AVX2 档
cargo bench -p ferritls-core           # criterion 基准（aead/hash/ecdh/sign/drbg/kem）
cargo bench -p ferritls-interop        # 全握手基准（含 ring 基线）
cargo bench -p ferritls-backend-x86_64 # 软/Ni 逐记录 A/B（aead_ni）
```

基准完整用法（过滤、`--save-baseline`/`--baseline` 回归工作流、参考
量级、新增约定）见 `docs/BENCHMARKS.md`。

Windows（msys2/windows-gnu）注意：带 cc 构建依赖的 dev-deps
（criterion 0.8 → alloca）需要 ucrt64 工具链在 PATH **最前**
（`export PATH="/c/msys64/ucrt64/bin:$PATH"`），否则 gcc 子进程混载
mingw64 DLL 会**静默崩溃**（cc-rs 报 exit 1 无诊断）——与 ring 构建
的已知约束同源。CI（Linux）不受影响。

---

## 7. 编码与提交规范

- rustfmt 默认配置；clippy `--all-targets -D warnings`；公共项必须有
  `///` 文档（骨架的 `todo!()` 也要写清属于哪个里程碑、向量来源）。
- 骨架约定：未实现的函数体为 `todo!("Mx")`，参数先 `let _ = ...;`
  消耗掉避免 unused 警告；实现落地时删除。
- 提交信息 conventional 风格（`feat:`/`fix:`/`docs:`/`ci:`/`test:`），
  一个提交一个主题；里程碑完成时引用里程碑号。
- 分支：`main` 保持随时可发布；功能分支 `feat/m1-sha2` 样式。
- CI 是硬门：本地过不了的 PR 不提交。
- **MSRV**：`[workspace.package]` 的 `rust-version`（当前 **1.88**），
  按**标量回退路径**（`--no-default-features`）实测锚定；默认 `simd`
  feature 经 RUSTC_BOOTSTRAP 跟随当前 stable 的 core::simd 形态，
  **不承诺跨工具链版本可复现**（旧工具链可复现构建 =
  `default-features = false`）。调低前先实测（1.85 已证不可行），并
  同步 CI 的 `msrv` job（钉定精确版本）。
- **Cargo.lock 纪律**：lock 入库且为唯一被验证的依赖组合——CI cargo
  调用一律 `--locked`（唯一例外 fuzz job）。改 `Cargo.toml` 必须同一
  提交刷新 `Cargo.lock`。
- **发布路径**：tag push / 手动 dispatch 走 `publish` job，`needs`
  覆盖全部门禁 + `environment: crates-io`（需人工批准）；发布用
  `cargo publish --locked`，tag 必须与 crate 版本一致。破坏性 API
  变更先 bump workspace 版本（semver）再合入。

---

## 8. FIPS 相关红线（详细路线在 docs/FIPS.md）

- **边界 = `ferritls-core` 的特定版本快照**。边界内代码动一发就要
  重验证；边界内只放密码学必需品（`der` 解析属边缘，申报为“非安全
  相关的支撑功能”）。
- 认证三阶段：**A** 工程就绪（已完成）→ **B** 算法证书（ACVP
  production，需 NVLAP 实验室，数万至十几万美元级）→ **C** 模块验证
  （12–24+ 个月，按快照，年度重验证）。阶段 B/C 不阻塞功能发布；
  provider 可用性与认证状态解耦。
- README / crate 描述中关于 FIPS 的措辞模板："organized as a FIPS
  140-3 cryptographic module boundary; **not yet CMVP-validated**"。

---

## 9. 当前状态（2026-10）

M0–M7 与 M8.1–M8.5 全部完成（含 P1/P2 性能轮、参数化收口轮、CI/发布
加固轮、测试加固轮）；workspace 版本 0.9.0（**尚未发布**——下个 tag
即 v0.9.0，crates.io 已发至 v0.6.0）。逐项记录与数字见
`docs/ROADMAP.md`；下一步 = M8 余项按需排期（TLS 1.2 / aarch64 后端；
候选 X448 / P-521 / Ed448，出口条件草案见 ROADMAP「M8 发布后方向」，
动手前先细化）与 FIPS 阶段 B 准备（docs/FIPS.md §3）。

**实现级注记**（修订对应实现前必读；只记不变式、陷阱与守护测试）：

- `aes.rs`（位切片平面，P2）：电路函数按 `Plane` trait 泛型——`u64`
  实例 = 标量回退路径，`Simd<u64,L>` 实例 = simd 档位（64/128/256/512
  块按公开 n 分发，n≤64 恒走 u64 档）。改电路必须跑双 oracle
  （`bitslice_circuits_match_scalar_exhaustive` +
  `encrypt_ctr_batch_matches_scalar` 的档位边界组）；本 rustc 的
  `Simd<T,N>` 对 N 无 trait bound，未来 rustc 要求时需补 where 子句；
  计数器装载/提取按 64-lane 组进行，组数上限 8（512 块）。
  GF(2^8) 折叠约减严禁混入 GF(2^4) 关系（x⁴=x+1 属 GF(16)）；乘法
  折叠必须覆盖 x^9/x^11/x^13 全部奇次项——两类错误都实际踩过、由
  穷举测试（65536 对 + 256 S-box 值）拦截。
- `aes.rs`（性能路径选择，P1.5）：位切片电路的平面操作数按"批"固定
  （64 lane 共享），收益来自 lane 填充率——单块走该电路实测慢 2×，
  已回退；单块热点（CCM CBC-MAC、GCM J0/tag_base）用 `sub_bytes`
  16 宽单次掩码扫描（LLVM 自动向量化）。显式 `u8x16` 的
  `simd_eq`+`select` 掩码扫描在 crate 内联上下文实测慢 2.5×
  （`Mask::select` 掩码↔向量往返未被消除；独立编译理想也不作数）——
  单块保持标量掩码扫描，改动前先实测。改动任一路径后必须跑
  `encrypt_ctr_batch_matches_scalar` / `sub_bytes_matches_scalar`
  双 oracle。
- `chacha20poly1305.rs`（Simd 通道，P2）：`rotl` 的右移量必须是
  `32 − r` 而非 `r`——`(v<<r)|(v>>r)` 仅在 r=16 自对偶时凑巧正确
  （曾实际产出错误密钥流，12/8/7 全错，由标量 oracle 拦截）；通道数
  按 `cfg(target_feature)` 三档（16/8/4），改档后必须重跑
  `blocks4_matches_scalar_and_rfc_anchor` 与
  `keystream_xor_matches_scalar_all_shapes`（整批/填充批/标量尾）；
  填充批只消耗 `ceil(rem/64)` 块，counter 按实际消耗推进（公开量）。
- `chacha20poly1305.rs`（Poly1305 分组吸收，P1.5）：
  `absorb_zeropadded` 的 4 块分组循环余 0 时不得再补零填充块（曾产出
  多余块、由边界长度等价测试拦截）；`fold_mod_p` 的掩码选择要求被
  丢弃高位均已进位传播到下一字（donna 不变式），改字组顺序前先重推
  值保持论证。
- `sha2.rs`（消息调度，2026-09-17 三轮实测定稿）：**软流水形态为
  当前最优**——64 字数组 + `w[i+16]` 融合进主循环第 i 轮头部
  （完全展开后 `if i < 48` 是编译期常量），较两段式默认快 ~14%
  （445 MB/s，BENCHMARKS §5.6）。三条已实测否决的改写勿重复：
  16 字滚动窗口融合（默认/+avx2 慢 ~3–5%，§5.5）、16 字窗口分块
  调度（比软流水慢 ~9%，§5.6）、`std::simd` u32x4 组调度（默认无
  增益、+avx512 回归 ~7%，§5.7——压缩轮串行链无 lane 并行可开发）；
  宽 ISA 的 LLVM 决策漂移（+65%）属已知容忍项。
- `fields.rs::from_bytes_be_mod`：条件减 p 的"还原"选择语义——
  value ≥ p 时才以 tmp = value − p 替换 acc，否则 acc 本就正确
  （tmp 只是人质，勿写回）；曾被误写为 acc += p 造成全量污染。现为
  掩码选择（acc 是秘密累加器，禁止分支），`geq_canonical` 为全宽
  比较（趟数与值无关），改动前先跑 `from_bytes_oracle_*`。
- `der.rs::parse_pkcs8_private_key`：AlgorithmIdentifier 的
  parameters **按算法强制**——Ed25519 必须省略（RFC 8410 §7）、EC
  必须为 namedCurve OID（RFC 5480）、RSA 必须为 NULL（RFC 8017
  §A.1）；`[0]` attributes 之后不得有尾随字节。回归矩阵在
  `tests/rsa_and_der.rs` 的 `der_pkcs8_*`。
- `selftest.rs::run_power_on_self_tests`：单飞锁（`SELF_TEST_RUN`）
  保护**跨越 `run_kats()` 全程**——若在 KAT 前释放，并发后来者会
  看到 guard=true 而 STATUS 仍 NotRun，误报 "self-test did not run"
  （曾为真实缺陷，`concurrent_first_call_all_get_result` 守护；触及
  自检状态的单元测试须经 `STATE_LOCK` 串行化）。
- `backend-x86_64/src/sha.rs`：`ShaNi::detect()` 探测 `sha` +
  `ssse3` + `sse4.1` **三条**（kernel 的 `#[target_feature]` 三者
  全要；token 是对三者的证明）；`power_up_kat` 经显式 token 进入
  kernel，**KAT 通过后才** `bind_token`（失败实现的执行核心不得
  全局可达）。
- `ecdh.rs`/`sign.rs`（盲化）：标量盲化消耗 OS 熵——
  `mul_base`/`public_key`/`public_key_sec1` 返回 `Result`，熵失败
  传播 `Error::EntropyFailed` 而非 panic（§5.3；勿"简化"回 unwrap）。
- `ecdh.rs::x25519_ladder`：u 坐标导入后必须 `from_raw` 进 Montgomery
  域（曾漏掉 → 全错一个 R 因子）。
- `ecdh.rs::mul_point_pub`：公开标量 k 入口先 k mod n 规范化——k ≥ n
  时中间前缀使 add_or_copy 落入 madd 的 h=0∧r=0 退化（曾污染 r0）；
  `ladder`（blind 路径 d' = d + r·n）仍保留该理论例外前缀，触发概率
  ~2⁻²⁵⁶，已文档化。
- `sign.rs`（Ed25519）：`compress()` 仿射转换是 X/Z、Y/Z（非
  Jacobian 的 Z²/Z³），符号位取 `to_raw()` 后的规范奇偶；
  `curve_d()`（返回 `2d` 的 `&'static` 缓存）与 `base_point()` 均为
  `OnceLock` 缓存——旧形态每次 `add()` 现场派生 `2d`（Fermat 模逆
  ~500 域乘 × 每标量乘 ~1024 次加法）导致 sign/verify 26 ms，改回
  "每次计算"即回归 120 倍。d 与 G 是公开曲线常数，缓存无零化/ct
  顾虑；缓存值仍由同一派生式计算（向量测试零改动守护等价性）。
- `sign.rs`（ECDSA）：RFC 6979 步骤 d–g 共两次 K 重构（0x00 与 0x01
  分隔符各一次，第二次必须用更新后的 V）；候选 k 与 n 比较而非取模；
  模数 n 的 BE 字节直接取 `S::P`（严禁 from_raw——模数 mod 自身为 0）。
- `sign.rs`（RSA Garner）：`h = (sp − sq)·qInv mod p` 需先将 diff
  转入 Montgomery 域再乘 raw qInv；`diff + p` 的回绕进位恰出现一次
  且必须丢弃。
- `drbg.rs`（无 DF）：seed_material 按 seedlen 异或折叠（非截断）；
  Generate 末次 Update 无条件执行（AI 空则 0^seedlen）；官方流程 =
  Instantiate → Reseed → Generate → Generate。
- `mlkem.rs`（FIPS 203）：**encrypt 的 e₁ 必须在 NTT⁻¹ 之后于系数域
  加入**——曾把系数域 e₁ 与 NTT 域矩阵项混做一次逆变换（u 全错而 v
  全对，由 ACVP 封装向量拦截）；**§7.2 模校验不能写成
  `ByteEncode₁₂∘ByteDecode₁₂` 往返**——12 位位打包下往返恒等，实质
  检查是解码系数全部 < q（由负例测试拦截）；**KAT/向量必须用同一
  案例的完整五元组（d,z,ek,dk,m,c,ss 同源）**——keyGen 组与
  encapDecap 组 tcId 同号但密钥材料无关，跨组拼接会拼出"实现错误"
  假象；NTT⁻¹ 末尾乘 3303（= 128⁻¹）是 FIPS 203 原文常量，勿"改正"
  为 256⁻¹。
- `mlkem.rs`（三参数集泛化，M8.4）：参数差异不止 k——512 的 η₁=3、
  1024 的 (du,dv)=(11,5)，都曾按"三集同参"写错（768 全绿而 512/1024
  全错，由新代 ACVP 向量逐字节拦截）；参数表收敛在 `fips203_params`
  单一 const fn，禁止在引擎代码里硬编码 du 派生长度（一律 `32*du`/
  `32*dv`）；stable 下公开类型只能用裸 const 长度参数
  （`MlkemEncapsKey<EK>`），表达式 const 泛型需 generic_const_exprs
  （禁用）；`MlkemDecapsKey::from_bytes` 的模校验只覆盖 ek 的 t̂
  编码段（前 384k 字节），把尾部 ρ 一并送入 `as_chunks::<384>` 会
  误拒合法密钥（曾实际发生）。
- `sha3.rs`（FIPS 202）：SHAKE-128 rate = 168 字节（c=256）、
  SHAKE-256 rate = 136 字节（c=512）——与 SHA3-256 的 136/SHA3-512
  的 72 记混即全错（曾实际写错，由官方向量立即拦截）；`Keccak`
  结构体文档曾写错 rate，数值以各类型宏实例化处的文档字符串为准。
- `ccm.rs`（运行时标签长引擎）：**标签截断必须先于 S0 异或**
  （RFC 3610 §2.4/§2.5 顺序）——全 M 矩阵测试以「M=8 标签 ≠ M=16
  标签前 8 字节」显式断言守护；L 推广到 8 后 ctr_raw/cbc_mac 的长度
  域展开必须经 u64（L > 4 时移位量超 u32 域，曾触发 shift-overflow
  panic）；密文与 M 无关（CTR 不依赖 M）是既有性质，矩阵测试以前缀
  一致断言锚定；`Aes128CcmAny` 的 nonce/M 校验（7..=13 / {4..16
  偶数}）在 seal/open 双侧入口，open 侧非法参数返回 `InvalidInput`
  先于任何运算；固定类型（Aes128Ccm/Aes128CcmTls/Aes128Ccm8Tls）为
  薄包装、委托同一引擎——改引擎必须保既有 M=16 向量一行不改全绿
  （回归 oracle）+ 官方 24 向量直跑。
- `quic.rs`（适配层，M8.5）：`quic::Algorithm` 的密钥材料入口是
  rustls 的 `AeadKey`（`pub(crate)` 构造，第三方不可构造）——自家
  PacketKey/HPKey 构造函数必须直接收裸字节 `&[u8; N]`，trait impl
  内部才做转换，否则向量测试无从下手；`write_hs` 的 KeyChange 时序
  见 §4；interop 内存回环 `drive` 必须逐包投递 + 每包后 flush 接收端
  （KeyChange 在本端 `write_hs` 才被消费安装，整批投递会在对端升级前
  送抵高层级包，曾以 "rx keys" panic 拦截）。
- `hkdf.rs`（RFC 5869 符合性，2026-11）：`expand_*` 拒绝
  `prk.len() < HashLen`（`InvalidInput`）——此前静默接受短 PRK；
  TLS 1.3 密钥调度走 rustls `HkdfUsingHmac` 不经此模块，改动只影响
  边界内公开 API（tests/hkdf.rs + wycheproof hkdf 组钉住）。
- `fields.rs`（from_bytes_le_mod 修复，2026-11）：条件减的选择语义
  必须与 from_bytes_be_mod 一致——LE 旧实现只看
  `geq_canonical(acc) && borrow==0`，漏掉倍增移位出 carry 的归约
  （carry=1 ⟹ value ≥ p 恒成立，须以回绕 tmp = acc − p + 2^(64n)
  归约）；曾产出未归约错误值，由超长导入 oracle
  （`from_bytes_oracle_overlength_*`）拦截——定长 oracle 的触发
  窗口 ~2⁻²⁴/步故此前未暴露。改任一 from_bytes_* 前先跑定长 +
  超长双 oracle。
- `sign.rs`（RSA 装载校验层级，2026-11）：对齐 BoringSSL 解析期
  `RSA_check_key` 层级——CRT 分量下界 ≥2、d mod (p−1) == dp、
  d mod (q−1) == dq（等式同时强制完全约简）、e·d ≡ 1 mod (p−1) 与
  mod (q−1)（等价于 mod λ(n)，无需大数长除）；d 字节长度上限
  n_bytes + 8（d0 < λ < n，+8 容纳 d0 + k·λ 的合理编码）。素性、
  √2 下界、|p−q| 距离与 n 小因子检验属 SP 800-56B 生成期层级，
  **不在装载路径**（OpenSSL 同为 opt-in/生成期）。校验块操作密钥
  文件材料、装载时一次，不涉消息级秘密（§5.1 纪律针对每消息运算）。
- `sign.rs`（verify_pss 盐长，2026-11）：由"盐长 = 哈希长度"放宽为
  按 RFC 8017 编码严格解码任意盐长（PS 全零 + 首个非零字节必须为
  0x01，salt 为其后任意长度）；MGF1 哈希仍固定同消息哈希（API 面
  约定，Wycheproof pss_misc 的 DistinctHash 组被裁剪过滤）。放宽
  只影响验证接受面（更合规）， wycheproof pss 组 18 例全绿钉住。

修订实现前重读 §5 与上述注记；下一步动手前先细化 ROADMAP「M8 发布后
方向」的出口条件草案。
