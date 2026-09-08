# FIPS 140-3 路线：边界定义、工程要求与认证三阶段

> **当前状态声明（必须保留在任何派生宣传中）**：ferritls **尚未**通过
> CMVP 认证，`fips` feature 表示“按 FIPS 批准模式运行”，不是认证声明。
> 截至 2026-09，**没有任何纯 Rust 密码模块通过 CMVP 认证**（最近先例
> 是 Go 标准库模块：CAVP 证书 A6650，2025-05 进入 Modules-In-Process）。

## 1. 模块边界

**边界 = `ferritls-core` crate 的一个锁定版本快照（编译产物）。**

- 边界内：全部密码学算法实现、DRBG、自检、DER 密钥解析（申报为支撑
  功能）、常数时间工具。
- 边界外：rustls、适配层、测试、互操作 crate。
- 边界内依赖白名单（新增须更新本表并过 PR 评审）：

| 依赖 | 用途 | 审计/验证状态 |
|---|---|---|
| subtle | 常数时间原语 | Quarkslab 对 dalek 系审计（2021）覆盖 subtle |
| zeroize | 秘密零化 | 体量极小，社区广泛使用；无已知公告 |
| getrandom | OS 熵（边界外输入） | 广泛审计（rustls 自身依赖链） |

- P2 起 `simd` 默认 feature 使用标准库 `core::simd`（portable_simd）
  的显式向量类型：**属 std，不是第三方依赖，白名单不变**；在 stable
  工具链上经 `RUSTC_BOOTSTRAP=1` 启用 `#![feature(portable_simd)]`
  编译（仓内 `.cargo/config.toml [env]` / CI env / 下游自带 env 三
  途径，`default-features = false` 可整体退出回标量路径）。portable_
  simd 稳定后该 env 依赖拆除。送审快照须连同该环境变量与目标特性
  一并记录（见 §6.1/§6.5）。

- 快照纪律：送审版本 `--locked` + 固定工具链构建；发布产物与送审产物
  可复现比对。**边界内任何源码改动都会使证书失效**，需要重验证或走
  CMVP 更新流程（Go 的先例：约每年重验证一次）。

## 2. 工程要求清单（阶段 A：M0–M7 内完成）

FIPS 140-3（ISO/IEC 19790）对软件模块的核心要求与我们的对应物：

| 要求 | 对应物 | 里程碑 |
|---|---|---|
| 上电自检（KAT per 批准算法 + 完整性测试） | `selftest` 模块；失败进入错误状态拒绝服务 | M5 |
| 批准的 RBG（SP 800-90A） | `drbg`：AES-256-CTR CTR-DRBG，每次生成以 128 位 OS 熵重播种 | M5 |
| 批准算法-only 的服务模式 | `fips` feature + `fips_mode_provider()` 套件清单 | M7 |
| SSP 零化 | ZeroizeOnDrop 清单（ARCHITECTURE.md §6） | M5 审计 |
| 算法实现与 CAVP/ACVP 向量一致 | tests/vectors/ + ACVP demo CI runner | M1–M7 |
| 密钥建立按批准方法（SP 800-56A） | P-256/384 ECDH；X25519 排除出批准模式 | M3 |
| 安全策略文档（SP 800-140Br1 结构） | 本文件持续演进为送审底稿 | 持续 |

批准/非批准算法表见 `ferritls-core/src/policy.rs`（SP 800-52r2 口径）。

## 3. 认证三阶段

### 阶段 A：工程就绪（现在 → M7，零外部成本）

边界、自检、DRBG、零化、门控、向量、文档。完成即“FIPS-ready”，
对下游的承诺止于“具备送审条件的工程形态”。

### 阶段 B：算法证书（CAVP/ACVP，需外部主体）

- 需要注册主体 + NVLAP 认可实验室（atsec / UL / Lightship / Acumen /
  Gossamer 等询价）。
- 流程：能力声明 → ACVP production 向量（仅实验室通道）→ 算法证书。
- 先用 ACVP demo server + 官方发布的静态向量集在 CI 预演（M7 建成）。
- 费用量级：实验室服务数万至十几万美元（无 NIST 官方费用；以报价为准）。

### 阶段 C：模块验证（CMVP）

- SP 800-140Br1 安全策略 → 实验室测试（ISO/IEC 24759）→ 提交 →
  Modules-In-Process → 证书（预期 12–24+ 个月，参考 Go 模块进度）。
- 证书落地后：在**锁定的快照版本**上引入 `fips-validated` feature，
  翻转 rustls `fips()` 语义为 `true`；其他版本仍为 `false`。
- 目标安全等级：Level 1（软件库的现实选择；Go/AWS-LC/wolfCrypt 的
  软件模块均为 L1）。
- 纯 Rust/无汇编的真实收益：实验室的源码审查范围内没有手写汇编需要
  注释证明——降低审查工作量，不降低要求。

## 4. 与 rustls 生态的 FIPS 现状对比

| 选项 | 状态 |
|---|---|
| rustls + aws-lc-rs `fips` feature | 当前唯一可用路径（AWS-LC-FIPS 证书 #4662/#5132 系列），C/汇编实现 |
| rustls + ring | 无 FIPS 声明 |
| rustls + rustls-rustcrypto | 明确声明非 FIPS |
| **rustls + ferritls** | 阶段 A（工程就绪）→ 目标阶段 C |

## 5. 风险登记

- **无先例风险**：首批纯 Rust 送审者会遇到实验室对 Rust 工具链/构建
  可复现性的额外盘问；对策：提前与实验室沟通工具链锁定方案，参考 Go
  模块的安全策略文档结构。
- **周期错配**：认证与开发解耦（AGENTS.md §8）；provider 功能发布
  不等证书。
- **FIPS 140-2 → 140-3 过渡期实验室产能紧张**（2026-09 起 140-2 模块
  转 Historical）：询价排期要趁早。
- **算法面演进**：SP 800-227（混合密钥建立）落地后，X25519MLKEM768
  是 X25519 进入批准模式的通道（M8+ 预研，依赖 ML-KEM 实现与验证）。

## 6. 安全策略底稿（SP 800-140Br1 结构，阶段 B/C 送审文档的骨架）

> 本节按 SP 800-140Br1 派生测试要求对应的安全策略章节组织，随实现
> 演进持续补全；**证书落地前不对外构成任何合规声明**。

### 6.1 密码模块规格（SP 800-140C §1）

- 模块：`ferritls-core`，纯软件实现（Software），版本 = crate 0.1.x
  的锁定源码快照 + `--locked` 依赖 + 固定 Rust 工具链（含
  `RUSTC_BOOTSTRAP=1` 编译环境与 `simd` feature 档位，P2 起）。
- 类型：多芯片独立独立软件模块；总体安全等级目标 Level 1。
- 批准模式：`fips` feature 编译单元，由 `policy::Approval` 与
  `fips_mode_provider()` 门控；非批准算法（X25519、Ed25519、
  ChaCha20-Poly1305）在批准模式下不出现在套件清单中。
- 模块边界：crate 编译产物；无 C/汇编/`unsafe`（crate 级
  `#![forbid(unsafe_code)]`）。

### 6.2 端口与接口（§2）

软件模块无物理端口。逻辑接口 = `ferritls-core` 公共 API：数据输入/
输出（密钥、消息、密文）、控制输入（模式选择）、状态输出
（`Error` 枚举）。TLS 协议行为属边界外（rustls + 适配层）。

### 6.3 角色、服务与认证（§3）

- 角色：单一操作者角色（Crypto Officer / User 合一，软件库惯例）。
- 服务：全部公开 API（见 ARCHITECTURE 模块地图）；不经认证即全部
  可用（Level 1 无认证要求）。
- CSP 访问：私钥/标量/共享秘密仅经 ZeroizeOnDrop 类型持有，不落盘。

### 6.4 物理安全（§4）

不适用（纯软件模块）。

### 6.5 操作环境（§5）

- 修改性：非可修改（Non-Modifiable）——库以编译产物分发，不含
  脚本解释器。
- 环境：Rust 工具链目标平台（win/linux/macos，x86_64/aarch64）；
  送审时锁定 rustc 版本、目标三元组与编译环境（P2 起 `simd` feature
  需 `RUSTC_BOOTSTRAP=1`；ChaCha20 通道宽度由目标特性决定，快照须
  记录所用 target-feature 组合）。无 OS 服务依赖（熵除外）。

### 6.6 密码算法（§6，SP 800-140D 口径）

| 算法 | 标准 | 状态（批准模式） | 证书 |
|---|---|---|---|
| AES-128/256-GCM | SP 800-38D | 批准 | 待 CAVP（阶段 B） |
| AES-128-CCM | SP 800-38C | 批准 | 待 CAVP |
| SHA-256/384/512 | FIPS 180-4 | 批准 | 待 CAVP |
| HMAC-SHA-2 | FIPS 198-1 / SP 800-107r1 | 批准 | 待 CAVP |
| HKDF-SHA-2 | SP 800-56C r2 | 批准 | 待 CAVP |
| ECDSA P-256/384 | FIPS 186-5（RFC 6979 nonce） | 批准 | 待 CAVP |
| RSA-PSS / RSA-PKCS#1（验证与签名） | FIPS 186-5 | 批准（PKCS#1 v1.5 仅限遗留验证用途，SP 800-131Ar2 口径） | 待 CAVP |
| AES-256-CTR DRBG | SP 800-90A | 批准（RBG） | 待 CAVP |
| ECDH P-256/384 | SP 800-56A r3 | 批准（KAS） | 待 CAVP |
| X25519、Ed25519、ChaCha20-Poly1305 | — | 非批准（Allowed but not approved） | — |

### 6.7 密钥管理（§7）

- 密钥生成：ECDSA/ECDH 标量由 DRBG（批准 RBG）生成，私钥算术上
  处于 [1, n−1]；RSA 密钥生成不在边界内（密钥经外部加载，M4 记录）。
- 密钥建立：ECDH 单向静态-短暂/短暂-短暂（TLS 1.3 语义），
  公钥做在曲线检查；共享秘密全零拒绝（小阶点）。
- 密钥输入/输出：PKCS#8 DER 解析（边界内，申报为支撑功能）；
  明文密钥不出现在日志/错误（错误枚举不含秘密内容）。
- 零化：全部持 CSP 类型实现 `Drop`→zeroize（ARCHITECTURE §6 清单）；
  中间值按作用域清零。
- 密钥存储：无持久化（内存库）。

### 6.8 EMI/EMC（§8）

不适用（纯软件模块）。

### 6.9 自检（§9）

- 上电自检（`selftest::ensure_passed`，任一失败进入错误状态拒绝
  服务直至重置）：
  - 已知答案测试：SHA-256/384/512、HMAC-SHA-256、HKDF-SHA-256、
    AES-128/256-GCM（加解密+篡改检测）、AES-128-CCM（往返+篡改）、
    ECDSA P-256 签名/验证（RFC 6979 KAT）、RSA-PSS/SPKI 链路 KAT、
    DRBG CAVP 流程 KAT；
  - 完整性测试：阶段 B 送审形态为校验和方案（软模块惯例），当前
    以 KAT 全绿 + `--locked` 构建近似，送审前补齐。
- 条件自检：DRBG 健康测试（RCT C=3 + 有界 APT，实例化时执行）；
  DRBG 每次生成前以 128 位 OS 熵重播种（Go 模块同策略）。

### 6.10 设计保证（§10）

- 配置管理：git 单一 main 分支 + conventional commits + 锁定快照
  （送审 tag）；CI（fmt/clippy/三平台 test/deny）为提交门禁。
- 文档：本文件 + ARCHITECTURE.md + AGENTS.md（含实现陷阱清单）。
- 开发工具：cargo/rustc 锁定版本；无第三方构建脚本进入边界。

### 6.11 其他攻击缓解（§11）

- 侧信道：常数时间纪律（AGENTS §5.1；比较/选择用 subtle，
  蒙哥马利阶梯固定模式，ECDSA 标量盲化，RSA 幂运算 scratch select
  + Garner 回绕掩码选择）——软实现残余风险在 README 声明；RSA
  私钥运算乘法盲化已落地（M4c：单次随机 r ∈ [1,n)，EM′ = EM·rᵉ
  后 CRT，r⁻¹ 去盲，中间值零化）。GHASH 乘法：P1 性能轮（2026-09）
  按 §5.1 查表二分判据由逐位实现改为 H 倍数 4-bit 表（索引仅公开
  AAD/密文/长度字节，访存模式与秘密无关）；AES 批量加密方向为
  位切片纯布尔电路（零查表；P2 起平面运算为显式 `core::simd`
  向量类型，批量档位按公开请求长度选择），单块方向为 16 宽单次
  全表掩码扫描（P1.5；访问模式与输入无关；P2 曾试显式 `u8x16`
  实测回退已撤销，保持 LLVM 自动向量化的标量形态）；ChaCha20
  批处理通道为显式 `Simd<u32, C>`（P2；C 由编译期目标特性决定，
  不依赖秘密）；Poly1305 4 块分组吸收为纯字组算术（P1.5，无查表、
  无秘密条件分支）。
- 攻击者可控输入不 panic：Wycheproof 2349 用例 + fuzz CI（M7）。
