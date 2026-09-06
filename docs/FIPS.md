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
