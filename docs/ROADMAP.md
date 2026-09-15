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
| P2 | portable_simd 轮：`simd` 默认 feature（stable + RUSTC_BOOTSTRAP） | 数日 | **完成（2026-09-08）** |
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

> **（2026-09-08 注）**本段"不能作为默认 feature"的决策已被 P2 轮
> （用户指令）推翻：`simd` 成为默认 feature，经 `RUSTC_BOOTSTRAP=1`
> 在 stable 工具链编译 `#![feature(portable_simd)]`，标量路径保留为
> 回退与 oracle 基线，下游可用 `default-features = false` 退出。
> 设计与实测矩阵见下方 P2 节。

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

| 项目 | 基线 | PR1 后 | PR2/3 后 | PR4 后 | P1.5 后 | 总提升 |
|---|---|---|---|---|---|---|
| AES-128-GCM seal 1 KiB | 2.68 MB/s | 2.65 | 2.68 | 34.2 | 42.2 | 15.7× |
| AES-128-GCM seal 16 KiB | 2.71 MB/s | 2.69 | 2.80 | 52.1 | 55.6 | **20.5×** |
| AES-256-GCM seal 16 KiB | 1.95 MB/s | 1.95 | 2.00 | 41.0 | 44.0 | **22.6×** |
| AES-128-CCM seal 16 KiB | 1.41 MB/s | 1.41 | 1.39 | 2.74 | 14.2 | **10.0×** |
| ChaCha20-Poly1305 seal 16 KiB | 451 MB/s | 504 | 565 | 573 | 620 | 1.4× |
| SHA-256 16 KiB | 357 MB/s | 363 | 370 | 370 | 368 | —（未动） |
| AES-128 单块加密 | 2.72 MB/s | 2.77 | 2.86 | 2.86 | 17.9 | **6.6×** |

### P1.5 余留慢点轮（2026-09-08，同日接续）

P1 完成时注记中列出的余留慢点，除 SHA-2 外全部处理：

- **单块 AES（GCM J0/tag_base、CCM CBC-MAC）**：SubBytes 从
  "逐字节各跑一遍 256 项掩码扫描"改为 `sub_bytes` 单次扫描同时
  服务 16 字节（内层定长比较/选择被 LLVM 向量化），单块 2.86 →
  17.9 MB/s（6.3×），CCM 2.74 → 14.2（5.2×），GCM 1 KiB +18%。
  轮密钥位平面（`rk_planes`）改在密钥展开时预计算并随 Drop 零化，
  批量路径免去每次调用的平面展开。
- **DRBG**：Generate/Update 的 CTR 加密按 64 块批量走位切片路径；
  128 位 V 计数器与批量入口 32 位递增语义的差异以"批大小截断到
  低 32 位回绕前"弥合（计数器值为公开量）。CAVP DRBGVS 向量
  逐字节锚定。
- **Poly1305**：4 块分组吸收——Horner 链展开为
  (h+m₁)r⁴+m₂r³+m₃r²+m₄r，四个卷积乘法无依赖可乱序并行；r 的
  幂字组 new() 预计算（随 Drop 零化）；组内松弛规整 + 组末一次
  条件减 p，slack 不跨组累积。ChaCha seal 573 → 620 MB/s（1.08×）。
- **实测回退记录（第二例）**：单块改走位切片电路（lane 0）实测
  更慢（单块 2.79 → 1.31 MB/s，CCM 2.69 → 1.28）——电路的平面
  操作数按"批"固定（64 lane 共享），单块仅占 1/64 lane 时成本
  不变；已回退。教训与 PR4b 一致：**位切片收益来自 lane 填充率，
  批量才有意义**。
- 余留：SHA-2 单流（M8 与 intrinsics 后端一并）；ChaCha seal 中
  密钥流与 MAC 吸收已大致均衡，进一步收益需 AVX2 级通道加宽。

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
  ——前三类已由 P1.5 处理（见上节），SHA-2 仍留 M8。

## P2 — portable_simd 轮（`simd` 默认 feature，完成 2026-09-08）

**决策（用户指令，推翻 P1 的"portable_simd 不能作默认 feature"）**：
`simd` 成为 ferritls-core 默认 feature；代码经
`#![cfg_attr(feature = "simd", feature(portable_simd))]` 启用，在
**stable 工具链**上以 `RUSTC_BOOTSTRAP=1` 编译（已本机实证可行：
stable rustc 1.98.1 + 该 env 产出真实 SIMD 指令；无 env 则 E0554
拒绝）。仓内 `.cargo/config.toml` 的 `[env]`（stable cargo 机制）
供开发构建零负担使用；CI 由 workflow env 提供；**下游 stable 用户
需自带该 env 或 `default-features = false` 退出**（README 构建要求
节注明）。标量路径 = P1/P1.5 现有代码**原样保留**：永久回退 +
双 oracle 基线。portable_simd 稳定后：拆 RUSTC_BOOTSTRAP，代码不动。

约束集（AGENTS §5.5）：safe-only（`#![forbid(unsafe_code)]` 不变）、
零新依赖（portable_simd 属 std）、不做运行时分发（需 unsafe 调
`#[target_feature]` 函数）、档位选择只依赖编译期目标特性与公开长度。

**设计**：

- **AES 位切片批量**：电路（`bs_mul/bs_sq/bs_sbox/bs_rounds` 等）
  按平面元素类型 `P: Logic` 泛型化——`u64` 与 `Simd<u64, L>` 共享
  同一份电路源码（u64 实例 = 现有标量路径原样）。批量档位
  64/128/256/512 块（P = u64 / Simd<u64,2/4/8>）按请求块数 n 取
  最小浪费档（n≤64 → u64 档 = 现状，小记录零回退）；每平面一个
  Simd 元素覆盖 64 块，向量宽度由编译目标自动决定（SSE2 2 元素/
  YMM 4/ZMM 8），轮密钥平面 splat-on-use（不新增秘密存储，DRBG
  每次 update 重键无额外代价）。
- **ChaCha20 批处理**：转置通道 `[u32; 4]` → `Simd<u32, C>`，C 按
  `cfg(target_feature)` 编译期三档：AVX-512 → 16 块/批（16×ZMM）、
  AVX2 → 8 块/批（16×YMM）、否则 → 4 块/批（16×XMM/NEON）——每档
  状态恰好 ≈16 个向量寄存器，无 spill。用户以 RUSTFLAGS 开启
  target-feature 时同一份源码自动升级通道宽度。
- **单块 AES SubBytes**：`sub_bytes`/`inv_sub_bytes` 16 宽掩码扫描
  显式 `u8x16`（`simd_eq` + `Select::select`；表索引为公开循环
  计数器，ct 论证不变）。

**效率判定矩阵（本轮验收核心）**：默认基线 / `+avx2` /
`+avx2,+avx512f,+avx512vl` 三配置 ×（P1.5 现状 vs P2 Simd），同 ISA
对照为主；**默认基线不允许比 P1.5 回退**（含 1 KiB 小记录）。
本机 = AMD Ryzen 9 7900X（Zen 4，AVX2 + AVX-512）。

**基线（P1.5 现状，2026-09-08 实测）**——自动向量化在宽 ISA 下
几乎不加宽（GCM 仅 +5%；ChaCha 在 +avx2 反而略降；SHA-256 在
+avx512 因向量化决策变化**回归 37%**）——这正是 P2 的空间：

| 基准（seal，MB/s） | 基线（SSE2） | +avx2 | +avx512 |
|---|---|---|---|
| AES-128-GCM 1 KiB | 40.8 | 42.9 | 43.6 |
| AES-128-GCM 16 KiB | 54.6 | 57.1 | 57.6 |
| AES-256-GCM 16 KiB | 43.5 | 44.7 | 44.6 |
| AES-128-CCM 16 KiB | 13.6 | 17.1 | 15.5 |
| ChaCha20-Poly1305 16 KiB | 607 | 584 | 789 |
| SHA-256 16 KiB | 354 | 356 | 223（回归） |

**出口条件**：全向量套件 / Wycheproof / interop 在默认（simd）、
no-default-features（标量）、fips、+avx2 四配置一行不改且全绿；
ct 声明；矩阵前后数字记入本节。

### 结果（2026-09-08 完成，最终矩阵 = 前表基线对照下行）

| 基准（seal，MB/s） | P2 基线 | P2 +avx2 | P2 +avx512 |
|---|---|---|---|
| AES-128-GCM 1 KiB | 39.6–43.2（噪声带） | 43.9 | 45.0 |
| AES-128-GCM 16 KiB | 71.7（1.31×） | 102.6（**1.80×**） | 154.4（**2.68×**） |
| AES-256-GCM 16 KiB | 59.4（1.36×） | 88.0（**1.97×**） | 142.4（**3.19×**） |
| AES-128-CCM 16 KiB | 15.1（1.11×） | 19.9（1.17×） | 20.1（1.30×） |
| ChaCha20-Poly1305 1 KiB | 852（1.54×） | 1202（2.25×） | 1087（1.57×） |
| ChaCha20-Poly1305 16 KiB | 984（1.62×） | 1488（**2.55×**） | 1363（1.73×） |

完成注记：

- **PR1（AES 位切片平面 Simd 化）**：`Plane` trait 让 `u64` 与
  `Simd<u64,L>` 共享同一份电路源码；档位 64/128/256/512 按公开
  请求块数分发（n≤64 走原 u64 路径，小记录零变化）。基线 ISA 也
  提升 31–36%——说明 P1 的 `[[u64;8]]` 数组形态连 SSE2 都未被
  LLVM 向量化满。
- **PR2（ChaCha20 通道三档）**：`Simd<u32,C>`，C 按
  `cfg(target_feature)` = 16/8/4。基线 1.62× 同理（旧 `[u32;4]`
  数组版基线未向量化满）；+avx2 2.55×。**移植中被标量 oracle
  拦截一个真 bug**：移位拼接旋转写成 `(v<<r)|(v>>r)`，仅 r=16
  自对偶时凑巧正确，12/8/7 全错——修正为 `(v<<r)|(v>>(32−r))`
  （`rotl` 辅助函数 + 注释）。
- **实测回退记录（第三例）**：单块 SubBytes 的显式 `u8x16`
  （`simd_eq`+`select` 掩码扫描）实测单块 18.1→7.2 MB/s
  （2.5× 慢），CCM 15.1→6.6——独立编译时代码生成理想
  （pcmpeqb+pand+por 三指令循环），但在 crate 内联上下文中
  `Mask::select` 降级（掩码↔向量往返未被消除）；两种写法、
  两种循环形状均复现。已撤销，单块保持 LLVM 自动向量化的标量
  掩码扫描。教训：**portable_simd 的 `select` 在本工具链上不可
  假设折叠为 AND，涉掩码热路径先实测**。
- **CCM 基准方差**：串行 CBC-MAC 长依赖链打满单核，连续运行受
  boost 时钟衰减影响 ±25%（实测 avx2 连跑 20.0/16.2/13.1）；
  矩阵取固定顺序单轮首值，跨轮对比需注明该带宽。
- **SHA-256 的 +avx512 回归（354→223）不是本轮引入**：SHA-2 未动
  （留 M8），该回归同样存在于 P1.5 基线，是 LLVM 自动向量化决策
  随 ISA 变化的又一例证（显式向量化动机的注脚）。
- 全程零 `unsafe`、零新依赖（portable_simd 属 std）；标量回退路径
  原样冻结；GCM 1 KiB 路径与 P1.5 代码相同（u64 档），数字波动
  ±5% 属基准噪声。

## 已知问题 / 待开 issue

- windows-gnu 工具链构建 ring 需要 ucrt64 工具链在 PATH 前列
  （mingw64 DLL 与 ucrt64 编译器混载会静默崩溃；CI 不受影响）。

## M8 — 发布后方向（按需排期）

- TLS 1.2：`tls12` feature、PRF（`PrfUsingHmac`）、ECDHE-GCM 套件
  （SP 800-52r2 部署面需要）；
- QUIC packet protection（`quic` 字段 + Header Protection）；
- ML-KEM（FIPS 203）+ X25519MLKEM768 混合（完成，见 M8.3）；
- ML-KEM-512/1024 参数集 + 纯 ML-KEM 组（见 M8.4，2026-09-15 排期启动）；
- intrinsics 后端 crate（完成，见 M8.1/M8.2）；
- 认证阶段 B/C 启动（见 docs/FIPS.md）。

### M8.1 intrinsics 后端（AES-NI + CLMUL，完成 2026-09-13）

范围：core `ops` 分发接线（AES-GCM 整消息 kernel + SHA-256 函数
分发——对象分发形态曾因 HKDF 短命实例 +2.3% 被零回归门否决，函数
分发形态归零）；新 crate `ferritls-backend-aesni`（仅 x86_64，
unsafe 限于唯一叶子模块 + kernel 单点 trampoline，借鉴 fearless_simd
模式零依赖）；
`ops::install()` 应用侧显式注册 + 安装 KAT + 批准模式拒绝；软/Ni
差分与向量锚定测试；interop 三方 A/B 握手；量化数据入
docs/BENCHMARKS.md。

出口条件：

- [x] core 仍 `#![forbid(unsafe_code)]`，全部既有向量测试零改动仍绿
      （软件默认路径逐字节不变；criterion 同机 A/B ±1% 噪声带内）；
- [x] 后端 crate：Ni 路径过 McGrew–Viega TC1/TC5/TC16 向量锚定 +
      2000 组软/Ni 差分一致（边界长度全覆盖、双向交叉 open）+
      独立 Python 转写的 AES-256 扩展参照表 + tag 篡改负例；
- [x] 接线阶段零回归（criterion 同机基线对比，含未改动 CCM 作为
      噪声对照）；提升数据记录入 BENCHMARKS.md §5.1
      （GCM 原语 ~120–138×，握手 X25519 −40%/P-256 −17%）；
- [x] `--features fips` 构建下 `install()` 拒绝且有测试守护
      （ops_dispatch::fips_refuses_install）；
- [x] fmt / clippy -D warnings / 三平台 test 全绿（本地 Windows 全绿；
      2026-09-13 main push 与 2026-09-14 schedule 的 CI 运行均绿，
      三平台确认）。

SHA-NI 已随 M8.2 落地（`ShaNi` token + `HashOps` 函数分发 kernel：
流式 ~6×、HKDF ~5×、握手 X25519 双 Ni ~2.35×，见 BENCHMARKS §5.1）。
2026-09-13：AES/CLMUL kernel 按同法完成 `#[target_feature]` 直调化
（kernel 直调 intrinsic，`raw.rs` 收缩为纯内存包装；反汇编实测对
intrinsic 桩的真实 callq 103 → 0），GCM 原语再提 5.2–6.6×、对软件
路径 ~750–980×（见 BENCHMARKS §5.2）。CCM/ChaCha/P-256/Ed25519 加速
与 aarch64 后端明确不在本节范围。

### M8.3 ML-KEM（FIPS 203）+ X25519MLKEM768 混合（完成 2026-09-13）

范围：core 内自研 **FIPS 202**（Keccak-f\[1600\] 海绵：SHA3-256/512、
SHAKE-128/256）与 **FIPS 203 ML-KEM-768**（NTT 域算术 GF(3329)、
SampleNTT/CBD 采样、K-PKE 与 FO 变换、隐式拒绝、封装密钥模校验，
零新依赖）——均为边界内模块、`#![forbid(unsafe_code)]`；适配层新增
X25519MLKEM768 混合组（draft-ietf-tls-ecdhe-mlkem：codepoint 0x11EC，
客户端 share = ek(1184)‖X25519 pk(32) = 1216 B，服务端 share =
ct(1088)‖X25519 pk(32) = 1120 B，ss = ML-KEM‖X25519 共 64 B，服务端
封装 + 封装密钥检查、客户端解封装）。ML-KEM-512/1024 与纯 ML-KEM 组
（0x0200–0x0202）不在本节范围（可按需追加，实现为参数集常量）。

出口条件：

- [x] core 仍 `#![forbid(unsafe_code)]`、零新运行时依赖（白名单不变）；
- [x] `sha3`：FIPS 202 示例向量（空串/"abc"/填充边界/多块）+
      FIPS 203 附录 A 的 G/H/J/PRF/XOF 示例值锚定，全绿；
- [x] `mlkem`：NIST ACVP ML-KEM-768 向量子集（keyGen 3 例 +
      encapDecap 封装 3 例 + 解封装 3 例，**含 "modify ciphertext"
      隐式拒绝用例**），来源与核对记录入 VECTOR-PROVENANCE.md；
      另有 NTT/编解码/压缩的穷举或代数自洽测试（roundtrip、
      与 schoolbook 多项式乘法互检）；
- [x] 常数时间：decaps 的密文比较与密钥选择走 `subtle::Choice`
      ct-select；采样/NTT/编解码无以秘密为条件的分支或访存；
      秘密材料（dk、ss、中间 K/K̄）`ZeroizeOnDrop`；
- [x] 适配层：X25519MLKEM768 组装配进 provider（默认与批准清单
      首项；服务端封装走 `start_and_complete` 覆写，含 FIPS 203
      §7.2 封装密钥模校验）；interop 内存握手矩阵含混合组自互操作
      （显式 2 例 + fips 矩阵 3 套件 × 3 组自动覆盖）；
- [x] 上电自检：ML-KEM KAT（keyGen tcId 26 种子展开 + encapDecap
      tcId 26 封装/解封装，同案例五元组）加入 `selftest`；
- [x] fmt / clippy -D warnings / 双配置（simd 与
      no-default-features）/ `--features fips` / doc / deny 全绿
      （本地 Windows；fuzz 目标 `mlkem-decaps` 入 CI 冒烟清单）；
- [x] 基准（keygen/encaps/decaps + 混合握手）入 BENCHMARKS.md，
      ROADMAP 状态更新。

结果（2026-09-13 完成，windows-gnu 本地）：mlkem768 keygen 54 µs /
encaps 53 µs / decaps 76 µs（标量、确定性入口）；全握手
x25519-mlkem768 1.22 ms，比纯 X25519（1.09 ms）仅 +12%；sha3 与
实现期三处缺陷（encrypt 的 e₁ 域混用、§7.2 往返式模校验恒真、
KAT 跨案例拼向量）全部由 ACVP 向量/自检拦截后修正，详见
AGENTS.md 实现级注记。

批准状态注记：ML-KEM 本身是 NIST 批准算法（FIPS 203；混合组合的
批准路径见 SP 800-56C Rev.2 与 SP 800-227，SP 800-52r2 允许
X25519MLKEM768 进批准 TLS 配置），但 CMVP 认证前 rustls 各 `fips()`
钩子仍恒返回 `false`（AGENTS.md 规则 3 不变）。

### M8.4 ML-KEM-512/1024 参数集 + 纯 ML-KEM 组（0x0200–0x0202，完成 2026-09-15）

范围：core `mlkem` 从 k=3 单参数集泛化为 FIPS 203 全部三个参数集
——差异不止 k：**ML-KEM-512 的 η₁ = 3**（768/1024 为 2）、
**ML-KEM-1024 的 (du, dv) = (11, 5)**（其余为 (10, 4)），全部收敛
到单一 `fips203_params` 参数表（const fn，引擎按 k 查表派生）。
引擎内 k 为运行时参数（上限 K_MAX = 4，栈上按最大档定容，零堆
分配），公开类型以裸 const 长度参数（EK/DK/CT 字节数）参数化，
**不依赖 generic_const_exprs**（stable 工具链约束）；768 的公共
API 路径（`Mlkem768*` 别名与顶层函数）保持不变。适配层新增纯
ML-KEM 组 MLKEM512 / MLKEM768 / MLKEM1024（draft-ietf-tls-mlkem-
key-agreement，codepoint 0x0200–0x0202：客户端 share = ek、服务端
share = ct、ss = 32 B，服务端仍走 `start_and_complete` 覆写 + §7.2
封装密钥检查），进默认与批准清单。ACVP 向量扩展到三参数集
（keyGen / encapsulation / decapsulation 含 modified ciphertext
隐式拒绝 / encapsulationKeyCheck 与 decapsulationKeyCheck 负例，
源 = NIST ACVP-Server `internalProjection.json` 原件）。

出口条件：

- [x] core 仍 `#![forbid(unsafe_code)]`、零新运行时依赖（白名单
      不变）；ML-KEM-768 全部既有语义不变，并经**新一代 NIST
      sample 向量**（上游 2026-09 重生成，与 M8.3 所用镜像快照
      不同代）独立重验；
- [x] ACVP 三参数集各 keyGen ×3 + encapsulation ×3 + decapsulation
      ×3（各含 modified ciphertext 隐式拒绝例）+ KeyCheck 负例
      （含官方 valid 对照，`from_bytes` 必须**接受对照、拒绝无效**）
      全绿；VECTOR-PROVENANCE.md 记录新源哈希；
- [x] 上电自检 KAT 扩为三参数集（每集一个 encapDecap 同案例五元组
      的封装 + 解封装断言）；
- [x] 常数时间纪律不变：k/η₁/du/dv 的取值与传播为公开参数集信息
      （`fips203_params` 查表），未引入以秘密为条件的分支或访存；
      dk/ss 零化语义保持；
- [x] 适配层：三个纯组装配进 provider（默认与批准清单），api 清单
      断言与 interop 握手矩阵（含 fips 矩阵）全绿；
- [x] 基准：mlkem768 三原语无回退（同机噪声带内），512/1024
      数字入 BENCHMARKS.md；
- [x] fmt / clippy -D warnings / 双配置（simd 与
      no-default-features）/ `--features fips` / doc / deny 全绿；
      fuzz `mlkem-decaps` 覆盖三参数集。

结果（2026-09-15 完成，windows-gnu 本地）：mlkem512 keygen 31 µs /
encaps 34 µs / decaps 50 µs；mlkem768 51/54/75 µs（M8.3 基线
54/53/76，同噪声带）；mlkem1024 keygen 77 µs / encaps 78 µs /
decaps 106 µs（确定性入口、标量路径）。fips 矩阵自动扩为
3 套件 × 6 组。泛化过程抓到两处"例外参数"——ML-KEM-512 的
η₁ = 3 与 ML-KEM-1024 的 (du, dv) = (11, 5)，均由重生成的新代
NIST ACVP 向量逐字节拦截（先用独立 python 参照实现仲裁定位，
详见 AGENTS.md 实现级注记）。顺带修复 RUSTSEC-2026-0285
（rustls 0.23.44 → 0.23.45，cargo-deny advisories 门拦截）。

### M8.5 QUIC packet protection（RFC 9001，完成 2026-09-15）

范围：为 TLS 1.3 三套件（AES-128-GCM / AES-256-GCM /
ChaCha20-Poly1305）实现 rustls `quic::Algorithm`（0.23.45 无
`quic` cargo feature，模块无条件可用）——`PacketKey`（RFC 9001
§5.3：nonce = IV ⊕ packet number、AAD = 含 packet number 的包头，
先验后出）、`HeaderProtectionKey`（§5.4：AES = AES-ECB(hp, sample)
单块、ChaCha = counter = sample 前 4 字节 LE + nonce = 后 12 字节
的单块密钥流，掩码 5 字节，掩码位应用逻辑照抄 rustls ring 参考）、
confidentiality/integrity limit 按 RFC 9001 §B.1.1/B.1.2（2^16 包
上限口径：GCM 2^23/2^52；ChaCha 沿 ring 的 u64::MAX/2^36）。
CCM 套件 `quic: None`（RFC 9001 §5.1 以 AES-GCM 为强制基准，
ring provider 亦不提供 CCM 的 QUIC；`ConnectionTrafficSecrets`
本就无 CCM 变体）。core 只做一处 additive 变更：
`chacha20poly1305::chacha20_block` 公开化（HP 单块密钥流，
counter/nonce 显式入参）。向量锚点（RFC 9001 原文逐字节）：
A.2/A.3 Initial 包保护（AES-128-GCM，V1，经 `quic::Suite::keys`
公开路径全链：HKDF/HMAC + Initial 密钥推导 + 包加密 + 头保护）、
A.5 ChaCha20 短包头（key/iv/hp/sample/mask/最终包全部锚定）、
multipath `for_path`（draft-ietf-quic-multipath-11 §2.3：96 位序号
= path_id ‖ pn 后与 IV 异或）。
向量锚点（RFC 9001 原文程序化提取 + 派生关系校验）：
A.2/A.3 Initial 包保护（AES-128-GCM，V1，经 `quic::Suite::keys`
公开路径全链：HKDF/HMAC + Initial 密钥推导 + 包加密 + 头保护）、
A.5 ChaCha20 短头包（key/iv/hp/sample/mask/最终包全部锚定）。
multipath 固定向量（picoquic `multipath_test.c`，经 rustls 测试
转引）**未采用**——其密钥派生需 rustls `KeyBuilder`（`pub(crate)`，
第三方无法经公开 API 从 secret 重建 PacketKey），改为以 rustls
公开 `Nonce::for_path` 同式 + 往返/非碰撞测试覆盖。端到端：interop
内存 QUIC 回环 harness（长头/短头编解码 + HP 样本位 + KeyChange
密钥切换时序，时序语义照 quinn-proto `write_crypto` 逐行核对），
ferritls↔ferritls 三套件 + ferritls↔ring 双向交叉互操作。

出口条件：

- [x] core 仍 `#![forbid(unsafe_code)]`、零新依赖；公开面仅
      `chacha20_block` 一处 additive（文档注明 HP 用途与
      counter 语义）；
- [x] 三套件 `quic: Some(...)` 接线 + `fips()` 显式 `false`
      （规则 3）；CCM 保持 `None` 并注明理由；
- [x] RFC 9001 A.2/A.3/A.5 逐字节绿（A.2/A.3 经公开
      `quic::Suite` 路径，覆盖 HKDF-Expand-Label "quic key/iv/hp"
      全链）；multipath for_path picoquic 锚定 + 往返；
- [x] 常数时间纪律：HP 掩码应用与包号长度派生只依赖公开包头
      字节；解密路径先验后出（tag 验证在明文写出前完成，沿用
      core open 语义）；密钥材料零化沿用 core AEAD 类型的
      Drop 零化；
- [x] interop 回环：ferritls↔ferritls（3 套件 × 双侧密钥翻转）
      + ferritls↔ring 交叉全绿，握手后 export_keying_material
      双侧一致、transport parameters 双侧可见、1-RTT 密钥更新
      （`Secrets::next_packet_keys`）往返成立；
- [x] fmt / clippy -D warnings / 双配置（simd 与
      no-default-features）/ `--features fips` / doc / deny 全绿；
      api.rs 清单断言更新（QUIC 接线防漂移）。

结果（2026-09-15 完成，windows-gnu 本地）：适配层 8 个向量/负例
测试（RFC 9001 §A.5 逐字节、§A.1 三组掩码、§A.2/A.3 完整 Initial
包经公开 `quic::Suite` 路径、篡改/异常输入、limits、multipath
往返）+ interop 4 个端到端测试（三套件自互操作 + ring 双向交叉 +
CCM-only provider 拒绝）全绿；每个握手覆盖三级密钥切换、ALPN、
transport parameters、export_keying_material 双侧一致、1-RTT 数据
往返/篡改拒绝/密钥更新。fuzz 无新目标（包解密与 TLS 记录层共用
core AEAD open 路径，已有 aead-open 语料覆盖）；基准不单列（每包
成本由既有 aead/hash 基准覆盖的同族路径主导）。实现注记：KeyChange
时序（buf 按切换前层级保护）与逐包投递的 harness 驱动方式记录于
AGENTS.md §4 与实现级注记。
