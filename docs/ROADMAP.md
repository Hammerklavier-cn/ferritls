# ferritls 路线图（M0–M8）

每个里程碑的出口条件 = “实现 + 向量核对 + 测试 unignore 全绿 + CI 绿”，
缺一不可（AGENTS.md §6.2）。已完成轮次只保留**结论与关键数字**：
验收过程细节不留档，基准数字的权威记录在 `docs/BENCHMARKS.md`，
实现陷阱在 AGENTS.md §9 注记。

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | 脚手架/CI/文档/骨架/向量测试预置 | 完成（2026-09） |
| M1 | SHA-2 + HMAC + HKDF | 完成（2026-09） |
| M2 | AES + GCM + CCM + ChaCha20-Poly1305 | 完成（2026-09） |
| M3 | X25519 + P-256/384 ECDH | 完成（2026-09） |
| M4 | ECDSA + RSA + Ed25519 + DER 解析（M4c 私钥盲化） | 完成（2026-09） |
| M5 | CTR-DRBG + 上电自检 + 零化审计 | 完成（2026-09） |
| M6 | rustls 集成 + 互操作矩阵 | 完成（2026-09） |
| M7 | 发布 0.1 + 批准模式打磨 + ACVP 预演 | 完成（2026-09） |
| P1/P1.5 | 性能轮：stable 自动向量化 | 完成（2026-09-08） |
| P2 | portable_simd 轮（`simd` 默认 feature） | 完成（2026-09-08） |
| M8.1/8.2 | x86_64 后端（AES-NI/CLMUL + SHA-NI） | 完成（2026-09-13） |
| M8.3/8.4 | SHA-3/SHAKE + ML-KEM 三参数集 + 混合/纯组 | 完成（2026-09-15） |
| M8.5 | QUIC 包保护（RFC 9001） | 完成（2026-09-15） |
| 参数化收口轮 | SHA-3 全家族、HKDF API 宏化、CCM 全 M + CCM_8 套件 | 完成（2026-09-17） |
| CI/发布加固 + 测试加固轮 | CI 全线 `--locked`、MSRV 1.88 门禁、publish needs 全门禁 + 人工批准；Wycheproof AEAD 入库、自检 KAT 16→20、mTLS/会话恢复/记录层/协商测试、fuzz 种子补全（策略已收敛入 AGENTS §6/§7） | 完成（2026-10） |
| M8 余项 | TLS 1.2 / aarch64 后端；候选 X448 / P-521 / Ed448 | **未排期** |

## M7 — 发布 0.1 与 FIPS 就绪（完成 2026-09）

注记（被测试文件引用的要点）：

- RFC 8448 §3 密钥调度以外部真值锚定；**记录级字节重放不可行**
  （rustls 未暴露足够的记录层注入点，只能在 provider 层核对全链
  派生值），详见 tests/schedule_rfc8448.rs 文档。
- Wycheproof 2349 用例入库，暴露并修复 der.rs 宽容解析与 Ed25519
  x=0 符号位两处缺陷。
- webpki 真实证书链校验暴露并修复 verify.rs 的 AlgorithmIdentifier
  编码语义（= SEQUENCE 内容，非完整 DER）。
- M4c：RSA 私钥运算乘法盲化（rᵉ 预盲 / r⁻¹ 去盲 + Garner 回绕
  常数时间化）。
- crates.io 发布自动化：推 tag `v*`（或手动 dispatch）→ 全量门禁 →
  单次 `cargo publish`（cargo 1.90 起 workspace 一次发布，core →
  rustls 拓扑序）；前置 = 仓库 secrets 的 CARGO_REGISTRY_TOKEN；
  v0.1.0–v0.6.0 已经 tag 触发发布。

## P1/P1.5 — 性能轮：stable 自动向量化（完成 2026-09-08）

零 `unsafe`、零新依赖、零 feature 开关（当时 `std::simd` 仍
nightly-only，不能作默认 feature——该判断后被 P2 轮以用户指令推翻）。
落地项：AEAD 输出 bulk-XOR、GHASH 瞬态 H 倍数 4-bit 表（公开索引，
用完零化）、ChaCha20 四块批处理 + Poly1305 流式吸收、64-lane 位切片
AES 批量加密、单块 SubBytes 16 宽单次掩码扫描、DRBG 批量 CTR、
Poly1305 4 块分组吸收、GCM 标签常数时间比较。

出口条件：全向量套件 / Wycheproof / interop 矩阵**一行不改且全绿** +
常数时间声明 + 基准前后数字（`cargo run -p ferritls-interop
--release --example perf`，同机对比）：

| 项目 | 基线 | P1.5 后 | 提升 |
|---|---|---|---|
| AES-128-GCM seal 1 KiB | 2.68 MB/s | 42.2 MB/s | 15.7× |
| AES-128-GCM seal 16 KiB | 2.71 | 55.6 | **20.5×** |
| AES-256-GCM seal 16 KiB | 1.95 | 44.0 | **22.6×** |
| AES-128-CCM seal 16 KiB | 1.41 | 14.2 | **10.0×** |
| ChaCha20-Poly1305 seal 16 KiB | 451 | 620 | 1.4× |
| SHA-256 16 KiB | 357 | 368 | —（未动，2026-09-17 收口，见 BENCHMARKS §5.6） |
| AES-128 单块加密 | 2.72 | 17.9 | **6.6×** |

实测回退（教训已收敛进 AGENTS §9 注记）：单块走位切片电路慢 2×
（lane 占用 1/64）；代数 S-box（x^254 链）替代掩码扫描慢 12%。
**位切片收益来自 lane 填充率，批量才有意义。**

## P2 — portable_simd 轮（`simd` 默认 feature，完成 2026-09-08）

决策（用户指令，推翻 P1 判断）：`simd` 成为默认 feature，stable
工具链经 `RUSTC_BOOTSTRAP=1` 编译 `#![feature(portable_simd)]`
（stable rustc 1.98.1 本机实证）；标量路径（P1/P1.5 代码）原样保留
= 永久回退 + 双 oracle 基线；portable_simd 稳定后拆 env、代码不动。
约束集见 AGENTS §5.5（safe-only、零新依赖、无运行时分发、档位选择
不依赖秘密）。

设计：AES 位切片电路按 `Plane` trait 泛型化（`u64` 与 `Simd<u64,L>`
共享同一份电路源码；批量档 64/128/256/512 按公开请求块数取最小浪费
档，n≤64 走 u64 档零回退）；ChaCha20 通道按 `cfg(target_feature)`
三档（AVX-512 16 块 / AVX2 8 块 / 基线 4 块，每档状态 ≈16 个向量
寄存器）。

最终矩阵（Zen 4，seal MB/s；括号 = 对 P1.5 基线倍数；本机
AMD Ryzen 9 7900X）：

| 基准 | P2 默认 | +avx2 | +avx512 |
|---|---|---|---|
| AES-128-GCM 1 KiB | 39.6–43.2（噪声带） | 43.9 | 45.0 |
| AES-128-GCM 16 KiB | 71.7（1.31×） | 102.6（**1.80×**） | 154.4（**2.68×**） |
| AES-256-GCM 16 KiB | 59.4（1.36×） | 88.0（**1.97×**） | 142.4（**3.19×**） |
| AES-128-CCM 16 KiB | 15.1（1.11×） | 19.9（1.17×） | 20.1（1.30×） |
| ChaCha20-Poly1305 1 KiB | 852（1.54×） | 1202（2.25×） | 1087（1.57×） |
| ChaCha20-Poly1305 16 KiB | 984（1.62×） | 1488（**2.55×**） | 1363（1.73×） |

要点：

- 默认基线也提升 31–62%——P1 的数组形态连 SSE2 都未被 LLVM
  向量化满；自动向量化在宽 ISA 下几乎不加宽，这正是显式向量化的空间。
- 实测回退第三例：单块 SubBytes 显式 `u8x16` 掩码扫描慢 2.5×
  （`Mask::select` 掩码↔向量往返未被消除）——**portable_simd 的
  `select` 不可假设折叠为 AND，涉掩码热路径先实测**。
- 移植中被标量 oracle 拦截一个真 bug：`(v<<r)|(v>>r)` 仅 r=16 自对偶
  时凑巧正确，必须 `(v<<r)|(v>>(32−r))`。
- CCM 基准方差 ±25%（串行 CBC-MAC 打满单核 + boost 时钟衰减），
  矩阵取固定顺序单轮首值。
- SHA-256 的 +avx512 回归（354→223 MB/s，后 +75%→+65%）是 LLVM
  自动向量化决策漂移、非本轮引入，列已知容忍项（BENCHMARKS §5.5–5.7）。

## M8 — 发布后方向（按需排期）

余项（动手前先补写出口条件）：

- **TLS 1.2**：`tls12` feature、PRF（复用 rustls `PrfUsingHmac`）、
  ECDHE-GCM 套件（SP 800-52r2 部署面需要）。
- **aarch64 后端**：NEON/FEAT_AES 等，对齐 x86_64 后端的 ops 模式。

### 候选余项（未排期；动手前先按本条目细化并补全出口条件）

- **X448**（RFC 7748）：`fp_field!` 新增 Fp448（8 limbs）→ 蒙哥马利
  阶梯复用 x25519 形态（钳制常量与位宽参数化）→ RFC 7748 §5.2/§6.1
  向量 + Wycheproof → kx.rs `NamedGroup::X448`（0x1E）+ 互操作。
  批准状态：非批准（SP 800-52r2 只许经 ML-KEM 混合进入批准模式）。
- **P-521**（含 `ecdsa_secp521r1_sha512`）：Fp521/Fp521Scalar
  （9 limbs，521 = 64×8 + 9，最高 limb 非全宽位掩码）→ `sw_curve!`
  实例 → RFC/Wycheproof ECDH+ECDSA 向量 → kx/verify/sign 三处接线。
  批准状态：批准（SP 800-52r2 允许面含 P-521）。
- **Ed448**（RFC 8032）：Goldilocks 域 GF(2^448−2^224−1) +
  SHAKE-256（已有）→ RFC 8032 §7.3/§7.4 向量 → verify/sign 接线。
  批准状态：非批准（FIPS 186-5 不含 EdDSA）。

三项共同前置：`fp_field!` 对非整字位宽素数（521、448）的支持论证
（Montgomery 域常量推导、limb 布局、高位掩码不变式）——先在分支上
完成域算术原型并跑穷举/性质测试，再进入向量接线。

### M8.1 intrinsics 后端（AES-NI + CLMUL，完成 2026-09-13）

core `ops` 分发接线 + 新 crate `ferritls-backend-x86_64`（仅 x86_64，
unsafe 限于唯一叶子模块 + kernel 单点 trampoline，零依赖）+
`ops::install()` 应用侧显式注册 + 安装 KAT + 批准模式拒绝（有测试
守护）。出口全绿：core 既有向量零改动、Ni 路径 McGrew–Viega 向量
锚定 + 2000 组软/Ni 差分、`--features fips` 下 install 拒绝。

关键教训：kernel 必须 `#[target_feature]` 直调 intrinsic（从无
feature 上下文调用不得内联，103 处真实 callq 吃光收益）；直调化后
GCM 原语再提 5.2–6.6×。数字见 BENCHMARKS §5.1/§5.2（Ni 对软件路径
~750–980×）。CCM/ChaCha/P-256/Ed25519 加速与 aarch64 不在本节范围。

### M8.2 SHA-NI 后端（完成 2026-09-13）

`ShaNi` token（探测 sha + ssse3 + sse4.1 三条）+ `HashOps` 函数分发
（对象分发形态因 HKDF 短命实例 +2.3% 被零回归门否决）：流式
SHA-256 ~6×、HKDF ~5×、X25519 握手双 Ni ~2.35×（BENCHMARKS §5.1）。
KAT 通过后才 `bind_token`。

### M8.3 ML-KEM（FIPS 203）+ X25519MLKEM768 混合（完成 2026-09-13）

core 内自研 FIPS 202（Keccak 海绵）与 FIPS 203 ML-KEM-768（零新
依赖）；适配层 X25519MLKEM768 混合组（0x11EC：share = ek(1184)‖
X25519 pk(32)，ss = ML-KEM‖X25519 共 64 B，服务端封装 + §7.2 封装
密钥检查）。出口全绿：FIPS 202/203 官方示例 + NIST ACVP 向量（含
modified-ciphertext 隐式拒绝）、ct 纪律（decaps ct-select）、自检
KAT、interop 混合握手、fuzz 目标 `mlkem-decaps`。

结果：mlkem768 keygen 54 µs / encaps 53 µs / decaps 76 µs；混合握手
1.22 ms，仅比纯 X25519（1.09 ms）+12%。实现期三处缺陷（encrypt 的
e₁ 域混用、§7.2 往返式模校验恒真、KAT 跨案例拼向量）全部由 ACVP
向量/自检拦截，注记见 AGENTS.md §9。

批准状态注记：ML-KEM 是 NIST 批准算法，但 CMVP 认证前 rustls 各
`fips()` 钩子仍恒返回 `false`（AGENTS.md 规则 3 不变）。

### M8.4 ML-KEM-512/1024 + 纯 ML-KEM 组（0x0200–0x0202，完成 2026-09-15）

`mlkem` 泛化为 FIPS 203 三参数集，差异收敛到单一 `fips203_params`
参数表——**差异不止 k**：ML-KEM-512 的 η₁ = 3、ML-KEM-1024 的
(du, dv) = (11, 5)，两处都曾按“三集同参”写错，由重生成的新代 NIST
ACVP 向量逐字节拦截（独立 python 参照仲裁定位）。引擎 k 为运行时
参数（K_MAX = 4，零堆分配），公开类型用裸 const 长度参数（不依赖
generic_const_exprs）；768 既有 API 不变。适配层纯 ML-KEM 三组进
默认与批准清单（服务端 `start_and_complete` 覆写 + §7.2 检查）。

结果：mlkem512 31/34/50 µs、mlkem768 51/54/75 µs（无回退）、
mlkem1024 77/78/106 µs；fips 矩阵自动扩为 3 套件 × 6 组。顺带修复
RUSTSEC-2026-0285（rustls 0.23.44 → 0.23.45）。

### M8.5 QUIC packet protection（RFC 9001，完成 2026-09-15）

三套件（AES-128/256-GCM、ChaCha20-Poly1305）实现 rustls
`quic::Algorithm`：PacketKey（nonce = IV ⊕ pn、先验后出）、
HeaderProtectionKey（AES-ECB / ChaCha20 单块掩码）、multipath
`for_path`；confidentiality/integrity limits 按 RFC 9001 §B.1。
CCM 恒 `quic: None`（RFC 9001 §5.1 以 AES-GCM 为强制基准，ring 同）。
core 唯一 additive 变更：`chacha20poly1305::chacha20_block` 公开化。

向量：RFC 9001 §A.2/A.3（完整 Initial 包，经公开 `quic::Suite::keys`
全链）+ §A.5（ChaCha 短头）逐字节；picoquic multipath 固定向量
**未采用**（rustls `KeyBuilder` 为 `pub(crate)`，第三方无法从 secret
重建 PacketKey），以 `Nonce::for_path` 同式 + 往返/非碰撞测试覆盖。
interop 内存 QUIC 回环：ferritls↔ferritls 三套件 + ferritls↔ring
双向交叉全绿（三级密钥切换、ALPN、transport parameters、
export_keying_material、1-RTT 密钥更新）。KeyChange 时序与逐包投递
的 harness 要点记录于 AGENTS.md §4 与实现级注记。

## 已知问题

- windows-gnu 工具链构建带 cc 依赖的 dev-deps 需要 ucrt64 在 PATH
  最前（静默崩溃；AGENTS.md §6.3，CI 不受影响）。
