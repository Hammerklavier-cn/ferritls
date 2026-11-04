# ferritls 基准测试指南

基准体系回答一个问题：**当前实现到底多慢、慢在哪、改动后有没有回归**
——AGENTS.md §5.5「先正确，后快」纪律的度量前提。工具为
[criterion](https://github.com/bheisler/criterion.rs)（0.8），以
dev-dependency 挂在 `ferritls-core` / `ferritls-interop` /
`ferritls-backend-x86_64` 上（dev 目标不进入 FIPS 边界）。CI 只做
编译冒烟（`cargo bench --no-run`）；实际测量在本地进行，不作为门禁。

## 1. 基准清单

| bench target | crate | 测量内容 | 吞吐单位 |
|---|---|---|---|
| `aead` | ferritls-core | AES-128/256-GCM、AES-128-CCM（TLS 参数集）、ChaCha20-Poly1305 的 seal/open，输入 1350 B（典型 TLS 记录）与 16 KiB，AAD 5 B | Bytes |
| `hash` | ferritls-core | SHA-256/384 流式、HMAC-SHA256、HKDF-SHA256 extract/expand | Bytes |
| `ecdh` | ferritls-core | X25519 / P-256 / P-384：`public_key`（纯标量乘）与 `diffie_hellman`（含公钥解析、在曲线检查、盲化） | — |
| `sign` | ferritls-core | ECDSA P-256/384（RFC 6979）、Ed25519、RSA-2048（PKCS#1 v1.5 与 PSS）sign/verify | — |
| `drbg` | ferritls-core | CTR-DRBG 生成 32 B——**含每次 generate 的 128 位 OS 熵重播种**（AGENTS.md §5.3 策略），即真实部署成本 | — |
| `kem` | ferritls-core | ML-KEM-512/768/1024 三参数集的 keygen / encaps / decaps（确定性入口） | — |
| `handshake` | ferritls-interop | TLS 1.3 内存全握手（进程内管道驱动）：ferritls × X25519 / P-256 + **ring 同套件基线**，AES-128-GCM。**软件路径**（不安装后端） | Elements |
| `aead_ni` | ferritls-backend-x86_64 | 软/Ni 逐记录对照：AES-128/256-GCM seal/open（Ni 侧经 token 直构，两路径同进程独立测） | Bytes |
| `hash_ni` | ferritls-backend-x86_64 | SHA-256 软/Ni 对照（同 core `hash` 案例，分安装前后） | Bytes |
| `handshake_ni` | ferritls-interop | 与 `handshake` 同法，**启动时安装 AES-NI 后端**（仅 x86_64；分属二进制，互不污染） | Elements |

要点：密钥/输入固定种子确定性构造，bench 循环内不调 OS 熵（唯一例外
`drbg/generate-32b` 的重播种——那是被测语义的一部分）；`handshake`
每次迭代 = 一次完整握手，每案例先验证配置可用、套件钉扎正确；RSA 用
内嵌 hex 的本地生成测试密钥。

## 2. 运行

```bash
cargo bench --workspace                     # 全部（完整一轮约 10–20 分钟）
cargo bench -p ferritls-core --bench aead   # 单 crate / 单目标
cargo bench -p ferritls-core --bench aead -- gcm128           # 子串过滤
cargo bench -p ferritls-core --bench ecdh -- ecdh/p256-dh --exact  # 精确单例
cargo bench -p ferritls-core --bench sign -- --sample-size 10 \
    --warm-up-time 0.3 --measurement-time 0.5                 # 快速冒烟
cargo bench -p ferritls-core --bench ecdh -- --list           # 列出案例名
```

输出解读：`time: [min mean max]` 为 bootstrap 置信区间；带
`Throughput` 的同时给行吞吐；与上次运行比较打印 `change: […]`
（p<0.05 才标 Regression/Improvement）。HTML 报告在
`target/criterion/report/index.html`。

## 3. 基线对比（回归检测工作流）

改动密码实现 / 优化 / 换后端前后的标准流程：

```bash
cargo bench -p ferritls-core --bench aead -- --save-baseline before   # 1) 改动前
# ……2) 做改动……
cargo bench -p ferritls-core --bench aead -- --baseline before        # 3) 对比
cargo bench -p ferritls-core --bench aead -- --baseline-lenient before # 案例增删过
```

- 不显式命名时 criterion 存默认基线 `base`，下次运行的 `change:`
  即与上次对比——日常开发零配置。
- 数据在 `target/criterion/`（不入库）。
- **回归判断只认同机同会话 A/B**；跨机器、跨时间绝对值无可比性
  （实测跨会话漂移可达 ±40%+）。

## 4. 配合 profiler

```bash
# 跳过统计分析，只持续迭代 10 秒（perf / VTune / Instruments / superpmi）
cargo bench -p ferritls-core --bench sign -- rsa2048 --profile-time 10
```

## 5. 参考量级与历史 A/B 记录

**警告**：以下全部数字只用于建立直觉，随机器/会话差异巨大，不作为
任何依据；判定一律按 §3 同会话对照。§5.0 为 P1/P2 之前的旧快照
（仅动机记录），现状看 §5.1–5.7 与 ROADMAP P1/P2 节。

### 5.0 早期量级（2026-09，P1/P2 之前；AES 行已过时两个数量级）

| 操作 | 量级 |
|---|---|
| ChaCha20-Poly1305 seal 1350 B | ~3 µs |
| AES-128-GCM seal/open 1350 B | ~0.5 ms（逐位 GHASH + 按位 S-box 是当时常数时间纪律下的有意取舍，AGENTS.md §5.1；P1/P2 后提速 20×+，Ni 后端再 750×+） |
| SHA-256 流式 16 KiB | ~42 µs |
| X25519 / P-256 / P-384 标量乘 | ~63 µs / ~0.5 ms / ~2.1 ms |
| ECDSA P-256 sign / verify | ~0.51 ms / ~0.63 ms |
| Ed25519 sign / verify | ~26 ms（当时离群值 = 实现缺陷，§5.4 已修复至 ~0.22/0.24 ms） |
| RSA-2048 私钥运算 / 公钥验证 | ~2.3 ms / ~0.27 ms |
| CTR-DRBG generate 32 B（含 OS 重播种） | ~39 µs |
| 全握手 ferritls × X25519 / P-256 | ~1.5 ms / ~3.2 ms |
| 全握手 ring × X25519（基线） | ~0.11 ms（~13× 差距 = M8 后端的目标空间） |

### 5.1 M8.1 软/Ni 对照（2026-09-10，同机同会话）

AES-NI + CLMUL + SHA-NI 后端（`ferritls-backend-x86_64`）相对软件
默认路径：

| 操作 | 软件路径 | AES-NI/CLMUL | 提升 |
|---|---|---|---|
| AES-128-GCM seal/open 1350 B | ~681/~697 µs | ~5.6 µs | ~120–125×（kernel 直调化后 ~750×+，§5.2） |
| AES-256-GCM seal 1350 B | ~969 µs | ~7.0 µs | ~138× |
| AES-128-GCM seal/open 16 KiB | ~8.20 ms | ~66.5 µs | ~123× |
| SHA-256 流式 1350 B / 16 KiB | ~4.25/~45.9 µs | ~0.68/~7.8 µs | ~6×（~1.7 周期/字节） |
| HMAC-SHA256 1350 B / HKDF extract / expand-64 | ~4.56 µs / ~752 ns / ~1.74 µs | ~0.80 µs / ~150 ns / ~391 ns | ~4.5–5.7× |
| 全握手 ferritls × X25519（双 Ni） | ~2.12 ms | ~0.90 ms | ~2.35×（同日 ring ~162 µs，差距 ~13×→~5.6×） |
| 全握手 ferritls × P-256 | ~4.60 ms | ~2.61 ms | ~1.8×（ECDH/ECDSA 软实现占主导） |

教训（target_feature 与内联）：该工具链的 intrinsic 是带 feature 的
安全函数，从无 feature 上下文调用不得内联——SHA-NI kernel 未进
feature 上下文时反而比软件慢 ~20%。kernel 标 `#[target_feature]`
直调 intrinsic 才兑现收益（AES 同病，§5.2；纪律已入 AGENTS §5.5）。

### 5.2 AES/CLMUL kernel 直调化 A/B（2026-09-13，同机同会话）

`gcm.rs` 全部 kernel 标 `#[target_feature(enable = "aes,pclmulqdq")]`
直调 intrinsic（泛型 kernel 按 N=11/15 单态化）；`raw.rs` 收缩为纯
内存包装。反汇编实测：对 intrinsic 桩的真实 `callq` **103 → 0**。

| 用例（criterion 均值） | 改造前 | 改造后 | 提升 |
|---|---|---|---|
| AES-128-GCM Ni seal/open 1350 B | 3.59/4.10 µs | 0.695/0.687 µs | 5.2–6.0× |
| AES-256-GCM Ni seal 1350 B | 4.64 µs | 0.750 µs | 6.2× |
| AES-128-GCM Ni seal/open 16 KiB | 46.8/45.8 µs | 7.73/7.63 µs | 6.0×（~1.4 周期/字节） |
| AES-256-GCM Ni seal 16 KiB | 55.9 µs | 8.47 µs | 6.6× |

软路径对照用例同会话变动 0.97–1.10×（噪声本底内），提升可归因于
本次改造。Ni 对软件路径的倍数扩大到 **~750–980×**。同会话握手：
X25519 软件 1.70 ms → 双 Ni 0.954 ms（~1.8×；当日 ring 0.125 ms）；
P-256 3.48 → 2.76 ms（~1.3×）。握手提升有限是预期内：负载小，剩余
大头是 P-256 ECDH/ECDSA 软实现。

### 5.3 ML-KEM 三参数集（M8.4，2026-09-15，windows-gnu 同会话）

三原语（µs，确定性入口，`cargo bench -p ferritls-core --bench kem`）：

| 参数集 | keygen | encaps | decaps |
|---|---|---|---|
| ML-KEM-512 | 31 | 34 | 50 |
| ML-KEM-768 | 51 | 54 | 75 |
| ML-KEM-1024 | 77 | 78 | 106 |

768 与 M8.3 基线（54/53/76）同噪声带，参数化无回退。全握手（软件
路径，AES-128-GCM）：x25519 1.09 ms / x25519-mlkem768 混合 1.22 ms
（**+12%**）/ p256 2.67 ms / ring 基线 114 µs——PQ 混合开销与主流
部署经验一致，仍比 P-256 经典握手快约 2.2×。

### 5.4 Ed25519 点运算常数缓存修复（2026-09-17）

缺陷：统一加法每次调用现场派生 `2d`（含 Fermat 模逆 ≈500+ 域乘），
每次 sign/verify ~1024 次重推导压过点乘本体（§5.0 表中 26 ms 的全部
原因）。修复：`curve_d()` / `base_point()` 各以 `OnceLock` 缓存
（d 与 G 是公开曲线常数，无零化/ct 顾虑；缓存值仍由同一派生式计算，
向量测试零改动）。sign 25.927 → 0.2168 ms（**~120×**）、verify
26.065 → 0.2441 ms（**~107×**）。

余留（若另立轮次）：专用 double 公式、radix-2^51 域算术、固定基
comb——注意 `scalar_mult` 的标量是秘密，窗口表须按 AGENTS §5.1
“索引仅公开数据”判据另行论证。

### 5.5 SHA-256 滚动窗口消息调度实测回退（2026-09-17，第四例回退）

16 字滚动窗口融合进 64 轮主循环（消除栈数组）：默认慢 ~3%、+avx2
慢 ~4.7%，唯一收益在 +avx512 档（回归 +73%→+29%）。**默认基线不
允许回退**（AGENTS §5.5 性能门），已整体回退。教训：先实测再立论。
（“维持 64 字数组两段式”的结论被同日 §5.6 软流水取代；滚动窗口
方向本身的否决依旧成立。）

### 5.6 SHA-256 软流水消息调度（2026-09-17 第二轮，已采纳）

形态：保留 64 字数组，取消独立展开循环——`w[i+16]` 融合进压缩主循环
第 i 轮头部（完全展开后 `if i < 48` 为编译期常量），调度加法链与
压缩轮关键路径并行。

| 配置（sha256-stream/16384） | 两段式（旧） | 软流水（新） | 变化 |
|---|---|---|---|
| 默认（SSE2） | 42.88 µs | 36.83 µs | **−14.2%**（382→445 MB/s） |
| +avx2 | 46.24 µs | 42.57 µs | −4.4% |
| +avx512f/vl | 75.26 µs | 60.84 µs | −18.6%（回归 +75%→+65%，未根除） |

1350 B / HMAC / HKDF 各用例同步 −14%。同轮第二候选“16 字窗口分块
调度”比软流水慢 ~9%，未采纳。正确性：三配置 151 测试全绿、常数时间
形态不变。宽 ISA 残余回归（+65%）维持已知容忍项。

### 5.7 SHA-256 `std::simd` 消息调度实测回退（2026-09-17 第三轮，第五例回退）

调度步搬 `u32x4`（σ₁ 环依赖两阶段破除）：默认 ≈0、+avx2 −1.1%、
+avx512 **+7.4%（回归）**。判定否决：64 轮压缩是严格串行链，SIMD
无 lane 并行可开发；软流水已让 LLVM 把调度与关键路径重叠，搬向量
端口无增益空间。**portable_simd 的收益前提是“存在未开发的 lane
并行”**（AES 位切片、ChaCha 多块有，SHA-256 单流没有）。软件路径
天花板即标量串行链本身——更大增益只来自硬件指令（SHA-NI ~6×，
§5.1；SHA-512 的 VSHA512* 属 x86_64 后端排期素材）。实验代码在本地
stash，复述本节即可再推导。

## 6. Windows（msys2/windows-gnu）本地注意

带 C 构建依赖的 dev-deps（criterion 0.8 → `alloca`）要求 ucrt64 在
PATH **最前**，否则 gcc 子进程混载 mingw64 DLL 静默崩溃（cc-rs 报
exit 1 无诊断）：`export PATH="/c/msys64/ucrt64/bin:$PATH"`。
已知环境交互：criterion alloca 扩展栈 + getrandom 组合下
`CtrDrbg::instantiate_from_os` 间歇 `EntropyFailed`（criterion 外
2 万次零失败，属基准环境问题）——因此只 bench `generate` 不 bench
实例化。

## 7. 新增基准的约定

1. 入口只走公开 API（与外部用户同一路径），不触碰内部函数。
2. 输入确定性（`pattern()` 风格伪随机填充），循环内不调 OS 熵；
   以 OS 熵为语义一部分的（DRBG generate）除外且须注释。
3. 按字节操作挂 `Throughput::Bytes`，单次操作挂 `Elements(1)`。
4. 单次 >1 ms 的操作调低 `sample_size`（如 RSA 组设 20）。
5. 新文件在 crate `Cargo.toml` 登记 `[[bench]] … harness = false`。
6. clippy `--all-targets -D warnings` 覆盖 benches，同样是硬门。
7. §1 清单表随新基准同步更新（AGENTS.md 规则 9 文档先行）。
