# ferritls 基准测试指南

基准体系回答一个问题：**当前纯软件实现到底多慢、慢在哪、改动后有没有
回归**。它是 AGENTS.md §5.5「先正确，后快」纪律的度量前提——没有基准，
M8 intrinsics 后端的价值无从证明，优化本身也无从把关。

工具为 [criterion](https://github.com/bheisler/criterion.rs)（0.8），
以 **dev-dependency** 形式挂在 `ferritls-core` 与 `ferritls-interop` 上
（dev 目标不进入 FIPS 边界，AGENTS.md 硬性规则 2）。CI 只做**编译冒烟**
（test job 里的 `cargo bench --no-run`，防止基准腐化）；实际测量在本地
或按需进行，不作为门禁。

## 1. 基准清单

| bench target | crate | 测量内容 | 吞吐单位 |
|---|---|---|---|
| `aead` | ferritls-core | AES-128/256-GCM、AES-128-CCM（TLS 参数集）、ChaCha20-Poly1305 的 seal/open，输入 1350 B（典型 TLS 记录）与 16 KiB，AAD 5 B | Bytes |
| `hash` | ferritls-core | SHA-256/384 流式、HMAC-SHA256、HKDF-SHA256 extract/expand | Bytes |
| `ecdh` | ferritls-core | X25519 / P-256 / P-384：`public_key`（纯标量乘）与 `diffie_hellman`（含公钥解析、在曲线检查、盲化） | — |
| `sign` | ferritls-core | ECDSA P-256/384（RFC 6979）、Ed25519、RSA-2048（PKCS#1 v1.5 与 PSS）sign/verify | — |
| `drbg` | ferritls-core | CTR-DRBG 生成 32 B——**含每次 generate 的 128 位 OS 熵重播种**（AGENTS.md §5.3 策略），即真实部署成本 | — |
| `kem` | ferritls-core | ML-KEM-512/768/1024 三参数集的 keygen / encaps / decaps（确定性入口，不含生产路径的一次 OS 熵读取；M8.3 起，M8.4 扩三集） | — |
| `handshake` | ferritls-interop | TLS 1.3 内存全握手（进程内管道驱动，无 TCP/线程噪声）：ferritls × X25519 / P-256 + **ring 同套件基线**，AES-128-GCM，双方钉扎。**软件路径**（不安装后端） | Elements |
| `aead_ni` | ferritls-backend-x86_64 | 软/Ni 逐记录对照：AES-128/256-GCM 的 seal/open，尺寸与 `aead` 一致（不安装，Ni 侧经 token 直构，两路径同进程独立测） | Bytes |
| `hash_ni` | ferritls-backend-x86_64 | SHA-256 软/Ni 对照：同 core `hash` 的案例（流式 1350/16K + HMAC + HKDF），同进程分安装前后（criterion 组按注册顺序同步执行，中间桥接安装） | Bytes |
| `handshake_ni` | ferritls-interop | 与 `handshake` 同法，**启动时安装 AES-NI 后端**（仅 x86_64；与 `handshake` 分属二进制，互不污染） | Elements |

要点：

- 所有密钥/输入用固定种子确定性构造，bench 循环内不调 OS 熵（唯一例外
  是 `drbg/generate-32b` 的重播种——那是被测语义的一部分）。
- `handshake` 每次迭代 = 一次完整握手（client+server 全部密码学计算与
  记录层组帧）；每案例先跑一次握手验证配置可用、套件钉扎正确。
- RSA 用内嵌 hex 的本地生成 2048 位测试密钥，不承载任何真实身份。

## 2. 运行

```bash
# 全部基准（core 6 个 + interop 2 个 + backend 2 个），完整一轮约 10–20 分钟
cargo bench --workspace

# 单 crate / 单目标
cargo bench -p ferritls-core --bench aead
cargo bench -p ferritls-interop --bench handshake
cargo bench -p ferritls-backend-x86_64 --bench aead_ni      # 软/Ni 逐记录
cargo bench -p ferritls-interop --bench handshake_ni       # Ni 全握手

# 子串过滤（跑一组，如全部 GCM 案例）
cargo bench -p ferritls-core --bench aead -- gcm128

# 精确匹配单个案例
cargo bench -p ferritls-core --bench ecdh -- ecdh/p256-dh --exact

# 快速冒烟（牺牲统计精度换时间，调参数前验证基准还能跑）
cargo bench -p ferritls-core --bench sign -- --sample-size 10 \
    --warm-up-time 0.3 --measurement-time 0.5

# 列出某目标的全部案例名
cargo bench -p ferritls-core --bench ecdh -- --list
```

输出解读：每行 `time: [min mean max]` 为 bootstrap 置信区间；带
`Throughput` 的基准同时给出行吞吐；与上次运行比较会打印
`change: […]`（p<0.05 才标为 Regression/Improvement，否则 No change）。

HTML 报告（含逐案例分布图）在 **`target/criterion/report/index.html`**，
浏览器打开即可。

## 3. 基线对比（回归检测工作流）

改动密码实现 / 优化 / 换后端前后的标准流程：

```bash
# 1) 改动前存基线
cargo bench -p ferritls-core --bench aead -- --save-baseline before

# 2) ……做改动……

# 3) 改动后对比（输出 Performance change 明细）
cargo bench -p ferritls-core --bench aead -- --baseline before

# 若部分案例在两个版本间增删过，用宽容模式（缺基线的案例跳过对比）：
cargo bench -p ferritls-core --bench aead -- --baseline-lenient before
```

- 不显式命名时，criterion 把每次运行存为默认基线 `base`，下次运行的
  `change:` 就是与上次的对比——日常开发什么都不用配。
- 全部数据在 `target/criterion/` 下（不入库，`target/` 已被 gitignore）。
- **回归判断只认同机基线对比**；跨机器、跨时间的绝对值没有可比性
  （见 §5 参考量级的警告）。

## 4. 配合 profiler

```bash
# 跳过统计分析，只持续迭代 10 秒（配合 perf / VTune / Instruments / superpmi）
cargo bench -p ferritls-core --bench sign -- rsa2048 --profile-time 10
```

## 5. 参考量级（仅示意，随机器差异巨大）

2026-09 在本地 Windows（msys2/ucrt64，x86_64）的量级记录，**只用于
建立直觉，不作为任何依据**。注意：本表为 **P1/P2 性能轮之前**的快照
（GCM/单块 AES 此后经位切片/GHASH 表等提速 6–23 倍，见 ROADMAP
P1/P2 节与 §5.1–5.2）——AES 行保留其"慢两个数量级"的原貌仅作动机
记录，不代表现状：

| 操作 | 量级 |
|---|---|
| ChaCha20-Poly1305 seal 1350 B | ~3 µs |
| AES-128-GCM seal/open 1350 B | ~0.5 ms（**比 ChaCha 慢两个数量级**：逐位 GHASH + 按位 S-box 是常数时间纪律下的有意取舍，AGENTS.md §5.1） |
| SHA-256 流式 16 KiB | ~42 µs |
| X25519 / P-256 / P-384 标量乘 | ~63 µs / ~0.5 ms / ~2.1 ms |
| ECDSA P-256 sign / verify | ~0.51 ms / ~0.63 ms |
| Ed25519 sign / verify | ~26 ms / ~26 ms（**当时的离群值**——后证实为实现缺陷：每次点加法重算 2d 的 Fermat 模逆；2026-09-17 已修复至 ~0.22/0.24 ms，见 §5.4） |
| RSA-2048 私钥运算 / 公钥验证 | ~2.3 ms / ~0.27 ms |
| CTR-DRBG generate 32 B（含 OS 重播种） | ~39 µs |
| 全握手 ferritls × X25519 / P-256 | ~1.5 ms / ~3.2 ms |
| 全握手 ring × X25519（基线） | ~0.11 ms（**约 13 倍差距** = M8 intrinsics 后端的目标空间） |

### 5.1 M8.1 软/Ni 对照（2026-09-10，同机同会话，软/Ni 可比）

AES-NI + CLMUL 后端（`ferritls-backend-x86_64`，仅 x86_64）相对软件
默认路径：

| 操作 | 软件路径 | AES-NI/CLMUL | 提升 |
|---|---|---|---|
| AES-128-GCM seal 1350 B | ~681 µs | ~5.6 µs | **~120×** |
| AES-128-GCM open 1350 B | ~697 µs | ~5.6 µs | **~125×** |
| AES-256-GCM seal 1350 B | ~969 µs | ~7.0 µs | **~138×** |
| AES-128-GCM seal 16 KiB | ~8.20 ms | ~66.5 µs | **~123×** |
| AES-128-GCM open 16 KiB | ~8.18 ms | ~65.5 µs | **~125×** |
| AES-256-GCM seal 16 KiB | ~11.4 ms | ~84.2 µs | **~136×** |
| SHA-256 流式 1350 B | ~4.25 µs | ~0.68 µs | **~6.2×** |
| SHA-256 流式 16 KiB | ~45.9 µs | ~7.8 µs | **~5.9×**（~1.7 周期/字节） |
| HMAC-SHA256 1350 B | ~4.56 µs | ~0.80 µs | **~5.7×** |
| HKDF-SHA256 extract | ~752 ns | ~150 ns | **~5.0×** |
| HKDF-SHA256 expand-64 | ~1.74 µs | ~391 ns | **~4.5×** |
| 全握手 ferritls × X25519（AEAD+SHA 双 Ni） | ~2.12 ms | ~0.90 ms | **~2.35×** |
| 全握手 ferritls × P-256 | ~4.60 ms | ~2.61 ms | ~1.8× |

要点：

- 握手 X25519 双 Ni 后 0.90 ms：同日 ring 基线 ~162 µs，差距从
  ~13× 缩至 **~5.6×**（剩余 = P-256/ECDSA 等软原语与记录层组帧）；
  P-256 案例提升较小（ECDH/ECDSA 软实现占主导）；
- **教训（target_feature 与内联）**：该工具链的 intrinsic 是带
  feature 的安全函数，从无 feature 上下文调用时编译器不得内联，
  每次包装调用都成为真实函数调用——SHA-NI kernel 未进入 feature
  上下文时比软件路径还慢 ~20%；标记 `#[target_feature]` 后直接
  调用 intrinsic（安全、编译为裸指令）才兑现全部收益。AES kernel
  同病（反汇编 103 处真实 `callq`），已于 2026-09-13 按同法落地，
  见 §5.2；
- **跨日绝对值不可比**：不同会话的机器状态差异可达 ±40%+（本次软
  路径相对上次会话整体漂移 +43%），回归判断只认同会话 A/B。

### 5.2 AES/CLMUL kernel 直调化 A/B（2026-09-13，同机同会话）

SHA-NI 同款修复落到 AES 侧：`gcm.rs` 全部 kernel 与 `#[inline]` 辅助
函数标注 `#[target_feature(enable = "aes,pclmulqdq")]`，体内直调
intrinsic（泛型 kernel 按 N=11/15 单态化，aesenc 链展开为直线代码，
keystream 异或改走单条 PXOR）；`raw.rs` 收缩为纯内存读写包装。改造
前后反汇编实测：对 AES/CLMUL intrinsic 桩的真实 `callq` **103 → 0**，
裸指令 aesenc×168 / pclmulqdq×20 / aeskeygenassist×24。

| 用例（criterion 均值） | 改造前 | 改造后 | 提升 |
|---|---|---|---|
| AES-128-GCM Ni seal 1350 B | 3.59 µs | 0.695 µs | **5.2×** |
| AES-128-GCM Ni open 1350 B | 4.10 µs | 0.687 µs | **6.0×** |
| AES-256-GCM Ni seal 1350 B | 4.64 µs | 0.750 µs | **6.2×** |
| AES-128-GCM Ni seal 16 KiB | 46.8 µs | 7.73 µs | **6.0×**（~1.4 周期/字节） |
| AES-128-GCM Ni open 16 KiB | 45.8 µs | 7.63 µs | **6.0×** |
| AES-256-GCM Ni seal 16 KiB | 55.9 µs | 8.47 µs | **6.6×** |

软路径对照用例（未改动代码）同会话变动 0.97–1.10×，在布局噪声本底
内——提升可归因于本次改造。Ni 对软件路径的倍数由 ~120–138× 扩大到
**~750–980×**（如 128 位 16 KiB：6197/7.73 ≈ 800×；256 位 16 KiB
≈ 984×）。既有正确性门全部原样通过（TC1/TC5/TC16 向量、2000 组软/Ni
差分、独立 AES-256 扩展参照表、安装 KAT）。

同会话补测握手（改造后当日三组同进程，跨会话绝对值与 09-10 不可比）：

| 全握手（AES-128-GCM） | 软件路径 | 双 Ni 后 | ring 基线（当日） |
|---|---|---|---|
| X25519 | 1.70 ms | 0.954 ms（~1.8×） | 0.125 ms（Ni 差距 ~7.6×） |
| P-256 | 3.48 ms | 2.76 ms（~1.3×） | — |

握手提升有限是预期内的：握手记录负载小，剩余大头是 P-256 ECDH/ECDSA
软实现（09-10 行的 ~2.35× / ~5.6× 为当日快照，跨会话不可比——本次
ring 绝对值就快了 ~23%）。


### 5.3 ML-KEM 三参数集（M8.3 起 768，M8.4 扩 512/1024；windows-gnu 本地同会话）

三原语（µs，确定性入口，`cargo bench -p ferritls-core --bench kem`，
M8.4 2026-09-15 实测）：

| 参数集 | keygen | encaps | decaps |
|---|---|---|---|
| ML-KEM-512 | 31 | 34 | 50 |
| ML-KEM-768 | 51 | 54 | 75 |
| ML-KEM-1024 | 77 | 78 | 106 |

768 与 M8.3 基线（54/53/76）同噪声带，参数化无回退。

全握手（`cargo bench -p ferritls-interop --bench handshake`，同会话
对照；软件路径、AES-128-GCM）：

| 案例 | 时间 |
|---|---|
| ferritls-x25519（经典） | 1.09 ms |
| ferritls-x25519-mlkem768（混合，M8.3 新增案例） | 1.22 ms（+12%） |
| ferritls-p256 | 2.67 ms |
| ring-baseline-x25519 | 114 µs |

结论：PQ 混合仅使握手 +12%（ML-KEM 三运算 ≈ 183 µs 标量），与
主流 PQ 过渡的部署经验一致；比 P-256 经典握手仍快约 2.2×。
跨会话/跨机器波动见 §3 工作流，判定一律以同会话对照为准。

### 5.4 Ed25519 点运算常数缓存修复（2026-09-17，同会话快速档）

**缺陷**：统一加法每次调用都经 `curve_d()` 现场派生 `2d`
（−121665/121666，含一次 Fermat 模逆 ≈ 500+ 次域乘），而
`scalar_mult` 是 256×(double+add) 恒定执行——每次 sign/verify
约 1024 次重推导，压过点乘本体（§5 参考表中 26 ms 的全部原因）。
`base_point()` 同理：每次调用重做 decompress（含 sqrt 模幂）。

**修复**：`curve_d()` 与 `base_point()` 各以 `OnceLock` 缓存
（std、safe、零新依赖、零 unsafe）。d 与 G 是公开曲线常数，缓存
无零化与秘密相关访存顾虑；缓存值仍由同一派生式计算，与旧实现
逐位一致——全部向量测试零改动通过。常数时间形态未变。

| 用例 | 修复前 | 修复后 | 提升 |
|---|---|---|---|
| sign/ed25519-sign | 25.927 ms | 216.8 µs | **~120×** |
| sign/ed25519-verify | 26.065 ms | 244.1 µs | **~107×** |

（快速档参数 `--sample-size 10 --warm-up-time 0.3
--measurement-time 0.5`；RFC 8032 五向量 + Wycheproof 全量 +
上电自检 KAT 在默认与 no-default-features 双配置原样绿。）

余留（若需进一步提速，另立轮次）：专用 double 公式（~6 乘 vs
通用 8 乘）、radix-2^51 域算术（mul 现走 schoolbook 全积 +
REDC）、基点乘的固定基 comb——注意 `scalar_mult` 的标量是秘密
（sign 的 r、verify 不透明），常规窗口表须按 AGENTS §5.1 的
"索引仅公开数据"判据另行论证。

### 5.5 SHA-256 消息调度滚动窗口实测回退（2026-09-17，第四例回退记录）

**尝试**：把 `compress256` 从"64 字全展开到栈数组、再跑主循环"的
两段式改为 **16 字滚动窗口**（`W[i]` 落槽 `i mod 16`，扩展折算槽偏移
j/j+1/j+9/j+14，融合进 64 轮主循环），预期消除栈流量与寄存器压力。
实测**不支持**该预期：

| 配置（sha256-stream/16384） | 64 字数组（旧） | 滚动窗口（新） | 新 vs 旧 |
|---|---|---|---|
| 默认（SSE2） | ~42.7 µs* | 44.0 µs | **慢 ~3%** |
| +avx2 | 41.9 µs | 43.9 µs | **慢 ~4.7%** |
| +avx512f/vl | 73.7 µs | 56.8 µs | 快 ~23% |

\* 由同会话 `--baseline` 比值折算；+avx2/+avx512 列为同会话直接
A/B（`--save-baseline` 互测）。

唯一收益在 +avx512 档（LLVM 对 64 字数组的向量化决策漂移造成的
回归由 ~+73% 收窄到 ~+29%），但**默认基线不允许回退**（AGENTS §5.5
性能门），且回归未消除。已整体回退——当时维持 64 字数组两段式
（与 HEAD 无 diff）。教训与 P2 第三例同构：**先实测再
立论**；SHA-2 软件路径的宽 ISA 回归列为已知容忍项（硬件面由
SHA-NI 覆盖，流式 ~6×，§5.1；批准模式下 install 拒装时以现形态为
顶，不阻塞发布）。（本节"维持两段式"的结论被**同日第二轮**的
软流水形态取代，见 §5.6；滚动窗口方向本身的否决依旧成立。）

### 5.6 SHA-256 软流水消息调度（2026-09-17 第二轮，已采纳）

**形态**：保留 64 字数组，但**取消独立的展开循环**——`w[i+16]`
的计算融合进压缩主循环第 i 轮头部（`if i < 48`；64 轮定长循环经
完全展开后该条件为编译期常量，无运行期分支）。调度加法链与压缩
轮关键路径并行，消除两段式的串行前导延迟——实测收益的主导项。

**同会话 A/B（sha256-stream/16384，`--save-baseline` 互测）**：

| 配置 | 两段式（旧） | 软流水（新） | 变化 |
|---|---|---|---|
| 默认（SSE2） | 42.88 µs | 36.83 µs | **−14.2%**（382→445 MB/s） |
| +avx2 | 46.24 µs | 42.57 µs | −4.4% |
| +avx512f/vl | 75.26 µs | 60.84 µs | −18.6%（回归 +75%→+65%，未根除） |

1350 B 流式 / HMAC-SHA256 / HKDF extract+expand 各用例同步
−14.0~−14.2%。同轮对照的第二候选"16 字窗口分块调度"（chunk
形态，寄存器窗口无栈数组）实测**比软流水慢 ~9%**，未采纳——
§5.5 对滚动窗口方向的否决依旧成立，被取代的只是"两段式为实测
最优"一句。

正确性：默认 / no-default-features / fips 三配置 151 测试全绿
（SHAVS 长消息、Wycheproof、上电自检逐字节零改动）；clippy 双
配置 `-D warnings` 干净；常数时间形态不变（数据无关算术）。
宽 ISA 残余回归（+avx512 相对默认 +65%）维持已知容忍项。

### 5.7 SHA-256 `std::simd` 消息调度实测回退（2026-09-17 第三轮，第五例回退）

**尝试**：软流水的调度步搬到 `u32x4`（一次 4 字；σ₁ 的组内环依赖
两阶段破除：无环部分以 `from_array` 窗口装载 + splat 移位向量
计算，缺失的 σ1(Y0)/σ1(Y1) 标量补进 lane 2/3）。等价性由 unit
测试 `schedule_next4_matches_textbook_expansion` 对照教科书逐字
展开守护（双配置绿）。

**实测（同会话 `--save-baseline` 互测，sha256-stream/16384）**：

| 配置 | 软流水（标量基线） | std::simd 调度 | 变化 |
|---|---|---|---|
| 默认（SSE2） | 37.1 µs | 37.1 µs | ≈0（p>0.3；1350 B 档 −0.2~−1.6% 微升） |
| +avx2 | 37.4 µs | 37.0 µs | −1.1% |
| +avx512f/vl | ~60.0 µs | 64.5 µs | **+7.4%（p<0.05，回归）** |

hkdf-expand-64 在默认档一次显示 −10%（p<0.05），复跑未稳定复现，
判小案例噪声，不构成立论。

**判定**：否决回退——64 轮压缩是严格串行链，SIMD 无法并行轮次
本体；调度只占循环体一小部分，且软流水形态下 LLVM 已把它与关键
路径重叠，搬到向量端口没有增益空间；+avx512 档 128 位操作与
`to_array` 拆散反而破坏 LLVM 既有调度（回归）。教训延续 §5.5/
§5.6：**portable_simd 的收益前提是"存在未开发的 lane 并行"**
（AES 位切片、ChaCha 多块有，SHA-256 单流没有）。实验代码保留于
本地 stash；复述本节即可再推导。**软件路径天花板即标量串行链
本身**——更大的增益只来自硬件指令（SHA-NI 覆盖 SHA-256 流式
~6×，§5.1；SHA-512 方向的 VSHA512*/SHA-512-VAES 属 x86_64 后端
排期素材，边界外）。

## 6. Windows（msys2/windows-gnu）本地注意

带 C 构建依赖的 dev-deps（criterion 0.8 → `alloca`）要求 ucrt64 工具链
在 PATH **最前**，否则 gcc 子进程混载 mingw64 DLL 会静默崩溃（cc-rs 报
exit 1 且无诊断输出）：

```bash
export PATH="/c/msys64/ucrt64/bin:$PATH"
```

已知环境交互：criterion 0.8 的 alloca 扩展栈与 `getrandom` 组合下，
`CtrDrbg::instantiate_from_os` 会间歇返回 `EntropyFailed`（criterion 外
2 万次循环零失败，属基准环境问题而非库缺陷）——因此不 bench 实例化，
仅 bench `generate`（其在 criterion 内已验证稳定）。

## 7. 新增基准的约定

1. **入口只走公开 API**（与外部用户同一路径），不触碰内部函数。
2. 输入确定性：用 `pattern()` 风格的伪随机填充，循环内不调 OS 熵；
   确实以 OS 熵为语义一部分的（如 DRBG generate）除外，且须注释说明。
3. 按字节处理的操作挂 `Throughput::Bytes`，单次操作（如握手）挂
   `Throughput::Elements(1)`。
4. 单次 >1 ms 的操作调低 `sample_size`（如 sign.rs 的 RSA 组设 20），
   控制整轮时长。
5. 新文件需在 crate 的 `Cargo.toml` 登记 `[[bench]] name = …
   harness = false`。
6. `cargo clippy --workspace --all-targets -- -D warnings` 覆盖 benches，
   同样是硬门。
7. 本文件 §1 的清单表随新基准同步更新（AGENTS.md 规则 9 的文档先行）。
