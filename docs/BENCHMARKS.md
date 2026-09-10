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
| `handshake` | ferritls-interop | TLS 1.3 内存全握手（进程内管道驱动，无 TCP/线程噪声）：ferritls × X25519 / P-256 + **ring 同套件基线**，AES-128-GCM，双方钉扎。**软件路径**（不安装后端） | Elements |
| `aead_ni` | ferritls-backend-aesni | 软/Ni 逐记录对照：AES-128/256-GCM 的 seal/open，尺寸与 `aead` 一致（不安装，Ni 侧经 token 直构，两路径同进程独立测） | Bytes |
| `hash_ni` | ferritls-backend-aesni | SHA-256 软/Ni 对照：同 core `hash` 的案例（流式 1350/16K + HMAC + HKDF），同进程分安装前后（criterion 组按注册顺序同步执行，中间桥接安装） | Bytes |
| `handshake_ni` | ferritls-interop | 与 `handshake` 同法，**启动时安装 AES-NI 后端**（仅 x86_64；与 `handshake` 分属二进制，互不污染） | Elements |

要点：

- 所有密钥/输入用固定种子确定性构造，bench 循环内不调 OS 熵（唯一例外
  是 `drbg/generate-32b` 的重播种——那是被测语义的一部分）。
- `handshake` 每次迭代 = 一次完整握手（client+server 全部密码学计算与
  记录层组帧）；每案例先跑一次握手验证配置可用、套件钉扎正确。
- RSA 用内嵌 hex 的本地生成 2048 位测试密钥，不承载任何真实身份。

## 2. 运行

```bash
# 全部基准（core 5 个 + interop 1 个），完整一轮约 10–20 分钟
cargo bench --workspace

# 单 crate / 单目标
cargo bench -p ferritls-core --bench aead
cargo bench -p ferritls-interop --bench handshake
cargo bench -p ferritls-backend-aesni --bench aead_ni      # 软/Ni 逐记录
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
建立直觉，不作为任何依据**：

| 操作 | 量级 |
|---|---|
| ChaCha20-Poly1305 seal 1350 B | ~3 µs |
| AES-128-GCM seal/open 1350 B | ~0.5 ms（**比 ChaCha 慢两个数量级**：逐位 GHASH + 按位 S-box 是常数时间纪律下的有意取舍，AGENTS.md §5.1） |
| SHA-256 流式 16 KiB | ~42 µs |
| X25519 / P-256 / P-384 标量乘 | ~63 µs / ~0.5 ms / ~2.1 ms |
| ECDSA P-256 sign / verify | ~0.51 ms / ~0.63 ms |
| Ed25519 sign / verify | ~26 ms / ~26 ms |
| RSA-2048 私钥运算 / 公钥验证 | ~2.3 ms / ~0.27 ms |
| CTR-DRBG generate 32 B（含 OS 重播种） | ~39 µs |
| 全握手 ferritls × X25519 / P-256 | ~1.5 ms / ~3.2 ms |
| 全握手 ring × X25519（基线） | ~0.11 ms（**约 13 倍差距** = M8 intrinsics 后端的目标空间） |

### 5.1 M8.1 软/Ni 对照（2026-09-10，同机同会话，软/Ni 可比）

AES-NI + CLMUL 后端（`ferritls-backend-aesni`，仅 x86_64）相对软件
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
  同理存在该开销（aesenc 调用链），后续可按同法优化；
- **跨日绝对值不可比**：不同会话的机器状态差异可达 ±40%+（本次软
  路径相对上次会话整体漂移 +43%），回归判断只认同会话 A/B。

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
