# ferritls 架构

本文描述目标架构与数据流。当前 M0–M7 与 M8.1–M8.5 已全部落地：
ferritls-core 全模块实现完毕（无 `todo!()` 残留），rustls 适配层、
互操作矩阵与 QUIC 包保护已建成；M8 起 AES-GCM/SHA-256 公开类型经
`ops` 分发（§4），硬件后端 `ferritls-backend-aesni` 以边界外 crate
形式挂接。改架构先改本文（AGENTS.md 规则 9）。

## 1. crate 分层与依赖方向

```
        ┌─────────────────────────────────────────────┐
        │ 应用（hyper / reqwest / 自研服务 …）         │
        └──────────────────┬──────────────────────────┘
                           │ rustls 0.23 CryptoProvider
        ┌──────────────────▼──────────────────────────┐
        │ ferritls-rustls   适配层（FIPS 边界外）      │
        │  provider / cipher / kx / sign / verify /   │
        │  random —— 只做 trait 装配，零密码学         │
        └──────────────────┬──────────────────────────┘
                           │ 单向依赖
        ┌──────────────────▼──────────────────────────┐
        │ ferritls-core    密码学核心（FIPS 边界内）   │
        │  L0  ct · policy · der · entropy            │
        │  L1  sha2 · sha3 · aes · chacha20poly1305   │
        │  L2  hmac · hkdf · gcm · ccm                │
        │  L3  ecdh · mlkem · sign · drbg · selftest  │
        │  依赖白名单：subtle / zeroize / getrandom   │
        └──────────────────▲──────────────────────────┘
                           │ ops::install()（应用侧显式，可选）
        ┌──────────────────┴──────────────────────────┐
        │ ferritls-backend-aesni  硬件后端（边界外，  │
        │  仅 x86_64）AES-NI + CLMUL GHASH；unsafe    │
        │  限于唯一叶子模块（§4）                     │
        └─────────────────────────────────────────────┘
```

约束：

- 依赖只能自上而下；`ferritls-core` 不依赖 rustls。
- 只有 `ferritls-rustls` 允许 import rustls 类型。
- `ferritls-interop` 的依赖不受限（ring/aws-lc-rs/openssl 作为对手盘）。
- `ferritls-backend-aesni` 依赖 core（实现其 ops trait）；**core 与
  适配层都不依赖它**——不安装即不存在，软件路径完全不受影响。
- 应用层兼容性源自同一条 rustls ^0.23 版本线：reqwest 0.12/0.13
  （各自以 `*-no-provider` feature 构建）与 ferritls 被 Cargo 统一到
  同一 rustls 实例，由 interop `tests/reqwest.rs` 回环握手守护。

## 2. rustls 接口映射表（0.23.45）

| rustls 需要的东西 | ferritls 提供 | 备注 |
|---|---|---|
| `cipher_suites: Vec<SupportedCipherSuite>` | `cipher::all_tls13_suites()` | 5 个 TLS 1.3 套件（2026-09 起，含 CCM_8 仅默认模式）；批准模式 3 个 |
| `Tls13CipherSuite.hash_provider` | 包装 `core::sha2` 为 `crypto::Hash` | 块长/输出长 + reset/update/finish |
| `Tls13CipherSuite.hkdf_provider` | `crypto::tls13::HkdfUsingHmac` + 包装的 `crypto::hmac::Hmac` | **复用 rustls 辅助器**，不手写密钥调度 |
| `Tls13CipherSuite.aead_alg` | 包装 `core::gcm`/`ccm`/`chacha20poly1305` 为 `Tls13AeadAlgorithm` | `extract_keys` 已支持 key exporter（GCM/ChaCha20；CCM 两档——M=16 的 CCM 与 M=8 的 CCM_8——因 rustls `ConnectionTrafficSecrets` 无对应变体返回 `UnsupportedOperationError`） |
| `Tls13CipherSuite.quic` | `quic::{QuicAes128Gcm,QuicAes256Gcm,QuicChacha20Poly1305}`（M8.5；CCM 两档均为 `None`） | `quic::Algorithm`（PacketKey：nonce = IV⊕pn、先验后出；HeaderProtectionKey：AES-ECB / ChaCha20 单块掩码，RFC 9001 §5.3/§5.4；multipath `for_path` 同式）；向量锚 RFC 9001 §A.2/A.3/A.5 |
| `kx_groups: &[&dyn SupportedKxGroup]` | `kx::{X25519,SecP256R1,SecP384R1,X25519MLKEM768,Mlkem512,Mlkem768,Mlkem1024}` | 经典 ECDH 用默认 `start_and_complete`；混合组（0x11EC）与纯 ML-KEM 组（0x0200–0x0202，M8.4）覆写 `start_and_complete`（KEM 数据依赖：服务端封装 + §7.2 封装密钥检查） |
| `ActiveKeyExchange` | `kx::Active*` 持有 core 的 ECDH/ML-KEM 私钥 | `complete` 消费 `Box<Self>`（混合组客户端在此解封装） |
| `signature_verification_algorithms` | `verify::SUPPORTED_ALGORITHMS` | webpki 消费；TLS1.3 每 scheme 取首项；webpki 传裸 key_value（无 SPKI 包装），core `VerifyKey` 构造器按该裸格式定义、适配层透传 |
| `secure_random` | `random::SystemRandom` → core `entropy`/`drbg` | M5 起批准模式走 DRBG |
| `key_provider` | `sign::KeyLoader` → core `der` + `sign::*Key` | 5 字段中容易漏的一个 |
| `rustls::sign::{SigningKey,Signer}` | `sign::{EcdsaP256Key,…}` | `sign()` 输入未哈希消息 |

## 3. TLS 1.3 数据流

```
ClientHello ──SupportedKxGroup::start()──► core::ecdh 私钥+公钥
                                          │
握手签名 ────SigningKey::choose_scheme───► core::sign（内部哈希+签名）
                                          │
密钥调度 ────rustls HkdfUsingHmac─────────► core::hkdf ←─ core::hmac ←─ core::sha2
                                          │
记录层 ──────Tls13AeadAlgorithm──────────► core::gcm/ccm/chacha20poly1305
                                          │
ClientHello.random ──SecureRandom::fill──► core::drbg（M5 起批准模式）/ core::entropy（其余）
```

ferritls-core 内部再经过 `ops` 分发（§4）：上表箭头默认落在软件直连
路径；应用显式安装硬件后端后，AES-GCM 的执行核心被替换，公开 API 与
trait 装配不变。

## 4. Ops 后端分发模式（优化入口）

每个原语的公开类型是薄壳；`ferritls-core::ops` 定义后端分发 trait 作为
硬件后端的唯一挂接点。**默认路径零分发开销**：未安装后端时，公开类型
内部经 `enum { Soft, Ext }` 直连软件实现（不经 trait 对象）；安装后，
新构造的实例取得 trait 对象执行核心，每消息一次 dyn 分发（不是每块/
每字节），µs–ms 级操作下分发开销不可见：

```rust
// ferritls-core::ops —— AEAD 侧（AES-GCM）
pub trait AeadGcm: Send + Sync {
    /// 合同为不可失败：前置条件由公开类型的类型系统保证。
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16];
    /// 就地解密并返回**计算出的**标签；标签比较由 core 公开类型以
    /// ct::verify_tag 完成——常数时间纪律集中在 core，后端只算不比。
    fn open_compute_tag(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8])
        -> [u8; 16];
    fn clone_box(&self) -> Box<dyn AeadGcm>;
}
pub trait AeadOps: Send + Sync {
    fn name(&self) -> &'static str;
    fn aes128_gcm(&self, key: &[u8; 16]) -> Box<dyn AeadGcm>;
    fn aes256_gcm(&self, key: &[u8; 32]) -> Box<dyn AeadGcm>;
}
/// 进程级一次性安装；批准模式或重复安装 → Err(Unsupported)。
pub fn install(backend: &'static dyn AeadOps) -> Result<(), Error>;
/// 未安装 → None（公开类型据此走零开销软件直连分支）。
pub fn installed_aead() -> Option<&'static dyn AeadOps>;

// SHA-256 侧为函数分发：后端不携带实例状态，只交出块压缩函数。
pub type Sha256Compress = fn(h: &mut [u32; 8], block: &[u8; 64]);
pub trait HashOps: Send + Sync {
    fn name(&self) -> &'static str;
    fn sha256_compress(&self) -> Sha256Compress;
}
pub fn install_hash(backend: &'static dyn HashOps) -> Result<(), Error>;
```

规则：

1. 软件实现是默认路径，常驻边界内；未安装任何后端时公开类型**直连**
   软件代码（零分发开销），行为与未接线时逐字节一致。
2. 硬件后端（AES-NI/CLMUL/SHA-ext）是**边界外的独立 crate**
   （`ferritls-backend-aesni`，仅 x86_64），经 `ops::install()` 显式
   注册：进程内一次安装、运行期不切换；安装前须通过后端自身 KAT。
   安装是**应用侧显式动作**——适配层与 provider 构造不隐式安装。
3. 批准模式下后端固定为软件后端（FIPS 边界按软件实现申报；引入硬件
   后端入边界 = 重新走实验室审查，阶段 C 的决策）；`fips` feature
   构建下 `install()` 直接拒绝。
4. 后端 crate 的 unsafe 纪律（借鉴 fearless_simd 的模式，零依赖自建）：
   crate 根 `#![deny(unsafe_code)]`；unsafe 存在于唯一 `#[allow(unsafe_code)]`
   私有叶子模块（**仅内存读写包装**——寄存器型 intrinsic 没有包装，
   只在 kernel 内直调）与各 kernel 文件的**单点**
   `#[allow(unsafe_code)]` trampoline（进入 `#[target_feature]`
   kernel 的调用）。CPU 能力 token 只能经运行时探测构造（能力在类型
   层面成为调用前置条件）。**kernel 必须标记 `#[target_feature]` 并
   在其上下文内直接调用 intrinsic**——该工具链的 intrinsic 是带
   feature 的安全函数，从无 feature 上下文调用不得内联（每次包装
   调用都是真实函数调用），会吃光硬件收益（实测：SHA-NI 未优化时
   反而比软件慢 ~20%；AES/CLMUL 同病——反汇编 103 处真实 callq，
   2026-09-13 直调化后清零，GCM 原语 5.2–6.6×，见 BENCHMARKS §5.2）。
5. 未接后端的原语（CCM/ChaCha20-Poly1305/ECDH/签名）保持软件实现
   直通；其 Ops trait 随对应硬件后端排期**同步定义**，禁止预写无用
   trait 堆积。（历史注记：SHA-256 曾试对象分发形态，因 HKDF 短命
   实例的逐实例检查 +2.3% 被零回归门否决；函数分发形态使其归零，
   hkdf 甚至因 finalize 直写重构改善 ~3.5%。）
6. **软件后端自身的性能重构**（稳定版、零 unsafe、边界内——P1/P2 性能
   轮的批量 XOR / 位切片 / 瞬态 H 倍数表 / `core::simd` 路径等）不经
   ops 分发——它就是对软件后端的常规维护，公开 API 不变；ops 分发
   仅服务边界外硬件后端 crate（AGENTS §5.5）。GHASH 的 H 倍数表属
   “索引公开、内容含秘密”类查表，判据见 AGENTS §5.1。

任何性能改动（含 M8 硬件后端）前后都用 `docs/BENCHMARKS.md` 的基线
工作流（`--save-baseline` / `--baseline`）在同机量化对比，禁止仅凭
直觉申报性能改进（AGENTS.md §5.5）。

## 5. 错误处理

- 边界内统一 `ferritls_core::Error`（`non_exhaustive`）。
- 对外（rustls 侧）转换为 `rustls::Error`：验证失败 →
  `rustls::Error::General("verification failed")` 或对应变体；错误信息
  **不得**泄露失败的具体阶段（防 oracle）。
- 解析失败与验证失败在 AEAD 打开路径上不可区分（同一错误码）。

## 6. 零化点清单（M5 验收核对）

| 位置 | 内容 |
|---|---|
| aes/gcm/ccm/chacha20poly1305 | 轮密钥、GHASH H、Poly1305 one-time key |
| sha2/hmac | HMAC 内部 ipad/opad 状态（哈希状态本身非秘密，随实现判断） |
| ecdh | 私钥标量、共享秘密 |
| sign | ECDSA 标量与 nonce、RSA CRT 参数与盲化因子、Ed25519 种子 |
| drbg | V、Key |
| 适配层 | `Active*` 结构里的 core 私钥（core 类型自带 ZeroizeOnDrop 即覆盖） |

## 7. 版本与升级策略

- 锚定 rustls 0.23.x 最新补丁；CI 的 `cargo update -p rustls --precise`
  跟踪补丁版（0.23 线内视为兼容）。
- rustls 0.24 出 RC 后加 CI 跟踪 job（git-dependency），差异全部隔离在
  `ferritls-rustls`（AGENTS.md §4 的 0.24 预警清单）。
- edition 2024（编译需 Rust ≥ 1.85）；不设 MSRV 下限承诺，跟随 CI 的
  当前 stable（依赖兼容性由 resolver 3 的 rust-version 感知兜底）。
