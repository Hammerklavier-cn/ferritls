# ferritls 架构

本文描述模块分层、数据流与 Ops 后端分发模式。M0–M7 与 M8.1–M8.5 已
全部落地（无 `todo!()` 残留）。改架构先改本文（AGENTS.md 规则 9）。

## 1. crate 分层与依赖方向

```
        ┌─────────────────────────────────────────────┐
        │ 应用（hyper / reqwest / 自研服务 …）         │
        └──────────────────┬──────────────────────────┘
                           │ rustls 0.23 CryptoProvider
        ┌──────────────────▼──────────────────────────┐
        │ ferritls-rustls   适配层（FIPS 边界外）      │
        │  provider / cipher / kx / sign / verify /   │
        │  random / quic —— 只做 trait 装配，零密码学  │
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
        │ ferritls-backend-x86_64  硬件后端（边界外， │
        │  仅 x86_64）AES-NI/CLMUL/SHA-NI；unsafe     │
        │  限于唯一叶子模块（§4）                     │
        └─────────────────────────────────────────────┘
```

约束：

- 依赖只能自上而下；`ferritls-core` 不依赖 rustls；只有
  `ferritls-rustls` 允许 import rustls 类型。
- `ferritls-interop` 的依赖不受限（ring/aws-lc-rs/openssl 作为对手盘）。
- `ferritls-backend-x86_64` 依赖 core（实现其 ops trait）；**core 与
  适配层都不依赖它**——不安装即不存在，软件路径完全不受影响。
- 应用层兼容性源自同一条 rustls ^0.23 版本线：reqwest 0.12/0.13
  （`*-no-provider` feature）与 ferritls 被 Cargo 统一到同一 rustls
  实例，由 interop `tests/reqwest.rs` 回环握手守护。

## 2. rustls 接口映射表（0.23.45）

| rustls 需要的东西 | ferritls 提供 | 备注 |
|---|---|---|
| `cipher_suites: Vec<SupportedCipherSuite>` | `cipher::all_tls13_suites()` | 5 个 TLS 1.3 套件（CCM_8 仅默认模式）；批准模式 3 个 |
| `Tls13CipherSuite.hash_provider` | 包装 `core::sha2` 为 `crypto::Hash` | 块长/输出长 + reset/update/finish |
| `Tls13CipherSuite.hkdf_provider` | `crypto::tls13::HkdfUsingHmac` + 包装的 `crypto::hmac::Hmac` | **复用 rustls 辅助器**，不手写密钥调度 |
| `Tls13CipherSuite.aead_alg` | 包装 `core::gcm`/`ccm`/`chacha20poly1305` 为 `Tls13AeadAlgorithm` | `extract_keys` 支持 key exporter（GCM/ChaCha20；CCM 两档因 rustls `ConnectionTrafficSecrets` 无对应变体返回 `UnsupportedOperationError`） |
| `Tls13CipherSuite.quic` | `quic::{QuicAes128Gcm,QuicAes256Gcm,QuicChacha20Poly1305}`（CCM 两档均 `None`） | PacketKey：nonce = IV⊕pn、先验后出；HeaderProtectionKey：AES-ECB / ChaCha20 单块掩码（RFC 9001 §5.3/§5.4）；multipath `for_path` 同式；向量锚 RFC 9001 §A.2/A.3/A.5 |
| `kx_groups: &[&dyn SupportedKxGroup]` | `kx::{X25519,SecP256R1,SecP384R1,X25519MLKEM768,Mlkem512,Mlkem768,Mlkem1024}` | 经典 ECDH 用默认 `start_and_complete`；混合组（0x11EC）与纯 ML-KEM 组（0x0200–0x0202）覆写（KEM 数据依赖：服务端封装 + FIPS 203 §7.2 封装密钥检查） |
| `ActiveKeyExchange` | `kx::Active*` 持有 core 的 ECDH/ML-KEM 私钥 | `complete` 消费 `Box<Self>`（混合组客户端在此解封装） |
| `signature_verification_algorithms` | `verify::SUPPORTED_ALGORITHMS` | webpki 消费；TLS 1.3 每 scheme 取首项；webpki 传裸 key_value（无 SPKI 包装），core `VerifyKey` 构造器按裸格式定义、适配层透传 |
| `secure_random` | `random::SystemRandom` → core `entropy`/`drbg` | 批准模式走 DRBG |
| `key_provider` | `sign::KeyLoader` → core `der` + `sign::*Key` | 5 字段中容易漏的一个 |
| `rustls::sign::{SigningKey,Signer}` | `sign::{EcdsaP256Key,…}` | `sign()` 输入未哈希消息 |

## 3. TLS 1.3 数据流

```
ClientHello ──SupportedKxGroup::start()──► core::ecdh / core::mlkem
握手签名 ────SigningKey::choose_scheme───► core::sign（内部哈希+签名）
密钥调度 ────rustls HkdfUsingHmac─────────► core::hkdf ←─ core::hmac ←─ core::sha2
记录层 ──────Tls13AeadAlgorithm──────────► core::gcm/ccm/chacha20poly1305
ClientHello.random ──SecureRandom::fill──► core::drbg（批准模式）/ core::entropy（其余）
```

core 内部再经 `ops` 分发（§4）：上图箭头默认落在软件直连路径；应用
显式安装硬件后端后 AES-GCM/SHA-256 的执行核心被替换，公开 API 与
trait 装配不变。

## 4. Ops 后端分发模式（硬件加速的唯一入口）

每个原语的公开类型是薄壳；`ferritls-core::ops` 定义后端分发 trait。
**默认路径零分发开销**：未安装后端时公开类型内部经
`enum { Soft, Ext }` 直连软件实现；安装后新构造的实例取得 trait 对象
执行核心，每消息一次 dyn 分发（非每块/每字节），µs–ms 级操作下不可见：

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

// SHA-256 侧为函数分发（对象分发曾因 HKDF 短命实例 +2.3% 被零回归门
// 否决）：后端不携带实例状态，只交出块压缩函数。
pub type Sha256Compress = fn(h: &mut [u32; 8], block: &[u8; 64]);
pub trait HashOps: Send + Sync {
    fn name(&self) -> &'static str;
    fn sha256_compress(&self) -> Sha256Compress;
}
pub fn install_hash(backend: &'static dyn HashOps) -> Result<(), Error>;
```

规则：

1. 软件实现是默认路径，常驻边界内；未安装后端时公开类型**直连**软件
   代码，行为与未接线时逐字节一致。
2. 硬件后端是**边界外独立 crate**，经 `ops::install()` 显式注册：
   进程内一次安装、运行期不切换；安装前须通过后端自身 KAT。安装是
   **应用侧显式动作**——适配层与 provider 构造不隐式安装。
3. 批准模式固定软件后端（FIPS 边界按软件实现申报；硬件后端入边界 =
   重走实验室审查，属阶段 C 决策）；`fips` feature 构建下
   `install()` 直接拒绝。
4. 后端 crate 的 unsafe 纪律（借鉴 fearless_simd，零依赖自建）：
   crate 根 `#![deny(unsafe_code)]`；unsafe 只在唯一
   `#[allow(unsafe_code)]` 私有叶子模块（**仅内存读写包装**）与各
   kernel 文件的**单点** trampoline；CPU 能力 token 只能经运行时探测
   构造（能力成为类型层面的调用前置条件）。**kernel 必须标
   `#[target_feature]` 并在其上下文内直调 intrinsic**——从无 feature
   上下文调用不得内联，会吃光硬件收益（实测 SHA-NI 反而慢 ~20%、
   AES 侧 103 处真实 callq，直调化后清零，见 BENCHMARKS §5.1/§5.2）。
5. 未接后端的原语（CCM/ChaCha20-Poly1305/ECDH/签名）保持软件直通；
   其 Ops trait 随对应硬件后端排期**同步定义**，禁止预写无用 trait。
6. **软件后端自身的性能重构**（P1/P2 的批量 XOR / 位切片 /
   `core::simd` 路径等）不经 ops 分发——属常规维护，公开 API 不变；
   ops 仅服务边界外硬件后端 crate（AGENTS §5.5）。GHASH 的 H 倍数表
   属“索引公开、内容含秘密”类查表，判据见 AGENTS §5.1。

任何性能改动前后都用 `docs/BENCHMARKS.md` 的基线工作流
（`--save-baseline` / `--baseline`）同机量化对比，禁止凭直觉申报
性能改进（AGENTS.md §5.5）。

## 5. 错误处理

- 边界内统一 `ferritls_core::Error`（`non_exhaustive`）。
- 对外（rustls 侧）转换为 `rustls::Error`；错误信息**不得**泄露失败
  的具体阶段（防 oracle）。
- 解析失败与验证失败在 AEAD 打开路径上不可区分（同一错误码）。

## 6. 零化点清单（M5 验收核对）

| 位置 | 内容 |
|---|---|
| aes/gcm/ccm/chacha20poly1305 | 轮密钥、GHASH H 与瞬态倍数表、Poly1305 one-time key 与 r 幂 |
| sha2/hmac | HMAC 内部 ipad/opad 状态（哈希状态本身非秘密，随实现判断） |
| ecdh | 私钥标量、共享秘密、盲化因子 |
| sign | ECDSA 标量与 nonce、RSA CRT 参数与盲化因子、Ed25519 种子 |
| mlkem | dk、ss、中间 K/K̃、ŝ、r/m 种子 |
| drbg | V、Key |
| 适配层 | `Active*` 结构里的 core 私钥（core 类型自带 ZeroizeOnDrop 即覆盖） |

## 7. 版本与升级策略

- 锚定 rustls 0.23.x 最新补丁；CI 的 `cargo update -p rustls --precise`
  跟踪补丁版（0.23 线内视为兼容）。
- rustls 0.24 出 RC 后加 CI 跟踪 job（git-dependency），差异全部隔离
  在 `ferritls-rustls`（AGENTS.md §4 的 0.24 预警清单）。
- edition 2024；MSRV 按标量回退路径锚定（AGENTS.md §7），默认 `simd`
  feature 跟随当前 stable 的 core::simd 形态。
