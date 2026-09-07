# ferritls 架构

本文描述目标架构与数据流。当前仓库处于 M0 骨架阶段：模块签名已定型，
实现按 ROADMAP 里程碑落地。改架构先改本文（AGENTS.md 规则 9）。

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
        │  L1  sha2 · aes · chacha20poly1305          │
        │  L2  hmac · hkdf · gcm · ccm                │
        │  L3  ecdh · sign · drbg · selftest          │
        │  依赖白名单：subtle / zeroize / getrandom   │
        └─────────────────────────────────────────────┘
```

约束：

- 依赖只能自上而下；`ferritls-core` 不依赖 rustls。
- 只有 `ferritls-rustls` 允许 import rustls 类型。
- `ferritls-interop` 的依赖不受限（ring/aws-lc-rs/openssl 作为对手盘）。

## 2. rustls 接口映射表（0.23.43）

| rustls 需要的东西 | ferritls 提供 | 备注 |
|---|---|---|
| `cipher_suites: Vec<SupportedCipherSuite>` | `cipher::all_tls13_suites()` | 4 个 TLS 1.3 套件；批准模式 3 个 |
| `Tls13CipherSuite.hash_provider` | 包装 `core::sha2` 为 `crypto::Hash` | 块长/输出长 + reset/update/finish |
| `Tls13CipherSuite.hkdf_provider` | `crypto::tls13::HkdfUsingHmac` + 包装的 `crypto::hmac::Hmac` | **复用 rustls 辅助器**，不手写密钥调度 |
| `Tls13CipherSuite.aead_alg` | 包装 `core::gcm`/`ccm`/`chacha20poly1305` 为 `Tls13AeadAlgorithm` | `extract_keys` M6 支持 key exporter |
| `Tls13CipherSuite.quic` | `None` | QUIC 是 M8+ |
| `kx_groups: &[&dyn SupportedKxGroup]` | `kx::{X25519,SecP256R1,SecP384R1}` | 经典 ECDH 用默认 `start_and_complete` |
| `ActiveKeyExchange` | `kx::Active*` 持有 core 的 ECDH 私钥 | `complete` 消费 `Box<Self>` |
| `signature_verification_algorithms` | `verify::SUPPORTED_ALGORITHMS` | webpki 消费；TLS1.3 每 scheme 取首项 |
| `secure_random` | `random::SystemRandom` → core `entropy`/`drbg` | M5 起批准模式走 DRBG |
| `key_provider` | `sign::KeyLoader` → core `der` + `sign::*Key` | 5 字段中容易漏的一个 |
| `rustls::sign::{SigningKey,Signer}` | `sign::{EcdsaP256Key,…}` | `sign()` 输入未哈希消息 |

## 3. TLS 1.3 数据流（M6 后）

```
ClientHello ──SupportedKxGroup::start()──► core::ecdh 私钥+公钥
                                          │
握手签名 ────SigningKey::choose_scheme───► core::sign（内部哈希+签名）
                                          │
密钥调度 ────rustls HkdfUsingHmac─────────► core::hkdf ←─ core::hmac ←─ core::sha2
                                          │
记录层 ──────Tls13AeadAlgorithm──────────► core::gcm/ccm/chacha20poly1305
                                          │
ClientHello.random ──SecureRandom::fill──► core::entropy（M5 前）/ core::drbg（后）
```

ferritls-core 内部再经过 `ops` 分发（§4），上表的所有箭头最终落在
软件后端。

## 4. Ops 后端分发模式（优化入口）

每个原语的公开类型是薄壳，内部经 `Ops` trait 调到具体后端：

```rust
// ferritls-core::ops（示例为 AeadOps，正式启用于 M2）
pub trait AeadOps: Send + Sync {
    fn name(&self) -> &'static str;
    fn seal_in_place(&self, nonce: &[u8], aad: &[u8], buf: &mut [u8])
        -> Result<[u8; 16], Error>;
    fn open_in_place(&self, nonce: &[u8], aad: &[u8], buf: &mut [u8], tag: &[u8])
        -> Result<(), Error>;
}
```

规则：

1. 软件实现（`SoftwareBackend`）是默认且当前唯一的后端，常驻边界内。
2. 硬件后端（AES-NI/SHA-ext/AVX512）是**边界外的独立 crate**，需要
   `unsafe`/intrinsics，经注册挂入；进程启动时探测一次（
   `is_x86_feature_detected!`），运行期不切换。
3. 批准模式下后端固定为软件后端（FIPS 边界按软件实现申报；引入硬件
   后端入边界 = 重新走实验室审查，阶段 C 的决策）。
4. 每个里程碑落地对应原语时**同步定义**其 Ops trait（避免事后重构），
   但禁止预写无实现的 trait 堆积。

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
- MSRV 1.75；提升 MSRV 需要评估 rustls 的 MSRV 再动。
