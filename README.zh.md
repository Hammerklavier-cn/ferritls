# ferritls

[English](README.md) | [简体中文](README.zh.md)

ferritls 是纯 Rust 的 [rustls](https://github.com/rustls/rustls)
`CryptoProvider`：密码学核心无 C、无汇编、无 `unsafe`，按 FIPS 140-3
模块边界组织。它是 `aws-lc-rs`（C/汇编、cmake、编译慢）与已停更的
`rustls-rustcrypto` 之外一条活跃维护、全程可审计的路线。

## 亮点

- **TLS 1.3 套件**：AES-128/256-GCM、AES-128-CCM（含 CCM_8）、
  ChaCha20-Poly1305
- **密钥交换**：X25519、secp256r1、secp384r1、抗量子 **ML-KEM**
  512/768/1024（FIPS 203）与 X25519MLKEM768 混合
- **证书签名**：ECDSA P-256/384、RSA-PSS / PKCS#1 v1.5、Ed25519
- **QUIC** 包保护（RFC 9001，GCM 与 ChaCha 套件）
- **批准模式**（`fips` feature）：仅 NIST 批准算法 + SP 800-90A
  CTR-DRBG + 上电自检
- 可选 **x86_64 硬件后端**（AES-NI / SHA-NI）：
  [`ferritls-backend-x86_64`](https://crates.io/crates/ferritls-backend-x86_64)，
  独立 crate、运行时注册（FIPS 边界外）
- 测试面：NIST/RFC/CAVP 官方向量、Wycheproof 2300+ 用例、rustls-ring
  交叉互操作、持续 fuzz

## 用法

```toml
[dependencies]
ferritls-rustls = "0.9"
```

```rust
// 进程内一次，在构建任何 TLS 配置之前：
ferritls_rustls::default_provider().install_default()?;

// 此后 rustls 默认使用 ferritls：
let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
```

不想碰进程全局状态时，显式传入 provider：

```rust
use std::sync::Arc;

let provider = Arc::new(ferritls_rustls::default_provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
```

详细用法——服务端配置、批准模式、QUIC、reqwest 集成——见
**[API 文档](https://docs.rs/ferritls-rustls)**。

### 硬件后端（x86_64，可选）

```toml
[dependencies]
ferritls-backend-x86_64 = "0.9"
```

```rust
// 进程内一次，在构造任何密钥对象之前（仅 x86_64 有内容；
// 其他目标上本 crate 为空，此块可直接裁掉）：
#[cfg(target_arch = "x86_64")]
ferritls_backend_x86_64::install()?;
```

细节——探测/KAT 失败语义、`fips` 构建拒绝、性能数字——见
[`ferritls-backend-x86_64` README](crates/ferritls-backend-x86_64/README.md)。

## 构建要求

默认 feature `simd` 使用标准库 `core::simd`（portable_simd），在
**stable 工具链**上需要 `RUSTC_BOOTSTRAP=1`（本仓库的
`.cargo/config.toml` 已自动提供）：

```bash
export RUSTC_BOOTSTRAP=1                                     # ① 保留 simd
# 或在 Cargo.toml 中：                                        # ② 标量回退
# ferritls-core = { version = "0.9", default-features = false }
```

nightly 工具链无需该变量；portable_simd 稳定后此要求自动移除。

## FIPS 140-3 状态

ferritls 按 FIPS 140-3 密码模块边界组织（边界 = `ferritls-core`
crate），**尚未通过 CMVP 认证**：一切 `fips()` 钩子返回 `false`，
`fips` feature 表示“按批准模式运行”而非认证声明。路线见
[docs/FIPS.md](docs/FIPS.md)。

## 许可

Apache-2.0 OR MIT（见 [LICENSE-APACHE](LICENSE-APACHE) 与
[LICENSE-MIT](LICENSE-MIT)）。贡献者（人类或 AI 代理）请先阅读
[AGENTS.md](AGENTS.md)。
