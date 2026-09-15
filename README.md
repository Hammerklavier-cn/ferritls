# ferritls

[简体中文](README.md) | [English](README.en.md)

纯 Rust 的 [rustls](https://github.com/rustls/rustls) `CryptoProvider`
密码后端：无 C、无汇编、无 `unsafe`，按 FIPS 140-3 模块边界组织。

## 为什么

| 替代对象 | 痛点 | ferritls |
|---|---|---|
| rustls-rustcrypto | 停更（2024-04 最后发版，README 挂"禁止生产使用"） | 活跃维护，接口锁定 rustls 0.23 |
| aws-lc-rs | C/汇编、cmake、编译慢、绑定 AWS-LC | 纯 Rust，`cargo build` 即得，边界全可审 |

## 能力

- **TLS 1.3 套件**：`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、
  `TLS_CHACHA20_POLY1305_SHA256`、`TLS_AES_128_CCM_SHA256`
- **密钥交换**：X25519、secp256r1、secp384r1、X25519MLKEM768 混合
- **抗量子**：FIPS 202 SHA-3/SHAKE 与 FIPS 203 ML-KEM 全部三个
  参数集（512/768/1024，边界内自研、零新依赖、NIST ACVP 向量锚定）；
  密钥交换含 X25519MLKEM768 混合（draft-ietf-tls-ecdhe-mlkem，
  codepoint 0x11EC，X25519 进入批准模式的通道）与纯 ML-KEM 三组
  （draft-ietf-tls-mlkem-key-agreement，codepoint 0x0200–0x0202）
- **QUIC**（RFC 9001，M8.5）：AES-GCM/ChaCha20-Poly1305 三套件的
  QUIC 包保护（`quic::Algorithm`：包保护 + 头保护 + multipath），
  RFC 9001 附录 A 样本逐字节锚定，与 rustls-ring 交叉互操作
- **签名/验证**：ECDSA P-256/384、RSA-PSS/PKCS#1（SHA-256/384/512）、Ed25519
- **批准模式**（`fips` feature）：仅 NIST 批准算法 + SP 800-90A
  CTR-DRBG（每次生成混入 OS 熵）+ 上电自检 KAT
- **测试面**：RFC/NIST/CAVP 官方向量、NIST ACVP ML-KEM-768 向量、
  RFC 8448 密钥调度、Wycheproof 2349 用例、rustls-ring 交叉互操作、
  webpki 证书链、cargo-fuzz 七目标
  （[向量溯源](docs/VECTOR-PROVENANCE.md)）
- **性能**（P1 自动向量化 + P2 显式 `std::simd`，默认启用，仍零
  `unsafe`）：位切片 AES + 分组 GHASH 表 + 批处理 ChaCha20——AES-GCM
  记录层较纯掩码基线提升约 19–21 倍（基线 ISA）；以
  `RUSTFLAGS="-C target-cpu=native"` 构建可自动启用 AVX2/AVX-512
  宽通道，详见 [docs/ROADMAP.md](docs/ROADMAP.md) P1/P2 节
- **可选硬件后端**（`ferritls-backend-aesni`，边界外独立 crate，仅
  x86_64）：AES-NI + CLMUL 的 AES-GCM 整消息 kernel 与 SHA-NI 的
  SHA-256 分发，运行时 CPU 探测 + 安装 KAT 自检，批准模式固定软件
  路径——GCM 原语较软件路径约 750–980 倍，详见
  [docs/BENCHMARKS.md](docs/BENCHMARKS.md) §5

```rust
let provider = ferritls_rustls::default_provider();
provider.install_default()?;
// 之后 ClientConfig::builder() / ServerConfig::builder() 默认使用它。
```

## 与 reqwest 集成

reqwest 0.12 与 0.13 两代依赖的都是 `rustls ^0.23`，与 ferritls 同一条
版本线——Cargo 统一为同一 rustls 实例，两代均直接兼容（interop
`tests/reqwest.rs` 以 0.12 线回环握手作回归防线）。feature 必须选
**no-provider 变体**，否则 reqwest 会编入 ring/aws-lc 并可能抢先成为
进程默认 provider（此后 `install_default()` 失败）：

```toml
# reqwest 0.13（rustls 为默认 TLS 后端；系统根证书走 rustls-platform-verifier）
reqwest = { version = "0.13", default-features = false,
            features = ["rustls-no-provider", "http2", "charset"] }

# reqwest 0.12（rustls 为可选后端；内置 webpki 根证书集）
reqwest = { version = "0.12", default-features = false,
            features = ["rustls-tls-webpki-roots-no-provider", "http2", "charset"] }
# 想用系统根证书：换成 rustls-tls-native-roots-no-provider。
```

```rust
// 必须在创建第一个 Client 之前安装：
ferritls_rustls::default_provider().install_default()?;
let client = reqwest::Client::new();
```

不想碰进程全局状态时，可显式构建 `ClientConfig` 经
`use_preconfigured_tls` 注入（0.12/0.13 均支持）；此时信任根与
**ALPN** 都要在 `ClientConfig` 里自行设置——reqwest 不修改预配置的
config，ALPN 缺失则 HTTP/2 静默不可用。另注意 ferritls 目前仅提供
TLS 1.3 套件（TLS 1.2 为 M8 余项），两代 reqwest 行为一致。

## 构建要求（默认 `simd` feature）

`ferritls-core` 的默认 feature `simd` 使用标准库 `core::simd`
（portable_simd），在 **stable 工具链**上需要 `RUSTC_BOOTSTRAP=1`
环境变量编译（本仓库内置 `.cargo/config.toml` 已自动提供，克隆即用）：

```bash
# 依赖本仓库时（crates.io / path / git）——二选一：
export RUSTC_BOOTSTRAP=1                      # ① 保留 simd
ferritls-core = { version = "0.5", default-features = false }  # ② 标量回退
```

- 通道宽度按编译目标自动选择：默认 x86-64/aarch64 基线（SSE2/NEON）；
  以 `RUSTFLAGS="-C target-feature=+avx2"` 或 `-C target-cpu=native`
  构建时同一份源码自动升级到 AVX2/AVX-512 通道。
- portable_simd 在 Rust 稳定通道发布后，此环境变量要求将自动移除。
- nightly 工具链无需该变量（原生支持 feature gate）。

## FIPS 140-3 声明

ferritls 按 FIPS 140-3 密码模块边界组织（边界 = `ferritls-core`
crate），**尚未通过 CMVP 认证**：一切 `fips()` 钩子在认证落地前返回
`false`，`fips` feature 表示“按批准模式运行”而非认证声明。目前没有
任何纯 Rust 模块通过 CMVP；路线与成本见 [docs/FIPS.md](docs/FIPS.md)。

## 仓库结构

| crate | 职责 |
|---|---|
| `ferritls-core` | 密码学核心 = FIPS 模块边界（`#![forbid(unsafe_code)]`） |
| `ferritls-rustls` | rustls CryptoProvider 适配层 |
| `ferritls-backend-aesni` | AES-NI/SHA-NI 硬件后端（边界外，仅 x86_64，经 `ops` 注册） |
| `ferritls-interop` | 互操作/E2E 测试宿主 |

贡献（人类或 AI 代理）请先读 [AGENTS.md](AGENTS.md)。

## 许可

Apache-2.0 OR MIT（见 [LICENSE-APACHE](LICENSE-APACHE)、
[LICENSE-MIT](LICENSE-MIT)）。
