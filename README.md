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
- **密钥交换**：X25519、secp256r1、secp384r1
- **签名/验证**：ECDSA P-256/384、RSA-PSS/PKCS#1（SHA-256/384/512）、Ed25519
- **批准模式**（`fips` feature）：仅 NIST 批准算法 + SP 800-90A
  CTR-DRBG（每次生成混入 OS 熵）+ 上电自检 KAT
- **测试面**：RFC/NIST/CAVP 官方向量、RFC 8448 密钥调度、Wycheproof
  2349 用例、rustls-ring 交叉互操作、webpki 证书链、cargo-fuzz 六目标
  （[向量溯源](docs/VECTOR-PROVENANCE.md)）
- **性能**（P1 性能轮，默认生效，仍零 `unsafe`）：位切片 AES
  （64 块/批）+ 分组 GHASH 表 + 批处理 ChaCha20——AES-GCM 记录层
  较纯掩码基线提升约 19–21 倍，详见 [docs/ROADMAP.md](docs/ROADMAP.md)
  P1 节

```rust
let provider = ferritls_rustls::default_provider();
provider.install_default()?;
// 之后 ClientConfig::builder() / ServerConfig::builder() 默认使用它。
```

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
| `ferritls-interop` | 互操作/E2E 测试宿主 |

贡献（人类或 AI 代理）请先读 [AGENTS.md](AGENTS.md)。

## 许可

Apache-2.0 OR MIT（见 [LICENSE-APACHE](LICENSE-APACHE)、
[LICENSE-MIT](LICENSE-MIT)）。
