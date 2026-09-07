# ferritls

纯 Rust 的 [rustls](https://github.com/rustls/rustls) `CryptoProvider`
密码后端：无 C、无汇编、无 `unsafe`，按 FIPS 140-3 模块边界组织。

**状态：M0–M6 完成**——`ferritls-core` 全部密码原语落地（RFC/NIST/CAVP
官方向量测试绿），rustls `CryptoProvider` 适配层接线完成，端到端 TLS 1.3
握手（内存内矩阵）通过。发布 0.1 前的收尾项（RFC 8448 轨迹、Wycheproof
全量、webpki 链校验测试）见 [路线图](docs/ROADMAP.md) M7。

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
