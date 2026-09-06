//! # ferritls-interop
//!
//! 互操作与端到端测试的宿主 crate（`publish = false`，不进 FIPS 边界，
//! 依赖不受白名单约束）。
//!
//! ## 测试矩阵（M6 建成）
//!
//! | 对手盘 | 内容 | 依赖 |
//! |---|---|---|
//! | ferritls ↔ ferritls | 本 provider 的完整握手（client/server 双向） | rustls |
//! | ferritls ↔ ring provider | 跨 provider TLS 1.3 握手 | rustls, ring（dev-dep） |
//! | ferritls ↔ aws-lc-rs provider | 跨 provider 握手 | rustls, aws-lc-rs（dev-dep） |
//! | ferritls ↔ OpenSSL | 命令行 `s_server`/`s_client` 互操作 | 系统 openssl |
//! | ferritls → 公网 | 对公共 TLS 服务器的真实客户端握手（examples） | 网络 |
//!
//! ## 验收基准（M6 的“完成”定义）
//!
//! 1. RFC 8448（TLS 1.3 官方握手轨迹）逐消息重放比对；
//! 2. 上表全部本地矩阵绿；公网冒烟（自选可复现端点）绿；
//! 3. 全部套件 × 全部 KX 组 × 双向签名算法的组合握手覆盖；
//! 4. `fips_mode_provider()` 矩阵（仅批准组合）同样绿。

// 本 crate 目前只有测试，无运行时 API。
