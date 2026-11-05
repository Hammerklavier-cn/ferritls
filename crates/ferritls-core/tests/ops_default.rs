//! ops 注册表默认态观测（2026-11 测试完备性轮）。
//!
//! **独立测试二进制**：本文件不安装任何后端（与 ops_dispatch.rs 的
//! mock 安装二进制分离），断言未安装路径下两个注册表均为空——
//! "公开类型直连软件实现"契约的前提观测点。

mod common;

use ferritls_core::ops;

/// 默认进程态：AEAD 与哈希注册表均为空（install 从未被调用）。
#[test]
fn registries_empty_before_install() {
    assert!(ops::installed_aead().is_none());
    assert!(ops::installed_hash().is_none());
}
