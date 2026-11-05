//! 适配层测试共享基础设施：目前仅承载 Ni 后端预 main 安装钩子。
//!
//! `api.rs` 通过 `mod common;` 引入。与
//! `crates/ferritls-interop/tests/common/mod.rs` 中的同名钩子保持同步
//! （两处逻辑一致，改动时同步）。

#![allow(dead_code)]

/// Ni 后端预 main 安装钩子（`FERRITLS_TEST_NI=1` 时）。
///
/// `install()` 是进程级且不可撤销的，必须早于任何密钥/provider 构造；
/// `#[ctor::ctor]` 保证本钩子在测试 harness 入口之前执行，既有测试一行
/// 不改、未来新增测试自动被覆盖。
#[cfg(target_arch = "x86_64")]
#[ctor::ctor(unsafe)]
fn install_ni_backends_for_tests() {
    if std::env::var_os("FERRITLS_TEST_NI").is_none() {
        return;
    }
    // 硬失败：CI 的 Ni 腿跑在必有 AES-NI/SHA 扩展的 x86_64 runner 上，
    // 安装失败若静默降级会变成"软件重跑"的假覆盖。批准模式（fips）构建
    // 下 core 拒绝一切安装，故该变量不得与 fips feature 腿叠加。
    ferritls_backend_x86_64::install()
        .expect("FERRITLS_TEST_NI=1 but AES-NI backend install failed");
    ferritls_backend_x86_64::install_hash()
        .expect("FERRITLS_TEST_NI=1 but SHA-NI backend install failed");
    eprintln!("[ni-test] AES-NI + SHA-NI backends installed for this test binary");
}
