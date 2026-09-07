//! 上电自检测试（M5）。
//!
//! KAT 失败注入在 src/selftest.rs 的 #[cfg(test)] 单元测试中覆盖
//! （force_fail_for_tests 钩子为 pub(crate)，集成测试不可见）。

use ferritls_core::selftest::{SelfTestStatus, run_power_on_self_tests, status};

#[test]
fn power_on_self_tests_pass() {
    assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
    // 幂等：再次执行不改变状态。
    assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
    assert_eq!(status(), SelfTestStatus::Passed);
}
