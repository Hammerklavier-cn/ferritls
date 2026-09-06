//! 上电自检测试（M5）。

use ferritls_core::selftest::{run_power_on_self_tests, status, SelfTestStatus};

#[test]
#[ignore = "M5: 待各算法 KAT 内建后启用"]
fn power_on_self_tests_pass() {
    assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
    // 幂等：再次执行不改变状态。
    assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
    assert_eq!(status(), SelfTestStatus::Passed);
}

// M5 扩展：错误状态注入测试——通过测试钩子强制某个 KAT 失败，断言
// 模块进入 Failed 且后续操作返回 Error::SelfTestFailed（测试钩子需要
// #[cfg(any(test, feature = "fips"))] 暴露，实现时设计）。
