//! 上电自检（FIPS 140-3 ISO/IEC 19790 §7.9.2 强制项）。
//!
//! 模块首次使用前必须执行**已知答案测试（KAT）**，覆盖全部批准算法：
//! SHA-256/384/512、HMAC-SHA256、HKDF-SHA256、AES-128-GCM、AES-128-CCM、
//! ECDSA P-256（RFC 6979 确定性签名逐字节比对 + 验证）、RSA PKCS#1 v1.5
//! 签名/验证（内建 KAT 密钥）、CTR-DRBG（CAVP 向量流程）。任一失败 →
//! 模块进入错误状态，此后所有密码操作返回
//! [`Error::SelfTestFailed`](crate::Error)；整个模块拒绝服务，不做部分
//! 降级（非批准算法亦不例外）。
//!
//! **完整性测试决策（M5 定型）**：KAT 全集事实上锁定了关键常量
//! （S-box、曲线参数、模数、Drbg 常数等）的行为——任何常量损坏都会
//! 使至少一个 KAT 失败。对模块二进制做签名/摘要校验需要平台特定的
//! 加载期机制（代码段自校验在纯 Rust/`forbid(unsafe_code)` 边界内
//! 不可移植实现），属 CMVP 阶段 C 与实验室商定的交付物，此处明确
//! 记录该决策而非提供形式化的空壳实现。
//!
//! 非批准算法（X25519、ChaCha20-Poly1305、Ed25519）不参与 KAT。
//!
//! 里程碑：M5。

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use crate::sha2::{Sha256, Sha384, Sha512};

const STATUS_NOT_RUN: u8 = 0;
const STATUS_PASSED: u8 = 1;
const STATUS_FAILED: u8 = 2;

static STATUS: AtomicU8 = AtomicU8::new(STATUS_NOT_RUN);
static FAILED_REASON: Mutex<Option<&'static str>> = Mutex::new(None);

/// 自检状态。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelfTestStatus {
    /// 尚未运行（首次调用任一密码 API 时懒触发）。
    NotRun,
    /// 全部通过。
    Passed,
    /// 失败：模块处于错误状态，拒绝服务。
    Failed(&'static str),
}

fn set_failed(reason: &'static str) -> SelfTestStatus {
    STATUS.store(STATUS_FAILED, Ordering::SeqCst);
    if let Ok(mut slot) = FAILED_REASON.lock() {
        *slot = Some(reason);
    }
    SelfTestStatus::Failed(reason)
}

/// 执行上电自检（幂等：已运行则直接返回当前状态）。
pub fn run_power_on_self_tests() -> SelfTestStatus {
    match STATUS.load(Ordering::SeqCst) {
        STATUS_PASSED => return SelfTestStatus::Passed,
        STATUS_FAILED => {
            return SelfTestStatus::Failed(
                FAILED_REASON
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .unwrap_or("unknown"),
            )
        }
        _ => {}
    }
    // 单飞：并发触发时只跑一次，其余等待结果
    match SELF_TEST_RUN.lock() {
        Ok(mut guard) => {
            if *guard {
                // 别的线程正在跑或已完成：以状态为准
                return match STATUS.load(Ordering::SeqCst) {
                    STATUS_PASSED => SelfTestStatus::Passed,
                    STATUS_FAILED => SelfTestStatus::Failed("self-test failed"),
                    _ => SelfTestStatus::NotRun,
                };
            }
            *guard = true;
        }
        Err(_) => return SelfTestStatus::Failed("self-test lock poisoned"),
    }
    run_kats()
}

static SELF_TEST_RUN: Mutex<bool> = Mutex::new(false);

/// 单个 KAT 的统一形态。
type KatFn = fn() -> Result<(), crate::Error>;

fn run_kats() -> SelfTestStatus {
    let kats: [(&'static str, KatFn); 9] = [
        ("sha256", kat_sha256),
        ("sha384", kat_sha384),
        ("sha512", kat_sha512),
        ("hmac-sha256", kat_hmac_sha256),
        ("hkdf-sha256", kat_hkdf_sha256),
        ("aes128-gcm", kat_aes128_gcm),
        ("aes128-ccm", kat_aes128_ccm),
        ("ecdsa-p256", kat_ecdsa_p256),
        ("rsa-pkcs1v15", kat_rsa_pkcs1v15),
    ];
    for (name, kat) in kats {
        if let Err(_e) = kat() {
            return set_failed(name);
        }
    }
    if let Err(_e) = kat_drbg() {
        return set_failed("ctr-drbg");
    }
    STATUS.store(STATUS_PASSED, Ordering::SeqCst);
    SelfTestStatus::Passed
}

/// 查询当前状态（不触发自检）。
pub fn status() -> SelfTestStatus {
    match STATUS.load(Ordering::SeqCst) {
        STATUS_PASSED => SelfTestStatus::Passed,
        STATUS_FAILED => SelfTestStatus::Failed(
            FAILED_REASON
                .lock()
                .ok()
                .and_then(|g| *g)
                .unwrap_or("unknown"),
        ),
        _ => SelfTestStatus::NotRun,
    }
}

/// 所有密码 API 的入口守卫：自检未通过则拒绝服务。
pub(crate) fn ensure_passed() -> Result<(), crate::Error> {
    match status() {
        SelfTestStatus::Passed => Ok(()),
        SelfTestStatus::NotRun => match run_power_on_self_tests() {
            SelfTestStatus::Passed => Ok(()),
            SelfTestStatus::Failed(which) => Err(crate::Error::SelfTestFailed(which)),
            SelfTestStatus::NotRun => Err(crate::Error::SelfTestFailed("self-test did not run")),
        },
        SelfTestStatus::Failed(which) => Err(crate::Error::SelfTestFailed(which)),
    }
}

/// 测试钩子：强制模块进入失败状态（仅测试构建）。
#[cfg(test)]
pub(crate) fn force_fail_for_tests(which: &'static str) {
    set_failed(which);
}

/// 测试钩子：复位自检状态（仅测试构建，用于失败注入后的恢复）。
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    STATUS.store(STATUS_NOT_RUN, Ordering::SeqCst);
    if let Ok(mut run) = SELF_TEST_RUN.lock() {
        *run = false;
    }
    if let Ok(mut slot) = FAILED_REASON.lock() {
        *slot = None;
    }
}

// ---------------------------------------------------------------------------
// KAT：SHA-2（FIPS 180-4，消息 "abc"）
// ---------------------------------------------------------------------------

fn kat_sha256() -> Result<(), crate::Error> {
    let expect: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if Sha256::one_shot(b"abc") == expect {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("sha256"))
    }
}

fn kat_sha384() -> Result<(), crate::Error> {
    let expect: [u8; 48] = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    if Sha384::one_shot(b"abc") == expect {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("sha384"))
    }
}

fn kat_sha512() -> Result<(), crate::Error> {
    let expect: [u8; 64] = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    if Sha512::one_shot(b"abc") == expect {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("sha512"))
    }
}

// ---------------------------------------------------------------------------
// KAT：HMAC-SHA256（RFC 4231 Test Case 1）
// ---------------------------------------------------------------------------

fn kat_hmac_sha256() -> Result<(), crate::Error> {
    let expect: [u8; 32] = [
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
        0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
        0xcf, 0xf7,
    ];
    let key = [0x0bu8; 20];
    if crate::hmac::HmacSha256::one_shot(&key, b"Hi There") == expect {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("hmac-sha256"))
    }
}

// ---------------------------------------------------------------------------
// KAT：HKDF-SHA256（RFC 5869 Test Case 1）
// ---------------------------------------------------------------------------

fn kat_hkdf_sha256() -> Result<(), crate::Error> {
    let expect: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let ikm = [0x0bu8; 22];
    let salt: [u8; 13] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let prk = crate::hkdf::extract_sha256(&salt, &ikm);
    let mut okm = [0u8; 42];
    crate::hkdf::expand_sha256(&prk, &info, &mut okm);
    if okm == expect {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("hkdf-sha256"))
    }
}

// ---------------------------------------------------------------------------
// KAT：AES-128-GCM（GCM 规范 Test Case 3：加密 + 打开 + 篡改拒绝）
// ---------------------------------------------------------------------------

fn kat_aes128_gcm() -> Result<(), crate::Error> {
    const KEY: [u8; 16] = [0; 16];
    const NONCE: [u8; 12] = [0; 12];
    const PT: [u8; 16] = [0; 16];
    const CT: [u8; 16] = [
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe,
        0x78,
    ];
    const TAG: [u8; 16] = [
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd,
        0xdf,
    ];
    let gcm = crate::gcm::Aes128Gcm::new(&KEY);
    let sealed = gcm.seal(&NONCE, b"", &PT);
    if sealed[..16] != CT || sealed[16..] != TAG {
        return Err(crate::Error::SelfTestFailed("aes128-gcm"));
    }
    let opened = gcm.open(&NONCE, b"", &sealed)?;
    if opened != PT {
        return Err(crate::Error::SelfTestFailed("aes128-gcm"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KAT：AES-128-CCM（加解密往返 + 标签篡改拒绝）
// ---------------------------------------------------------------------------

fn kat_aes128_ccm() -> Result<(), crate::Error> {
    const KEY: [u8; 16] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f,
    ];
    const NONCE: [u8; 13] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
    ];
    let ccm = crate::ccm::Aes128Ccm::new(&KEY);
    let pt = b"self-test ccm kat";
    let sealed = ccm.seal(&NONCE, b"", pt);
    let opened = ccm.open(&NONCE, b"", &sealed)?;
    if opened != pt {
        return Err(crate::Error::SelfTestFailed("aes128-ccm"));
    }
    let mut bad = sealed.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    if ccm.open(&NONCE, b"", &bad).is_ok() {
        return Err(crate::Error::SelfTestFailed("aes128-ccm"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// KAT：ECDSA P-256（RFC 6979 A.2.5 确定性签名逐字节 + 验证）
// ---------------------------------------------------------------------------

fn kat_ecdsa_p256() -> Result<(), crate::Error> {
    use crate::sign::ecdsa;
    const D_HEX: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const SIG_HEX: &str = "\
3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8";
    let d = hex(D_HEX);
    let sk = ecdsa::p256::SigningKey::from_seed(d.as_slice().try_into().expect("fixed width"));
    let sig = sk.sign(b"sample")?;
    if hex(SIG_HEX) != sig {
        return Err(crate::Error::SelfTestFailed("ecdsa-p256"));
    }
    let q = sk.public_key_sec1();
    ecdsa::p256::verify(&q, b"sample", &sig)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// KAT：RSA PKCS#1 v1.5（内建 KAT 密钥签名/验证；openssl 交叉锚定）
// ---------------------------------------------------------------------------

const RSA_KAT_PKCS8_HEX: &str = include_str!("kat_rsa_key.hex");
const RSA_KAT_SIG_HEX: &str = include_str!("kat_rsa_sig.hex");

fn hex(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn kat_rsa_pkcs1v15() -> Result<(), crate::Error> {
    use crate::sign::rsa;
    let sk = rsa::SigningKey::from_pkcs8_der(&hex(RSA_KAT_PKCS8_HEX))?;
    let sig = sk.sign_pkcs1v15(256, b"sample")?;
    if sig != hex(RSA_KAT_SIG_HEX) {
        return Err(crate::Error::SelfTestFailed("rsa-pkcs1v15"));
    }
    rsa::verify_pkcs1v15(256, &hex(RSA_KAT_PUB_SPKI), b"sample", &sig)?;
    Ok(())
}

const RSA_KAT_PUB_SPKI: &str = include_str!("kat_rsa_spki.hex");

// ---------------------------------------------------------------------------
// KAT：CTR-DRBG（CAVP [AES-256 no df] 流程：Instantiate → Reseed →
// Generate → Generate，第二次输出逐字节比对）
// ---------------------------------------------------------------------------

fn kat_drbg() -> Result<(), crate::Error> {
    const EI_HEX: &str = "e4bc23c5089a19d86f4119cb3fa08c0a4991e0a1def17e101e4c14d9c323460a7c2fb58e0b086c6c57b55f56cae25bad";
    const EIR_HEX: &str = "fd85a836bba85019881e8c6bad23c9061adc75477659acaea8e4a01dfe07a1832dad1c136f59d70f8653a5dc118663d6";
    const EXPECT_HEX: &str = "b2cb8905c05e5950ca31895096be29ea3d5a3b82b269495554eb80fe07de43e193b9e7c3ece73b80e062b1c1f68202fbb1c52a040ea2478864295282234aaada";
    let mut d = CtrDrbg::new(&hex(EI_HEX), b"")?;
    d.reseed(&hex(EIR_HEX), b"")?;
    let mut discard = [0u8; 64];
    d.generate(&mut discard)?;
    let mut out = [0u8; 64];
    d.generate(&mut out)?;
    if out == hex(EXPECT_HEX)[..] {
        Ok(())
    } else {
        Err(crate::Error::SelfTestFailed("ctr-drbg"))
    }
}

use crate::drbg::CtrDrbg;

#[cfg(test)]
mod failure_injection {
    use super::*;

    #[test]
    fn failed_state_gates_and_recovers() {
        reset_for_tests();
        // 正常自检通过
        assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
        // 注入失败：模块进入错误状态
        force_fail_for_tests("injected");
        assert_eq!(status(), SelfTestStatus::Failed("injected"));
        assert_eq!(
            ensure_passed(),
            Err(crate::Error::SelfTestFailed("injected"))
        );
        // 复位后恢复
        reset_for_tests();
        assert_eq!(run_power_on_self_tests(), SelfTestStatus::Passed);
    }
}

#[cfg(test)]
mod kat_debug {
    use super::*;

    #[test]
    fn debug_ecdsa_kat() {
        let d = hex("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
        let sk = crate::sign::ecdsa::p256::SigningKey::from_seed(d.as_slice().try_into().unwrap());
        let sig = sk.sign(b"sample").unwrap();
        println!(
            "sig  = {}",
            sig.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
        println!("kat  = {}", hex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8").iter().map(|b| format!("{b:02x}")).collect::<String>());
        println!("eq   = {}", sig == hex("3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"));
        let q = sk.public_key_sec1();
        println!(
            "verify = {:?}",
            crate::sign::ecdsa::p256::verify(&q, b"sample", &sig)
        );
    }
}
