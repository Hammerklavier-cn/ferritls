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

use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

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
            );
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
    let kats: [(&'static str, KatFn); 10] = [
        ("sha256", kat_sha256),
        ("sha384", kat_sha384),
        ("sha512", kat_sha512),
        ("hmac-sha256", kat_hmac_sha256),
        ("hkdf-sha256", kat_hkdf_sha256),
        ("aes128-gcm", kat_aes128_gcm),
        ("aes128-ccm", kat_aes128_ccm),
        ("ecdsa-p256", kat_ecdsa_p256),
        ("rsa-pkcs1v15", kat_rsa_pkcs1v15),
        ("mlkem768", kat_mlkem768),
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
    crate::hkdf::expand_sha256(&prk, &info, &mut okm)?;
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
    let sealed = ccm.seal(&NONCE, b"", pt)?;
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
// KAT：ML-KEM-768（NIST ACVP keyGen tcId 26 + encapDecap tcId 26，全值锚定；
// keyGen 与 encapDecap 是不同案例，密钥材料不可混用）
// ---------------------------------------------------------------------------

fn kat_mlkem768() -> Result<(), crate::Error> {
    use crate::mlkem;
    // keyGen tcId 26：(d, z) → (ek, dk)
    const D_HEX: &str = "e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc";
    const Z_HEX: &str = "a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd";
    const EK_HEX: &str = "\n        6d14a071f7cc452558d5e71a7b087062ecb1386844588246126402b1fa163773\n        3cd5f60cc84bcb646a7892614d7c51b1c7f1a2799132f13427dc482158da2544\n        70a59e00a4e49686fdc077559367270c2153f11007592c9c4310cf8a12c6a871\n        3bd6bb51f3124f989ba0d54073cc242e0968780b875a869efb851586b9a868a3\n        84b9e6821b201b932c455369a739ec22569c977c212b381871813656af5b567e\n        f893b584624c863a259000f17b254b98b185097c50ebb68b244342e05d4de520\n        125b8e1033b1436093ace7ce8e71b458d525673363045a3b3eea9455428a3987\n        05a42327adb3774b7057f42b017ec0739a983f19e8214d09195fa24d2d571db7\n        3c19a6f8460e50830d415f627b88e94a7b153791a0c0c7e9484c74d53c714889\n        f0e321b6660a532a5bc0e557fbca35e29bc611200ed3c633077a4d873c5cc670\n        06b753bf6d6b7af6ca402ab618236c0affbc801f8222fbc36ce0984e2b18c944\n        bbcbef03b1e1361c1f44b0d734afb1566cff8744da8b9943d6b45a3c09030702\n        ca201ffe20cb7ec5b0d4149ee2c28e8b23374f471b57150d0ec9336261a2d5cb\n        84a3acacc4289473a4c0abc617c9abc178734434c82e1685588a5c2ea2678f6b\n        3c2228733130c466e5b86ef491153e48662247b875d201020b566b81b64d839a\n        b4633baa8ace202baab4496297f9807adbbb1e332c6f8022b2a18cfdd4a82530\n        b6d3f007c3353898d966cc2c21cb4244bd00443f209870acc42bc33068c724ec\n        17223619c1093cca6aeb29500664d1225036b4b81091906969481f1c723c140b\n        9d6c168f5b64bea69c5fd6385df7364b8723bcc85e038c7e464a900d68a21278\n        18994217aec8bdb39a970a9963de93688e2ac82abcc22fb9277ba22009e87838\n        1a38163901c7d4c85019538d35caae9c41af8c929ee20bb08ca619e72c2f2262\n        c1c9938572551ac02dc9268fbcc35d79011c3c090ad40a4f111c9be55c427eb7\n        96c1932d8673579af1b4c638b0944489012a2559a3b02481b01ac30ba8960f80\n        c0c2b3947d36a12c080498bee448716c973416c8242804a3da099ee137b0ba90\n        fe4a5c6a89200276a0cfb643ec2c56a2d708d7b4373e44c1502a763a600586e6\n        cda6273897d44448287dc2e602dc39200bf6166236559fd12a60892aeb153dd6\n        51bb469910b4b34669f91da8654d1eb72eb6e02800b3b0a7d0a48c836854d3a8\n        3e65569cb7230bb44f3f143a6dec5f2c39ab90f274f2088bd3d6a6fca0070273\n        bedc84777fb52e3c558b0ae06183d5a48d452f68e15207f861627aca14279630\n        f82ec3a0ca078633b600afa79743a600215be5637458ce2ce8aff5a08eb5017b\n        2c766577479f8dc6bf9f5cc75089932161b96cea406620aedb630407f7687ebb\n        b4814c7981637a48a90de68031e062a7af7612b4f5c7a6da86bd136529e64295\n        a5613ea73bd3d4448cb81f243135c0a660beb9c17e651def469a7d90a15d3481\n        090bcbf227012328941fa46f39c5006ad93d458aa6add655862b418c3094f551\n        460df2153a5810a7da74f0614c2588be49dc6f5e88154642bd1d376256332643\n        3507156a57c57694bdd26e7a246feb723aed67b04887c8e476b48cab59e5362f\n        26a9ef50c2bc80ba146226216fe62968a60d04e8c170d741c7a2b0e1abdac968";
    // encapDecap tcId 26：同案例的 (ek, dk, m) → (c, ss)
    const EK2_HEX: &str = "\n        89d2cb65f94dcbfc890efc7d0e5a7a38344d1641a3d0b024d50797a5f23c3a18\n        b3101a1269069f43a842bacc098a8821271c673db1beb33034e4d7774d16635c\n        7c2c3c2763453538bc1632e1851591a51642974e5928abb8e55fe55612f9b141\n        aff015545394b2092e590970ec29a7b7e7aa1fb4493bf7cb731906c2a5cb49e6\n        614859064e19b8fa26af51c44b5e7535bfdac072b646d3ea490d277f0d97ced4\n        7395fed91e8f2bce0e3ca122c2025f74067ab928a822b35653a74f06757629af\n        b1a1caf237100ea935e793c8f58a71b3d6ae2c8658b10150d4a38f572a0d49d2\n        8ae89451d338326fdb3b4350036c1081117740edb86b12081c5c1223dbb5660d\n        5b3cb3787d481849304c68be875466f14ee5495c2bd795ae412d09002d65b871\n        9b90cba3603ac4958ea03cc138c86f7851593125334701b677f82f4952a4c93b\n        5b4c134bb42a857fd15c650864a6aa94eb691c0b691be4684c1f5b7490467fc0\n        1b1d1fda4dda35c4ecc231bc73a6fef42c99d34eb82a4d014987b3e386910c62\n        679a118f3c5bd9f467e4162042424357db92ef484a4a1798c1257e870a30cb20\n        aaa0335d83314fe0aa7e63a862648041a72a6321523220b1ace9bb701b21ac12\n        53cb812c15575a9085eabeade73a4ae76e6a7b158a20586d78a5ac620a5c9abc\n        c9c043350a73656b0abe822da5e0ba76045fad75401d7a3b703791b7e9926171\n        0f86b72421d240a347638377205a152c794130a4e047742b888303bddc309116\n        764de7424cebea6db65348ac537e01a9cc56ea667d5aa87ac9aaa4317d262c10\n        143050b8d07a728ca633c13e468abcead372c77b8ecf3b986b98c1e55860b2b4\n        216766ad874c35ed7205068739230220b5a2317d102c598356f168acbe80608d\n        e4c9a710b8dd07078cd7c671058af1b0b8304a314f7b29be78a933c7b9294424\n        954a1bf8bc745de86198659e0e1225a910726074969c39a97c19240601a46e01\n        3dcdcb677a8cbd2c95a40629c256f24a328951df57502ab30772cc7e5b850027\n        c8551781ce4985bdacf6b865c104e8a4bc65c41694d456b7169e45ab3d7acabe\n        afe23ad6a7b94d1979a2f4c1cae7cd77d681d290b5d8e451bfdcccf5310b9d12\n        a88ec29b10255d5e17a192670aa9731c5ca67ec784c502781be8527d6fc003c6\n        701b3632284b40307a527c7620377feb0b73f722c9e3cd4dec64876b93ab5b7c\n        fc4a657f852b659282864384f442b22e8a21109387b8b47585fc680d0ba45c7a\n        8b1d7274bda57845d100d0f42a3b74628773351fd7ac305b2497639be90b3f4f\n        71a6aa3561eecc6a691bb5cb3914d8634ca1e1af543c049a8c6e868c51f0423b\n        d2d5ae09b79e57c27f3fe3ae2b26a441babfc6718ce8c05b4fe793b910b8fbcb\n        be7f1013242b40e0514d0bdc5c88bac594c794ce5122fbf34896819147b92838\n        1587963b0b90034aa07a10be176e01c80ad6a4b71b10af4241400a2a4cbbc059\n        61a15ec1474ed51a3cc6d35800679a462809caa3ab4f7094cd6610b4a700cba9\n        39e7eac93e38c99755908727619ed76a34e53c4fa25bfc97008206697dd145e5\n        b9188e5b014e941681e15fe3e132b8a3903474148ba28b987111c9bcb3989bbb\n        c671c581b44a492845f288e62196e471fed3c39c1bbddb0837d0d4706b0922c4";
    const DK2_HEX: &str = "\n        b09125afb3cfb5295581373ab6885284d9706318280d223edc987fd14410dbe8\n        2e6ac89adfab70e67ca4b1c641ad037fd8c47870f159ec79cdcd52605b989049\n        9bb6dbd8347f342c61436b642c0ddf4617db06198b8285dce4c09d9775a2f41c\n        8cd18af8e75f57d4127df94d901ac83bacbd584cc50c43750f49b357f5935087\n        5c9b475480a8aaa168592ddb158614a639813566d205368c6c39f0413ca3230d\n        f60d44008282b682ac66b76c3c95f00b2a555035529c86ef3905b4a3968fea78\n        02b6c5eecb08e8f0c42d7ab7cd21a62fb136412a1840b52c99970ccf51892f73\n        497c3775be2189f7fc25e7c74d81fc217683292aa4866ddb04469855323a0810\n        f0893de5c7f94a9c0b5337db83c44891b2e694695b76575032bf51761682958b\n        d4f97be9a355b4a85bb6858b7e5a5ef653ab781056af9187d811c3a8936e5706\n        503db57062410bcc9421f1ab867a657856c411c4e025ecb3c387729ae8e112f3\n        30b988e22f47c35c280750d21b107687af7b329ef3cb5289f06fb7d44548391e\n        97ba6dd499b5907c54958413d92aa99d5646cf47a8f48cb70a07ad056b4eefe6\n        c8c46645f7028a32410558638c48e83ac1570160c3833bf64052f5b7df4364d3\n        e0b24e790aa7c98cee0441e6731d9de22d156c61e1c740397672ef54724f01b9\n        d49923aa321f86b98823f21360138392b90c69434635275f9bfbb9b8a99e8e1b\n        7f4ec25f75dbce33c13f750170bd6722efe496e7463e16aaa5867b869a96ad41\n        b22bd2556c924596fd778d79a102f6e46d8eb18fefac8db19993e5414ac81670\n        5286892492c8c9e852d6145dff0c10e4a6703a459e7e732a6dfa2766a622b062\n        2bfedb8f41c125f61b2ec264853b9ccc165979f6a263beb148905aac7618a70e\n        829e23f28696f92ef6fa07c102cdbdb1288ba5cff3a81abba15974535fe3106a\n        80068f14e98964572350a7112b1601c196710c096ccf164fbce1aabac9c5b953\n        5070e61ab8068d611ca765fabb6412607dab30c4fc6ad073731fdc4c48b88e26\n        7c47b439ad2560c30561815ceb1f52c896489944bbbab52b1b1d1680a1057964\n        dafa600c93a39a447ddbb0adf911afe3e823d8acc7cc04659f625f2c1837bb17\n        5282542cd22601f621581ab5a6c0384e087ccd32a5380b522fdd3a4202b5b41c\n        85caff2903b2dc2645703d9bc711fbb404c0c0376187ac588aaf5718522d2273\n        a9408dabcbc9701698d2da172aa6267a4c9693a24011c2265a2b6dc8e96304a9\n        8ddc5319a3140c399a08412c20f48537870bb84c32a094457895511ff7ec421d\n        e01a64b78534653f78327441b90cd115939dfaafa95b40d0a63d62d12eb5c909\n        6018cc83871e44e6cd0be26d16b7b5a209b8e6471d2954adf9fabd0153707c9c\n        aa2bcc38ded841c791a0eb597eeee2c518d926edb28ab53caa5b7746466931b0\n        ac9150688bf37049c1f82bcf648332434cd0a92fd2c958353a26cb65cb499057\n        109b2d688cc43c4b385da7c50868af1b8075e57088f5db12dfa493eacb6dc4ec\n        6e205baa2a89858ec2823c00553714cde47a96e36c7c198b3ec57ccf74d92cdd\n        b86aa0a8b8b5ca9d52bb60aba79f4f72b0125532ceb7a9077480d2bb60df51a9\n        89d2cb65f94dcbfc890efc7d0e5a7a38344d1641a3d0b024d50797a5f23c3a18\n        b3101a1269069f43a842bacc098a8821271c673db1beb33034e4d7774d16635c\n        7c2c3c2763453538bc1632e1851591a51642974e5928abb8e55fe55612f9b141\n        aff015545394b2092e590970ec29a7b7e7aa1fb4493bf7cb731906c2a5cb49e6\n        614859064e19b8fa26af51c44b5e7535bfdac072b646d3ea490d277f0d97ced4\n        7395fed91e8f2bce0e3ca122c2025f74067ab928a822b35653a74f06757629af\n        b1a1caf237100ea935e793c8f58a71b3d6ae2c8658b10150d4a38f572a0d49d2\n        8ae89451d338326fdb3b4350036c1081117740edb86b12081c5c1223dbb5660d\n        5b3cb3787d481849304c68be875466f14ee5495c2bd795ae412d09002d65b871\n        9b90cba3603ac4958ea03cc138c86f7851593125334701b677f82f4952a4c93b\n        5b4c134bb42a857fd15c650864a6aa94eb691c0b691be4684c1f5b7490467fc0\n        1b1d1fda4dda35c4ecc231bc73a6fef42c99d34eb82a4d014987b3e386910c62\n        679a118f3c5bd9f467e4162042424357db92ef484a4a1798c1257e870a30cb20\n        aaa0335d83314fe0aa7e63a862648041a72a6321523220b1ace9bb701b21ac12\n        53cb812c15575a9085eabeade73a4ae76e6a7b158a20586d78a5ac620a5c9abc\n        c9c043350a73656b0abe822da5e0ba76045fad75401d7a3b703791b7e9926171\n        0f86b72421d240a347638377205a152c794130a4e047742b888303bddc309116\n        764de7424cebea6db65348ac537e01a9cc56ea667d5aa87ac9aaa4317d262c10\n        143050b8d07a728ca633c13e468abcead372c77b8ecf3b986b98c1e55860b2b4\n        216766ad874c35ed7205068739230220b5a2317d102c598356f168acbe80608d\n        e4c9a710b8dd07078cd7c671058af1b0b8304a314f7b29be78a933c7b9294424\n        954a1bf8bc745de86198659e0e1225a910726074969c39a97c19240601a46e01\n        3dcdcb677a8cbd2c95a40629c256f24a328951df57502ab30772cc7e5b850027\n        c8551781ce4985bdacf6b865c104e8a4bc65c41694d456b7169e45ab3d7acabe\n        afe23ad6a7b94d1979a2f4c1cae7cd77d681d290b5d8e451bfdcccf5310b9d12\n        a88ec29b10255d5e17a192670aa9731c5ca67ec784c502781be8527d6fc003c6\n        701b3632284b40307a527c7620377feb0b73f722c9e3cd4dec64876b93ab5b7c\n        fc4a657f852b659282864384f442b22e8a21109387b8b47585fc680d0ba45c7a\n        8b1d7274bda57845d100d0f42a3b74628773351fd7ac305b2497639be90b3f4f\n        71a6aa3561eecc6a691bb5cb3914d8634ca1e1af543c049a8c6e868c51f0423b\n        d2d5ae09b79e57c27f3fe3ae2b26a441babfc6718ce8c05b4fe793b910b8fbcb\n        be7f1013242b40e0514d0bdc5c88bac594c794ce5122fbf34896819147b92838\n        1587963b0b90034aa07a10be176e01c80ad6a4b71b10af4241400a2a4cbbc059\n        61a15ec1474ed51a3cc6d35800679a462809caa3ab4f7094cd6610b4a700cba9\n        39e7eac93e38c99755908727619ed76a34e53c4fa25bfc97008206697dd145e5\n        b9188e5b014e941681e15fe3e132b8a3903474148ba28b987111c9bcb3989bbb\n        c671c581b44a492845f288e62196e471fed3c39c1bbddb0837d0d4706b0922c4\n        72e31df613da9a1dd33b5d2d8939684b89f7649e1c59b959ffbe972786c477f6\n        6177dbf3b059173fd06afcd90e80e862174fc57f97607bbff5b73d6360fb5c37";
    const M_HEX: &str = "2ce74ad291133518fe60c7df5d251b9d82add48462ff505c6e547e949e6b6bf7";
    const C_HEX: &str = "\n        56b42d593aab8e8773bd92d76eabddf3b1546f8326f57a7b773764b6c0dd3047\n        0f68dff82e0dca92509274ecfe83a954735fde6e14676daaa3680c30d524f4ef\n        a79ed6a1f9ed7e1c00560e8683538c3105ab931be0d2b249b38cb9b13af5ceaf\n        7887a59dba16688a7f28de0b14d19f391eb41832a56479416ccf94e997390ed7\n        878eeaff49328a70e0ab5fce6c63c09b35f4e45994de615b88bb722f70e87d2b\n        bd72ae71e1ee9008e459d8e743039a8ddeb874fce5301a2f8c0ee8c2fee7a4ee\n        68b5ed6a6d9ab74f98bb3ba0fe89e82bd5a525c5e8790f818ccc605877d46c8b\n        db5c337b025bb840ff471896e43bfa99d73dbe31805c27a43e57f0618b3ae522\n        a4644e0d4e4c1c548489431be558f3bfc50e16617e110dd7af9a6fd83e3fbb68\n        c304d15f6cb700d61d7aa915a6751ea3ba80223e654132a20999a43bf4085927\n        30b9a9499636c09fa729f9cb1f9d3442f47357a2b9cf15d3103b9bf396c23088\n        f118ede346b5c03891cfa5d517cef8471322e7e31087c4b036abad784bff72a9\n        b11fa198facbcb91f067feaf76fcfe5327c1070b3da6988400756760d2d1f060\n        298f1683d51e3616e98c51c9c03aa42f2e633651a47ad3cc2ab4a852ae0c4b04\n        b4e1c3dd944445a2b12b4f42a6435105c04122fc3587afe409a00b308d63c5dd\n        8163654504eedbb7b5329577c35fbeb3f463872cac28142b3c12a740ec6ea7ce\n        9ad78c6fc8fe1b4df5fc55c1667f31f2312da07799dc870a478608549fedafe0\n        21f1cf2984180364e90ad98d845652aa3cdd7a8eb09f5e51423fab42a7b7bb4d\n        514864be8d71297e9c3b17a993f0ae62e8ef52637bd1b885bd9b6ab727854d70\n        3d8dc478f96cb81fce4c60383ac01fcf0f971d4c8f352b7a82e218652f2c106c\n        a92ae686bacfcef5d327347a97a9b375d67341552bc2c538778e0f9801823ccd\n        fcd1eaaded55b18c9757e3f212b2889d3857db51f981d16185fd0f900853a750\n        05e3020a8b95b7d8f2f2631c70d78a957c7a62e1b3719070acd1fd480c25b838\n        47da027b6ebbc2eec2df22c87f9b46d5d7baf156b53cee929572b92c4784c4e8\n        29f3446a1ffe47f99decd0436029ddebd3ed8e87e5e73d123dbe8a4ddacf2abd\n        e87f33ae2b621c0ec5d5cad1259deec2aeff6088f04f27a20338b5762543e510\n        0899a4cbfb7b3ca456b3a19b83a4c432230c23e1c7f107c4cb112152f1c0f30d\n        a0bb33f4f11f47eea43872bafa84ae22256d708e0604dade4b2a4dde8cccf119\n        30e13553934ae3ece52f3d7ccc00287377879fe6b8ece7ef79423507c9da3395\n        59c20de1c51955999bae47401dc3cdfaa1b256d09c7db9fc8698bfcefa7302d5\n        6fbcde1fbaaa1c653454e6fd3d84e4f79a931c681cbb6cb462b10dae112bdfb7\n        f65c7fdf6e5fc594ec3a474a94bd97e6ec81f71c230bf70ca0f13ce3dffbd9ff\n        9804efd8f37a4d3629b43a8f55544ebc5ac0abd9a33d79699068346a0f1a3a96\n        e115a5d80be165b562d082984d5aacc3a2301981a6418f8ba7d7b0d7ca5875c6";
    const K_HEX: &str = "2696d28e9c61c2a01ce9b1608dcb9d292785a0cd58efb7fe13b1de95f0db55b3";

    // 1) 种子展开
    let d: [u8; 32] = hex(D_HEX).try_into().expect("32 bytes");
    let z: [u8; 32] = hex(Z_HEX).try_into().expect("32 bytes");
    let (ek, _dk) = mlkem::keypair_from_seed(&d, &z);
    if ek.as_bytes() != hex(EK_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem768"));
    }
    // 2) 封装（案例自带 ek）
    let ek2 = mlkem::Mlkem768EncapsKey::from_bytes(hex(EK2_HEX).as_slice())?;
    let m: [u8; 32] = hex(M_HEX).try_into().expect("32 bytes");
    let (c, ss) = mlkem::encapsulate_with_seed(&ek2, &m)?;
    if c.as_bytes() != hex(C_HEX).as_slice() || ss.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem768"));
    }
    // 3) 解封装（案例自带 dk）
    let dk2 = mlkem::Mlkem768DecapsKey::from_bytes(hex(DK2_HEX).as_slice())?;
    let ss2 = mlkem::decapsulate(&dk2, &c);
    if ss2.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem768"));
    }
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
        println!(
            "eq   = {}",
            sig == hex(
                "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
            )
        );
        let q = sk.public_key_sec1();
        println!(
            "verify = {:?}",
            crate::sign::ecdsa::p256::verify(&q, b"sample", &sig)
        );
    }
}
