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
    let kats: [(&'static str, KatFn); 12] = [
        ("sha256", kat_sha256),
        ("sha384", kat_sha384),
        ("sha512", kat_sha512),
        ("hmac-sha256", kat_hmac_sha256),
        ("hkdf-sha256", kat_hkdf_sha256),
        ("aes128-gcm", kat_aes128_gcm),
        ("aes128-ccm", kat_aes128_ccm),
        ("ecdsa-p256", kat_ecdsa_p256),
        ("rsa-pkcs1v15", kat_rsa_pkcs1v15),
        ("mlkem512", kat_mlkem512),
        ("mlkem768", kat_mlkem768),
        ("mlkem1024", kat_mlkem1024),
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
    ecdsa::p256::VerifyKey::from_sec1_point(&q)?.verify(b"sample", &sig)?;
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

fn kat_mlkem512() -> Result<(), crate::Error> {
    use crate::mlkem::k512;
    // NIST ACVP（2026-09 代）：步骤 1 用 keyGen tcId 1，
    // 步骤 2/3 用 encapDecap encapsulation tcId 1 的完整五元组（ek/dk/m/c/k 同案例）
    const D_HEX: &str = "47b893474672ba92e4b12ee44fb32953af8e8503b5fb471d1614fb8a021a660a";
    const Z_HEX: &str = "1f8cb39e9e30bc458a0dc5408884b1187fb217018df760fa57317703b844a0a9";
    const EK_KEYGEN_HEX: &str = "
        28266a088b3482439bca01afb7ca5c6136a979b5159985a9484b36b679a5f7b9
        819eb63577891f7bb9cb98413ccc434adc79a16d6ab3076569ce6291c59b5d64
        612a7fb0c15013200bc8bebb03a570174b5e4363aed86eb02a220d281fb5457f
        0a549fc5051d49a6b2015259a2c3084f405e1769952260675586a58490405927
        5a265234ef3abf88c171a80898fc783358bbc9803c8789027d917c9ebacbc568
        cc18de84c85454b94249586c0c6e2b8a16fa789c51212dd1728ee9b8c6c40528
        bf93826fa82368419623032af27b5694305816811d3ca85805100e9c1a9621e5
        089e54cb47f5a8fea0b49ef81c6b5187f48924c7947d6b61697a4a8a18452ef8
        03336ad4be503275bcacc03c181405f7b1dc9b47fb169eb37bbe27e29c763a4e
        52b9a42520388cf09b8edbcdf41ccf6537190e6156c37cc1aac63c0f90ce78d0
        b9b190c548d71b6f26cc8f585ea14004b5b30aaa100b2adc1263828833b24e46
        163b41446f98c882092a39941867b80632e2097674a793935227db0b8577e03a
        69c50a514c7473c892e3fba7c4316bdabc952a70644176687d4191323bad93d8
        5a3ca250868c0747e6c44f6126c874afbec0bdd4503cb2c59a69816e7d410994
        1467579a1ffe6a4f50fa379051729dab6e2f61432f15be67d667c7cc1054742b
        2b953078a5cf88d9133087309d88c61da240d99c59137329907b47865321ecd5
        564e987333b4cb607b0afca86769dc95b2f921357213fcb80c3b152918e9bab2
        228c0a1b77897ac68ce55088165f87f397da9790873b62c5383c0ccc370f0267
        cbe195651ccf336182c22ac3924b76c9e779b7a271d166b6d24b84242b7e73cc
        723f764039f6c851744034c3304db0c091a5764fdc9d593556ff734b82a87ccb
        c38ca99564d988bbd2d1bf071bb160722d365104fb27610651a8ed817f2742a6
        b5a1273a61acaf4460b0ab1456a9922351400a1c7d95d856d6e3370622c9c416
        4bc6b401435624a98b95caeb274f34ce92038d785068cdd8cf44c38d84acb2c4
        66a2756c870ee78c26e738cc451002304eb8c90ab24b6463eb124d779f937a2e
        3692611d2e34d57b36cc4b2cd3b31ff485c6684d408b972e0d5ca7d2224aae4e";
    const EK_HEX: &str = "
        17e5129b2029f3281987d6624725b64c51cf8dca3562372bacb7ae15fa9f2ff6
        ab47659b7d305b61f55f571315ff69aa49e1388100319a650e86c59ba3024c3d
        ec83d4aaab661c452f6cb6a8d2638c133c599045329ccc8f677d24683df1146e
        e1c7318c3763a47acff81a03927b9bac5a49dc285c4ee204c4d72dbb1c97fe53
        c622e621338669fcfac1e30a36f0a9769bbb2ba408787ee629cec383f29aaaab
        d46e22133f339c08e29b82c4faaf0f676e1c2b04377975dc3a3b246488edd163
        6c58abcd65b8198b6fa8a8475ef541daf34b5adb9db0589d8958b62a88930eeb
        1c0c352b1e57bc7882c89efa318457813f2b55b96881e7f75c3dc97357681e54
        553ae099095ac38b34c00199952602c481c0f1cf74b550ce7c4f6c5876aff076
        dd921942db377e1749f0306f77443a2f058d785854c7e32b67f49bcb99a5e18a
        ab607c649b892b4da7cc7af31557149f02b19460fb49e5051a7251ade0083cdc
        1b0b0ca9633220c2b3c532fa2cbc0dc6cffcd4455e0005d06cafc727c778375c
        b67ac461b3627a653c843baeaef866c7f67746262ff6d76536255c89045a172c
        bfaa123d6eca3e56fc922f437a14f78d1adb54b3e54e8dd530450b8500e15a54
        c97471cb26ab437394480282ba6b7a786c28857baf387725bb4342b4c3abe4cb
        f90612b04c8bdc1599c2d4c66b80b1a1941440040a42aabe03e1ccb0b4190780
        b6603bb69ec199b063826beaa5447c88427c6bd7a06e4164a490b955152979b8
        f5bc9417598af01bcc371577189e1775165b9610b9f75aeea277018b1c2c0439
        1115b6f353afeecbaa18aa4001db94fcdc5f46ea520e9836bc5a4576b58c59fc
        3f75634946d8cc1b1081ce93aba8566304169332fa316d4ba675a086ad879379
        63511e4a1845ea38689b564e11295672098cf01d5d4bab0338121128a682b048
        e6aa31b83c65ff861e123010433a3c7607ae5e90c438067f637b44adf8798cd0
        980ec83bdaeb4d427a8f8d88c519e52542f07734a645a2a5bd4d6521a4b64a96
        a10f35002780169b35e35f01ca74fe6207b8b475ebc079647cc10aec3c29683e
        071d87b82abbdd6d369e326e475325ed5ae7ed232b37f49388c06a740d421204";
    const DK_HEX: &str = "
        c9096f060a1c4c974253d2b64feb0e40d05ff5426fe9665252968c4948a2a363
        a5b7f5523e5abd4e63393e9cab0148701529548cfc58901a4840517423f9a3e5
        0327d1610bd291a2a051ac231144ac924b6845a735784daf24cacc9c17e11739
        9b94967284900390ad35857979385a04929eb2094bc6444236da94d39ab74ea6
        40470a068b69880da1846c6211b0222174d84f5f0649a7e266a58091bfd9b49b
        9478f1801934a86293e8af643340541676f98a2d1b62a4835766fb6441172cbb
        a0942b3665bebb1ca202ab8a7a0c655bc232e89a0027fc49f7ea49ff21564482
        30602b70c6988e4fd182dc95338f1206d2fbc699fb12ac636ef6084735f3962e
        e26d494423baa907d8d05d6076556f6279bb878b6466559d309a57c93843173d
        ae1b281ea2a30a7c7325d8593579b07d574a73c51a8ae17092a80aa30c35bd6c
        b76e122019ba2668551cb9640a07a3b5aa3c83a575ae78552928344dc4388433
        3414c48a9bcaa45620c46334e508e7750b24cc696002995725159c334a909074
        a1a3719d53c3ea2cb8df03c3953192162444f116453ba19b2ad380769851dd59
        455fa0b4e1367da0bab063922846ea85ff119fb7e0447d464cbac53fbdfaa0ea
        ba3e1be31b1243c6b1468369523c03e06ffdc714bf2cc171a8189cc3a8f4840d
        b69860a6608b1b9c56a356cebc6c8fd01763e086566bc582ecb52db10a0c4ac9
        7d94c25b5ab2cef0c42fcf26bd7a88044ea20b16041727573d156a8fb69a31b5
        c015201733a0e84ded1757e3988dbcbc5571c8588286a418c149a49ca31b73cc
        7321cbf83947395538152ac6b36b39daa538aea236db64827d660e574911fa09
        4d4e9a279820be06d4bd4bd3492643964d432bd8dc5c0828b7f5993a50d25415
        88a6b37022cce055814845cbac226807216b0839f449039651a43488400ba602
        e6244b720629ddf3c9e88a894d524a0d60327f748a1be86a25a2bf41225fcfd9
        848b917edb0b081e71bd50c09c0eb38286939879e23e942a6d4d649b4ca123f7
        2c202f1240b9ec63c7410340c5c7c78baa5ba70b55172bc1c44abde4af86d380
        17e5129b2029f3281987d6624725b64c51cf8dca3562372bacb7ae15fa9f2ff6
        ab47659b7d305b61f55f571315ff69aa49e1388100319a650e86c59ba3024c3d
        ec83d4aaab661c452f6cb6a8d2638c133c599045329ccc8f677d24683df1146e
        e1c7318c3763a47acff81a03927b9bac5a49dc285c4ee204c4d72dbb1c97fe53
        c622e621338669fcfac1e30a36f0a9769bbb2ba408787ee629cec383f29aaaab
        d46e22133f339c08e29b82c4faaf0f676e1c2b04377975dc3a3b246488edd163
        6c58abcd65b8198b6fa8a8475ef541daf34b5adb9db0589d8958b62a88930eeb
        1c0c352b1e57bc7882c89efa318457813f2b55b96881e7f75c3dc97357681e54
        553ae099095ac38b34c00199952602c481c0f1cf74b550ce7c4f6c5876aff076
        dd921942db377e1749f0306f77443a2f058d785854c7e32b67f49bcb99a5e18a
        ab607c649b892b4da7cc7af31557149f02b19460fb49e5051a7251ade0083cdc
        1b0b0ca9633220c2b3c532fa2cbc0dc6cffcd4455e0005d06cafc727c778375c
        b67ac461b3627a653c843baeaef866c7f67746262ff6d76536255c89045a172c
        bfaa123d6eca3e56fc922f437a14f78d1adb54b3e54e8dd530450b8500e15a54
        c97471cb26ab437394480282ba6b7a786c28857baf387725bb4342b4c3abe4cb
        f90612b04c8bdc1599c2d4c66b80b1a1941440040a42aabe03e1ccb0b4190780
        b6603bb69ec199b063826beaa5447c88427c6bd7a06e4164a490b955152979b8
        f5bc9417598af01bcc371577189e1775165b9610b9f75aeea277018b1c2c0439
        1115b6f353afeecbaa18aa4001db94fcdc5f46ea520e9836bc5a4576b58c59fc
        3f75634946d8cc1b1081ce93aba8566304169332fa316d4ba675a086ad879379
        63511e4a1845ea38689b564e11295672098cf01d5d4bab0338121128a682b048
        e6aa31b83c65ff861e123010433a3c7607ae5e90c438067f637b44adf8798cd0
        980ec83bdaeb4d427a8f8d88c519e52542f07734a645a2a5bd4d6521a4b64a96
        a10f35002780169b35e35f01ca74fe6207b8b475ebc079647cc10aec3c29683e
        071d87b82abbdd6d369e326e475325ed5ae7ed232b37f49388c06a740d421204
        f31404c1c625039560adfe0bf427c4502b115fa8d02d78b4f2ef1a45078a1f80
        52c2a1a06087a52fc79b8cf7f2fcd41d18f5a98190d84a0379870db22186ecb7";
    const M_HEX: &str = "dcacfe4de1c115da106acd1eefeafdc7f0f4e5707453ee2d6b0d69d34cc0ef4a";
    const C_HEX: &str = "
        1c3204a5a2c031077459e24a179fc80f8833e19f36e7ac0d3071bfbd2d48fcf1
        352b96efd0fa3195b44a27ec575b2794909e4089421e56409ad00cf472680f43
        8e0a6d39e88fe6b938ef722c7b7f75f714264c8f22c528a63985c75d2412278b
        137acd29003cad1711a2637c630164507b7d3c0acd1dd3ba6e689411df6d3eee
        410ec8c93ef27bc82019c3943b85e645519bec1105d4738388c7a5452a67880d
        e88d65c1626a55a4565b5c26b20bbfc33f2dcecf938149d8b58b19dfb5f451c3
        a9fb5ab3dc486c435f5397b6e32416a9306d9869b91231adfcc9a4ad3d956ec4
        9832c3ef2a6ed50638f6633d5a8fa7bb7b04ef45ff9b57d6ea7b771d57c3e5b9
        bf96e03abd601bb46e5ce3e104233e7be642b082a610fcebea684c516aa39a05
        1ddb87025ca849816e177c17c10115939b98b5d9f95323328cb5250c4e38b7e9
        32481d20bcbc66b0becb3dc1aa196f5fe207b28f36344a3c00f2fbe179878d6c
        7981467fc2df70d079088f09b4d2cb56d5dede593a77b31930e8f6138dfc7f9a
        7295fb372c1a33713610b2be51f311e7ce6050ec276e5c3a50790ee4cb815110
        52ab659dd54f4baf211eacdc2a4e987c7e2eb8b384f06813c2542bf765c3e6b1
        42968bf3c66414d01a205964e743777040a6a9879c84681b6f6b3f2f2b0b0455
        952a99a21cd609c1fd7be71ba6a1c9589445dc69cf1d4937763ac640df853fd3
        e6dc9143467e473ff4b89975f24cca51506830c279ad8bf806611e836f405e8c
        1fc36208e99acb764316bd7c42d2e248b1dc3d5c551ab77fc168296853129c31
        f5722707791fd5f9aaabc4fd4c82a99970a93f274fd0d6252edcaedc076bf598
        4e6e28056bb831ff289cb0f6ee87bc4816712da0f322a51765f5f230d0de72cb
        b4714c9cfe56c1bd727dd7d3f7c1b5b83029c81a22b8fd430b137003b63f29b7
        10a1a2c549f9ab0b5ac8a123935a1a3bf627690252aef65f20681e2e9a664321
        cdf5fde1943c196ba2f04e42e35f62ce77198f01a747a14d57d7ed46259189a6
        aa3363fc178a8cc5499f033f9b8d90d327aafab7de16831e8325d337ab3dcdf1";
    const K_HEX: &str = "2d74374b55d29aa585e144a29ba4f0a96537a73b4f176c5527075f66e38e8858";

    // 1) 种子展开（keyGen 案例）
    let d: [u8; 32] = hex(D_HEX).try_into().expect("32 bytes");
    let z: [u8; 32] = hex(Z_HEX).try_into().expect("32 bytes");
    let (ek, _dk) = k512::keypair_from_seed(&d, &z);
    if ek.as_bytes() != hex(EK_KEYGEN_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem512"));
    }
    // 2) 封装（encapDecap 案例自带 ek）
    let ek2 = k512::EncapsKey::from_bytes(hex(EK_HEX).as_slice())?;
    let m: [u8; 32] = hex(M_HEX).try_into().expect("32 bytes");
    let (c, ss) = k512::encapsulate_with_seed(&ek2, &m)?;
    if c.as_bytes() != hex(C_HEX).as_slice() || ss.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem512"));
    }
    // 3) 解封装（同案例 dk）
    let dk2 = k512::DecapsKey::from_bytes(hex(DK_HEX).as_slice())?;
    let ss2 = k512::decapsulate(&dk2, &c);
    if ss2.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem512"));
    }
    Ok(())
}

fn kat_mlkem1024() -> Result<(), crate::Error> {
    use crate::mlkem::k1024;
    // NIST ACVP（2026-09 代）：步骤 1 用 keyGen tcId 51，
    // 步骤 2/3 用 encapDecap encapsulation tcId 51 的完整五元组（ek/dk/m/c/k 同案例）
    const D_HEX: &str = "f3a706faf090c03db506863ab0b20bd8a1627956318e88c67eb875e8e7266009";
    const Z_HEX: &str = "35d2bc43dd1cc879f765bf2a0c5e297889dde910e57e2bb0eae417b90ab7a275";
    const EK_KEYGEN_HEX: &str = "
        8d0923ca8a2da2b4146ec25321122b8a5aa8afe0c03415273008a46ee83031e9
        8aaaa125abc75d3b30322560c197e75dd0e48a348099f7b2144d7b8a8660a4a9
        7bcf19c0583bd9bb2123033cd7bb5a14b08b817831a673a28170f5f6443c0551
        913a327cba18c3a053c4040250403b70ab9588832403aa0fc37665e04980fe16
        02e7d2715d9cbc00515df432a4f5b32b3bc92ae3f31700166d498123e9457650
        9b712b18491b1435ee7ab7aeb1ad30d72348c3cc083abe24a8b12097bf32f792
        476288eecc3bf630adcdac6aca7950d9839501a448500742bae37f109203a809
        b2b960a307e25347a32c3eab79288173a878789b296e9e8c1c28c5bb3ac47260
        1c9765f7b77225a810c7b85370bef4a5b079d2015ada54236b8f33840675f9b2
        eb427a1b5974cd5c61b24010886c5a7bda5bbed974af7217f3338ad719cb308a
        8bcb1b6d6ed2a1643736c29095e8a8452a3a36c7bb5ae58cbfdc61529466a90f
        454ed6895b0861083dd1371999b2f559a3a487cf59a074fb49215ea6a6be656f
        9af17b121a2447cb7985590e9738842b899ba57ac311810ae2d9794f37483dd6
        bccb64af6d56588ae94665961c025c3aa2861974c236bca4bd8ff5509f7ab774
        593e7c5549e57c2f18d15c0515094ad9a0dfaa0601e524f8231156b627bb25a0
        dae04dacd0a66c041cef400583fc13bae640291a39a5c5ca8bca1ad5c683cdd8
        290891a76940817dd8c9f52678780548e37a05806600801426dbb950c3b2ba34
        e24cc77864dd91b39f1408c716a69df63342854e50a245fb50977b9410ded2c9
        3f86b1f9d5a78b87bf81e51ca620a7e8566b19ab700964a40e3266415228d432
        156e5cbdf52364a90483a55c39b3fb16fc7465a3f8ac801b70b9fb28b583444b
        a5c1a73722d417a9d6d9b7deb08bc6b330ff27cf61ab8831e27758c64af3b121
        50cb7b33abc29858106d63686d8762459abf9413850ae53ed6313f76f83d0fb8
        ab34374e7df693e4a1b3e5a8ad0ce820afe1cf401acde650a8101b0946022d52
        178e19613c42b88b07cc04eaa81dfb28ac9dc076236b67219a30f8f945dd57bd
        2f335c52d59372308d38993467db53da3382b74867b616481bd0091a2232c111
        6dc88a589db9107224a681008c67c589186a6929549beef92253db02b0c8aa9f
        9c875a670266c72bcbdb4f5625043703c1a0457395832e4c335180462ed2220c
        59e7361903c107d85457f6cd82eb820d0855d97675c2e0151cdb73c2885ddb78
        49d74541580124e890116a65bc068093b57914e20c937c60a3eb25576f1a976a
        9583839b672144cd4a45c3477a45c29b4e0bc2bdbd206585c9b7a7741c8b6b57
        93a92797a15ae7a5b73a74b2971463634ba52aa792af05530730b6d0a89a3461
        56b733677932bd36593a7496130cc458dcc5ca987c21960604ec8a8c53960566
        80cbf3f1aac4f401aa5029fb2150434bb4706c31a2d54e4297939fa7c9c6f857
        00613ceb65c7f03ac56eb86e2d27ccc6dcb7b9394dcdb942ff222d86958a996c
        0cb6a8a44f97a70441c95fa71250116eec20863c0b5a643458788ab001f8869d
        909922f51ee547a1e889255b3a0599c65842e5ab8d73872f053bc62392ea5389
        6d328102d460bf1609583c22c3b43780ec6dad0319eb4a5a65b4756c3cb40eaa
        935183bf8bd46abe76ba46e199103a5313c3235f49c915e097bca804de680781
        d8365731beac6789a9203fb8787c4c070e00a13a6722a66a28236db179825653
        d33ccf898b72c6b8450d97afd3276bb13340519cbeda708d12a858f54c49f454
        7195b7788a9150b2649e36aa394121926d568a488b16d3557b2a32af57d11fc3
        373f80a28c0723273d362502e7c428ab44d3cbabf9ea585fd1bd0c9846556a1e
        196b78cf951592984a0a8487a78c2317d7aca4118e1049750a0788f0d66ad9e4
        8e34731130aba0b427360a856d96d80b3f028fdd3aba9035c10106ba1c0934be
        d36c6d7c7434249654ea89fc22137f4ab903653b75fb25b6f01635e6cc7d39cf
        1508690562826b49b6ffc59e0dd35022e541f8ba0d304aa5b4e20606907c4243
        95666c54abc2b8fb009847c86317685000c231215c8c15945860f6a85ddb98a8
        c3a527f2749d3c027e694e8f0b0f0fa454913aadb635aadd452f7128bf775256
        9669a8b93290eb92e78f6adff23e89f57f3890753b51f12f3f3a8a654e677847";
    const EK_HEX: &str = "
        2191abb6d6beee29c5780758a970349879b61a028deea5404731292346c81eeb
        1d17766afbcaa68c867d91132f34a494e28caa767241b50902f4825771865fc8
        d633736248963a253dd52c1a07c7177cb6df74c43c3c74d7133da9dc915fe14b
        5bc30b86153e7b86be04189f4ce8ceb6e5cb69808d35640ac50335b1633162e2
        8260300646153be7b26a84c1c565956f8577c95cfa80b68978cd7a79e49c7e80
        8b21cdb460ed8388c4859670333b69980b2f9a0f78d7a5b9d8554893a0b5c524
        47b15318828989816f43406abfa4950607a5a57cba62f5c4340ac3d294191687
        c7d2b60ef2d83f6bec15b1618129b78577447bd1e36a87142b9c552c8cd2304f
        35b81b3bc5196c3840c0346d513ec8862ba14a172c051402f7398707a6133c8e
        88e5b57f9b9eec18aed1404ea1c47be5169e5d558e262a231a75925d25c49965
        0c8ac031be580cfb185a0e0362ce2194c53713a630cb59600c1942908ff5142b
        02364b74b3f5474301ab2da4188dca640961142f28584ebe810683c046b59cc2
        cc07025da63a5e8c5e99e24fbae183329886279c2d58d0b8cac1c7b3033f05e7
        65c75414748687ff03c00b36709d41c5968528f178cd03b813b69054d3e20fb6
        a04a713b1b169ab5f0369810fc5cd967a866b70a2d87514605794930be9b7b5d
        49d08f5cb08d84fc5beecb994dd2a5fc10aeeb4cce1ed251fd4815a9d06eea6a
        77f18c56acabb1f7c478dd52218b7bbf9770a51c3ac96402548a1bb22dd0c29f
        422330057179ec2d91e1aee27bbcb1eb4671324265e28676090896e332535ba2
        e9169c54113f19a45229c2448078ae08f7213f347244527ef726855ca054ab7a
        1ed1a40a285a60d04c00ccfa8fd318cf182705ddb888df652669b3224cf54ed6
        d00db5121331b40c7e35b1945925e5ac1503a999899317a2370020d818733303
        27db7cc1d430e32c6570fccffeea90a871a4b04ca9a8065ab20a6459f1806221
        a5482802f14a68893b111607c4e085a5a6410c027c1bf5fa33adeccea576211f
        272cc942acacc879de398477780a26e7545ed693edd66ad24772b0c0c4b033a7
        3ed94e1d02c384d1a288a78f5d8838b5ac0b37855dc59b987ec9b0f5c6868b03
        19f3372024fc15b247144f925d3edc453fb8551ec1ca734a37a3972b8cc9b84a
        217a4d0bc0d08c815359aba59a07eed998133587e062cf735a8521a18ac2059e
        3f142f12ccc5ae024ca33b8e4a285be5a3ced460c2c3675b956294ef2c61c96a
        88441665d56b2029688efe4540dc35abf5957bf9477f58277851719547510f22
        d01a13d0047c5b88372a654c732aff395dbf825829a06e6ae6923296218ab9ad
        33d0b07a0b6a3f3b3dd8428a1f82b72a921853d94c5d400494494f0d168148b5
        392f386b16c6056d6b8d767b7f4d918a9384c855c8b4de8450eb6ccc2df18528
        cba0a3552d5704683aa3aaf52751fd5a17801a76a58a75038533c1576e8668b5
        d290ceb20cb1ff91317d9b418311c11e617d10b4b0e9055aef5cc6ebf8b91f02
        44ed9854fde463e55112a238038750cd016735613b9c461996b90a3b4d4b0d8b
        8825ec087fb138ab868a04cb3c9249b5b118f81ed06b99e6b521f206a32a4013
        e876c6c80b36af39ac197a21b78b5f2713aa45c74335f32676c2ac2902710ec4
        2af5984687a672e0466831c7b436300b30351795b22b3a939347a7b744831baf
        e78c3bf09a8224a958568f75d71f822941dfd64d8969ada5b73c847272b59144
        91bbce5f0c09ef501babd95190f93201ab413e833f7924b696d5c2b622722459
        32a6d9c35e1670aa3bc57cd41b8d61a52aaa6d80bb774f922ecb41cd58469c4d
        cac698f6730890237602064b148650c17e6edcb3713382fe755e46f3abe0c6c4
        5184ae5c5c861e35a0e2bab2b4e8a4775584351170152512c7e99e96f285b916
        605b53b91d6c501f51a93129483046cb2dfa16d4a540ed2b6ab18bbdfba2b201
        baa20297ab1fe7133757c07dc041971aa4219157d77628f31aaf520650a2250a
        dad1524e58268d21cc62e2469c8425e86359dbcaa066acb466e06947a1c144e5
        3ee0dc930432c806c493b2bb25757b1e2c775a27a896ec25b58e8a78d4dac918
        15a1f3d90635ea25ae13cefa77877dc0c2f0678ade307243b438c54aa69dda53
        9b8a41c1b3c98c77fceb2c0bc2025a272d927943ea338cdf32a0dec8b187df5c";
    const DK_HEX: &str = "
        e4b509441c4df0443db6bc96f707be70d0b8af557ef228c78050699779b16550
        2ba1a600230c849225552250b78c10c2a5e244b5364383d29bd8a75889da089d
        c4485dc4289a559931c6cce9c8b95df482e5496ffde9b526f0055e241a19a7cb
        15a2a85ea042cae75eaae29de68ca3cc1c1de7c1a0c187897f5a45c6a9225171
        6d801c36f315b3738a489bc4ccaa2094b5f9af9524252fdb1f822b5ea1c63e66
        96b0dbc1177c9124cdf9cdbd8529f78088d232693b67ad1fc08362c3c6b44213
        e559a8a48562505565bc01cc2fa62acf736e3e5040b10b621b606b57598548ea
        7f040203dc777580c2326dbb36dbc3befe89b977179d32001414d1100a70025b
        652e8517ccd0b4c44012bb38d99599f27866a222f96b347483369a496627e47e
        5f8a6f0aa899c7427822c25bce4205ccd22e1a00ae6b30cd190243d51519a4c5
        1602568f883ba4bf8885998c0a0eabcb14e7a9d801376101a0e94282ca82492f
        ba69d301920282b5aaba6940442bd7703855390f5db42d7f9794e7bb192e628d
        119561a2597ae0e7301e7668a8a3aca6db1716465c48400fb1e841751235f641
        77854295bc7a9c060c7f5e3b9da8eba23b9199bdb69f524b8be03b6096f2ab36
        b377251888ac728657b66e5f54c71ae311e7a0528baac222da7c5b519d4c04ce
        fba133423666663a9154640a6e767c14575d910a80a8a71f0936433be8ce46a5
        a8e5a70f279bc3cee79665cc9835a3c295fc325285650bd0b1046669ab775a26
        49259d4903bc2554bd741a29027b6c65a99a16c97f79accf2818b90800a5fc29
        b401c1705892500b2899d1863390aa7b4884f2fc2593d437a1232777e6466f52
        83c5b05d8b06bed8860f35129d92fc57e0e32f504611835b6083c6383ed99124
        f282cac39d8fb17b5e079d25dc4756f30185653fcc408d4ec3c6845020a2073b
        b2569113017ce9121bdf0a9b43d850b03510f5b10b5a92b072f6b26a38a21536
        4d526a44176c0869c4895aa248f3d108e4dc5959ea2adf5a4ebf90b6cf05b9bc
        8444d118547967957ff9a81e31912eb20158836d3b63c45a628aa1d35790c512
        c0b7b0788b390bd687d5aa2dc6d63331a7152fcb36af850234d98d0f22304f50
        a4767c9293a185fac14a11d124a9d4ce53972de8eb3f57e471d5a3414d752bac
        832f12eca919d84d3832180ce6cf3b975da2e544958ca3a96c1e549067ff498e
        accc3eb475c5fee3b85017c087663d0792324280c111d83105d67929aa64056b
        ae2e5823bd7762750a051c24a466fb003e2b61e0b675f62c4764038fa2489983
        f21602240edf812e0a557ac8e6a812b4108141937d9a053f052c218b69e3169e
        4cea78602172f7000d6631b09a42b1efab6771d01ca58535ebb63d8924444419
        a26ea3bb60e96abea8c203271fa41a008e889f141b2af3f4bef78228cc00632d
        f9285a2624ba71118015ca2f0c4f2a641f753b257b90a26a016bcdc666fa065e
        cf4257c0db1eee815e5a7285d944a1d9e18986a84f5980955960b79a957a893c
        a206e2161e037498c896ed49659e32893e84c992cb3ea814a636d87a77f3479b
        ab07bb9a6af00a71c49a22fad59a818b26513c27aaf389b1f5737176a46809a2
        9337aec0c8569df87402a56327dcce27e5088959bdbc39c8d324adaef1060146
        ad3085cd737007fd550ae78135b98301f0667164375a83ec2e28a47255f1c994
        9cccbad619186825664aad07c35ea7241d29072b9bab1ffac5b4427c2b7c026b
        3dcaaf765a67d0e1630dab279376439b98141dbb7e54f104a4a00a64d743b6d2
        598e757fae50c9811c7d0c0864a144899bbc923a6722a49827a0c6aa3d62c558
        133331537dda0cc2d2f8702d6282aa4220b0d31be6eb2bb5147bd2822f587945
        b7444de151925a03c3e9969624155c21e205ec75cc5957a2268962a0f5861036
        a55bc50e1aeaa0022664c761b530c9790b3591f7d587ce40ba48d43f390a89f3
        660c98ca9c011ccd1dc1616469c008e2974fe128e802c96a9271aed831797c85
        7c345427791d6f3625c2dc3931733675d37165ab4e50174587679cf3319386b9
        7df1685aba1ab2caa00a1378cd577511ade21ec94236a9944e07e885dc12602e
        762fa5b284d73c8f9cd8395da0c3b075bd9eec465b6a4ff6e125546a3903ea84
        2191abb6d6beee29c5780758a970349879b61a028deea5404731292346c81eeb
        1d17766afbcaa68c867d91132f34a494e28caa767241b50902f4825771865fc8
        d633736248963a253dd52c1a07c7177cb6df74c43c3c74d7133da9dc915fe14b
        5bc30b86153e7b86be04189f4ce8ceb6e5cb69808d35640ac50335b1633162e2
        8260300646153be7b26a84c1c565956f8577c95cfa80b68978cd7a79e49c7e80
        8b21cdb460ed8388c4859670333b69980b2f9a0f78d7a5b9d8554893a0b5c524
        47b15318828989816f43406abfa4950607a5a57cba62f5c4340ac3d294191687
        c7d2b60ef2d83f6bec15b1618129b78577447bd1e36a87142b9c552c8cd2304f
        35b81b3bc5196c3840c0346d513ec8862ba14a172c051402f7398707a6133c8e
        88e5b57f9b9eec18aed1404ea1c47be5169e5d558e262a231a75925d25c49965
        0c8ac031be580cfb185a0e0362ce2194c53713a630cb59600c1942908ff5142b
        02364b74b3f5474301ab2da4188dca640961142f28584ebe810683c046b59cc2
        cc07025da63a5e8c5e99e24fbae183329886279c2d58d0b8cac1c7b3033f05e7
        65c75414748687ff03c00b36709d41c5968528f178cd03b813b69054d3e20fb6
        a04a713b1b169ab5f0369810fc5cd967a866b70a2d87514605794930be9b7b5d
        49d08f5cb08d84fc5beecb994dd2a5fc10aeeb4cce1ed251fd4815a9d06eea6a
        77f18c56acabb1f7c478dd52218b7bbf9770a51c3ac96402548a1bb22dd0c29f
        422330057179ec2d91e1aee27bbcb1eb4671324265e28676090896e332535ba2
        e9169c54113f19a45229c2448078ae08f7213f347244527ef726855ca054ab7a
        1ed1a40a285a60d04c00ccfa8fd318cf182705ddb888df652669b3224cf54ed6
        d00db5121331b40c7e35b1945925e5ac1503a999899317a2370020d818733303
        27db7cc1d430e32c6570fccffeea90a871a4b04ca9a8065ab20a6459f1806221
        a5482802f14a68893b111607c4e085a5a6410c027c1bf5fa33adeccea576211f
        272cc942acacc879de398477780a26e7545ed693edd66ad24772b0c0c4b033a7
        3ed94e1d02c384d1a288a78f5d8838b5ac0b37855dc59b987ec9b0f5c6868b03
        19f3372024fc15b247144f925d3edc453fb8551ec1ca734a37a3972b8cc9b84a
        217a4d0bc0d08c815359aba59a07eed998133587e062cf735a8521a18ac2059e
        3f142f12ccc5ae024ca33b8e4a285be5a3ced460c2c3675b956294ef2c61c96a
        88441665d56b2029688efe4540dc35abf5957bf9477f58277851719547510f22
        d01a13d0047c5b88372a654c732aff395dbf825829a06e6ae6923296218ab9ad
        33d0b07a0b6a3f3b3dd8428a1f82b72a921853d94c5d400494494f0d168148b5
        392f386b16c6056d6b8d767b7f4d918a9384c855c8b4de8450eb6ccc2df18528
        cba0a3552d5704683aa3aaf52751fd5a17801a76a58a75038533c1576e8668b5
        d290ceb20cb1ff91317d9b418311c11e617d10b4b0e9055aef5cc6ebf8b91f02
        44ed9854fde463e55112a238038750cd016735613b9c461996b90a3b4d4b0d8b
        8825ec087fb138ab868a04cb3c9249b5b118f81ed06b99e6b521f206a32a4013
        e876c6c80b36af39ac197a21b78b5f2713aa45c74335f32676c2ac2902710ec4
        2af5984687a672e0466831c7b436300b30351795b22b3a939347a7b744831baf
        e78c3bf09a8224a958568f75d71f822941dfd64d8969ada5b73c847272b59144
        91bbce5f0c09ef501babd95190f93201ab413e833f7924b696d5c2b622722459
        32a6d9c35e1670aa3bc57cd41b8d61a52aaa6d80bb774f922ecb41cd58469c4d
        cac698f6730890237602064b148650c17e6edcb3713382fe755e46f3abe0c6c4
        5184ae5c5c861e35a0e2bab2b4e8a4775584351170152512c7e99e96f285b916
        605b53b91d6c501f51a93129483046cb2dfa16d4a540ed2b6ab18bbdfba2b201
        baa20297ab1fe7133757c07dc041971aa4219157d77628f31aaf520650a2250a
        dad1524e58268d21cc62e2469c8425e86359dbcaa066acb466e06947a1c144e5
        3ee0dc930432c806c493b2bb25757b1e2c775a27a896ec25b58e8a78d4dac918
        15a1f3d90635ea25ae13cefa77877dc0c2f0678ade307243b438c54aa69dda53
        9b8a41c1b3c98c77fceb2c0bc2025a272d927943ea338cdf32a0dec8b187df5c
        f84e555ebe890141df38cd7d478b75c658d3f5e9d8a114494478289a74a042fd
        59434802516a1a73500c7ae6875f2df34a48054af2d4d19b60db6e7432acf2e7";
    const M_HEX: &str = "2f1e2ca7bd72af847cac38cdefc4d345909d7517543edf32e2fc491ba05eb5c3";
    const C_HEX: &str = "
        d892e0948544d020ece56f00c6495b9bd1c469ac0f134002c864d10cf61c6c78
        87890276a7546310ea077741d83428f22b60e2a40ed8bbf5d9227893bb0b7417
        df4380323426ebc9744ef35a1bb6dab1181ff0b677e8c9b6574360994f96eb87
        c3524e15e468283169d90d8a994bed0da9cd778ca239ca6c225390221fd408a3
        eae541a032d714f3d078dd1ec722ca83fffc92a416f46fc1e8710c3f8e9cd452
        c016f483985a5c1d951fe2b03c4ac2c9a0ba71f6ffa4b29ede76df69cad594d1
        0618b94e783fddaf11cc801ed5036feb4a70d071079944b7d9f1ffbb98f123dc
        34a52a40de57e079a1f8b180da9e6ecaa47a111f3c054dd9563d7e74b95ac65a
        b453afe0bf0dcec5578fe6fbc2d9eb91932799ea64b2dfa95b2c9c6e931ffb0a
        5a499ddc42c6d6b563d5a6c1f34dbcb36f57e6c10c69feadc70a3d01f5f3715f
        6bea0d3e2e7ac2b04e01ca80a2e187bb7d9efa5ee257b9c3caea3947d785ca56
        a76d0b6692a69418935dfc36fd9b26758f5e1043d5c2a6d5cc1556aed592bbcd
        652f4024bf324910f8caa2415171f3ec8b1cc494f2b519cbd2b13d317672de60
        f0a3d400e6079f85c3cdad0da5a17f2efaccec03d3c2e85b063ac3cb29f2fc48
        50705b8d472e35dc12d06a7d021db302ca883dc7d4a57b7a9e1d023960d4ea5e
        39c9d5bf328b8e4ac0afc3a6c990f598f373059ad28edbeb90412472c637877e
        a82e7105caf467a15ce961695f2ff04c750e277e78c1ce9e490a5c45168936bc
        f79261b95fb20afccdce790e0aedde204da4f6734700fc1ce05239f4ead0a496
        fd8f733049ef9b6ecc54d5c635b56d6fcac7aba1ba32d707d888b820ce3e794c
        2562798210d726c6c5db3d22a214f3f2a1f2477fcb77377af41d0f3f0ac635e7
        bf0674cebb672ea93b9504efa8c5aafb7458e41a1d85c28841877ff2f444005c
        d1c1e4227573e8151184786489c7cc39549f8a29b9c4d68be38f24081fe239c5
        d0e14ad5e361720836a72a99ce88e47bf3e6a1a9eb57cdc3724cb4789fb88c13
        5ca9ccd94ccc9bd73ee8a796bfea36e894ed27b0791e8ad23fcda5ae7c167d57
        74aa00468d97bd0fd2b9bd78d01e1e39a66994a369212d95d7886be00f2b7a1f
        187c85b873f33cb7d3e4c23993f7bc9ff7abbc6fd9d5c54f06e5f31b79da992b
        c0f2aa79a36bd00483ca0add2dcb2be36c27dc913668f030128e82281e5e66e8
        7c75dce3fc60431ce6a19c6c45e19a2d84430e945034b7da6c506ef009493af2
        2f701088e01c20acb21972ff28d284d2a57a69d108161938f028011ba985e2b9
        25532b52eed878646579183eb0ef3fb57be1e05c1bd2b68d0e4a9ce104e0ecdf
        b30268e6c007812fd88498d97795447e7f88ce8a3bcd161b1e34dcf77413b778
        f88a3ad66f247f7664d0f6af31ec1dadc00fec09d6ac63fc8a802c3752484b5b
        43555381043fdd30ef5d7dcf4f5b68eb89f08a0fe5ecb65d6d9418ca5283ca39
        8d3129cd3b44edf5e3568c953ce2b66a28b473cab0c43918a05c5a4358d13926
        04495d06b395187caa6b36050b436b218485466cb6643eda7ac66aaeea758715
        a22a8849066879cc966da7e0f7e843a1e234920aecf2a4fed2f78c69a6c103a5
        a535d77976b1e40bb0d75d6e370212017734f2b0be9f3f87c5583634ea6a998d
        8fe9ce5e5905f2a6abb9d635425d06731c1227eb634a3603d081cb1a7c2b0c16
        85942efd6f65992dd39aa67cd954fa0310a0f5866ac6121e27e349d5c2adf37a
        672c1dfb021a855000f0c0c29489926b997930b20df641120ef8605cfd9482ee
        a9344918aec689f580a94508f318e63eadc3eb7486b9fcd7a92ba16f5e02cf78
        ef73f528fae3a43d451c58261a82b3735e09d4f4679ce112803505006cbae6ea
        f641a6f66b0c51ee90095735d87ad88c3d19cd7888248fcc3872939605f20597
        6ef6c6aa52f8316e9def841594373fcd177f0e24d8975653a29f738fa8f0d457
        f2d72b7c00a4b7a66fb080f705a8bd599314354e65842af598b8a2a40f6cb320
        8762ac6cd467d06a2e987a7af72e355bea297da87bc9250ebe8d8f85cf292200
        a21d93475ba46be78c17c1605c10b97659859f08f980114955e68361e180c980
        15aa46a776070c4f2b328a903a70ad226742f0022279179fd2530390f190e300
        8f7202c83a6a15866df848c8a150d12287451dec8ee7f04c1c3121e4bba687d7";
    const K_HEX: &str = "5087e3b0c90bf601dd6501e071270eff8683621e9f5d67a7a668e50c4f460a75";

    // 1) 种子展开（keyGen 案例）
    let d: [u8; 32] = hex(D_HEX).try_into().expect("32 bytes");
    let z: [u8; 32] = hex(Z_HEX).try_into().expect("32 bytes");
    let (ek, _dk) = k1024::keypair_from_seed(&d, &z);
    if ek.as_bytes() != hex(EK_KEYGEN_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem1024"));
    }
    // 2) 封装（encapDecap 案例自带 ek）
    let ek2 = k1024::EncapsKey::from_bytes(hex(EK_HEX).as_slice())?;
    let m: [u8; 32] = hex(M_HEX).try_into().expect("32 bytes");
    let (c, ss) = k1024::encapsulate_with_seed(&ek2, &m)?;
    if c.as_bytes() != hex(C_HEX).as_slice() || ss.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem1024"));
    }
    // 3) 解封装（同案例 dk）
    let dk2 = k1024::DecapsKey::from_bytes(hex(DK_HEX).as_slice())?;
    let ss2 = k1024::decapsulate(&dk2, &c);
    if ss2.expose_bytes() != hex(K_HEX).as_slice() {
        return Err(crate::Error::SelfTestFailed("mlkem1024"));
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
    let pk = rsa::VerifyKey::from_spki_der(&hex(RSA_KAT_PUB_SPKI))?;
    pk.verify_pkcs1v15(256, b"sample", &sig)?;
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
        let vk = crate::sign::ecdsa::p256::VerifyKey::from_sec1_point(&q).unwrap();
        println!("verify = {:?}", vk.verify(b"sample", &sig));
    }
}
