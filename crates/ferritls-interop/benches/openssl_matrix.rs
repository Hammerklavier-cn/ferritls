//! 跨后端 × OpenSSL 对照矩阵（原语级，BENCHMARKS.md §8）。
//!
//! 同一批案例上测量 ferritls 三种真实部署配置与 OpenSSL（系统 libcrypto，
//! 经 openssl crate 绑定）的差距：
//!
//! - `ferritls-scalar`：`--no-default-features` 构建（MSRV 可复现路径）；
//! - `ferritls-simd`：默认构建（core::simd 软件路径）；
//! - `ferritls-simd-ni`：默认构建 + 组间安装 AES-NI/CLMUL 与 SHA-NI 后端
//!   （未加速原语仍走 simd 软件路径；SHA-256 派生的 HMAC/HKDF/签名消息
//!   哈希亦走 Ni——故本组全部案例重测，不做「复制 simd」的省略）。
//!
//! 标量与 simd 是编译期 feature，无法同进程共存；simd 与 simd+Ni 用
//! `hash_ni` 式「组间安装桥」同进程先后测（AEAD 实例保持构造时的执行
//! 核心，SHA-256 压缩经注册表分发）。完整矩阵由 `tools/bench_matrix.py`
//! 依次驱动两条腿并聚合出 Markdown 报告；单腿手动运行：
//!
//! ```bash
//! cargo bench -p ferritls-interop --bench openssl_matrix --no-default-features  # 标量 + openssl 锚点
//! cargo bench -p ferritls-interop --bench openssl_matrix                        # simd + simd+Ni + openssl 锚点
//! ```
//!
//! openssl 侧公平性（详见 BENCHMARKS §8）：AES-GCM/ChaCha 走「密钥编排
//! 一次摊销、每记录仅重设 IV」的 CipherCtx 复用形态（与 ferritls 预展开
//! 密钥的 seal/open 路径同构）；CCM 与 HMAC/签名走 one-shot EVP 形态
//! （每次完整构造上下文，对 openssl 偏保守）。每次启动先做跨实现交叉
//! 自检：相同密钥材料下 ferritls 与 openssl 的确定性输出逐字节核对
//! （GCM/CCM/ChaCha/SHA/HMAC/HKDF/RSA-PKCS1v15/Ed25519/X25519），随机
//! nonce 的 ECDSA 与 PSS 做双向互验——自检失败即 panic（基准失效不得
//! 静默，与 perf.rs 同一纪律）。
//!
//! ML-KEM 不在本矩阵：openssl crate（0.10.82）未暴露 encapsulate/
//! decapsulate 绑定（上游 rust-openssl 尚未封装 EVP_PKEY_encapsulate），
//! 无法对称测量，待绑定落地再补。
//!
//! openssl 依赖仅 linux（Cargo.toml target 门控）；非 linux 平台 openssl
//! 组与交叉自检缺席，ferritls 各列照常测量（报告无锚点列）。

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use ferritls_core::ccm::Aes128CcmTls;
use ferritls_core::chacha20poly1305::ChaCha20Poly1305;
use ferritls_core::ecdh::{p256, x25519};
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};
use ferritls_core::hkdf;
use ferritls_core::hmac::HmacSha256;
use ferritls_core::sha2::{Sha256, Sha512};
use ferritls_core::sign;

/// 本地生成的 RSA-2048 测试私钥（PKCS#8 DER，hex）——与 ferritls-core
/// 的 sign 基准同一把钥匙，使两侧逐字节核对成为可能。
const RSA_PKCS8_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100aa5fe49ba0e592f203b1aec89c13de304256dd31c8b9030aaca9d57b4ad77872b2543f041767beda5c61c1ba5892c1995c72ff7840cfab4f700324f034fecbb240f7346c12535b72cd8a29de499df722a921ce2990f5e163fe36c5f025266878afeed8e74fd1d35b3d7f49f66589d07a4d2cd707ee1b69086d9259cb47d6aad8b52b1a72d62c1d713f2bac3f1328d988dc7f3c09799a4d4903d7500b9c76db3df4a8465a89332e39e38cfc87a8636ecfc2159646a93252220885e8124c3d259bdd54b144311dbadf1bef469ae93d08c1acd454947342b8f750d045d8ab82d8d3eaf0c519a87e65112d0f8560ccce5eff9d2069acfd0e482ffcb46a162bf0839d020301000102820100033e903be67478b7e31a1f19f2deedfc3d472a2f28835d6b769e455273ba66b0c874923ea1b3780ef0736c1d0052cb1d0085b017ba243a3ee9032650ecb16d6f978d1d927146e516ea9316f904addd66eb91993b71673d438a33c0d131e3e959630049611e4400a25c29705f20cfdf08752fc5688140445fc4b664bf5a3edc41fc3b99073ec92d0e67e306245529bbac1bf6bbe70540a902f78b2bade7e2920af4279a0a32b3f389aba4b429d07582c6bdcf140fd1d1f2e59afccb2be2d741f11745310cb7823c16eecd816972955120803fadfb92255cac5b2e68a8a7e3a657c1936dd351c69455c904751742666f6b51f9265165e312ffe6c967b11446488102818100d8ae7e446fe069a9d231d5e5640c2a7a37792f050c4f89df01647aea3d7a69ae0b15c9e10eeae4bf1fe19e8027d374260a8108f3067bb4adbaa6e37092bc718a164d42e2939f2359620ec68f5151124a71f0ab07b67ee5ef69c55cdfb3c95ba0d407df404bd419b447d5fc1425f8a4903cdd041a287ad41ca484dd053cdbedab02818100c94a4cd42e6a17f7a47a3dddedde274b6fed7680e86f38d2ebdb3272b0f08f9bc4f2093bc96e64394a912689d608c05ad3ecc8a132c2c69246d0a063c5fc70b745bd84f6d58122c521fdfe9e775aca9b0ce74ea0673d80a08c381230a66e5d524920d0c5c060d5f469b01406312768061093bf4eaf8e593570887a8159e0bbd70281804effdf7d6824b3a17cc73aaaf5bd11c7996e0f5c91ce75ffde6c19fc4909d679e404bfa3d462839fc329e935e44f4deb88acdeec6c12b21f1d0c37a4157bab11a36bebd4dbe98b63cd4281d642d98207ae5f069c3b472ce20af8301247644489f084263b34ea51accefc0f79f11624398a573265af188939202a68c2be1b991d02818100a7c73896bb414f4ce959c2eb92f352c97c37f048ae74d6666895424d7ad268c12bbd9a98ace348c2c036906adf6e57f6dd224670a680d746e1a3cfac9a403a2b6903f92a4cf7e0657459e3bb6e3ccd17c3ffa0f7ee55c33b0ee545b42b655e7fd1d87a6bfa583cbe06c1ef4ee1f5b8ad2570214b92e511d28b4416e86e63f5ed0281806fac5e66bcc2feffb82eee16804e55db90e1c6c01c7019d88a671cef7abbfdc21d34edc555053b793c4ebed6fa4cf819c9f891380b249c8de7c4fc14972b60d71eab74b41458fbcd96e2ee4c085d31dcb074f44c23ac95a339267fa0ff41566aadc5691b8b787cf7860d7e3b87af0ad81463272e90fbea7216934b0ddfea03f0";

/// 对应公钥（SPKI DER，hex）。
const RSA_SPKI_HEX: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa5fe49ba0e592f203b1aec89c13de304256dd31c8b9030aaca9d57b4ad77872b2543f041767beda5c61c1ba5892c1995c72ff7840cfab4f700324f034fecbb240f7346c12535b72cd8a29de499df722a921ce2990f5e163fe36c5f025266878afeed8e74fd1d35b3d7f49f66589d07a4d2cd707ee1b69086d9259cb47d6aad8b52b1a72d62c1d713f2bac3f1328d988dc7f3c09799a4d4903d7500b9c76db3df4a8465a89332e39e38cfc87a8636ecfc2159646a93252220885e8124c3d259bdd54b144311dbadf1bef469ae93d08c1acd454947342b8f750d045d8ab82d8d3eaf0c519a87e65112d0f8560ccce5eff9d2069acfd0e482ffcb46a162bf0839d0203010001";

const SIZES: [usize; 2] = [1350, 16384];
const AAD: [u8; 5] = [0x17, 0x03, 0x03, 0x10, 0x00];
const NONCE: [u8; 12] = [0x42; 12];

/// 确定性伪随机填充（bench 内不调 OS 熵，与 core 各基准同式）。
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect()
}

/// 当前 ferritls 配置的案例前缀：编译期 feature 决定标量/simd 档。
fn backend_label() -> &'static str {
    if cfg!(feature = "simd") {
        "ferritls-simd"
    } else {
        "ferritls-scalar"
    }
}

/// 安装桥之后的第三配置前缀（仅 simd 构建下测量，见模块文档；
/// cfg 与 ferritls_ni_leg 的安装条件一致，标量/非 x86_64 构建不定义）。
#[cfg(all(target_arch = "x86_64", feature = "simd"))]
const NI_LABEL: &str = "ferritls-simd-ni";

// ---------------------------------------------------------------------------
// ferritls 侧矩阵（三种配置共用一份案例定义；标量/simd 为安装前实例，
// simd+Ni 为安装后构造的实例——AEAD 持有构造时执行核心，SHA-256 压缩
// 经注册表现在分发给 Ni 内核）。
// ---------------------------------------------------------------------------

fn ferritls_matrix(c: &mut Criterion, backend: &str) {
    // --- AEAD（案例与 core `aead` 基准一致）---
    let mut aead = c.benchmark_group("matrix-aead");
    let pt = pattern(0x5a, *SIZES.iter().max().unwrap());
    for size in SIZES {
        aead.throughput(Throughput::Bytes(size as u64));
        let pt: &[u8] = &pt[..size];

        let gcm128 = Aes128Gcm::new(&[0x01; 16]);
        let ct128 = gcm128.seal(&NONCE, &AAD, pt);
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/gcm128-seal"), size),
            pt,
            |b, pt| b.iter(|| gcm128.seal(&NONCE, &AAD, pt)),
        );
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/gcm128-open"), size),
            &ct128,
            |b, ct| b.iter(|| gcm128.open(&NONCE, &AAD, ct).expect("tag valid")),
        );

        let gcm256 = Aes256Gcm::new(&[0x02; 32]);
        let ct256 = gcm256.seal(&NONCE, &AAD, pt);
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/gcm256-seal"), size),
            pt,
            |b, pt| b.iter(|| gcm256.seal(&NONCE, &AAD, pt)),
        );
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/gcm256-open"), size),
            &ct256,
            |b, ct| b.iter(|| gcm256.open(&NONCE, &AAD, ct).expect("tag valid")),
        );

        let ccm = Aes128CcmTls::new(&[0x03; 16]);
        let ct_ccm = ccm.seal(&NONCE, &AAD, pt).expect("ccm length ok");
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/ccm128-seal"), size),
            pt,
            |b, pt| b.iter(|| ccm.seal(&NONCE, &AAD, pt).expect("ccm length ok")),
        );
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/ccm128-open"), size),
            &ct_ccm,
            |b, ct| b.iter(|| ccm.open(&NONCE, &AAD, ct).expect("tag valid")),
        );

        let chacha = ChaCha20Poly1305::new(&[0x04; 32]);
        let ct_chacha = chacha.seal(&NONCE, &AAD, pt);
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/chacha20poly1305-seal"), size),
            pt,
            |b, pt| b.iter(|| chacha.seal(&NONCE, &AAD, pt)),
        );
        aead.bench_with_input(
            BenchmarkId::new(format!("{backend}/chacha20poly1305-open"), size),
            &ct_chacha,
            |b, ct| b.iter(|| chacha.open(&NONCE, &AAD, ct).expect("tag valid")),
        );
    }
    aead.finish();

    // --- HASH / MAC / KDF（案例与 core `hash` 基准一致）---
    let mut hash = c.benchmark_group("matrix-hash");
    let data = pattern(0x6b, *SIZES.iter().max().unwrap());
    for size in SIZES {
        hash.throughput(Throughput::Bytes(size as u64));
        let data: &[u8] = &data[..size];
        hash.bench_with_input(
            BenchmarkId::new(format!("{backend}/sha256-stream"), size),
            data,
            |b, d| {
                b.iter(|| {
                    let mut h = Sha256::new();
                    h.update(d);
                    h.finalize()
                })
            },
        );
        hash.bench_with_input(
            BenchmarkId::new(format!("{backend}/sha512-stream"), size),
            data,
            |b, d| {
                b.iter(|| {
                    let mut h = Sha512::new();
                    h.update(d);
                    h.finalize()
                })
            },
        );
    }

    let hmac_key = pattern(0x71, 32);
    let hmac_msg = pattern(0x72, 1350);
    hash.throughput(Throughput::Bytes(hmac_msg.len() as u64));
    hash.bench_function(format!("{backend}/hmac-sha256-1350"), |b| {
        b.iter(|| HmacSha256::one_shot(&hmac_key, &hmac_msg))
    });

    let salt = pattern(0x73, 32);
    let ikm = pattern(0x74, 32);
    hash.bench_function(format!("{backend}/hkdf-sha256-extract"), |b| {
        b.iter(|| hkdf::extract_sha256(&salt, &ikm))
    });
    let prk = hkdf::extract_sha256(&salt, &ikm);
    let info = pattern(0x75, 40);
    let mut okm = [0u8; 64];
    hash.bench_function(format!("{backend}/hkdf-sha256-expand-64"), |b| {
        b.iter(|| hkdf::expand_sha256(&prk, &info, &mut okm).expect("okm length ok"))
    });
    hash.finish();

    // --- ECDH（完整 derive：对端公钥导入/校验 + 盲化标量乘）---
    let mut ecdh = c.benchmark_group("matrix-ecdh");
    ecdh.throughput(Throughput::Elements(1));
    let seed32 = [0x11u8; 32];
    let sk25519 = x25519::SecretKey::from_seed(seed32);
    let pk25519 = sk25519.public_key();
    ecdh.bench_function(format!("{backend}/x25519-dh"), |b| {
        b.iter(|| sk25519.diffie_hellman(&pk25519).expect("shared secret"))
    });

    let sk256 = p256::SecretKey::from_seed(seed32);
    let pk256 = sk256.public_key().expect("p256 public key");
    ecdh.bench_function(format!("{backend}/p256-dh"), |b| {
        b.iter(|| sk256.diffie_hellman(&pk256).expect("shared secret"))
    });
    ecdh.finish();

    // --- 签名（案例与 core `sign` 基准一致；RSA 组调低 sample_size）---
    let mut sg = c.benchmark_group("matrix-sign");
    sg.throughput(Throughput::Elements(1));
    let msg = pattern(0x7d, 64);

    let sk_ec = sign::ecdsa::p256::SigningKey::from_seed([0x22u8; 32]);
    let pub_ec = sk_ec.public_key_sec1().expect("p256 public key");
    let sig_ec = sk_ec.sign(&msg).expect("p256 sign");
    sg.bench_function(format!("{backend}/ecdsa-p256-sign"), |b| {
        b.iter(|| sk_ec.sign(&msg).expect("p256 sign"))
    });
    sg.bench_function(format!("{backend}/ecdsa-p256-verify"), |b| {
        let vk = sign::ecdsa::p256::VerifyKey::from_sec1_point(&pub_ec).expect("p256 key");
        b.iter(|| vk.verify(&msg, &sig_ec).expect("p256 verify"))
    });

    let sk_ed = sign::ed25519::SigningKey::from_seed([0x24u8; 32]);
    let pub_ed = sk_ed.public_key();
    let sig_ed = sk_ed.sign(&msg);
    sg.bench_function(format!("{backend}/ed25519-sign"), |b| {
        b.iter(|| sk_ed.sign(&msg))
    });
    sg.bench_function(format!("{backend}/ed25519-verify"), |b| {
        let vk = sign::ed25519::VerifyKey::from_raw_bytes(&pub_ed).expect("ed25519 key");
        b.iter(|| vk.verify(&msg, &sig_ed).expect("ed25519 verify"))
    });

    sg.sample_size(20);
    let rsa_sk = sign::rsa::SigningKey::from_pkcs8_der(&hex(RSA_PKCS8_HEX)).expect("rsa key");
    let rsa_pk = sign::rsa::VerifyKey::from_spki_der(&hex(RSA_SPKI_HEX)).expect("rsa pubkey");
    let sig15 = rsa_sk.sign_pkcs1v15(256, &msg).expect("rsa pkcs1v15 sign");
    let sig_pss = rsa_sk.sign_pss(256, &msg).expect("rsa pss sign");
    sg.bench_function(format!("{backend}/rsa2048-pkcs1v15-sign"), |b| {
        b.iter(|| rsa_sk.sign_pkcs1v15(256, &msg).expect("rsa pkcs1v15 sign"))
    });
    sg.bench_function(format!("{backend}/rsa2048-pkcs1v15-verify"), |b| {
        b.iter(|| {
            rsa_pk
                .verify_pkcs1v15(256, &msg, &sig15)
                .expect("rsa pkcs1v15 verify")
        })
    });
    sg.bench_function(format!("{backend}/rsa2048-pss-sign"), |b| {
        b.iter(|| rsa_sk.sign_pss(256, &msg).expect("rsa pss sign"))
    });
    sg.bench_function(format!("{backend}/rsa2048-pss-verify"), |b| {
        b.iter(|| {
            rsa_pk
                .verify_pss(256, &msg, &sig_pss)
                .expect("rsa pss verify")
        })
    });
    sg.finish();
}

// ---------------------------------------------------------------------------
// openssl 侧（仅 linux）：矩阵案例 + 跨实现交叉自检 + 版本 banner。
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod openssl_side {
    use super::*;
    use openssl::bn::BigNumContext;
    use openssl::cipher::Cipher as EvpCipher;
    use openssl::cipher_ctx::CipherCtx;
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
    use openssl::hash::{MessageDigest, hash as ossl_hash};
    use openssl::kdf::{HkdfMode, hkdf as ossl_hkdf};
    use openssl::md::Md;
    use openssl::nid::Nid;
    use openssl::pkey::{Id, PKey};
    use openssl::rsa::Padding;
    use openssl::sign::{RsaPssSaltlen, Signer, Verifier};

    pub const LABEL: &str = "openssl";

    pub fn version() -> &'static str {
        openssl::version::version()
    }

    /// AES-GCM / ChaCha20-Poly1305 复用形态：构造时做一次密钥编排
    /// （EVP_EncryptInit/DecryptInit 带 cipher+key），每记录仅重设 IV、
    /// 喂 AAD/数据、收 tag——与 ferritls「预展开密钥实例 + 每记录 seal」
    /// 同构。EVP 的 IV-only 重设会正确重置 GCM/Poly1305 运行态，该前提
    /// 由 `crosscheck` 的连续两记录一致性逐次运行时钉死。
    struct ReusableAead {
        ctx: CipherCtx,
    }

    impl ReusableAead {
        fn new(
            cipher: &'static openssl::cipher::CipherRef,
            key: &[u8],
            nonce: &[u8; 12],
            encrypt: bool,
        ) -> Self {
            let mut ctx = CipherCtx::new().expect("EVP_CIPHER_CTX_new");
            if encrypt {
                ctx.encrypt_init(Some(cipher), Some(key), Some(nonce))
            } else {
                ctx.decrypt_init(Some(cipher), Some(key), Some(nonce))
            }
            .expect("openssl cipher init");
            Self { ctx }
        }

        fn seal_ctx(cipher: &'static openssl::cipher::CipherRef, key: &[u8]) -> Self {
            Self::new(cipher, key, &NONCE, true)
        }

        fn open_ctx(cipher: &'static openssl::cipher::CipherRef, key: &[u8]) -> Self {
            Self::new(cipher, key, &NONCE, false)
        }

        /// 返回 ct‖tag（与 ferritls `seal` 的输出形状一致）。
        fn seal(&mut self, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
            self.ctx
                .encrypt_init(None, None, Some(nonce))
                .expect("iv re-init");
            // AAD：output=None 形态（EVP 对该调用报告的 outlen 语义不含
            // 写出，忽略返回值）。
            let _ = self.ctx.cipher_update(aad, None).expect("aad update");
            let mut out = vec![0u8; pt.len() + 16];
            let n = self
                .ctx
                .cipher_update(pt, Some(&mut out))
                .expect("encrypt update");
            let f = self.ctx.cipher_final(&mut []).expect("encrypt final");
            assert_eq!(f, 0, "stream cipher final must write nothing");
            let mut tag = [0u8; 16];
            self.ctx.tag(&mut tag).expect("get tag");
            out.truncate(n);
            out.extend_from_slice(&tag);
            out
        }

        /// 输入 ct‖tag；tag 校验失败时 panic（基准输入恒为合法密文）。
        fn open(&mut self, nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Vec<u8> {
            let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
            self.ctx
                .decrypt_init(None, None, Some(nonce))
                .expect("iv re-init");
            let _ = self.ctx.cipher_update(aad, None).expect("aad update");
            let mut out = vec![0u8; ct.len()];
            let n = self
                .ctx
                .cipher_update(ct, Some(&mut out))
                .expect("decrypt update");
            self.ctx.set_tag(tag).expect("set tag");
            self.ctx.cipher_final(&mut []).expect("tag valid");
            out.truncate(n);
            out
        }
    }

    /// CCM one-shot：EVP CCM 的严格 ctrl 顺序——「cipher → SET_IVLEN →
    /// SET_TAG → key+iv → SET_DATALEN → AAD → 数据 → final → GET_TAG」。
    ///
    /// 关键陷阱（3.5.9 实测钉死）：**SET_TAG 必须先于 key init**——
    /// provider 的 `setkey` 会把 tag 长度快照进 CCM128 内核上下文；晚于
    /// key init 的 SET_TAG 只改 PROV 层 `m`、内核不变，GET_TAG 按
    /// `len > 内核 m` 静默拒绝（ErrorStack 为空，rc=0）。解密侧的值形式
    /// SET_TAG 同理前置。openssl crate 自带的 `encrypt_aead`/`decrypt_aead`
    /// 把 tag ctrl 放在 key init 之后，对本版 provider 的 CCM M=16 结构性
    /// 不可用，故此处直接走 CipherCtx 复刻正确序列。默认 IV 长度 13，
    /// TLS 的 12 字节 nonce 亦须显式 SET_IVLEN。解密侧 tag 校验在 update
    /// 内完成（`auth_decrypt` 比对），final 只做状态收尾。每次完整上下文，
    /// 与 ferritls `seal/open` 的 one-shot 形态对称。
    fn ccm_seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        let mut ctx = CipherCtx::new().expect("EVP_CIPHER_CTX_new");
        ctx.encrypt_init(Some(EvpCipher::aes_128_ccm()), None, None)
            .expect("ccm cipher init");
        ctx.set_iv_length(nonce.len()).expect("ccm iv len");
        ctx.set_tag_length(16).expect("ccm tag len");
        ctx.encrypt_init(None, Some(key), Some(nonce))
            .expect("ccm key init");
        ctx.set_data_len(pt.len()).expect("ccm data len");
        let _ = ctx.cipher_update(aad, None).expect("ccm aad");
        let mut out = vec![0u8; pt.len() + 16];
        let n = ctx
            .cipher_update(pt, Some(&mut out))
            .expect("ccm encrypt update");
        let f = ctx.cipher_final(&mut out[n..]).expect("ccm final");
        assert_eq!(f, 0, "ccm final must write nothing");
        let mut tag = [0u8; 16];
        ctx.tag(&mut tag).expect("ccm get tag");
        out.truncate(n);
        out.extend_from_slice(&tag);
        out
    }

    fn ccm_open(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Vec<u8> {
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - 16);
        let mut ctx = CipherCtx::new().expect("EVP_CIPHER_CTX_new");
        ctx.decrypt_init(Some(EvpCipher::aes_128_ccm()), None, None)
            .expect("ccm cipher init");
        ctx.set_iv_length(nonce.len()).expect("ccm iv len");
        // 值形式 SET_TAG：置期望 tag 与长度 m（同样必须先于 key init）。
        ctx.set_tag(tag).expect("ccm set tag");
        ctx.decrypt_init(None, Some(key), Some(nonce))
            .expect("ccm key init");
        ctx.set_data_len(ct.len()).expect("ccm data len");
        let _ = ctx.cipher_update(aad, None).expect("ccm aad");
        let mut out = vec![0u8; ct.len()];
        let n = ctx
            .cipher_update(ct, Some(&mut out))
            .expect("ccm decrypt update (tag valid)");
        let f = ctx.cipher_final(&mut []).expect("ccm final");
        assert_eq!(f, 0, "ccm final must write nothing");
        out.truncate(n);
        out
    }

    /// 从 SEC1 未压缩点构造可交给 Deriver/Verifier 的 PKey。
    fn p256_pubkey(
        group: &EcGroup,
        sec1: &[u8],
        bn: &mut BigNumContext,
    ) -> PKey<openssl::pkey::Public> {
        let point = EcPoint::from_bytes(group, sec1, bn).expect("sec1 point");
        let ec = EcKey::from_public_key(group, &point).expect("ec pubkey");
        PKey::from_ec_key(ec).expect("pkey from ec")
    }

    /// 与 ferritls 矩阵完全同名的 openssl 案例（backend 前缀 = "openssl"）。
    pub fn matrix(c: &mut Criterion) {
        let backend = LABEL;

        // --- AEAD ---
        let mut aead = c.benchmark_group("matrix-aead");
        let pt = pattern(0x5a, *SIZES.iter().max().unwrap());
        let k128 = [0x01u8; 16];
        let k256 = [0x02u8; 32];
        let kc = [0x03u8; 16];
        let kch = [0x04u8; 32];
        for size in SIZES {
            aead.throughput(Throughput::Bytes(size as u64));
            let pt: &[u8] = &pt[..size];

            let mut gcm128 = ReusableAead::seal_ctx(EvpCipher::aes_128_gcm(), &k128);
            let ct128 = gcm128.seal(&NONCE, &AAD, pt);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/gcm128-seal"), size),
                pt,
                |b, pt| b.iter(|| gcm128.seal(&NONCE, &AAD, pt)),
            );
            let mut gcm128d = ReusableAead::open_ctx(EvpCipher::aes_128_gcm(), &k128);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/gcm128-open"), size),
                &ct128,
                |b, ct| b.iter(|| gcm128d.open(&NONCE, &AAD, ct)),
            );

            let mut gcm256 = ReusableAead::seal_ctx(EvpCipher::aes_256_gcm(), &k256);
            let ct256 = gcm256.seal(&NONCE, &AAD, pt);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/gcm256-seal"), size),
                pt,
                |b, pt| b.iter(|| gcm256.seal(&NONCE, &AAD, pt)),
            );
            let mut gcm256d = ReusableAead::open_ctx(EvpCipher::aes_256_gcm(), &k256);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/gcm256-open"), size),
                &ct256,
                |b, ct| b.iter(|| gcm256d.open(&NONCE, &AAD, ct)),
            );

            let ct_ccm = ccm_seal(&kc, &NONCE, &AAD, pt);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/ccm128-seal"), size),
                pt,
                |b, pt| b.iter(|| ccm_seal(&kc, &NONCE, &AAD, pt)),
            );
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/ccm128-open"), size),
                &ct_ccm,
                |b, ct| b.iter(|| ccm_open(&kc, &NONCE, &AAD, ct)),
            );

            let mut chacha = ReusableAead::seal_ctx(EvpCipher::chacha20_poly1305(), &kch);
            let ct_chacha = chacha.seal(&NONCE, &AAD, pt);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/chacha20poly1305-seal"), size),
                pt,
                |b, pt| b.iter(|| chacha.seal(&NONCE, &AAD, pt)),
            );
            let mut chachad = ReusableAead::open_ctx(EvpCipher::chacha20_poly1305(), &kch);
            aead.bench_with_input(
                BenchmarkId::new(format!("{backend}/chacha20poly1305-open"), size),
                &ct_chacha,
                |b, ct| b.iter(|| chachad.open(&NONCE, &AAD, ct)),
            );
        }
        aead.finish();

        // --- HASH / MAC / KDF ---
        let mut hash = c.benchmark_group("matrix-hash");
        let data = pattern(0x6b, *SIZES.iter().max().unwrap());
        for size in SIZES {
            hash.throughput(Throughput::Bytes(size as u64));
            let data: &[u8] = &data[..size];
            hash.bench_with_input(
                BenchmarkId::new(format!("{backend}/sha256-stream"), size),
                data,
                |b, d| {
                    b.iter(|| {
                        let digest = ossl_hash(MessageDigest::sha256(), d).expect("sha256");
                        digest.to_vec()
                    })
                },
            );
            hash.bench_with_input(
                BenchmarkId::new(format!("{backend}/sha512-stream"), size),
                data,
                |b, d| {
                    b.iter(|| {
                        let digest = ossl_hash(MessageDigest::sha512(), d).expect("sha512");
                        digest.to_vec()
                    })
                },
            );
        }

        let hmac_key = pattern(0x71, 32);
        let hmac_msg = pattern(0x72, 1350);
        hash.throughput(Throughput::Bytes(hmac_msg.len() as u64));
        hash.bench_function(format!("{backend}/hmac-sha256-1350"), |b| {
            b.iter(|| {
                let pkey = PKey::hmac(&hmac_key).expect("hmac pkey");
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("hmac signer");
                signer.sign_oneshot_to_vec(&hmac_msg).expect("hmac sign")
            })
        });

        let salt = pattern(0x73, 32);
        let ikm = pattern(0x74, 32);
        hash.bench_function(format!("{backend}/hkdf-sha256-extract"), |b| {
            b.iter(|| {
                let mut prk = [0u8; 32];
                ossl_hkdf(
                    Md::sha256(),
                    &ikm,
                    Some(&salt),
                    None,
                    HkdfMode::ExtractOnly,
                    None,
                    &mut prk,
                )
                .expect("hkdf extract");
                prk
            })
        });
        let prk = hkdf::extract_sha256(&salt, &ikm);
        let info = pattern(0x75, 40);
        hash.bench_function(format!("{backend}/hkdf-sha256-expand-64"), |b| {
            b.iter(|| {
                let mut okm = [0u8; 64];
                ossl_hkdf(
                    Md::sha256(),
                    &prk,
                    None,
                    Some(&info),
                    HkdfMode::ExpandOnly,
                    None,
                    &mut okm,
                )
                .expect("hkdf expand");
                okm
            })
        });
        hash.finish();

        // --- ECDH（对端公钥字节 → 共享秘密，与 ferritls diffie_hellman 对称）---
        let mut ecdh = c.benchmark_group("matrix-ecdh");
        ecdh.throughput(Throughput::Elements(1));
        let seed32 = [0x11u8; 32];

        let sk25519 = x25519::SecretKey::from_seed(seed32);
        let pk25519 = sk25519.public_key();
        let priv25519 = PKey::private_key_from_raw_bytes(&seed32, Id::X25519).expect("x25519 priv");
        ecdh.bench_function(format!("{backend}/x25519-dh"), |b| {
            b.iter(|| {
                let peer =
                    PKey::public_key_from_raw_bytes(&pk25519, Id::X25519).expect("x25519 pub");
                let mut deriver = Deriver::new(&priv25519).expect("deriver");
                deriver.set_peer(&peer).expect("set peer");
                deriver.derive_to_vec().expect("derive")
            })
        });

        let sk256 = p256::SecretKey::from_seed(seed32);
        let pk256 = sk256.public_key().expect("p256 public key");
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256 group");
        let mut bn = BigNumContext::new().expect("bn ctx");
        let priv256 = {
            let ec = EcKey::generate(&group).expect("ec keygen");
            PKey::from_ec_key(ec).expect("pkey from ec")
        };
        ecdh.bench_function(format!("{backend}/p256-dh"), |b| {
            b.iter(|| {
                let peer = p256_pubkey(&group, &pk256, &mut bn);
                let mut deriver = Deriver::new(&priv256).expect("deriver");
                deriver.set_peer(&peer).expect("set peer");
                deriver.derive_to_vec().expect("derive")
            })
        });
        ecdh.finish();

        // --- 签名（one-shot 形态：每次完整构造签名/验证上下文）---
        let mut sg = c.benchmark_group("matrix-sign");
        sg.throughput(Throughput::Elements(1));
        let msg = pattern(0x7d, 64);

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256 group");
        let mut bn = BigNumContext::new().expect("bn ctx");
        let ecdsa_priv = {
            let ec = EcKey::generate(&group).expect("ec keygen");
            PKey::from_ec_key(ec).expect("pkey from ec")
        };
        let f_sk_ec = sign::ecdsa::p256::SigningKey::from_seed([0x22u8; 32]);
        let f_pub_ec = f_sk_ec.public_key_sec1().expect("p256 public key");
        let f_sig_ec = f_sk_ec.sign(&msg).expect("p256 sign");
        let f_pub_ec_pkey = p256_pubkey(&group, &f_pub_ec, &mut bn);
        sg.bench_function(format!("{backend}/ecdsa-p256-sign"), |b| {
            b.iter(|| {
                let mut signer =
                    Signer::new(MessageDigest::sha256(), &ecdsa_priv).expect("ecdsa signer");
                signer.sign_oneshot_to_vec(&msg).expect("ecdsa sign")
            })
        });
        sg.bench_function(format!("{backend}/ecdsa-p256-verify"), |b| {
            b.iter(|| {
                let mut verifier =
                    Verifier::new(MessageDigest::sha256(), &f_pub_ec_pkey).expect("ecdsa verifier");
                assert!(
                    verifier
                        .verify_oneshot(&f_sig_ec, &msg)
                        .expect("ecdsa verify")
                );
            })
        });

        let ed_seed = [0x24u8; 32];
        let f_sk_ed = sign::ed25519::SigningKey::from_seed(ed_seed);
        let f_pub_ed = f_sk_ed.public_key();
        let f_sig_ed = f_sk_ed.sign(&msg);
        let ed_priv =
            PKey::private_key_from_raw_bytes(&ed_seed, Id::ED25519).expect("ed25519 priv");
        let ed_pub_pkey =
            PKey::public_key_from_raw_bytes(&f_pub_ed, Id::ED25519).expect("ed25519 pub");
        sg.bench_function(format!("{backend}/ed25519-sign"), |b| {
            b.iter(|| {
                let mut signer = Signer::new_without_digest(&ed_priv).expect("ed25519 signer");
                signer.sign_oneshot_to_vec(&msg).expect("ed25519 sign")
            })
        });
        sg.bench_function(format!("{backend}/ed25519-verify"), |b| {
            b.iter(|| {
                let mut verifier =
                    Verifier::new_without_digest(&ed_pub_pkey).expect("ed25519 verifier");
                assert!(
                    verifier
                        .verify_oneshot(&f_sig_ed, &msg)
                        .expect("ed25519 verify")
                );
            })
        });

        sg.sample_size(20);
        let rsa_priv = PKey::private_key_from_pkcs8(&hex(RSA_PKCS8_HEX)).expect("rsa pkcs8");
        let rsa_pub = PKey::public_key_from_der(&hex(RSA_SPKI_HEX)).expect("rsa spki");
        let f_rsa_sk = sign::rsa::SigningKey::from_pkcs8_der(&hex(RSA_PKCS8_HEX)).expect("rsa key");
        let f_sig15 = f_rsa_sk
            .sign_pkcs1v15(256, &msg)
            .expect("rsa pkcs1v15 sign");
        let f_sig_pss = f_rsa_sk.sign_pss(256, &msg).expect("rsa pss sign");
        sg.bench_function(format!("{backend}/rsa2048-pkcs1v15-sign"), |b| {
            b.iter(|| {
                let mut signer = Signer::new(MessageDigest::sha256(), &rsa_priv).expect("signer");
                signer.set_rsa_padding(Padding::PKCS1).expect("padding");
                signer.sign_oneshot_to_vec(&msg).expect("rsa sign")
            })
        });
        sg.bench_function(format!("{backend}/rsa2048-pkcs1v15-verify"), |b| {
            b.iter(|| {
                let mut verifier =
                    Verifier::new(MessageDigest::sha256(), &rsa_pub).expect("verifier");
                verifier.set_rsa_padding(Padding::PKCS1).expect("padding");
                assert!(verifier.verify_oneshot(&f_sig15, &msg).expect("rsa verify"));
            })
        });
        sg.bench_function(format!("{backend}/rsa2048-pss-sign"), |b| {
            b.iter(|| {
                let mut signer = Signer::new(MessageDigest::sha256(), &rsa_priv).expect("signer");
                signer.set_rsa_padding(Padding::PKCS1_PSS).expect("padding");
                signer
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .expect("saltlen");
                signer.sign_oneshot_to_vec(&msg).expect("rsa sign")
            })
        });
        sg.bench_function(format!("{backend}/rsa2048-pss-verify"), |b| {
            b.iter(|| {
                let mut verifier =
                    Verifier::new(MessageDigest::sha256(), &rsa_pub).expect("verifier");
                verifier
                    .set_rsa_padding(Padding::PKCS1_PSS)
                    .expect("padding");
                verifier
                    .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                    .expect("saltlen");
                assert!(
                    verifier
                        .verify_oneshot(&f_sig_pss, &msg)
                        .expect("rsa verify")
                );
            })
        });
        sg.finish();
    }

    /// 跨实现交叉自检：相同密钥材料下确定性原语逐字节核对，随机 nonce
    /// 原语双向互验。任何失败都意味着基准本身失效（或 EVP 复用形态在
    /// 当前 OpenSSL 版本上行为异常）——panic 而非静默。
    pub fn crosscheck() {
        let pt = pattern(0x5a, 1350);

        // GCM128 复用形态：逐字节一致 + 连续两记录重置正确 + 换明文第三记录。
        let f = Aes128Gcm::new(&[0x01; 16]);
        let want = f.seal(&NONCE, &AAD, &pt);
        let mut o = ReusableAead::seal_ctx(EvpCipher::aes_128_gcm(), &[0x01; 16]);
        let got1 = o.seal(&NONCE, &AAD, &pt);
        assert_eq!(got1, want, "openssl gcm128 seal ≠ ferritls");
        assert_eq!(
            o.seal(&NONCE, &AAD, &pt),
            got1,
            "openssl gcm128 复用形态未正确重置（第二记录被状态污染）"
        );
        let pt2 = pattern(0x5b, 500);
        let want2 = f.seal(&NONCE, &AAD, &pt2);
        assert_eq!(o.seal(&NONCE, &AAD, &pt2), want2, "openssl gcm128 第三记录");
        let mut od = ReusableAead::open_ctx(EvpCipher::aes_128_gcm(), &[0x01; 16]);
        assert_eq!(
            od.open(&NONCE, &AAD, &want),
            pt,
            "openssl gcm128 open ≠ 明文"
        );
        assert_eq!(
            od.open(&NONCE, &AAD, &want2),
            pt2,
            "openssl gcm128 open 复用第二记录"
        );

        // GCM256 复用形态。
        let f256 = Aes256Gcm::new(&[0x02; 32]);
        let want256 = f256.seal(&NONCE, &AAD, &pt);
        let mut o256 = ReusableAead::seal_ctx(EvpCipher::aes_256_gcm(), &[0x02; 32]);
        assert_eq!(
            o256.seal(&NONCE, &AAD, &pt),
            want256,
            "openssl gcm256 seal ≠ ferritls"
        );
        assert_eq!(
            o256.seal(&NONCE, &AAD, &pt),
            want256,
            "openssl gcm256 复用形态未正确重置"
        );
        let mut o256d = ReusableAead::open_ctx(EvpCipher::aes_256_gcm(), &[0x02; 32]);
        assert_eq!(
            o256d.open(&NONCE, &AAD, &want256),
            pt,
            "openssl gcm256 open ≠ 明文"
        );

        // ChaCha20-Poly1305 复用形态。
        let fc = ChaCha20Poly1305::new(&[0x04; 32]);
        let wantc = fc.seal(&NONCE, &AAD, &pt);
        let mut oc = ReusableAead::seal_ctx(EvpCipher::chacha20_poly1305(), &[0x04; 32]);
        assert_eq!(
            oc.seal(&NONCE, &AAD, &pt),
            wantc,
            "openssl chacha seal ≠ ferritls"
        );
        assert_eq!(
            oc.seal(&NONCE, &AAD, &pt),
            wantc,
            "openssl chacha 复用形态未正确重置"
        );
        let mut ocd = ReusableAead::open_ctx(EvpCipher::chacha20_poly1305(), &[0x04; 32]);
        assert_eq!(
            ocd.open(&NONCE, &AAD, &wantc),
            pt,
            "openssl chacha open ≠ 明文"
        );

        // CCM one-shot。
        let fccm = Aes128CcmTls::new(&[0x03; 16]);
        let wantccm = fccm.seal(&NONCE, &AAD, &pt).expect("ccm seal");
        let gotccm = ccm_seal(&[0x03; 16], &NONCE, &AAD, &pt);
        assert_eq!(gotccm, wantccm, "openssl ccm seal ≠ ferritls");
        assert_eq!(
            ccm_open(&[0x03; 16], &NONCE, &AAD, &wantccm),
            pt,
            "openssl ccm open ≠ 明文"
        );

        // SHA-256 / SHA-512 / HMAC / HKDF。
        let d256 = ossl_hash(MessageDigest::sha256(), &pt).expect("sha256");
        assert_eq!(&d256[..], &Sha256::one_shot(&pt)[..], "sha256 digest");
        let d512 = ossl_hash(MessageDigest::sha512(), &pt).expect("sha512");
        assert_eq!(&d512[..], &Sha512::one_shot(&pt)[..], "sha512 digest");

        let hmac_key = pattern(0x71, 32);
        let hmac_msg = pattern(0x72, 1350);
        let otag = {
            let pkey = PKey::hmac(&hmac_key).expect("hmac pkey");
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("hmac signer");
            signer.sign_oneshot_to_vec(&hmac_msg).expect("hmac sign")
        };
        assert_eq!(
            &otag[..],
            &HmacSha256::one_shot(&hmac_key, &hmac_msg)[..],
            "hmac tag"
        );

        let salt = pattern(0x73, 32);
        let ikm = pattern(0x74, 32);
        let mut o_prk = [0u8; 32];
        ossl_hkdf(
            Md::sha256(),
            &ikm,
            Some(&salt),
            None,
            HkdfMode::ExtractOnly,
            None,
            &mut o_prk,
        )
        .expect("hkdf extract");
        let f_prk = hkdf::extract_sha256(&salt, &ikm);
        assert_eq!(&o_prk[..], &f_prk[..], "hkdf prk");
        let info = pattern(0x75, 40);
        let mut o_okm = [0u8; 64];
        ossl_hkdf(
            Md::sha256(),
            &f_prk,
            None,
            Some(&info),
            HkdfMode::ExpandOnly,
            None,
            &mut o_okm,
        )
        .expect("hkdf expand");
        let mut f_okm = [0u8; 64];
        hkdf::expand_sha256(&f_prk, &info, &mut f_okm).expect("okm length ok");
        assert_eq!(&o_okm[..], &f_okm[..], "hkdf okm");

        // X25519：同一对 (seed, pub) 的共享秘密逐字节一致。
        let seed32 = [0x11u8; 32];
        let f_sk = x25519::SecretKey::from_seed(seed32);
        let f_pk = f_sk.public_key();
        let f_ss = f_sk.diffie_hellman(&f_pk).expect("x25519 dh");
        let o_priv = PKey::private_key_from_raw_bytes(&seed32, Id::X25519).expect("x25519 priv");
        let o_pub = PKey::public_key_from_raw_bytes(&f_pk, Id::X25519).expect("x25519 pub");
        let o_ss = {
            let mut deriver = Deriver::new(&o_priv).expect("deriver");
            deriver.set_peer(&o_pub).expect("set peer");
            deriver.derive_to_vec().expect("derive")
        };
        assert_eq!(o_ss.as_slice(), f_ss.as_bytes(), "x25519 共享秘密");

        // ECDSA P-256：随机 nonce，双向互验。
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("p256 group");
        let mut bn = BigNumContext::new().expect("bn ctx");
        let msg = pattern(0x7d, 64);
        let f_sk_ec = sign::ecdsa::p256::SigningKey::from_seed([0x22u8; 32]);
        let f_pub_ec = f_sk_ec.public_key_sec1().expect("p256 public key");
        let f_sig_ec = f_sk_ec.sign(&msg).expect("p256 sign");
        let f_pub_ec_pkey = p256_pubkey(&group, &f_pub_ec, &mut bn);
        let o_ec_priv = {
            let ec = EcKey::generate(&group).expect("ec keygen");
            PKey::from_ec_key(ec).expect("pkey from ec")
        };
        let o_sig = {
            let mut signer =
                Signer::new(MessageDigest::sha256(), &o_ec_priv).expect("ecdsa signer");
            signer.sign_oneshot_to_vec(&msg).expect("ecdsa sign")
        };
        let o_pub_sec1 = o_ec_priv
            .ec_key()
            .expect("ec key")
            .public_key()
            .to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut bn)
            .expect("pub to_bytes");
        let o_verified = {
            let mut verifier =
                Verifier::new(MessageDigest::sha256(), &f_pub_ec_pkey).expect("verifier");
            verifier.verify_oneshot(&f_sig_ec, &msg).expect("verify")
        };
        assert!(o_verified, "openssl 拒绝 ferritls 的 ECDSA 签名");
        let f_vk = sign::ecdsa::p256::VerifyKey::from_sec1_point(&o_pub_sec1).expect("p256 key");
        f_vk.verify(&msg, &o_sig)
            .expect("ferritls 拒绝 openssl 的 ECDSA 签名");

        // Ed25519：确定性，逐字节一致 + 互验。
        let ed_seed = [0x24u8; 32];
        let f_sk_ed = sign::ed25519::SigningKey::from_seed(ed_seed);
        let f_pub_ed = f_sk_ed.public_key();
        let f_sig_ed = f_sk_ed.sign(&msg);
        let o_ed_priv =
            PKey::private_key_from_raw_bytes(&ed_seed, Id::ED25519).expect("ed25519 priv");
        let o_sig_ed = {
            let mut signer = Signer::new_without_digest(&o_ed_priv).expect("ed25519 signer");
            signer.sign_oneshot_to_vec(&msg).expect("ed25519 sign")
        };
        assert_eq!(o_sig_ed, f_sig_ed, "openssl ed25519 签名 ≠ ferritls");
        let o_ed_pub_pkey =
            PKey::public_key_from_raw_bytes(&f_pub_ed, Id::ED25519).expect("ed25519 pub");
        let o_ed_ok = {
            let mut verifier =
                Verifier::new_without_digest(&o_ed_pub_pkey).expect("ed25519 verifier");
            verifier.verify_oneshot(&f_sig_ed, &msg).expect("verify")
        };
        assert!(o_ed_ok, "openssl 拒绝 ferritls 的 ed25519 签名");
        sign::ed25519::VerifyKey::from_raw_bytes(&f_pub_ed)
            .expect("ed25519 key")
            .verify(&msg, &o_sig_ed)
            .expect("ferritls 拒绝 openssl 的 ed25519 签名");

        // RSA-2048：PKCS1v15 确定性逐字节；PSS 双向互验。
        let f_rsa_sk = sign::rsa::SigningKey::from_pkcs8_der(&hex(RSA_PKCS8_HEX)).expect("rsa key");
        let f_rsa_pk = sign::rsa::VerifyKey::from_spki_der(&hex(RSA_SPKI_HEX)).expect("rsa pubkey");
        let f_sig15 = f_rsa_sk.sign_pkcs1v15(256, &msg).expect("rsa sign");
        let o_rsa_priv = PKey::private_key_from_pkcs8(&hex(RSA_PKCS8_HEX)).expect("rsa pkcs8");
        let o_rsa_pub = PKey::public_key_from_der(&hex(RSA_SPKI_HEX)).expect("rsa spki");
        let o_sig15 = {
            let mut signer = Signer::new(MessageDigest::sha256(), &o_rsa_priv).expect("signer");
            signer.set_rsa_padding(Padding::PKCS1).expect("padding");
            signer.sign_oneshot_to_vec(&msg).expect("rsa sign")
        };
        assert_eq!(o_sig15, f_sig15, "openssl rsa pkcs1v15 签名 ≠ ferritls");
        let f_sig_pss = f_rsa_sk.sign_pss(256, &msg).expect("rsa pss sign");
        let o_pss_ok = {
            let mut verifier =
                Verifier::new(MessageDigest::sha256(), &o_rsa_pub).expect("verifier");
            verifier
                .set_rsa_padding(Padding::PKCS1_PSS)
                .expect("padding");
            verifier
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .expect("saltlen");
            verifier.verify_oneshot(&f_sig_pss, &msg).expect("verify")
        };
        assert!(o_pss_ok, "openssl 拒绝 ferritls 的 rsa pss 签名");
        let o_sig_pss = {
            let mut signer = Signer::new(MessageDigest::sha256(), &o_rsa_priv).expect("signer");
            signer.set_rsa_padding(Padding::PKCS1_PSS).expect("padding");
            signer
                .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
                .expect("saltlen");
            signer.sign_oneshot_to_vec(&msg).expect("rsa sign")
        };
        f_rsa_pk
            .verify_pss(256, &msg, &o_sig_pss)
            .expect("ferritls 拒绝 openssl 的 rsa pss 签名");

        eprintln!("openssl crosscheck: all green");
    }
}

// ---------------------------------------------------------------------------
// 腿结构：banner → ferritls(标量/simd) → openssl(仅 linux，先交叉自检)
// → 安装桥(x86_64) → ferritls(simd+Ni)。
// ---------------------------------------------------------------------------

fn banner(_c: &mut Criterion) {
    eprintln!(
        "FERRITLS_MATRIX_META simd={} arch={}",
        cfg!(feature = "simd"),
        std::env::consts::ARCH
    );
    #[cfg(target_os = "linux")]
    eprintln!("FERRITLS_MATRIX_META openssl={:?}", openssl_side::version());
}

fn ferritls_soft_leg(c: &mut Criterion) {
    ferritls_matrix(c, backend_label());
}

#[cfg(target_os = "linux")]
fn openssl_leg(c: &mut Criterion) {
    openssl_side::crosscheck();
    openssl_side::matrix(c);
}

#[cfg(not(target_os = "linux"))]
fn openssl_leg(_c: &mut Criterion) {
    eprintln!("openssl unavailable on this platform; matrix has no openssl column");
}

/// 组间安装桥：AEAD 与 SHA 各自独立安装（CPU 可能只支持其一）。
/// simd+Ni 配置仅在 simd 构建下测量（scalar+Ni 不是被测的三配置之一）。
fn install_bridge(_c: &mut Criterion) {
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        let mut installed = false;
        match ferritls_backend_x86_64::install() {
            Ok(()) => {
                eprintln!("FERRITLS_MATRIX_META ni_aead=installed");
                installed = true;
            }
            Err(e) => eprintln!("FERRITLS_MATRIX_META ni_aead=unavailable({e:?})"),
        }
        match ferritls_backend_x86_64::install_hash() {
            Ok(()) => {
                eprintln!("FERRITLS_MATRIX_META ni_hash=installed");
                installed = true;
            }
            Err(e) => eprintln!("FERRITLS_MATRIX_META ni_hash=unavailable({e:?})"),
        }
        if !installed {
            eprintln!("no NI backend installed; simd-ni group will skip");
        }
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
    eprintln!("simd-ni leg not applicable (non-x86_64 or scalar build); skipping");
}

fn ferritls_ni_leg(c: &mut Criterion) {
    // 仅 simd 构建（与 install_bridge 的安装条件一致）；安装失败时
    // ops 注册表仍为空 → 跳过，避免把 simd 数字误标成 simd-ni。
    #[cfg(all(target_arch = "x86_64", feature = "simd"))]
    {
        if ferritls_core::ops::installed_aead().is_none()
            && ferritls_core::ops::installed_hash().is_none()
        {
            eprintln!("ni backends not installed; skipping simd-ni group");
            return;
        }
        ferritls_matrix(c, NI_LABEL);
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "simd")))]
    let _ = c;
}

criterion_group!(
    benches,
    banner,
    ferritls_soft_leg,
    openssl_leg,
    install_bridge,
    ferritls_ni_leg
);
criterion_main!(benches);
