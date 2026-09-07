//! TLS 1.3 密码套件装配（M6）。
//!
//! HKDF 复用 rustls 内建 [`rustls::crypto::tls13::HkdfUsingHmac`]，包装
//! 本 crate 实现的 [`rustls::crypto::hmac::Hmac`]（不在边界内重写密钥
//! 调度）；AEAD 为 ferritls-core 的 GCM/CCM/ChaCha20-Poly1305 适配。
//!
//! 注意：`quic` 字段为 `None` = 本套件不参与 QUIC 握手（QUIC packet
//! protection 是 M8+ 项）。

use rustls::crypto::CipherSuiteCommon;
use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce, PrefixedPayload, Tls13AeadAlgorithm, UnsupportedOperationError, make_tls13_aad,
};
use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use rustls::crypto::hmac::{self, Hmac, Key};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::{
    ConnectionTrafficSecrets, ContentType, Error, ProtocolVersion, SupportedCipherSuite,
    Tls13CipherSuite,
};

use ferritls_core::chacha20poly1305::ChaCha20Poly1305;
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

use ferritls_core::ccm::Aes128CcmTls;

/// 套件清单（顺序即偏好）。同时被 `tests/api.rs` 断言，防止清单与
/// 文档漂移。
pub const TLS13_SUITE_NAMES: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
];

// ---------------------------------------------------------------------------
// Hash 适配（SHA-256 / SHA-384）
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Sha256Hash;

struct Sha256Ctx(ferritls_core::sha2::Sha256);

impl Context for Sha256Ctx {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Hash for Sha256Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Ctx(ferritls_core::sha2::Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&ferritls_core::sha2::Sha256::one_shot(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

#[derive(Debug)]
struct Sha384Hash;

struct Sha384Ctx(ferritls_core::sha2::Sha384);

impl Context for Sha384Ctx {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Hash for Sha384Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha384Ctx(ferritls_core::sha2::Sha384::new()))
    }

    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&ferritls_core::sha2::Sha384::one_shot(data))
    }

    fn output_len(&self) -> usize {
        48
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

pub(crate) static SHA256_HASH: &dyn Hash = &Sha256Hash;
pub(crate) static SHA384_HASH: &dyn Hash = &Sha384Hash;

// ---------------------------------------------------------------------------
// Hmac 适配（rustls::crypto::hmac；供 HkdfUsingHmac 复用）
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct HmacSha256Impl;

#[derive(Debug)]
struct HmacSha256Key(Vec<u8>);

impl Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut buf = Vec::with_capacity(first.len() + 16 * middle.len() + last.len());
        buf.extend_from_slice(first);
        for m in middle {
            buf.extend_from_slice(m);
        }
        buf.extend_from_slice(last);
        hmac::Tag::new(&ferritls_core::hmac::HmacSha256::one_shot(&self.0, &buf))
    }

    fn tag_len(&self) -> usize {
        32
    }
}

impl Hmac for HmacSha256Impl {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha256Key(key.to_vec()))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

#[derive(Debug)]
struct HmacSha384Impl;

#[derive(Debug)]
struct HmacSha384Key(Vec<u8>);

impl Key for HmacSha384Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        let mut buf = Vec::with_capacity(first.len() + 16 * middle.len() + last.len());
        buf.extend_from_slice(first);
        for m in middle {
            buf.extend_from_slice(m);
        }
        buf.extend_from_slice(last);
        hmac::Tag::new(&ferritls_core::hmac::HmacSha384::one_shot(&self.0, &buf))
    }

    fn tag_len(&self) -> usize {
        48
    }
}

impl Hmac for HmacSha384Impl {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        Box::new(HmacSha384Key(key.to_vec()))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

static HMAC_SHA256_IMPL: HmacSha256Impl = HmacSha256Impl;
static HMAC_SHA384_IMPL: HmacSha384Impl = HmacSha384Impl;
static HKDF_USING_HMAC_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256_IMPL);
static HKDF_USING_HMAC_SHA384: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA384_IMPL);

pub(crate) static HKDF_SHA256_PROVIDER: &dyn rustls::crypto::tls13::Hkdf = &HKDF_USING_HMAC_SHA256;
pub(crate) static HKDF_SHA384_PROVIDER: &dyn rustls::crypto::tls13::Hkdf = &HKDF_USING_HMAC_SHA384;

// ---------------------------------------------------------------------------
// AEAD 适配：GCM
// ---------------------------------------------------------------------------

const TAG_LEN: usize = 16;

/// 从 `AeadKey` 提取定长密钥字节。
fn key_bytes<const N: usize>(key: &AeadKey) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(key.as_ref());
    out
}

/// GCM 实例（按密钥长度选择 AES-128/256）。
enum GcmInstance {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl GcmInstance {
    fn seal(&self, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            GcmInstance::Aes128(g) => g.seal(&nonce.0, aad, plaintext),
            GcmInstance::Aes256(g) => g.seal(&nonce.0, aad, plaintext),
        }
    }

    fn open(&self, nonce: &Nonce, aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            GcmInstance::Aes128(g) => g.open(&nonce.0, aad, ct_tag),
            GcmInstance::Aes256(g) => g.open(&nonce.0, aad, ct_tag),
        }
        .map_err(|_| Error::DecryptError)
    }
}

fn gcm_of<const N: usize>(key: &AeadKey) -> GcmInstance {
    if N == 32 {
        GcmInstance::Aes256(Aes256Gcm::new(&key_bytes::<32>(key)))
    } else {
        GcmInstance::Aes128(Aes128Gcm::new(&key_bytes::<16>(key)))
    }
}

struct GcmEncrypter<const N: usize> {
    gcm: GcmInstance,
    iv: Iv,
    _n: std::marker::PhantomData<[u8; N]>,
}

struct GcmDecrypter<const N: usize> {
    gcm: GcmInstance,
    iv: Iv,
    _n: std::marker::PhantomData<[u8; N]>,
}

impl<const N: usize> GcmEncrypter<N> {
    fn seal(&self, nonce: &Nonce, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        self.gcm.seal(nonce, aad, plaintext)
    }
}

impl<const N: usize> GcmDecrypter<N> {
    fn open(&self, nonce: &Nonce, aad: &[u8], ct_tag: &[u8]) -> Result<Vec<u8>, Error> {
        self.gcm.open(nonce, aad, ct_tag)
    }
}

impl<const N: usize> MessageEncrypter for GcmEncrypter<N> {
    fn encrypt(
        &mut self,
        msg: rustls::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<rustls::crypto::cipher::OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        let mut plain = msg.payload.to_vec();
        plain.push(msg.typ.to_array()[0]);
        let sealed = self.seal(&nonce, &aad, &plain);

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&sealed);
        Ok(rustls::crypto::cipher::OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // RFC 8446 §5.1：TLS 1.3 应用数据记录沿用 legacy 版本 0x0303
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl<const N: usize> MessageDecrypter for GcmDecrypter<N> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN + 1 {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain = self
            .open(&nonce, &aad, payload)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = plain.len();
        payload[..plain_len].copy_from_slice(&plain);
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

macro_rules! gcm_aead {
    ($name:ident, $key_len:expr, $secret:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name;

        impl Tls13AeadAlgorithm for $name {
            fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
                Box::new(GcmEncrypter::<$key_len> {
                    gcm: gcm_of::<$key_len>(&key),
                    iv,
                    _n: std::marker::PhantomData,
                })
            }

            fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
                Box::new(GcmDecrypter::<$key_len> {
                    gcm: gcm_of::<$key_len>(&key),
                    iv,
                    _n: std::marker::PhantomData,
                })
            }

            fn key_len(&self) -> usize {
                $key_len
            }

            fn extract_keys(
                &self,
                key: AeadKey,
                iv: Iv,
            ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
                Ok(ConnectionTrafficSecrets::$secret { key, iv })
            }
        }
    };
}

gcm_aead!(Gcm128Aead, 16, Aes128Gcm, "AES-128-GCM AEAD 适配（批准）。");
gcm_aead!(Gcm256Aead, 32, Aes256Gcm, "AES-256-GCM AEAD 适配（批准）。");

// ---------------------------------------------------------------------------
// AEAD 适配：ChaCha20-Poly1305（非批准，仅默认模式）
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Chacha20Poly1305Aead;

struct ChachaEncrypter {
    aead: ChaCha20Poly1305,
    iv: Iv,
}

struct ChachaDecrypter {
    aead: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for ChachaEncrypter {
    fn encrypt(
        &mut self,
        msg: rustls::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<rustls::crypto::cipher::OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        let mut plain = msg.payload.to_vec();
        plain.push(msg.typ.to_array()[0]);
        let sealed = self.aead.seal(&nonce.0, &aad, &plain);

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&sealed);
        Ok(rustls::crypto::cipher::OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for ChachaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN + 1 {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain = self
            .aead
            .open(&nonce.0, &aad, payload)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = plain.len();
        payload[..plain_len].copy_from_slice(&plain);
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(ChachaEncrypter {
            aead: ChaCha20Poly1305::new(&key_bytes::<32>(&key)),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(ChachaDecrypter {
            aead: ChaCha20Poly1305::new(&key_bytes::<32>(&key)),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

// ---------------------------------------------------------------------------
// AEAD 适配：AES-128-CCM（TLS 1.3 参数集，nonce 12 / L=3）
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Ccm128Aead;

struct CcmEncrypter {
    ccm: Aes128CcmTls,
    iv: Iv,
}

struct CcmDecrypter {
    ccm: Aes128CcmTls,
    iv: Iv,
}

impl MessageEncrypter for CcmEncrypter {
    fn encrypt(
        &mut self,
        msg: rustls::crypto::cipher::OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<rustls::crypto::cipher::OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        let mut plain = msg.payload.to_vec();
        plain.push(msg.typ.to_array()[0]);
        let sealed = self.ccm.seal(&nonce.0, &aad, &plain);

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&sealed);
        Ok(rustls::crypto::cipher::OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

impl MessageDecrypter for CcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < TAG_LEN + 1 {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload.len());
        let plain = self
            .ccm
            .open(&nonce.0, &aad, payload)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = plain.len();
        payload[..plain_len].copy_from_slice(&plain);
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

impl Tls13AeadAlgorithm for Ccm128Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(CcmEncrypter {
            ccm: Aes128CcmTls::new(&key_bytes::<16>(&key)),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(CcmDecrypter {
            ccm: Aes128CcmTls::new(&key_bytes::<16>(&key)),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // ConnectionTrafficSecrets 无 CCM 变体：导出 traffic secrets（key
        // exporter / key log）对 CCM 套件不可用——与 AGENTS.md §4 记载一致
        Err(UnsupportedOperationError)
    }
}

// ---------------------------------------------------------------------------
// 套件静态表与装配
// ---------------------------------------------------------------------------

static GCM128_AEAD: Gcm128Aead = Gcm128Aead;
static GCM256_AEAD: Gcm256Aead = Gcm256Aead;
static CHACHA_AEAD: Chacha20Poly1305Aead = Chacha20Poly1305Aead;
static CCM128_AEAD: Ccm128Aead = Ccm128Aead;

static TLS13_AES_128_GCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: SHA256_HASH,
        // draft-irtf-aead-limits-08 §5.1.1（与 rustls ring provider 一致）
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: HKDF_SHA256_PROVIDER,
    aead_alg: &GCM128_AEAD,
    quic: None,
};

static TLS13_AES_256_GCM_SHA384: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: SHA384_HASH,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: HKDF_SHA384_PROVIDER,
    aead_alg: &GCM256_AEAD,
    quic: None,
};

static TLS13_CHACHA20_POLY1305_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: SHA256_HASH,
        // draft-irtf-aead-limits-08 §5.2.1
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: HKDF_SHA256_PROVIDER,
    aead_alg: &CHACHA_AEAD,
    quic: None,
};

static TLS13_AES_128_CCM_SHA256: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: rustls::CipherSuite::TLS13_AES_128_CCM_SHA256,
        hash_provider: SHA256_HASH,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: HKDF_SHA256_PROVIDER,
    aead_alg: &CCM128_AEAD,
    quic: None,
};

/// `TLS_AES_128_GCM_SHA256`（批准）。
pub fn tls13_aes_128_gcm_sha256() -> SupportedCipherSuite {
    SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256)
}

/// `TLS_AES_256_GCM_SHA384`（批准）。
pub fn tls13_aes_256_gcm_sha384() -> SupportedCipherSuite {
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384)
}

/// `TLS_CHACHA20_POLY1305_SHA256`（非批准，仅默认模式）。
pub fn tls13_chacha20_poly1305_sha256() -> SupportedCipherSuite {
    SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256)
}

/// `TLS_AES_128_CCM_SHA256`（批准，SP 800-52r2 面向受限环境）。
pub fn tls13_aes_128_ccm_sha256() -> SupportedCipherSuite {
    SupportedCipherSuite::Tls13(&TLS13_AES_128_CCM_SHA256)
}

/// 默认模式全部套件（偏好序）。
pub fn all_tls13_suites() -> Vec<SupportedCipherSuite> {
    vec![
        tls13_aes_128_gcm_sha256(),
        tls13_aes_256_gcm_sha384(),
        tls13_chacha20_poly1305_sha256(),
        tls13_aes_128_ccm_sha256(),
    ]
}

/// 批准模式套件（无 ChaCha20-Poly1305）。
pub fn fips_tls13_suites() -> Vec<SupportedCipherSuite> {
    vec![
        tls13_aes_128_gcm_sha256(),
        tls13_aes_256_gcm_sha384(),
        tls13_aes_128_ccm_sha256(),
    ]
}
