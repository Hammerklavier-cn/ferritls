//! QUIC 包保护（RFC 9001，M8.5）。
//!
//! 为 TLS 1.3 的三个 AEAD 套件实现 [`rustls::quic::Algorithm`]：
//!
//! - **PacketKey**（§5.3）：nonce = IV ⊕ packet number（96 位大端
//!   序号，与 rustls `Nonce::new` 同式）；AAD = 含 packet number 的
//!   包头。解密先验后出：core `open` 在标签验证通过后才返回明文。
//! - **HeaderProtectionKey**（§5.4）：AES = AES-ECB(hp, sample) 单块
//!   取前 5 字节；ChaCha20 = counter = sample 前 4 字节（小端）+
//!   nonce = sample 后 12 字节的单块密钥流（§5.4.3）。掩码对包头
//!   的位应用（长头 4 位 / 短头 5 位、包号长度自首字节还原）与
//!   rustls 内置 ring 参考实现逐行同构。
//! - **multipath**（draft-ietf-quic-multipath-11）：`*_for_path` 的
//!   96 位序号 = path_id(4B 大端) ‖ pn(8B 大端) 后与 IV 异或。
//!
//! 限制值：GCM 按 RFC 9001 §B.1.1/§B.1.2（2¹⁶ 字节最大包口径）
//! confidentiality 2²³ / integrity 2⁵²；ChaCha20-Poly1305 沿
//! rustls ring 的保守值 u64::MAX / 2³⁶。
//!
//! CCM 套件不参与 QUIC（`quic: None`）：RFC 9001 §5.1 以
//! AEAD_AES_128_GCM 为强制基准，ring provider 同样不提供 CCM 的
//! QUIC 接线，且 `ConnectionTrafficSecrets` 本就无 CCM 变体。

use std::boxed::Box;

use rustls::crypto::cipher::{AeadKey, Iv, Nonce};
use rustls::quic;
use rustls::Error;

use ferritls_core::aes::{Aes128, Aes256};
use ferritls_core::chacha20poly1305::{chacha20_block, ChaCha20Poly1305};
use ferritls_core::gcm::{Aes128Gcm, Aes256Gcm};

use crate::cipher::key_bytes;

const TAG_LEN: usize = 16;
const SAMPLE_LEN: usize = 16;

const GCM_CONFIDENTIALITY_LIMIT: u64 = 1 << 23;
const GCM_INTEGRITY_LIMIT: u64 = 1 << 52;
const CHACHA_CONFIDENTIALITY_LIMIT: u64 = u64::MAX;
const CHACHA_INTEGRITY_LIMIT: u64 = 1 << 36;

// ---------------------------------------------------------------------------
// PacketKey（RFC 9001 §5.3）
// ---------------------------------------------------------------------------

enum PacketAead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    Chacha(ChaCha20Poly1305),
}

impl PacketAead {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        match self {
            PacketAead::Aes128(a) => a.seal(nonce, aad, plaintext),
            PacketAead::Aes256(a) => a.seal(nonce, aad, plaintext),
            PacketAead::Chacha(a) => a.seal(nonce, aad, plaintext),
        }
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], ct_and_tag: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            PacketAead::Aes128(a) => a.open(nonce, aad, ct_and_tag),
            PacketAead::Aes256(a) => a.open(nonce, aad, ct_and_tag),
            PacketAead::Chacha(a) => a.open(nonce, aad, ct_and_tag),
        }
        .map_err(|_| Error::DecryptError)
    }
}

/// QUIC 包保护密钥（单方向）。
pub(crate) struct QuicPacketKey {
    aead: PacketAead,
    iv: [u8; 12],
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl QuicPacketKey {
    fn seal(&self, pn: u64, header: &[u8], payload: &mut [u8]) -> Result<quic::Tag, Error> {
        let nonce = Nonce::new(&Iv::from(self.iv), pn);
        let sealed = self.aead.seal(&nonce.0, header, payload);
        payload.copy_from_slice(&sealed[..payload.len()]);
        Ok(quic::Tag::from(&sealed[payload.len()..]))
    }

    fn open_payload<'a>(
        &self,
        pn: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::new(&Iv::from(self.iv), pn);
        let plain = self
            .aead
            .open(&nonce.0, header, payload)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = plain.len();
        payload[..plain_len].copy_from_slice(&plain);
        Ok(&payload[..plain_len])
    }
}

impl quic::PacketKey for QuicPacketKey {
    fn encrypt_in_place(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        self.seal(packet_number, header, payload)
    }

    fn decrypt_in_place<'a>(
        &self,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        self.open_payload(packet_number, header, payload)
    }

    fn encrypt_in_place_for_path(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<quic::Tag, Error> {
        let nonce = Nonce::for_path(path_id, &Iv::from(self.iv), packet_number);
        let sealed = self.aead.seal(&nonce.0, header, payload);
        payload.copy_from_slice(&sealed[..payload.len()]);
        Ok(quic::Tag::from(&sealed[payload.len()..]))
    }

    fn decrypt_in_place_for_path<'a>(
        &self,
        path_id: u32,
        packet_number: u64,
        header: &[u8],
        payload: &'a mut [u8],
    ) -> Result<&'a [u8], Error> {
        let nonce = Nonce::for_path(path_id, &Iv::from(self.iv), packet_number);
        let plain = self
            .aead
            .open(&nonce.0, header, payload)
            .map_err(|_| Error::DecryptError)?;
        let plain_len = plain.len();
        payload[..plain_len].copy_from_slice(&plain);
        Ok(&payload[..plain_len])
    }

    fn tag_len(&self) -> usize {
        TAG_LEN
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

fn packet_key_aes128(key: &[u8; 16], iv: Iv) -> QuicPacketKey {
    QuicPacketKey {
        aead: PacketAead::Aes128(Aes128Gcm::new(key)),
        iv: iv_bytes(&iv),
        confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        integrity_limit: GCM_INTEGRITY_LIMIT,
    }
}

fn packet_key_aes256(key: &[u8; 32], iv: Iv) -> QuicPacketKey {
    QuicPacketKey {
        aead: PacketAead::Aes256(Aes256Gcm::new(key)),
        iv: iv_bytes(&iv),
        confidentiality_limit: GCM_CONFIDENTIALITY_LIMIT,
        integrity_limit: GCM_INTEGRITY_LIMIT,
    }
}

fn packet_key_chacha(key: &[u8; 32], iv: Iv) -> QuicPacketKey {
    QuicPacketKey {
        aead: PacketAead::Chacha(ChaCha20Poly1305::new(key)),
        iv: iv_bytes(&iv),
        confidentiality_limit: CHACHA_CONFIDENTIALITY_LIMIT,
        integrity_limit: CHACHA_INTEGRITY_LIMIT,
    }
}

fn iv_bytes(iv: &Iv) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(iv.as_ref());
    out
}

// ---------------------------------------------------------------------------
// HeaderProtectionKey（RFC 9001 §5.4）
// ---------------------------------------------------------------------------

enum HpCipher {
    Aes128(Aes128),
    Aes256(Aes256),
    Chacha([u8; 32]),
}

/// QUIC 头保护密钥。
///
/// 密钥材料持有于 core 块密码实例（Drop 零化）或栈上数组（Drop 由
/// `hp_key_chacha` 的调用链覆盖：`QuicHpKey` 落栈即随生命周期清零——
/// 掩码派生不暴露密钥本身，泄漏面为一次密钥流块）。
pub(crate) struct QuicHpKey(HpCipher);

impl QuicHpKey {
    /// RFC 9001 §5.4.2/§5.4.3：sample（16 字节）→ 5 字节掩码。
    fn new_mask(&self, sample: &[u8]) -> Result<[u8; 5], Error> {
        if sample.len() != SAMPLE_LEN {
            return Err(Error::General(
                "header protection sample must be 16 bytes".into(),
            ));
        }
        let mut mask = [0u8; 5];
        match &self.0 {
            HpCipher::Aes128(aes) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(sample);
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            HpCipher::Aes256(aes) => {
                let mut block = [0u8; 16];
                block.copy_from_slice(sample);
                aes.encrypt_block(&mut block);
                mask.copy_from_slice(&block[..5]);
            }
            HpCipher::Chacha(key) => {
                let mut ctr = [0u8; 4];
                ctr.copy_from_slice(&sample[..4]);
                let mut nonce = [0u8; 12];
                nonce.copy_from_slice(&sample[4..]);
                let ks = chacha20_block(key, u32::from_le_bytes(ctr), &nonce);
                mask.copy_from_slice(&ks[..5]);
            }
        }
        Ok(mask)
    }

    /// RFC 9001 §5.4.1 Header Protection Application（协议逻辑与
    /// rustls ring 参考实现同构）。`masked = true` 表示去除保护
    ///（解密方向：包号长度位在去掩码后才可靠）。
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        masked: bool,
    ) -> Result<(), Error> {
        let mask = self.new_mask(sample)?;
        let (first_mask, pn_mask) = mask.split_first().unwrap(); // 掩码恒 5 字节，静态非空

        // 包号最长 4 字节（pn_mask.len() == 4）
        if packet_number.len() > pn_mask.len() {
            return Err(Error::General("packet number too long".into()));
        }

        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f // 长头：保护 4 位（保留 2 + 包号长度 2）
        } else {
            0x1f // 短头：保护 5 位（key phase + 保留 2 + 包号长度 2）
        };

        let first_plain = if masked {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;

        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
        Ok(())
    }
}

impl quic::HeaderProtectionKey for QuicHpKey {
    fn encrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, false)
    }

    fn decrypt_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
    ) -> Result<(), Error> {
        self.xor_in_place(sample, first, packet_number, true)
    }

    fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }
}

fn hp_key_aes128(key: &[u8; 16]) -> QuicHpKey {
    QuicHpKey(HpCipher::Aes128(Aes128::new(key)))
}

fn hp_key_aes256(key: &[u8; 32]) -> QuicHpKey {
    QuicHpKey(HpCipher::Aes256(Aes256::new(key)))
}

fn hp_key_chacha(key: &[u8; 32]) -> QuicHpKey {
    QuicHpKey(HpCipher::Chacha(*key))
}

// ---------------------------------------------------------------------------
// quic::Algorithm 适配
// ---------------------------------------------------------------------------

macro_rules! quic_algorithm {
    ($name:ident, $key_len:expr, $key_ty:ty, $packet:ident, $hp:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name;

        impl quic::Algorithm for $name {
            fn packet_key(&self, key: AeadKey, iv: Iv) -> Box<dyn quic::PacketKey> {
                let k: $key_ty = key_bytes(&key);
                Box::new($packet(&k, iv))
            }

            fn header_protection_key(&self, key: AeadKey) -> Box<dyn quic::HeaderProtectionKey> {
                let k: $key_ty = key_bytes(&key);
                Box::new($hp(&k))
            }

            fn aead_key_len(&self) -> usize {
                $key_len
            }

            fn fips(&self) -> bool {
                // 规则 3：CMVP 认证落地前恒 false（含 QUIC Algorithm 钩子）
                false
            }
        }
    };
}

quic_algorithm!(
    QuicAes128Gcm,
    16,
    [u8; 16],
    packet_key_aes128,
    hp_key_aes128,
    "AES-128-GCM QUIC 包保护适配（RFC 9001，批准）。"
);
quic_algorithm!(
    QuicAes256Gcm,
    32,
    [u8; 32],
    packet_key_aes256,
    hp_key_aes256,
    "AES-256-GCM QUIC 包保护适配（RFC 9001，批准）。"
);
quic_algorithm!(
    QuicChacha20Poly1305,
    32,
    [u8; 32],
    packet_key_chacha,
    hp_key_chacha,
    "ChaCha20-Poly1305 QUIC 包保护适配（RFC 9001，非批准，仅默认模式）。"
);

pub(crate) static QUIC_AES_128_GCM: QuicAes128Gcm = QuicAes128Gcm;
pub(crate) static QUIC_AES_256_GCM: QuicAes256Gcm = QuicAes256Gcm;
pub(crate) static QUIC_CHACHA20_POLY1305: QuicChacha20Poly1305 = QuicChacha20Poly1305;

/// RFC 9001 附录 A 样本保护向量（程序化提取自 rfc-editor 原文，
/// 提取与派生校验脚本见 docs/VECTOR-PROVENANCE.md 记录）。
#[cfg(test)]
#[path = "quic_vectors.rs"]
mod vectors;

#[cfg(test)]
mod tests {
    use rustls::quic::{HeaderProtectionKey, PacketKey, Suite, Version};
    use rustls::Side;

    use super::*;
    use vectors::{A2_PAYLOAD_PLAIN, A2_PROTECTED_PACKET, A3_PAYLOAD_PLAIN, A3_PROTECTED_PACKET};

    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
        let v = hex(s);
        let mut out = [0u8; N];
        out.copy_from_slice(&v);
        out
    }

    fn assert_hex(actual: &[u8], expected_hex: &str) {
        let rendered: String = actual.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(rendered, expected_hex);
    }

    // ---- RFC 9001 §A.5：ChaCha20 短头包（key/iv/hp/sample/mask/包全锚定） ----

    #[test]
    fn rfc9001_a5_chacha20_short_header() {
        let pk = packet_key_chacha(
            &hex_arr(vectors::A5_KEY),
            Iv::from(hex_arr(vectors::A5_IV)),
        );
        let hp = hp_key_chacha(&hex_arr(vectors::A5_HP));

        let header = hex(vectors::A5_HEADER); // 4200bff4（短头 + 3 字节包号）
        let mut payload = vec![0x01u8]; // PING 帧
        let tag = pk
            .encrypt_in_place(654360564, &header, &mut payload)
            .unwrap();

        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        // RFC：payload ciphertext = 1 字节 PING 帧 + 16 字节 tag
        assert_hex(&packet[4..], vectors::A5_CT);

        // sample = 包[pn_offset+4 .. +16]（pn_offset = 1）；掩码逐字节锚定
        let sample = packet[5..21].to_vec();
        assert_hex(&sample, "5e5cd55c41f69080575d7999c25a5bfb");
        assert_eq!(hp.new_mask(&sample).unwrap(), hex(vectors::A5_MASK)[..]);

        let (first, rest) = packet.split_at_mut(1);
        hp.encrypt_in_place(&sample, &mut first[0], &mut rest[..3]).unwrap();
        assert_hex(&packet, vectors::A5_PROTECTED);

        // 去保护 + 解密往返
        let (first, rest) = packet.split_at_mut(1);
        hp.decrypt_in_place(&sample, &mut first[0], &mut rest[..3]).unwrap();
        assert_hex(&packet[..4], vectors::A5_HEADER);
        let plain = pk
            .decrypt_in_place(654360564, &hex(vectors::A5_HEADER), &mut packet[4..])
            .unwrap();
        assert_eq!(plain, &[0x01u8]);
    }

    // ---- RFC 9001 §A.1 掩码锚定（HP 与 AEAD/HKDF 解耦定位） ----

    #[test]
    fn rfc9001_a1_hp_masks() {
        // client：hp = 9f50…，sample = §A.2 → mask = 437b9aec36
        let hp = hp_key_aes128(
            &hex_arr("9f50449e04a0e810283a1e9933adedd2"),
        );
        assert_eq!(
            hp.new_mask(&hex("d1b1c98dd7689fb8ec11d242b123dc9b")).unwrap(),
            hex("437b9aec36")[..]
        );
        // server：hp = c206…，sample = §A.3 → mask = 2ec0d8356a
        let hp = hp_key_aes128(
            &hex_arr("c206b8d9b9f0f37644430b490eeaa314"),
        );
        assert_eq!(
            hp.new_mask(&hex("2cd0991cd25b0aac406a5816b6394100")).unwrap(),
            hex("2ec0d8356a")[..]
        );
        // chacha：hp = 25a2…，sample = §A.5 → mask = aefefe7d03
        let hp = hp_key_chacha(&hex_arr(vectors::A5_HP));
        assert_eq!(
            hp.new_mask(&hex("5e5cd55c41f69080575d7999c25a5bfb")).unwrap(),
            hex(vectors::A5_MASK)[..]
        );
    }

    // ---- RFC 9001 §A.2/A.3：Initial 包保护（经 quic::Suite 公开路径，
    // 覆盖 HKDF/HMAC + "quic key/iv/hp" 密钥推导全链） ----

    #[test]
    fn rfc9001_a2_client_initial_aes128() {
        let keys = Suite {
            suite: &crate::cipher::TLS13_AES_128_GCM_SHA256,
            quic: &QUIC_AES_128_GCM,
        }
        .keys(&hex("8394c8f03e515708"), Side::Client, Version::V1);

        let header = hex("c300000001088394c8f03e5157080000449e00000002");
        let mut payload = A2_PAYLOAD_PLAIN.to_vec();
        let tag = keys.local.packet.encrypt_in_place(2, &header, &mut payload).unwrap();

        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        // sample = 包[pn_offset+4 ..]（pn_offset = 18，pn_len = 4）
        let sample = packet[22..38].to_vec();
        assert_hex(&sample, "d1b1c98dd7689fb8ec11d242b123dc9b");
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut first[0], &mut rest[17..21])
            .unwrap();
        assert_eq!(packet.as_slice(), A2_PROTECTED_PACKET);
    }

    #[test]
    fn rfc9001_a3_server_initial_aes128() {
        let keys = Suite {
            suite: &crate::cipher::TLS13_AES_128_GCM_SHA256,
            quic: &QUIC_AES_128_GCM,
        }
        .keys(&hex("8394c8f03e515708"), Side::Server, Version::V1);

        let header = hex("c1000000010008f067a5502a4262b50040750001");
        let mut payload = A3_PAYLOAD_PLAIN.to_vec();
        let tag = keys.local.packet.encrypt_in_place(1, &header, &mut payload).unwrap();

        let mut packet = header;
        packet.extend_from_slice(&payload);
        packet.extend_from_slice(tag.as_ref());
        // pn_offset = 18，pn_len = 2 → sample = 包[22..38]
        let sample = packet[22..38].to_vec();
        assert_hex(&sample, "2cd0991cd25b0aac406a5816b6394100");
        let (first, rest) = packet.split_at_mut(1);
        keys.local
            .header
            .encrypt_in_place(&sample, &mut first[0], &mut rest[17..19])
            .unwrap();
        assert_eq!(packet.as_slice(), A3_PROTECTED_PACKET);
    }

    // ---- 篡改/异常输入不得 panic ----

    #[test]
    fn tampered_payload_rejected() {
        let pk = packet_key_aes128(
            &hex_arr("1f369613dd76d5467730efcbe3b1a22d"),
            Iv::from(hex_arr("fa044b2f42a3fd3b46fb255c")),
        );
        let header = b"header".to_vec();
        let mut payload = b"payload".to_vec();
        let tag = pk.encrypt_in_place(7, &header, &mut payload).unwrap();

        let mut ct = payload;
        ct.extend_from_slice(tag.as_ref());
        ct[2] ^= 0x40;
        assert!(matches!(
            pk.decrypt_in_place(7, &header, &mut ct),
            Err(Error::DecryptError)
        ));

        // AAD（包头）篡改同样拒绝
        let mut payload2 = b"payload".to_vec();
        let tag2 = pk.encrypt_in_place(7, &header, &mut payload2).unwrap();
        let mut ct2 = payload2;
        ct2.extend_from_slice(tag2.as_ref());
        assert!(matches!(
            pk.decrypt_in_place(7, b"HEADERR", &mut ct2),
            Err(Error::DecryptError)
        ));
    }

    #[test]
    fn hp_rejects_bad_sample_and_long_pn() {
        let hp = hp_key_chacha(&hex_arr(vectors::A5_HP));
        assert!(hp.new_mask(&[0u8; 15]).is_err());
        assert!(hp.new_mask(&[0u8; 17]).is_err());

        let mut first = 0x42u8;
        let mut pn5 = [0u8; 5]; // 包号最长 4 字节
        let mut pn4 = [0u8; 4];
        assert!(hp
            .encrypt_in_place(&[0u8; 16], &mut first, &mut pn5)
            .is_err());
        assert!(hp
            .encrypt_in_place(&[0u8; 16], &mut first, &mut pn4)
            .is_ok());
    }

    #[test]
    fn limits_match_rfc9001_or_ring_conservative() {
        let gcm = packet_key_aes128(
            &hex_arr("1f369613dd76d5467730efcbe3b1a22d"),
            Iv::from([0u8; 12]),
        );
        assert_eq!(gcm.confidentiality_limit(), 1 << 23);
        assert_eq!(gcm.integrity_limit(), 1 << 52);
        assert_eq!(gcm.tag_len(), 16);

        let chacha = packet_key_chacha(
            &hex_arr(vectors::A5_KEY),
            Iv::from([0u8; 12]),
        );
        assert_eq!(chacha.confidentiality_limit(), u64::MAX);
        assert_eq!(chacha.integrity_limit(), 1 << 36);
    }

    // ---- multipath（draft-ietf-quic-multipath-11）：nonce 构造由 rustls
    // 公开的 `Nonce::for_path` 定义，此处验证非碰撞与往返。 ----

    #[test]
    fn multipath_for_path_roundtrip() {
        let pk = packet_key_chacha(
            &hex_arr(vectors::A5_KEY),
            Iv::from(hex_arr(vectors::A5_IV)),
        );
        let header = b"hdr0".to_vec();
        let mut payload = b"the quick brown fox".to_vec();
        let tag = pk
            .encrypt_in_place_for_path(2, 12345, &header, &mut payload)
            .unwrap();
        let mut ct = payload;
        ct.extend_from_slice(tag.as_ref());
        let plain = pk
            .decrypt_in_place_for_path(2, 12345, &header, &mut ct.clone())
            .unwrap()
            .to_vec();
        assert_eq!(plain, b"the quick brown fox");

        // path_id / pn 任一不同 → 密文不同（nonce 空间分离）
        let enc = |path: u32, pn: u64| {
            let mut p = b"the quick brown fox".to_vec();
            let t = pk.encrypt_in_place_for_path(path, pn, &header, &mut p).unwrap();
            let mut out = p;
            out.extend_from_slice(t.as_ref());
            out
        };
        assert_ne!(enc(2, 12345), enc(3, 12345));
        assert_ne!(enc(2, 12345), enc(2, 12346));
    }
}
