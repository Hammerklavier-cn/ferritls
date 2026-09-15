//! 最小内存 QUIC 传输（M8.5）：仅包头编解码 + 包保护（HP/AEAD），
//! 足以驱动 rustls `quic::Connection` 的完整 TLS 1.3 握手。
//!
//! 真实 QUIC 传输栈（流/可靠性/拥塞/重传）不在测试范围；本 harness
//! 的价值在于让 provider 的 `quic::Algorithm` 经受真实协议时序——
//! Initial/Handshake/1-RTT 密钥切换（`write_hs` 的 KeyChange 语义与
//! quinn-proto `write_crypto` 一致：buf 按切换前层级保护）、HP 样本
//! 取位、包头位运算——并与 rustls-ring 交叉互操作。
//!
//! CID 建模：客户端初始 DCID（8 B，初始密钥推导输入）+ 空 SCID；
//! 服务端 SCID 固定 8 B；服务端在首个 Initial 包中按其 DCID 推导
//! 初始密钥（RFC 9001 §5.2）。

#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::quic::{self, ClientConnection, Connection, KeyChange, ServerConnection, Version};
use rustls::{CipherSuite, ClientConfig, ServerConfig, Side};

pub const QUIC_VERSION: Version = Version::V1;

/// 服务端 SCID（harness 内固定；仅需非空且两侧一致路由）。
const SERVER_SCID: [u8; 8] = [0x71, 0x40, 0x2d, 0x51, 0x0e, 0x8a, 0x3b, 0xc2];

/// 从 provider 取 AES-128-GCM 套件作为 Initial 包保护套件
/// （RFC 9001 §5.2 强制基准；跨 provider 时各用各的实现）。
pub fn provider_initial_suite(provider: &CryptoProvider) -> Option<quic::Suite> {
    let t13 = provider
        .cipher_suites
        .iter()
        .find(|s| s.suite() == CipherSuite::TLS13_AES_128_GCM_SHA256)?
        .tls13()
        .expect("aes128gcm is tls13");
    Some(quic::Suite {
        suite: t13,
        quic: t13.quic.expect("aes128gcm must support QUIC"),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Initial = 0,
    Handshake = 1,
    OneRtt = 2,
}

fn idx(level: Level) -> usize {
    level as usize
}

struct LevelKeys {
    local: Option<quic::DirectionalKeys>,
    remote: Option<quic::DirectionalKeys>,
}

impl LevelKeys {
    const NONE: LevelKeys = LevelKeys {
        local: None,
        remote: None,
    };
}

/// 一个受保护 QUIC 包（跨 harness 传输的完整 wire 形态）。
pub struct Packet {
    level: Level,
    /// 包头 DCID（客户端 Initial 包 = 客户端初始 DCID）
    dcid: Vec<u8>,
    scid: Vec<u8>,
    /// 包号字段在 raw 中的偏移
    pn_offset: usize,
    /// 完整包：HP 保护的包头 + 密文 + tag
    raw: Vec<u8>,
}

/// 内存 QUIC 端点（rustls TLS 状态 + 三级包保护密钥）。
pub struct Endpoint {
    conn: Connection,
    initial_suite: quic::Suite,
    levels: [LevelKeys; 3],
    tx: Level,
    /// 本端源 CID（客户端 SCID = 空；服务端 = SERVER_SCID）
    my_cid: Vec<u8>,
    /// 对端 CID（包头 DCID 的取值）
    peer_cid: Vec<u8>,
    pn: u64,
    next_secrets: Option<quic::Secrets>,
}

impl Endpoint {
    pub fn new_client(
        config: Arc<ClientConfig>,
        initial_suite: quic::Suite,
        dcid: [u8; 8],
        params: Vec<u8>,
    ) -> Result<Self, rustls::Error> {
        let conn = ClientConnection::new(
            config,
            QUIC_VERSION,
            ServerName::try_from("localhost".to_string()).expect("server name"),
            params,
        )?;
        let keys = quic::Keys::initial(
            QUIC_VERSION,
            initial_suite.suite,
            initial_suite.quic,
            &dcid,
            Side::Client,
        );
        Ok(Self {
            conn: conn.into(),
            initial_suite,
            levels: [
                LevelKeys {
                    local: Some(keys.local),
                    remote: Some(keys.remote),
                },
                LevelKeys::NONE,
                LevelKeys::NONE,
            ],
            tx: Level::Initial,
            my_cid: Vec::new(),
            peer_cid: dcid.to_vec(),
            pn: 0,
            next_secrets: None,
        })
    }

    pub fn new_server(
        config: Arc<ServerConfig>,
        initial_suite: quic::Suite,
        params: Vec<u8>,
    ) -> Result<Self, rustls::Error> {
        let conn = ServerConnection::new(config, QUIC_VERSION, params)?;
        // 服务端初始密钥在收到首个 Initial 包时按其 DCID 推导（handle）
        Ok(Self {
            conn: conn.into(),
            initial_suite,
            levels: [LevelKeys::NONE, LevelKeys::NONE, LevelKeys::NONE],
            tx: Level::Initial,
            my_cid: SERVER_SCID.to_vec(),
            peer_cid: Vec::new(),
            pn: 0,
            next_secrets: None,
        })
    }

    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    pub fn is_handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// 1-RTT 密钥更新（RFC 9001 §6）：两侧各调一次，HP 密钥不变。
    pub fn update_1rtt_keys(&mut self) {
        let set = self
            .next_secrets
            .as_mut()
            .expect("1-RTT secrets")
            .next_packet_keys();
        let keys = self.levels[idx(Level::OneRtt)]
            .local
            .as_mut()
            .expect("1rtt");
        keys.packet = set.local;
        let keys = self.levels[idx(Level::OneRtt)]
            .remote
            .as_mut()
            .expect("1rtt");
        keys.packet = set.remote;
    }

    /// 发送一个 1-RTT 应用数据包（不经 TLS 层；验证包保护本身）。
    pub fn seal_1rtt_data(&mut self, payload: &[u8]) -> Packet {
        self.protect(Level::OneRtt, payload.to_vec())
    }

    /// 解开对端 1-RTT 数据包（不喂 TLS 层）。
    pub fn open_1rtt_data(&mut self, pkt: Packet) -> Result<Vec<u8>, rustls::Error> {
        let keys = self.levels[idx(pkt.level)]
            .remote
            .as_ref()
            .expect("rx keys");
        self.unprotect(&pkt, keys).map(|(plain, _)| plain)
    }

    /// 排空 TLS 层待发数据为受保护包（时序照 quinn-proto write_crypto：
    /// buf 按 KeyChange 之前的层级保护）。
    pub fn flush(&mut self, out: &mut VecDeque<Packet>) -> Result<(), rustls::Error> {
        loop {
            let space = self.tx;
            let mut buf = Vec::new();
            let kc = self.conn.write_hs(&mut buf);
            if !buf.is_empty() {
                out.push_back(self.protect(space, buf));
            }
            match kc {
                Some(KeyChange::Handshake { keys }) => {
                    self.levels[idx(Level::Handshake)] = LevelKeys {
                        local: Some(keys.local),
                        remote: Some(keys.remote),
                    };
                    self.tx = Level::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    self.levels[idx(Level::OneRtt)] = LevelKeys {
                        local: Some(keys.local),
                        remote: Some(keys.remote),
                    };
                    self.tx = Level::OneRtt;
                    self.next_secrets = Some(next);
                }
                None => break,
            }
        }
        Ok(())
    }

    /// 解开对端包并把明文喂给 TLS 层。
    pub fn handle(&mut self, pkt: Packet) -> Result<(), rustls::Error> {
        // 服务端首个 Initial：按包头 DCID 推导初始密钥（RFC 9001 §5.2）
        if pkt.level == Level::Initial && self.levels[0].remote.is_none() {
            let keys = quic::Keys::initial(
                QUIC_VERSION,
                self.initial_suite.suite,
                self.initial_suite.quic,
                &pkt.dcid,
                Side::Server,
            );
            self.levels[0] = LevelKeys {
                local: Some(keys.local),
                remote: Some(keys.remote),
            };
        }
        let keys = self.levels[idx(pkt.level)]
            .remote
            .as_ref()
            .expect("rx keys");
        let (plain, scid) = self.unprotect(&pkt, keys)?;
        if pkt.level != Level::OneRtt {
            self.peer_cid = scid;
        }
        self.conn.read_hs(&plain)
    }

    fn protect(&mut self, level: Level, payload: Vec<u8>) -> Packet {
        let keys = self.levels[idx(level)].local.as_ref().expect("tx keys");
        let pn = self.pn;
        self.pn += 1;
        let header = self.build_header(level, pn, payload.len());
        let pn_offset = header.len() - 4;
        let mut buf = payload;
        let tag = keys
            .packet
            .encrypt_in_place(pn, &header, &mut buf)
            .expect("seal");
        let mut raw = header;
        raw.extend_from_slice(&buf);
        raw.extend_from_slice(tag.as_ref());
        // RFC 9001 §5.4.2：sample = 包[pn_offset+4 .. +16]
        let sample = raw[pn_offset + 4..pn_offset + 20].to_vec();
        let (first, rest) = raw.split_at_mut(1);
        keys.header
            .encrypt_in_place(
                &sample,
                &mut first[0],
                &mut rest[pn_offset - 1..pn_offset + 3],
            )
            .expect("hp");
        Packet {
            level,
            dcid: self.peer_cid.clone(),
            scid: self.my_cid.clone(),
            pn_offset,
            raw,
        }
    }

    fn build_header(&self, level: Level, pn: u64, payload_len: usize) -> Vec<u8> {
        const PN_LEN: u64 = 4;
        // 长度 varint（2 字节形态，覆盖包号 + 载荷 + tag）
        let len = PN_LEN + payload_len as u64 + 16;
        assert!(len <= 0x3fff, "harness length varint overflow");
        let mut h = Vec::new();
        match level {
            Level::Initial | Level::Handshake => {
                let type_bits = match level {
                    Level::Initial => 0x00u8,
                    _ => 0x20u8, // Handshake = type 2
                };
                // 长头：0x80 + 固定位 0x40 + type<<4；末 2 位 = pn_len-1
                h.push(0xc0 | type_bits | (PN_LEN - 1) as u8);
                h.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
                h.push(self.peer_cid.len() as u8);
                h.extend_from_slice(&self.peer_cid);
                h.push(self.my_cid.len() as u8);
                h.extend_from_slice(&self.my_cid);
                if level == Level::Initial {
                    h.push(0x00); // token 长度 = 0（无 Retry）
                }
                h.extend_from_slice(&[0x40 | (len >> 8) as u8, len as u8]);
                h.extend_from_slice(&pn.to_be_bytes());
            }
            Level::OneRtt => {
                // 短头：固定位 + pn_len
                h.push(0x40 | (PN_LEN - 1) as u8);
                h.extend_from_slice(&self.peer_cid);
                h.extend_from_slice(&pn.to_be_bytes());
            }
        }
        h
    }

    /// HP 去保护 + 包号解析 + AEAD 解密。返回（明文, 对端 SCID）。
    fn unprotect(
        &self,
        pkt: &Packet,
        keys: &quic::DirectionalKeys,
    ) -> Result<(Vec<u8>, Vec<u8>), rustls::Error> {
        let mut raw = pkt.raw.clone();
        let pn_offset = pkt.pn_offset;
        let sample = raw[pn_offset + 4..pn_offset + 20].to_vec();
        let (first, rest) = raw.split_at_mut(1);
        keys.header.decrypt_in_place(
            &sample,
            &mut first[0],
            &mut rest[pn_offset - 1..pn_offset + 3],
        )?;
        let pn_len = (first[0] & 0x03) as usize + 1;
        let mut b = [0u8; 4];
        b.copy_from_slice(&raw[pn_offset..pn_offset + 4]);
        let pn = u32::from_be_bytes(b) as u64;
        // AAD = 去保护后的完整包头（含包号字段）
        let aad_end = pn_offset + pn_len;
        let header = raw[..aad_end].to_vec();
        let plain = keys
            .packet
            .decrypt_in_place(pn, &header, &mut raw[aad_end..])?
            .to_vec();
        Ok((plain, pkt.scid.clone()))
    }
}

/// 驱动两侧直至握手完成。
///
/// 逐包投递且每包投递后立即 flush 接收端：KeyChange 只在本端
/// `write_hs` 时被消费安装，若整批投递会在对端升级密钥前送抵
/// 下一层级的包（quinn 按数据报内 CRYPTO 顺序同样如此交错）。
/// 双向连续一轮无包即收敛；上限防挂死。
pub fn drive(client: &mut Endpoint, server: &mut Endpoint) -> Result<(), rustls::Error> {
    let mut c2s: VecDeque<Packet> = VecDeque::new();
    let mut s2c: VecDeque<Packet> = VecDeque::new();
    client.flush(&mut c2s)?;
    for _ in 0..200 {
        let mut progressed = false;
        if let Some(p) = c2s.pop_front() {
            server.handle(p)?;
            server.flush(&mut s2c)?;
            progressed = true;
        }
        if let Some(p) = s2c.pop_front() {
            client.handle(p)?;
            client.flush(&mut c2s)?;
            progressed = true;
        }
        if !progressed && c2s.is_empty() && s2c.is_empty() {
            return Ok(());
        }
    }
    panic!("QUIC handshake did not converge in 200 rounds");
}

const TEST_PARAMS: &[u8] = b"ferritls-quic-interop-params";
const TEST_ALPN: &[u8] = b"ftls-quic/1";

/// 构建一对内存 QUIC 端点并完成握手 + 后置断言（协商套件、ALPN、
/// transport parameters、export_keying_material 双侧一致、1-RTT
/// 数据包双向往返）。
pub fn quic_handshake(
    client_provider: CryptoProvider,
    server_provider: CryptoProvider,
    expect_suite: rustls::CipherSuite,
) {
    let client_initial =
        provider_initial_suite(&client_provider).expect("client provider has aes128gcm");
    let server_initial =
        provider_initial_suite(&server_provider).expect("server provider has aes128gcm");

    let mut client_cfg = crate::common::client_config(client_provider);
    client_cfg.alpn_protocols = vec![TEST_ALPN.to_vec()];
    let mut server_cfg = crate::common::server_config(server_provider).expect("server config");
    server_cfg.alpn_protocols = vec![TEST_ALPN.to_vec()];

    let mut client = Endpoint::new_client(
        Arc::new(client_cfg),
        client_initial,
        // RFC 9001 §A.2 的示例 DCID
        [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08],
        TEST_PARAMS.to_vec(),
    )
    .expect("client conn");
    let mut server =
        Endpoint::new_server(Arc::new(server_cfg), server_initial, TEST_PARAMS.to_vec())
            .expect("server conn");

    drive(&mut client, &mut server).expect("drive");

    assert!(!client.is_handshaking(), "client handshake complete");
    assert!(!server.is_handshaking(), "server handshake complete");

    // 协商套件一致
    let negotiated = client
        .conn()
        .negotiated_cipher_suite()
        .expect("client suite");
    assert_eq!(negotiated.suite(), expect_suite);

    // transport parameters 双侧可见
    assert_eq!(
        client.conn().quic_transport_parameters(),
        Some(TEST_PARAMS),
        "client sees server params"
    );
    assert_eq!(
        server.conn().quic_transport_parameters(),
        Some(TEST_PARAMS),
        "server sees client params"
    );

    // ALPN 协商一致
    assert_eq!(client.conn().alpn_protocol(), Some(TEST_ALPN));
    assert_eq!(server.conn().alpn_protocol(), Some(TEST_ALPN));

    // export_keying_material：同一 label/context 双侧导出一致
    let mut c = [0u8; 32];
    let mut s = [0u8; 32];
    client
        .conn()
        .export_keying_material(&mut c, b"EXPORTER ftls quic", Some(b"ctx"))
        .expect("client export");
    server
        .conn()
        .export_keying_material(&mut s, b"EXPORTER ftls quic", Some(b"ctx"))
        .expect("server export");
    assert_eq!(c, s, "exported keying material must agree");

    // 1-RTT 数据包往返（HP + AEAD，短头包）
    let pkt = client.seal_1rtt_data(b"ping over quic 1rtt");
    let got = server.open_1rtt_data(pkt).expect("server open 1rtt");
    assert_eq!(got, b"ping over quic 1rtt");
    let pkt = server.seal_1rtt_data(b"pong over quic 1rtt");
    let got = client.open_1rtt_data(pkt).expect("client open 1rtt");
    assert_eq!(got, b"pong over quic 1rtt");

    // 篡改必须被拒绝（AEAD 认证 + HP/包号一致）
    let mut pkt = client.seal_1rtt_data(b"tamper me");
    let n = pkt.raw.len();
    pkt.raw[n - 3] ^= 0x08;
    assert!(
        server.open_1rtt_data(pkt).is_err(),
        "tampered 1-RTT packet must be rejected"
    );

    // 密钥更新（RFC 9001 §6）：两侧 lockstep 各推一次后往返成立
    client.update_1rtt_keys();
    server.update_1rtt_keys();
    let pkt = client.seal_1rtt_data(b"after key update");
    let got = server.open_1rtt_data(pkt).expect("post-update open");
    assert_eq!(got, b"after key update");
}
