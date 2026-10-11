//! 会话层功能互操作：TLS 1.3 会话恢复（ticket/PSK）与 KeyLog 导出。
//!
//! - 会话恢复：rustls 的 ticket 加密是提供方无关的内部职责（此处用
//!   rustls-ring 的 `Ticketer`），但 PSK binder 计算、
//!   pre-shared-key 扩展与恢复握手的完整密钥调度全部经 ferritls 的
//!   HKDF——此前从未在握手层执行过。
//! - KeyLog：rustls 以 `Tls13AeadAlgorithm::extract_keys` 的产出调用
//!   `KeyLog::log`——本测试端到端验证适配层的 extract_keys 实现
//!   （密码学正确性在 cipher.rs 单元测试锚定，这里验证接线与格式）。

mod common;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rustls::KeyLog;
use rustls::{CipherSuite, ClientConnection, HandshakeKind, ServerConnection};

const SUITE: CipherSuite = CipherSuite::TLS13_AES_128_GCM_SHA256;

/// 一条 KeyLog 记录：(label, client_random, secret)。
type LogEntry = (String, Vec<u8>, Vec<u8>);

/// 捕获型 KeyLog。
#[derive(Debug, Default)]
struct CaptureLog(Mutex<Vec<LogEntry>>);

impl KeyLog for CaptureLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        self.0
            .lock()
            .unwrap()
            .push((label.to_string(), client_random.to_vec(), secret.to_vec()));
    }
    fn will_log(&self, _label: &str) -> bool {
        true
    }
}

/// 会话恢复：第一次完整握手拿到 ticket，第二次同一配置连接必须以
/// Resumed 形式完成（两侧观察点一致）。恢复握手的 PSK 密钥调度
/// （binder HKDF-Extract、early secret 链）走 ferritls。
#[test]
fn tls13_session_resumption_full_then_resumed() {
    let provider = ferritls_rustls::default_provider();
    let mut server_cfg = common::server_config(provider.clone()).expect("server config");
    server_cfg.ticketer = rustls::crypto::ring::Ticketer::new().expect("ticketer");
    let mut client_cfg = common::client_config(provider);
    client_cfg.resumption = rustls::client::Resumption::in_memory_sessions(16);

    common::handshake_ping_pong_with(
        server_cfg.clone(),
        client_cfg.clone(),
        SUITE,
        |server: &mut ServerConnection| {
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        },
        |client: &mut ClientConnection| {
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        },
    )
    .expect("first (full) handshake");

    common::handshake_ping_pong_with(
        server_cfg,
        client_cfg,
        SUITE,
        |server: &mut ServerConnection| {
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        },
        |client: &mut ClientConnection| {
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
        },
    )
    .expect("second (resumed) handshake");
}

/// KeyLog 端到端：两侧都挂 CaptureLog，一次握手后每个 TLS 1.3 label
/// 恰好各被记录两次（客户端+服务端各一），secret 均为 32 字节、两侧
/// 一致、非全零；所有条目共享同一 client_random。
#[test]
fn keylog_receives_tls13_traffic_secrets_via_extract_keys() {
    let provider = ferritls_rustls::default_provider();
    let log = Arc::new(CaptureLog::default());

    let mut server_cfg = common::server_config(provider.clone()).expect("server config");
    server_cfg.key_log = log.clone();
    let mut client_cfg = common::client_config(provider);
    client_cfg.key_log = log.clone();

    common::handshake_ping_pong_with(server_cfg, client_cfg, SUITE, |_| {}, |_| {})
        .expect("handshake");

    let entries = log.0.lock().unwrap();
    assert!(
        !entries.is_empty(),
        "key log received nothing — KeyLog wiring broken"
    );
    for label in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        let hits: Vec<&LogEntry> = entries.iter().filter(|(l, _, _)| l == label).collect();
        assert_eq!(hits.len(), 2, "label {label} must be logged once per side");
        assert_eq!(hits[0].2.len(), 32, "{label} secret length (AES-128)");
        assert_eq!(
            hits[0].2, hits[1].2,
            "{label} secret identical on both sides"
        );
        assert!(
            hits[0].2.iter().any(|&b| b != 0),
            "{label} secret must not be all-zero"
        );
    }
    let randoms: HashSet<Vec<u8>> = entries.iter().map(|(_, r, _)| r.clone()).collect();
    assert_eq!(randoms.len(), 1, "all entries share one client_random");
}
