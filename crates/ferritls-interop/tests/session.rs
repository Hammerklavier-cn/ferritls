//! 会话层功能互操作：TLS 1.3 会话恢复（ticket/PSK）与 KeyLog 导出。
//!
//! - 会话恢复：rustls 的 ticket 加密是提供方无关的内部职责（此处用
//!   rustls-ring 的 `Ticketer`），但 PSK binder 计算、
//!   pre-shared-key 扩展与恢复握手的完整密钥调度全部经 ferritls 的
//!   HKDF——此前从未在握手层执行过。
//! - KeyLog：rustls 0.23 在密钥调度处（key_schedule.rs
//!   `derive_logged_secret`）直接以派生出的原始 traffic secret 调用
//!   `KeyLog::log`，**不经过** `Tls13AeadAlgorithm::extract_keys`——
//!   故 GCM 与 CCM 的 key log 行为一致（均有全部 5 个 label）。
//!   extract_keys 的产出只喂给 `dangerous_extract_secrets`（kTLS 式
//!   导出）与 `refresh_traffic_keys`（key update）两个端点——适配层
//!   对 CCM 恒 Err（`ConnectionTrafficSecrets` 无 CCM 变体）的契约
//!   以 `extract_keys` 单元测试（cipher.rs）与下方的
//!   dangerous_extract_secrets 端到端测试共同锚定。

mod common;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rustls::KeyLog;
use rustls::{CipherSuite, ClientConnection, Connection, Error, HandshakeKind, ServerConnection};

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

/// 钉扎 CCM 家族套件的 provider（X25519 组）。
fn ccm_provider(suite: rustls::SupportedCipherSuite) -> rustls::crypto::CryptoProvider {
    common::ferritls_pinned(suite, ferritls_rustls::kx::X25519_GROUP)
}

/// CCM 套件会话恢复：恢复握手（PSK binder、early secret 链）只依赖
/// 套件的 hkdf_provider，与 extract_keys 恒 Err 无关——CCM 下
/// Full → Resumed 必须与 GCM 行为一致。
#[test]
fn ccm_session_resumption_full_then_resumed() {
    let suite = ferritls_rustls::cipher::tls13_aes_128_ccm_sha256();
    let provider = ccm_provider(suite);
    let mut server_cfg = common::server_config(provider.clone()).expect("server config");
    server_cfg.ticketer = rustls::crypto::ring::Ticketer::new().expect("ticketer");
    let mut client_cfg = common::client_config(provider);
    client_cfg.resumption = rustls::client::Resumption::in_memory_sessions(16);

    common::handshake_ping_pong_with(
        server_cfg.clone(),
        client_cfg.clone(),
        suite.suite(),
        |server: &mut ServerConnection| {
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
        },
        |client: &mut ClientConnection| {
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
        },
    )
    .expect("first (full) ccm handshake");

    common::handshake_ping_pong_with(
        server_cfg,
        client_cfg,
        suite.suite(),
        |server: &mut ServerConnection| {
            assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
        },
        |client: &mut ClientConnection| {
            assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
        },
    )
    .expect("second (resumed) ccm handshake");
}

/// CCM 的 KeyLog：key log 出自密钥调度的原始 traffic secret（不经
/// extract_keys），故 CCM 连接同样收到全部 5 个 TLS 1.3 label——
/// 「extract_keys 恒 Err」不意味 key log 停摆。逐条保真检查已由
/// GCM 侧 `keylog_receives_tls13_traffic_secrets_via_extract_keys`
/// 覆盖，此处只钉扎 CCM 的 label 面。
#[test]
fn keylog_receives_tls13_secrets_for_ccm_too() {
    let suite = ferritls_rustls::cipher::tls13_aes_128_ccm_sha256();
    let provider = ccm_provider(suite);
    let log = Arc::new(CaptureLog::default());

    let mut server_cfg = common::server_config(provider.clone()).expect("server config");
    server_cfg.key_log = log.clone();
    let mut client_cfg = common::client_config(provider);
    client_cfg.key_log = log.clone();

    common::handshake_ping_pong_with(server_cfg, client_cfg, suite.suite(), |_| {}, |_| {})
        .expect("ccm handshake");

    let entries = log.0.lock().unwrap();
    for label in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        let hits = entries.iter().filter(|(l, _, _)| l == label).count();
        assert_eq!(hits, 2, "label {label} must be logged once per side (CCM)");
    }
    let randoms: HashSet<Vec<u8>> = entries.iter().map(|(_, r, _)| r.clone()).collect();
    assert_eq!(randoms.len(), 1, "all entries share one client_random");
}

/// extract_keys 的 Err 面（端到端）：`dangerous_extract_secrets` 是
/// rustls 唯一以 `Tls13AeadAlgorithm::extract_keys` 产出为输入的公开
/// 端点（enable_secret_extraction 打开后才会抵达 extract_keys——
/// 关闭时 rustls 在 conn.rs 入口即报 "Secret extraction is
/// disabled"）。CCM（M=16）与 CCM_8（M=8）两侧导出必须 Err
/// （`ConnectionTrafficSecrets` 无 CCM 变体 → UnsupportedOperationError
/// → Error::General("operation not supported")），GCM 对照必须 Ok——
/// 双向钉扎适配层契约。
#[test]
fn ccm_extract_secrets_unsupported_while_gcm_supported() {
    fn extract_secrets_after_handshake(
        suite: rustls::SupportedCipherSuite,
    ) -> (Result<(), Error>, Result<(), Error>) {
        let provider = common::ferritls_pinned(suite, ferritls_rustls::kx::X25519_GROUP);
        let mut server_cfg = common::server_config(provider.clone()).expect("server config");
        server_cfg.enable_secret_extraction = true;
        let mut client_cfg = common::client_config(provider);
        client_cfg.enable_secret_extraction = true;
        let (mut server_io, mut client_io) = common::raw_tcp_pair();
        let mut client = Connection::from(
            ClientConnection::new(
                Arc::new(client_cfg),
                rustls::pki_types::ServerName::try_from("localhost".to_string())
                    .expect("server name"),
            )
            .expect("client conn"),
        );
        let mut server =
            Connection::from(ServerConnection::new(Arc::new(server_cfg)).expect("server conn"));
        common::drive_handshake_pair(&mut client, &mut client_io, &mut server, &mut server_io)
            .expect("baseline handshake");
        (
            client.dangerous_extract_secrets().map(|_| ()),
            server.dangerous_extract_secrets().map(|_| ()),
        )
    }

    for (name, suite) in [
        ("CCM", ferritls_rustls::cipher::tls13_aes_128_ccm_sha256()),
        (
            "CCM_8",
            ferritls_rustls::cipher::tls13_aes_128_ccm_8_sha256(),
        ),
    ] {
        let (client, server) = extract_secrets_after_handshake(suite);
        for (side, result) in [("client", client), ("server", server)] {
            match result {
                Err(Error::General(msg)) => assert_eq!(
                    msg, "operation not supported",
                    "{name} {side}: extract_keys must be the failure source"
                ),
                other => panic!("{name} {side}: expected Err(General), got {other:?}"),
            }
        }
    }

    // GCM 对照：同一路径两侧均可导出。
    let (client, server) =
        extract_secrets_after_handshake(ferritls_rustls::cipher::tls13_aes_128_gcm_sha256());
    assert!(
        client.is_ok(),
        "GCM client: extract must succeed ({client:?})"
    );
    assert!(
        server.is_ok(),
        "GCM server: extract must succeed ({server:?})"
    );
}
