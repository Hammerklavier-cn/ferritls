//! reqwest 0.12 应用层集成冒烟测试。
//!
//! reqwest 0.12 与 0.13 都依赖 rustls ^0.23（与 ferritls-rustls 同一条
//! 版本线，Cargo 统一为同一 crate 实例），ferritls 对两代 reqwest 的
//! 兼容面一致；本测试以 0.12 线作回归防线，覆盖 README 文档的两种
//! 接入路径：
//!
//! 1. `install_default()` 进程默认 provider：reqwest 以 `*-no-provider`
//!    feature 构建（不带任何内建 provider），建客户端时拾取进程默认
//!    ——即 ferritls；
//! 2. `use_preconfigured_tls(config)`：`builder_with_provider` 显式
//!    构建 `ClientConfig` 注入，不碰进程全局状态。
//!
//! 服务端为测试内置的最小 HTTP/1.1 over TLS（裸 `ServerConnection` +
//! `complete_io`，与 webpki.rs 同范式，不引入 tokio）：ALPN 固定
//! "http/1.1"（reqwest 开着 http2，服务端若不锁 ALPN 会协商出 h2），
//! 并回传协商事实（ALPN / 协议版本 / 套件）供断言，证明流量确实
//! 跑在 ferritls 上。

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{CipherSuite, ProtocolVersion, ServerConnection};

const CERTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/certs");

fn pem(name: &str) -> CertificateDer<'static> {
    let path = format!("{CERTS}/{name}");
    CertificateDer::from_pem_file(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn leaf_key() -> PrivateKeyDer<'static> {
    let path = format!("{CERTS}/leaf.key.der");
    let der = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    PrivateKeyDer::Pkcs8(der.into())
}

/// 服务端配置：P-256 链（leaf → int），ferritls provider，ALPN 锁 http/1.1。
fn server_config() -> rustls::ServerConfig {
    let mut cfg =
        rustls::ServerConfig::builder_with_provider(Arc::new(ferritls_rustls::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![pem("leaf.pem"), pem("int.pem")], leaf_key())
            .expect("server config");
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

/// 服务端回传的协商事实：证明流量确实跑在 ferritls 上。
#[derive(Debug)]
struct ServerFacts {
    alpn: Option<Vec<u8>>,
    version: Option<ProtocolVersion>,
    suite: Option<CipherSuite>,
}

/// 起一个一次性最小 HTTPS（HTTP/1.1）服务：握手完成后读掉请求头、
/// 回固定 200 响应并把协商事实发回。返回端口、事实接收端与线程句柄。
fn spin_up_server(
    cfg: rustls::ServerConfig,
) -> (
    u16,
    Receiver<ServerFacts>,
    std::thread::JoinHandle<std::io::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = channel();
    let handle = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut io, _) = listener.accept()?;
        io.set_read_timeout(Some(Duration::from_secs(30)))?;

        let mut conn = ServerConnection::new(Arc::new(cfg))
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        while conn.is_handshaking() {
            conn.complete_io(&mut io)?;
        }

        // 读 HTTP 请求头（以 \r\n\r\n 结尾即视为完整）。
        let mut req = Vec::new();
        let mut chunk = [0u8; 512];
        loop {
            match conn.reader().read(&mut chunk) {
                Ok(0) => {
                    return Err(std::io::Error::new(ErrorKind::UnexpectedEof, "eof"));
                }
                Ok(n) => {
                    req.extend_from_slice(&chunk[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    conn.complete_io(&mut io)?;
                }
                Err(e) => return Err(e),
            }
        }

        let _ = tx.send(ServerFacts {
            alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
            version: conn.protocol_version(),
            suite: conn.negotiated_cipher_suite().map(|s| s.suite()),
        });

        conn.writer().write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
        )?;
        while conn.wants_write() {
            conn.complete_io(&mut io)?;
        }
        Ok(())
    });
    (port, rx, handle)
}

/// 断言服务端观察到的事实：ALPN http/1.1、TLS 1.3、ferritls 套件之一。
fn assert_ferritls_negotiated(facts: ServerFacts) {
    assert_eq!(facts.alpn.as_deref(), Some(b"http/1.1".as_slice()), "alpn");
    assert_eq!(facts.version, Some(ProtocolVersion::TLSv1_3), "version");
    assert!(
        matches!(
            facts.suite,
            Some(
                CipherSuite::TLS13_AES_128_GCM_SHA256
                    | CipherSuite::TLS13_AES_256_GCM_SHA384
                    | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                    | CipherSuite::TLS13_AES_128_CCM_SHA256
                    | CipherSuite::TLS13_AES_128_CCM_8_SHA256
            )
        ),
        "unexpected suite: {:?}",
        facts.suite
    );
}

/// 驱动一次 GET 并断言 200 + 响应体；服务端线程收尾并断言协商事实。
fn assert_get_hello(client: &reqwest::blocking::Client) {
    let (port, rx, server) = spin_up_server(server_config());
    let resp = client
        .get(format!("https://localhost:{port}/"))
        .send()
        .expect("send");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().expect("body"), "hello");

    server.join().expect("server thread").expect("server io");
    assert_ferritls_negotiated(rx.recv().expect("facts"));
}

/// 路径一（README 主推）：进程默认 provider。
///
/// `install_default` 必须先于本测试二进制内任何 rustls `builder()`
/// 调用——reqwest 以 no-provider feature 构建，rustls 没有内建
/// provider 可回落；若无人安装默认，首次 `builder()` 直接 panic
/// （这正是该 feature 组合的防护语义）。`Err` 表示已装默认（两条
/// 测试并行时各自都装 ferritls，值一致），可安全忽略。
#[test]
fn reqwest_blocking_get_via_install_default() {
    let _ = ferritls_rustls::default_provider().install_default();

    let root = std::fs::read(format!("{CERTS}/root.pem")).expect("read root.pem");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .add_root_certificate(reqwest::Certificate::from_pem(&root).expect("root certificate"))
        .build()
        .expect("client");

    assert_get_hello(&client);
}

/// 路径二：显式 `use_preconfigured_tls`，不碰进程全局 provider 状态。
#[test]
fn reqwest_blocking_get_via_preconfigured_tls() {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pem("root.pem")).expect("add root");
    let mut tls =
        rustls::ClientConfig::builder_with_provider(Arc::new(ferritls_rustls::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    // reqwest 不会修改预配置的 ClientConfig：ALPN 必须由调用方自设
    // （与 reqwest 自建配置相同，同时提供 h2 与 http/1.1），否则
    // HTTP/2 静默不可用。
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_preconfigured_tls(tls)
        .build()
        .expect("client");

    assert_get_hello(&client);
}
