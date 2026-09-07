//! webpki 真实证书链校验测试（M7）。
//!
//! 以 rustls 内建的 webpki 验证器（`with_root_certificates` 路径）走
//! 完整 X.509 链校验：本仓库 `verify.rs` 的 9 个
//! `SignatureVerificationAlgorithm` 首次在真实证书链下被 webpki 驱动
//! （链上签名、CertificateVerify、时间与 EKU/SAN 校验）。
//!
//! 证书链（tests/certs/，openssl 3.2 生成，P-256 全链）：
//! root（CA:TRUE pathlen:1）→ intermediate（CA:TRUE pathlen:0）→
//! leaf（CN=localhost，EKU serverAuth，SAN DNS:localhost）；
//! root2 为无关自签根，用于「不可信根」负例。

use std::io::Read;
use std::io::Write;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection};

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

fn provider() -> rustls::crypto::CryptoProvider {
    ferritls_rustls::default_provider()
}

/// 服务端配置：叶 + 中间证书链，ferritls provider 签名。
fn server_config() -> rustls::ServerConfig {
    rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![pem("leaf.pem"), pem("int.pem")], leaf_key())
        .expect("server config")
}

/// 客户端配置：webpki 验证器 + 指定信任根（ferritls provider 的验证算法）。
fn client_config(root: &str) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pem(root)).expect("add root");
    rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// 驱动一次完整握手并交换 ping/pong；任何失败即 panic。
fn assert_handshake_ok(client_cfg: rustls::ClientConfig) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");

    let (tx, rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || -> std::io::Result<()> {
        let r = (|| -> std::io::Result<()> {
            let mut conn = ServerConnection::new(Arc::new(server_config()))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let mut server_io = server_io;
            while conn.is_handshaking() {
                conn.complete_io(&mut server_io)?;
            }
            let mut buf = [0u8; 4];
            let mut got = 0;
            loop {
                match conn.reader().read(&mut buf[got..]) {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "eof",
                        ));
                    }
                    Ok(n) => {
                        got += n;
                        if got == 4 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        conn.complete_io(&mut server_io)?;
                    }
                    Err(e) => return Err(e),
                }
            }
            assert_eq!(&buf, b"ping");
            conn.writer().write_all(b"pong")?;
            while conn.wants_write() {
                conn.complete_io(&mut server_io)?;
            }
            Ok(())
        })();
        let _ = tx.send(r);
        Ok(())
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .expect("client conn");
    let mut client_io = client_io;
    let server_err = || {
        rx.try_recv()
            .ok()
            .and_then(|r: std::io::Result<()>| r.err())
    };
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut client_io) {
            let msg = match server_err() {
                Some(se) => format!("client: {e}; server: {se}"),
                None => format!("client: {e}"),
            };
            server.join().ok();
            panic!("handshake failed: {msg}");
        }
    }
    conn.writer().write_all(b"ping").expect("write");
    let mut buf = [0u8; 4];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(4) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                conn.complete_io(&mut client_io)
                    .unwrap_or_else(|e| panic!("drive: {e}; server: {:?}", server_err()));
            }
            Err(e) => panic!("read: {e}; server: {:?}", server_err()),
        }
    }
    assert_eq!(&buf, b"pong");
    server.join().expect("server thread").expect("server io");
}

/// 驱动握手直到客户端返回证书错误；返回该错误。
fn assert_handshake_rejected(client_cfg: rustls::ClientConfig, what: &str) -> std::io::Error {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");

    // 负例中服务端的结果无关紧要：只管驱动到出错/关闭。
    let server = std::thread::spawn(move || {
        if let Ok(mut conn) = ServerConnection::new(Arc::new(server_config())) {
            let mut server_io = server_io;
            for _ in 0..100 {
                match conn.complete_io(&mut server_io) {
                    Ok(_) if conn.is_handshaking() => continue,
                    _ => break,
                }
            }
        }
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_cfg),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .expect("client conn");
    let mut client_io = client_io;
    let mut err = None;
    for _ in 0..100 {
        match conn.complete_io(&mut client_io) {
            Ok(_) if conn.is_handshaking() => continue,
            Ok(_) => panic!("{what}: handshake unexpectedly completed"),
            Err(e) => {
                err = Some(e);
                break;
            }
        }
    }
    server.join().ok();
    err.unwrap_or_else(|| panic!("{what}: no rejection observed"))
}

#[test]
fn webpki_chain_handshake_ok() {
    assert_handshake_ok(client_config("root.pem"));
}

#[test]
fn webpki_rejects_untrusted_root() {
    let e = assert_handshake_rejected(client_config("root2.pem"), "untrusted root");
    assert!(
        format!("{e}").to_lowercase().contains("cert"),
        "expected certificate error, got: {e}"
    );
}

#[test]
fn webpki_rejects_tampered_leaf() {
    // 篡改叶证书签名区最后一个字节（HMAC/AEAD 之外的真实签名路径负例）
    let mut leaf = pem("leaf.pem").to_vec();
    let n = leaf.len();
    leaf[n - 1] ^= 0x01;
    let leaf = CertificateDer::from(leaf);

    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![leaf, pem("int.pem")], leaf_key())
        .expect("tampered cert still DER-parsable at config time");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server_io = std::net::TcpStream::connect(addr).expect("connect");
    let client_io = listener
        .incoming()
        .next()
        .expect("incoming")
        .expect("accept");
    let server = std::thread::spawn(move || {
        if let Ok(mut conn) = ServerConnection::new(Arc::new(server_cfg)) {
            let mut server_io = server_io;
            for _ in 0..100 {
                match conn.complete_io(&mut server_io) {
                    Ok(_) if conn.is_handshaking() => continue,
                    _ => break,
                }
            }
        }
    });

    let mut conn = ClientConnection::new(
        Arc::new(client_config("root.pem")),
        ServerName::try_from("localhost".to_string()).unwrap(),
    )
    .expect("client conn");
    let mut client_io = client_io;
    let mut rejected = false;
    for _ in 0..100 {
        match conn.complete_io(&mut client_io) {
            Ok(_) if conn.is_handshaking() => continue,
            Ok(_) => panic!("tampered leaf accepted"),
            Err(_) => {
                rejected = true;
                break;
            }
        }
    }
    server.join().ok();
    assert!(rejected, "tampered leaf was not rejected");
}
