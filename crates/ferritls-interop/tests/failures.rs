//! 失败路径互操作：握手完成后向线路注入畸形 TLS 记录，钉扎记录层
//! 解密面的「失败即断连」契约。
//!
//! 动机：适配层三个 `MessageDecrypter`（GCM/ChaCha/CCM，cipher.rs）的
//! 短记录守卫（`payload.len() < tag + 1 → DecryptError`）此前零端到端
//! 覆盖——decrypter 单测绕过了 rustls deframer → decrypter → fatal
//! alert 的全链路。这里以裸 TCP 字节注入两类记录：
//! - 短记录：声明长度低于 tag+1 下界，命中守卫分支；
//! - 合法长度垃圾密文：绕过守卫，命中 AEAD 标签校验失败分支。
//!
//! 两侧断言（rustls 0.23.45 vendored 源语义，conn.rs
//! `handle_deframe_error`）：接收侧 `complete_io` 以 `DecryptError`
//! 终结并向对端发 fatal alert；注入侧读回的 wire alert 为
//! `bad_record_mac`（rustls 将解密失败映射为 BadRecordMac——RFC 8446
//! 对记录解密失败的惯例告警——而非 decrypt_error）。任一情形连接必须
//! 终结于错误，绝不静默接受或挂死。

mod common;

use std::io::Write;
use std::sync::Arc;

use rustls::{AlertDescription, Connection, Error};

/// 组装一条裸 TLS 记录：外层 TLSPlaintext（type = application_data +
/// legacy version 0x0303 + 16 位长度），payload 原样作为「密文」字节。
fn opaque_record(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x17, 0x03, 0x03];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// 确定性伪随机密文形态字节（pattern 风格，非秘密）：合法长度但
/// AEAD 标签必然校验失败。
fn garbage(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect()
}

/// 单线程顺序驱动：正常握手完成后向线路注入 `record` 裸字节，断言
/// 两侧都以错误收场（服务端本地 `DecryptError`；客户端收到
/// `bad_record_mac` fatal alert）。读超时与轮数上限由
/// [`common::raw_tcp_pair`] / [`common::drive_handshake_pair`] 兜底，
/// 测试不可能挂死。
fn inject_and_expect_decrypt_error(suite: rustls::SupportedCipherSuite, record: &[u8]) {
    let provider = common::ferritls_pinned(suite, ferritls_rustls::kx::X25519_GROUP);
    let server_cfg = common::server_config(provider.clone()).expect("server config");
    let client_cfg = common::client_config(provider);

    let (mut server_io, mut client_io) = common::raw_tcp_pair();
    let mut client = Connection::from(
        rustls::ClientConnection::new(
            Arc::new(client_cfg),
            rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name"),
        )
        .expect("client conn"),
    );
    let mut server =
        Connection::from(rustls::ServerConnection::new(Arc::new(server_cfg)).expect("server conn"));

    // 正向对照：两侧各自完成正常握手（客户端发出 Finished、服务端消费）。
    common::drive_handshake_pair(&mut client, &mut client_io, &mut server, &mut server_io)
        .expect("baseline handshake");

    // 注入畸形记录（绕过 rustls 直接写原始字节）。
    client_io.write_all(record).expect("inject raw record");
    client_io.flush().expect("flush injected record");

    // 接收侧：解密失败 → 本地 DecryptError + 对外 fatal alert。
    let mut rounds = 0u32;
    let server_err = loop {
        rounds += 1;
        assert!(rounds < 100, "server did not fail on malformed record");
        if let Err(e) = common::step_connection(&mut server, &mut server_io) {
            break e;
        }
    };
    assert_eq!(
        server_err,
        Error::DecryptError,
        "malformed record must surface DecryptError on the receiving side"
    );

    // 注入侧：读回服务端的 fatal alert。
    let mut rounds = 0u32;
    let client_err = loop {
        rounds += 1;
        assert!(rounds < 100, "client did not receive the fatal alert");
        if let Err(e) = common::step_connection(&mut client, &mut client_io) {
            break e;
        }
    };
    assert_eq!(
        client_err,
        Error::AlertReceived(AlertDescription::BadRecordMac),
        "wire alert for TLS 1.3 decrypt failure must be bad_record_mac"
    );
}

// ---------- GCM（GcmDecrypter：短记录守卫 + 标签校验） ----------

/// 5 字节 payload < tag(16)+1：命中 GcmDecrypter 短记录守卫。
#[test]
fn gcm128_short_record_below_tag_bound_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        &opaque_record(&[0xa5; 5]),
    );
}

/// 合法长度（200 B）垃圾密文：绕过守卫，GCM 标签校验失败。
#[test]
fn gcm128_garbage_ciphertext_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_gcm_sha256(),
        &opaque_record(&garbage(200)),
    );
}

// ---------- ChaCha20-Poly1305（ChachaDecrypter） ----------

/// 5 字节 payload < tag(16)+1：命中 ChachaDecrypter 短记录守卫。
#[test]
fn chacha_short_record_below_tag_bound_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(),
        &opaque_record(&[0xa5; 5]),
    );
}

/// 合法长度（200 B）垃圾密文：Poly1305 标签校验失败。
#[test]
fn chacha_garbage_ciphertext_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_chacha20_poly1305_sha256(),
        &opaque_record(&garbage(200)),
    );
}

// ---------- CCM（CcmDecrypter，M=16 / M=8 两档） ----------

/// 5 字节 payload < M(16)+1：命中 CcmDecrypter 短记录守卫。
#[test]
fn ccm_short_record_below_tag_bound_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_ccm_sha256(),
        &opaque_record(&[0xa5; 5]),
    );
}

/// 合法长度（200 B）垃圾密文：CCM 标签校验失败（M=16）。
#[test]
fn ccm_garbage_ciphertext_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_ccm_sha256(),
        &opaque_record(&garbage(200)),
    );
}

/// 5 字节 payload < M(8)+1：CCM_8 档的短记录守卫（M=8 下界与
/// GCM/ChaCha 的 17 不同，守卫是按 M 参数化的同一分支）。
#[test]
fn ccm8_short_record_below_tag_bound_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_ccm_8_sha256(),
        &opaque_record(&[0xa5; 5]),
    );
}

/// 合法长度（200 B）垃圾密文：CCM 标签校验失败（M=8）。
#[test]
fn ccm8_garbage_ciphertext_fails() {
    inject_and_expect_decrypt_error(
        ferritls_rustls::cipher::tls13_aes_128_ccm_8_sha256(),
        &opaque_record(&garbage(200)),
    );
}
