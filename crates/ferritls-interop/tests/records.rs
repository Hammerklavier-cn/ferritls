//! 记录层边界互操作：TLS 满记录（16 KiB）与 `max_fragment_size`
//! 强制分片下的多记录传输。此前数据面固定为 4 字节 ping/pong，
//! 单记录容量与分片路径从未上过线。

mod common;

use ferritls_rustls::default_provider;

/// 确定性伪随机负载（pattern 风格，非秘密）。
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// 恰好一条满记录（TLSPlaintext 上限 16384 B 明文）双向往返。
#[test]
fn max_length_record_16k_roundtrip() {
    let provider = default_provider();
    let data = payload(16 * 1024);
    common::transfer_roundtrip(
        common::server_config(provider.clone()).expect("server config"),
        common::client_config(provider),
        &data,
    )
    .expect("16 KiB roundtrip");
}

/// 两侧 `max_fragment_size = 512` 强制把 4 KiB 负载拆成多条记录：
/// 分片组装与对端按流重组路径。
#[test]
fn forced_fragmentation_roundtrip() {
    let provider = default_provider();
    let mut server_cfg = common::server_config(provider.clone()).expect("server config");
    server_cfg.max_fragment_size = Some(512);
    let mut client_cfg = common::client_config(provider);
    client_cfg.max_fragment_size = Some(512);
    let data = payload(4096);
    common::transfer_roundtrip(server_cfg, client_cfg, &data).expect("fragmented roundtrip");
}

/// 1 字节最小负载（单记录边界另一端）。
#[test]
fn minimal_record_roundtrip() {
    let provider = default_provider();
    common::transfer_roundtrip(
        common::server_config(provider.clone()).expect("server config"),
        common::client_config(provider),
        b"x",
    )
    .expect("1-byte roundtrip");
}
