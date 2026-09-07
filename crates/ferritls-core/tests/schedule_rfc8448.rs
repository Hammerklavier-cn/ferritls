//! RFC 8448 §3「Simple 1-RTT Handshake」密钥调度全链验证（M7）。
//!
//! 以 RFC 8448 官方轨迹为外部真值，逐级复算 TLS 1.3 密钥调度：X25519
//! 共享秘密 → HKDF-Extract / Expand-Label → traffic secrets → Finished
//! verify_data → record 层 traffic keys → resumption。全部字节常量由
//! `tools/extract_rfc8448.py` 从 rfc-editor.org 官方文本程序化提取
//! （AGENTS.md 规则 7，禁止人工转录），生成时脚本用 Python 独立复算了
//! 全部中间值并与 RFC 标注逐字节比对通过。覆盖 `ecdh::x25519`、
//! `sha2::Sha256`、`hmac::HmacSha256`、`hkdf::{extract_sha256,
//! expand_sha256}`。
//!
//! 说明：rustls 的 ServerHello random / ClientHello 扩展集无法在
//! provider 层注入，完整记录级字节重放不可行（ROADMAP M7 注记）；本
//! 测试把轨迹中 provider 负责的部分（KDF 栈 + ECDH）按外部真值逐字节
//! 锚定，transcript 编码部分由 ring 交叉互操作测试（interop）锚定。

mod common;

use common::{assert_hex, hex};
use ferritls_core::{ecdh::x25519, hkdf, hmac, sha2};

#[rustfmt::skip]
mod rfc8448 {
    //! 官方轨迹常量：名称 → 小写十六进制（见 tools/extract_rfc8448.py）。
    pub(super) const _DOC: &str = "generated; do not edit by hand";
    pub(super) const CLIENT_PRIV: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
    pub(super) const CLIENT_PUB: &str = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
    pub(super) const SERVER_PRIV: &str = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";
    pub(super) const SERVER_PUB: &str = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    pub(super) const CLIENT_HELLO: &str = concat!(
        "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef",
        "6283024dece7000006130113031302010000910000000b000900000673657276",
        "6572ff01000100000a00140012001d0017001800190100010101020103010400",
        "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e",
        "51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603",
        "020308040805080604010501060102010402050206020202002d00020101001c",
        "00024001",
    );
    pub(super) const SERVER_HELLO: &str = concat!(
        "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155",
        "772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb",
        "f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304",
    );
    pub(super) const ENCRYPTED_EXTENSIONS: &str = concat!(
        "080000240022000a00140012001d00170018001901000101010201030104001c",
        "0002400100000000",
    );
    pub(super) const CERTIFICATE: &str = concat!(
        "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a",
        "864886f70d01010b0500300e310c300a06035504031303727361301e170d3136",
        "303733303031323335395a170d3236303733303031323335395a300e310c300a",
        "0603550403130372736130819f300d06092a864886f70d010101050003818d00",
        "30818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826",
        "d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312",
        "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda4308467480",
        "30530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a",
        "8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355",
        "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5",
        "b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a5",
        "8c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102",
        "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0",
        "a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de10000",
    );
    pub(super) const CERTIFICATE_VERIFY: &str = concat!(
        "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145a",
        "b3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248ee",
        "aaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c",
        "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea2",
        "0d53dfacd42f74f3",
    );
    pub(super) const SERVER_FINISHED: &str = concat!(
        "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454",
        "b78f0718",
    );
    pub(super) const CLIENT_FINISHED: &str = concat!(
        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2",
        "edd5ce61",
    );
    pub(super) const DH_SHARED: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    pub(super) const EARLY: &str = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    pub(super) const TH_SERVER_HELLO: &str = "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";
    pub(super) const DERIVED_HANDSHAKE: &str = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
    pub(super) const HANDSHAKE_SECRET: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    pub(super) const CLIENT_HS_TRAFFIC: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    pub(super) const SERVER_HS_TRAFFIC: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    pub(super) const DERIVED_MASTER: &str = "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4";
    pub(super) const MASTER_SECRET: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    pub(super) const SERVER_FINISHED_KEY: &str = "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8";
    pub(super) const SERVER_VERIFY_DATA: &str = "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";
    pub(super) const CLIENT_FINISHED_KEY: &str = "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4";
    pub(super) const CLIENT_VERIFY_DATA: &str = "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";
    pub(super) const TH_APPLICATION: &str = "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";
    pub(super) const CLIENT_AP_TRAFFIC: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    pub(super) const SERVER_AP_TRAFFIC: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    pub(super) const EXPORTER_MASTER: &str = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50";
    pub(super) const TH_RESUMPTION: &str = "209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d";
    pub(super) const RESUMPTION_MASTER: &str = "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c";
    pub(super) const RESUMPTION_SECRET: &str = "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3";
    pub(super) const SERVER_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
    pub(super) const SERVER_HS_IV: &str = "5d313eb2671276ee13000b30";
    pub(super) const SERVER_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
    pub(super) const SERVER_AP_IV: &str = "cf782b88dd83549aadf1e984";
    pub(super) const CLIENT_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
    pub(super) const CLIENT_HS_IV: &str = "5bd3c71b836e0b76bb73265f";
    pub(super) const CLIENT_AP_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
    pub(super) const CLIENT_AP_IV: &str = "5b78923dee08579033e523d9";
}

use rfc8448::*;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// TLS 1.3 HKDF-Expand-Label（RFC 8446 §7.1）。label 与 context 都是
/// 带 1 字节长度前缀的向量：
/// info = uint16(len) || uint8(len) || "tls13 " || label || uint8(ctx_len) || ctx
fn expand_label(prk: &[u8], label: &str, context_hash: &[u8], out_len: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context_hash.len());
    info.extend_from_slice(&(out_len as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(context_hash.len() as u8);
    info.extend_from_slice(context_hash);
    let mut okm = vec![0u8; out_len];
    hkdf::expand_sha256(prk, &info, &mut okm);
    okm
}

/// 密钥调度前半段：early → derived → handshake secret（各测试复用）。
fn handshake_secret() -> [u8; 32] {
    let zero32 = [0u8; 32];
    let empty_hash = sha256(&[]);
    let early = hkdf::extract_sha256(&zero32, &zero32);
    assert_hex(&early, EARLY, "early secret");
    let derived = expand_label(&early, "derived", &empty_hash, 32);
    assert_hex(&derived, DERIVED_HANDSHAKE, "derived (handshake)");
    let hs = hkdf::extract_sha256(&derived, &hex(DH_SHARED));
    assert_hex(&hs, HANDSHAKE_SECRET, "handshake secret");
    hs
}

#[test]
fn x25519_shared_secret_matches_rfc8448() {
    let client = x25519::SecretKey::from_seed(hex(CLIENT_PRIV).try_into().unwrap());
    let server = x25519::SecretKey::from_seed(hex(SERVER_PRIV).try_into().unwrap());
    assert_hex(&client.public_key(), CLIENT_PUB, "client public key");
    assert_hex(&server.public_key(), SERVER_PUB, "server public key");
    let c2s = client
        .diffie_hellman(&hex(SERVER_PUB))
        .expect("client side dh");
    let s2c = server
        .diffie_hellman(&hex(CLIENT_PUB))
        .expect("server side dh");
    assert_hex(c2s.as_bytes(), DH_SHARED, "dh shared (client view)");
    assert_hex(s2c.as_bytes(), DH_SHARED, "dh shared (server view)");
}

#[test]
fn traffic_secrets_match_rfc8448() {
    let hs = handshake_secret();
    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);
    assert_hex(&th_sh, TH_SERVER_HELLO, "transcript hash CH..SH");
    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);
    assert_hex(&c_hs, CLIENT_HS_TRAFFIC, "client hs traffic secret");
    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);
    assert_hex(&s_hs, SERVER_HS_TRAFFIC, "server hs traffic secret");
    let empty_hash = sha256(&[]);
    let derived_master = expand_label(&hs, "derived", &empty_hash, 32);
    assert_hex(&derived_master, DERIVED_MASTER, "derived (master)");
    let zero32 = [0u8; 32];
    let master = hkdf::extract_sha256(&derived_master, &zero32);
    assert_hex(&master, MASTER_SECRET, "master secret");
}

#[test]
fn finished_verify_data_matches_rfc8448() {
    let hs = handshake_secret();
    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);
    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);
    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);

    // server Finished：finished_key = Expand-Label(s_hs, "finished", "", 32)，
    // verify_data = HMAC(finished_key, Transcript-Hash(CH..CV))。
    let th_cv = sha256(&[
        &hex(CLIENT_HELLO),
        &hex(SERVER_HELLO),
        &hex(ENCRYPTED_EXTENSIONS),
        &hex(CERTIFICATE),
        &hex(CERTIFICATE_VERIFY),
    ]);
    let fk_s = expand_label(&s_hs, "finished", &[], 32);
    assert_hex(&fk_s, SERVER_FINISHED_KEY, "server finished_key");
    let vd_s = hmac::HmacSha256::one_shot(&fk_s, &th_cv);
    assert_hex(&vd_s, SERVER_VERIFY_DATA, "server verify_data");

    // client Finished：transcript 到 server Finished 为止。
    let th_sf = sha256(&[
        &hex(CLIENT_HELLO),
        &hex(SERVER_HELLO),
        &hex(ENCRYPTED_EXTENSIONS),
        &hex(CERTIFICATE),
        &hex(CERTIFICATE_VERIFY),
        &hex(SERVER_FINISHED),
    ]);
    assert_hex(&th_sf, TH_APPLICATION, "transcript hash CH..SFin");
    let fk_c = expand_label(&c_hs, "finished", &[], 32);
    assert_hex(&fk_c, CLIENT_FINISHED_KEY, "client finished_key");
    let vd_c = hmac::HmacSha256::one_shot(&fk_c, &th_sf);
    assert_hex(&vd_c, CLIENT_VERIFY_DATA, "client verify_data");
}

#[test]
fn application_secrets_and_traffic_keys_match_rfc8448() {
    let hs = handshake_secret();
    let empty_hash = sha256(&[]);
    let zero32 = [0u8; 32];
    let th_sh = sha256(&[&hex(CLIENT_HELLO), &hex(SERVER_HELLO)]);
    let c_hs = expand_label(&hs, "c hs traffic", &th_sh, 32);
    let s_hs = expand_label(&hs, "s hs traffic", &th_sh, 32);
    let master = hkdf::extract_sha256(&expand_label(&hs, "derived", &empty_hash, 32), &zero32);

    // 应用流量秘密（transcript 到 server Finished）。
    let th_app = sha256(&[
        &hex(CLIENT_HELLO),
        &hex(SERVER_HELLO),
        &hex(ENCRYPTED_EXTENSIONS),
        &hex(CERTIFICATE),
        &hex(CERTIFICATE_VERIFY),
        &hex(SERVER_FINISHED),
    ]);
    let c_ap = expand_label(&master, "c ap traffic", &th_app, 32);
    assert_hex(&c_ap, CLIENT_AP_TRAFFIC, "client ap traffic secret");
    let s_ap = expand_label(&master, "s ap traffic", &th_app, 32);
    assert_hex(&s_ap, SERVER_AP_TRAFFIC, "server ap traffic secret");
    let exp_master = expand_label(&master, "exp master", &th_app, 32);
    assert_hex(&exp_master, EXPORTER_MASTER, "exporter master secret");

    // record 层 traffic keys（key/iv 展开的 transcript 上下文为空）。
    assert_hex(
        &expand_label(&s_hs, "key", &[], 16),
        SERVER_HS_KEY,
        "server hs write key",
    );
    assert_hex(
        &expand_label(&s_hs, "iv", &[], 12),
        SERVER_HS_IV,
        "server hs write iv",
    );
    assert_hex(
        &expand_label(&c_hs, "key", &[], 16),
        CLIENT_HS_KEY,
        "client hs write key",
    );
    assert_hex(
        &expand_label(&c_hs, "iv", &[], 12),
        CLIENT_HS_IV,
        "client hs write iv",
    );
    assert_hex(
        &expand_label(&s_ap, "key", &[], 16),
        SERVER_AP_KEY,
        "server ap write key",
    );
    assert_hex(
        &expand_label(&s_ap, "iv", &[], 12),
        SERVER_AP_IV,
        "server ap write iv",
    );
    assert_hex(
        &expand_label(&c_ap, "key", &[], 16),
        CLIENT_AP_KEY,
        "client ap write key",
    );
    assert_hex(
        &expand_label(&c_ap, "iv", &[], 12),
        CLIENT_AP_IV,
        "client ap write iv",
    );
}

#[test]
fn resumption_master_matches_rfc8448() {
    let hs = handshake_secret();
    let empty_hash = sha256(&[]);
    let zero32 = [0u8; 32];
    let master = hkdf::extract_sha256(&expand_label(&hs, "derived", &empty_hash, 32), &zero32);

    // resumption master：transcript 到 client Finished；ticket nonce = 00 00。
    let th_res = sha256(&[
        &hex(CLIENT_HELLO),
        &hex(SERVER_HELLO),
        &hex(ENCRYPTED_EXTENSIONS),
        &hex(CERTIFICATE),
        &hex(CERTIFICATE_VERIFY),
        &hex(SERVER_FINISHED),
        &hex(CLIENT_FINISHED),
    ]);
    assert_hex(&th_res, TH_RESUMPTION, "transcript hash CH..CFin");
    let res_master = expand_label(&master, "res master", &th_res, 32);
    assert_hex(&res_master, RESUMPTION_MASTER, "resumption master secret");
    let resumption = expand_label(&res_master, "resumption", &[0x00, 0x00], 32);
    assert_hex(&resumption, RESUMPTION_SECRET, "resumption secret");
}
