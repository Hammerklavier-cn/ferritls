//! 签名基准：ECDSA P-256/P-384（RFC 6979 确定性 nonce）、Ed25519、
//! RSA-2048（PKCS#1 v1.5 与 PSS 的私钥运算 + 公钥验证）。
//!
//! RSA 密钥为本地生成的 2048 位测试密钥（hex 内嵌，仅用于基准测量，
//! 不承载任何真实身份）；RSA 私钥运算在纯软件实现下较慢，该组调低
//! sample_size。运行：`cargo bench -p ferritls-core --bench sign`。

use criterion::{Criterion, criterion_group, criterion_main};
use ferritls_core::sign;

/// 本地生成的 RSA-2048 测试私钥（PKCS#8 DER，hex）。
const RSA_PKCS8_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100aa5fe49ba0e592f203b1aec89c13de304256dd31c8b9030aaca9d57b4ad77872b2543f041767beda5c61c1ba5892c1995c72ff7840cfab4f700324f034fecbb240f7346c12535b72cd8a29de499df722a921ce2990f5e163fe36c5f025266878afeed8e74fd1d35b3d7f49f66589d07a4d2cd707ee1b69086d9259cb47d6aad8b52b1a72d62c1d713f2bac3f1328d988dc7f3c09799a4d4903d7500b9c76db3df4a8465a89332e39e38cfc87a8636ecfc2159646a93252220885e8124c3d259bdd54b144311dbadf1bef469ae93d08c1acd454947342b8f750d045d8ab82d8d3eaf0c519a87e65112d0f8560ccce5eff9d2069acfd0e482ffcb46a162bf0839d020301000102820100033e903be67478b7e31a1f19f2deedfc3d472a2f28835d6b769e455273ba66b0c874923ea1b3780ef0736c1d0052cb1d0085b017ba243a3ee9032650ecb16d6f978d1d927146e516ea9316f904addd66eb91993b71673d438a33c0d131e3e959630049611e4400a25c29705f20cfdf08752fc5688140445fc4b664bf5a3edc41fc3b99073ec92d0e67e306245529bbac1bf6bbe70540a902f78b2bade7e2920af4279a0a32b3f389aba4b429d07582c6bdcf140fd1d1f2e59afccb2be2d741f11745310cb7823c16eecd816972955120803fadfb92255cac5b2e68a8a7e3a657c1936dd351c69455c904751742666f6b51f9265165e312ffe6c967b11446488102818100d8ae7e446fe069a9d231d5e5640c2a7a37792f050c4f89df01647aea3d7a69ae0b15c9e10eeae4bf1fe19e8027d374260a8108f3067bb4adbaa6e37092bc718a164d42e2939f2359620ec68f5151124a71f0ab07b67ee5ef69c55cdfb3c95ba0d407df404bd419b447d5fc1425f8a4903cdd041a287ad41ca484dd053cdbedab02818100c94a4cd42e6a17f7a47a3dddedde274b6fed7680e86f38d2ebdb3272b0f08f9bc4f2093bc96e64394a912689d608c05ad3ecc8a132c2c69246d0a063c5fc70b745bd84f6d58122c521fdfe9e775aca9b0ce74ea0673d80a08c381230a66e5d524920d0c5c060d5f469b01406312768061093bf4eaf8e593570887a8159e0bbd70281804effdf7d6824b3a17cc73aaaf5bd11c7996e0f5c91ce75ffde6c19fc4909d679e404bfa3d462839fc329e935e44f4deb88acdeec6c12b21f1d0c37a4157bab11a36bebd4dbe98b63cd4281d642d98207ae5f069c3b472ce20af8301247644489f084263b34ea51accefc0f79f11624398a573265af188939202a68c2be1b991d02818100a7c73896bb414f4ce959c2eb92f352c97c37f048ae74d6666895424d7ad268c12bbd9a98ace348c2c036906adf6e57f6dd224670a680d746e1a3cfac9a403a2b6903f92a4cf7e0657459e3bb6e3ccd17c3ffa0f7ee55c33b0ee545b42b655e7fd1d87a6bfa583cbe06c1ef4ee1f5b8ad2570214b92e511d28b4416e86e63f5ed0281806fac5e66bcc2feffb82eee16804e55db90e1c6c01c7019d88a671cef7abbfdc21d34edc555053b793c4ebed6fa4cf819c9f891380b249c8de7c4fc14972b60d71eab74b41458fbcd96e2ee4c085d31dcb074f44c23ac95a339267fa0ff41566aadc5691b8b787cf7860d7e3b87af0ad81463272e90fbea7216934b0ddfea03f0";

/// 对应公钥（SPKI DER，hex）。
const RSA_SPKI_HEX: &str = "30820122300d06092a864886f70d01010105000382010f003082010a0282010100aa5fe49ba0e592f203b1aec89c13de304256dd31c8b9030aaca9d57b4ad77872b2543f041767beda5c61c1ba5892c1995c72ff7840cfab4f700324f034fecbb240f7346c12535b72cd8a29de499df722a921ce2990f5e163fe36c5f025266878afeed8e74fd1d35b3d7f49f66589d07a4d2cd707ee1b69086d9259cb47d6aad8b52b1a72d62c1d713f2bac3f1328d988dc7f3c09799a4d4903d7500b9c76db3df4a8465a89332e39e38cfc87a8636ecfc2159646a93252220885e8124c3d259bdd54b144311dbadf1bef469ae93d08c1acd454947342b8f750d045d8ab82d8d3eaf0c519a87e65112d0f8560ccce5eff9d2069acfd0e482ffcb46a162bf0839d0203010001";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("valid hex"))
        .collect()
}

/// 确定性伪随机填充（bench 内不调 OS 熵）。
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign");
    let msg = pattern(0x7d, 64);

    // ECDSA P-256（SHA-256，RFC 6979）
    let sk256 = sign::ecdsa::p256::SigningKey::from_seed([0x22u8; 32]);
    let pub256 = sk256.public_key_sec1();
    let sig256 = sk256.sign(&msg).expect("p256 sign");
    group.bench_function("ecdsa-p256-sign", |b| {
        b.iter(|| sk256.sign(&msg).expect("p256 sign"))
    });
    group.bench_function("ecdsa-p256-verify", |b| {
        let vk = sign::ecdsa::p256::VerifyKey::from_sec1_point(&pub256).expect("p256 key");
        b.iter(|| vk.verify(&msg, &sig256).expect("p256 verify"))
    });

    // ECDSA P-384（SHA-384，RFC 6979）
    let sk384 = sign::ecdsa::p384::SigningKey::from_seed([0x23u8; 48]);
    let pub384 = sk384.public_key_sec1();
    let sig384 = sk384.sign(&msg).expect("p384 sign");
    group.bench_function("ecdsa-p384-sign", |b| {
        b.iter(|| sk384.sign(&msg).expect("p384 sign"))
    });
    group.bench_function("ecdsa-p384-verify", |b| {
        let vk = sign::ecdsa::p384::VerifyKey::from_sec1_point(&pub384).expect("p384 key");
        b.iter(|| vk.verify(&msg, &sig384).expect("p384 verify"))
    });

    // Ed25519（非批准，但为 TLS 1.3 实际提供的验证算法之一）
    let esk = sign::ed25519::SigningKey::from_seed([0x24u8; 32]);
    let epk = esk.public_key();
    let esig = esk.sign(&msg);
    group.bench_function("ed25519-sign", |b| b.iter(|| esk.sign(&msg)));
    group.bench_function("ed25519-verify", |b| {
        let vk = sign::ed25519::VerifyKey::from_raw_bytes(&epk).expect("ed25519 key");
        b.iter(|| vk.verify(&msg, &esig).expect("ed25519 verify"))
    });

    // RSA-2048：私钥运算较慢，调低 sample_size 控制总时长。
    group.sample_size(20);
    let rsa_sk = sign::rsa::SigningKey::from_pkcs8_der(&hex(RSA_PKCS8_HEX)).expect("rsa key");
    let rsa_pk = sign::rsa::VerifyKey::from_spki_der(&hex(RSA_SPKI_HEX)).expect("rsa pubkey");
    let rsa_sig15 = rsa_sk.sign_pkcs1v15(256, &msg).expect("rsa pkcs1v15 sign");
    let rsa_sig_pss = rsa_sk.sign_pss(256, &msg).expect("rsa pss sign");
    group.bench_function("rsa2048-pkcs1v15-sign", |b| {
        b.iter(|| rsa_sk.sign_pkcs1v15(256, &msg).expect("rsa pkcs1v15 sign"))
    });
    group.bench_function("rsa2048-pkcs1v15-verify", |b| {
        b.iter(|| {
            rsa_pk
                .verify_pkcs1v15(256, &msg, &rsa_sig15)
                .expect("rsa pkcs1v15 verify")
        })
    });
    group.bench_function("rsa2048-pss-sign", |b| {
        b.iter(|| rsa_sk.sign_pss(256, &msg).expect("rsa pss sign"))
    });
    group.bench_function("rsa2048-pss-verify", |b| {
        b.iter(|| {
            rsa_pk
                .verify_pss(256, &msg, &rsa_sig_pss)
                .expect("rsa pss verify")
        })
    });

    group.finish();
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
