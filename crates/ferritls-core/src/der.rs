//! 最小 DER 解析：PKCS#8 / SEC1 / PKCS#1 私钥与 SPKI 公钥的拆包。
//!
//! 只为 [`crate::sign`] 的密钥加载与 rustls `KeyProvider` 服务，
//! **不是**通用 ASN.1 库。X.509 证书解析由 rustls-webpki 负责，在边界外。
//!
//! 安全：解析对象为攻击者可控输入——任何畸形输入返回
//! [`Error::InvalidInput`](crate::Error)，绝不 panic、绝不越界。

use crate::Error;

/// 算法 OID（DER 编码的 AlgorithmIdentifier 内容里常用值）。
pub mod oid {
    /// id-ecPublicKey（1.2.840.10045.2.1）
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    /// prime256v1（1.2.840.10045.3.1.7）
    pub const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    /// secp384r1（1.3.132.0.34）
    pub const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    /// rsaEncryption（1.2.840.113549.1.1.1）
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    /// Ed25519（1.3.101.112）
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];
}

/// 读取一个 TLV 元素：返回 (tag, 内容切片, 剩余字节)。
pub fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    if input.len() < 2 {
        return Err(Error::InvalidInput);
    }
    let tag = input[0];
    // 长度首字节
    let first = input[1] as usize;
    let (len, rest_off) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        // 长度过长（>4 字节）或非最短编码一律拒绝
        if n == 0 || n > 4 || n + 2 > input.len() {
            return Err(Error::InvalidInput);
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | input[2 + k] as usize;
        }
        // 非最短编码拒绝（首字节为 0）
        if input[2] == 0 {
            return Err(Error::InvalidInput);
        }
        (len, 2 + n)
    };
    if rest_off + len > input.len() {
        return Err(Error::InvalidInput);
    }
    Ok((
        tag,
        &input[rest_off..rest_off + len],
        &input[rest_off + len..],
    ))
}

/// 期望指定 tag 的 TLV。
pub fn expect(tag: u8, input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (t, content, rest) = read_tlv(input)?;
    if t != tag {
        return Err(Error::InvalidInput);
    }
    Ok((content, rest))
}

/// SEQUENCE 内容。
pub fn sequence(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    expect(0x30, input)
}

/// OCTET STRING 内容。
pub fn octet_string(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    expect(0x04, input)
}

/// BIT STRING：去掉首个未使用位数 octet（必须为 0）。
pub fn bit_string(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (content, rest) = expect(0x03, input)?;
    if content.is_empty() || content[0] != 0 {
        return Err(Error::InvalidInput);
    }
    Ok((&content[1..], rest))
}

/// OBJECT IDENTIFIER（返回原始内容字节）。
pub fn object_identifier(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    expect(0x06, input)
}

/// INTEGER：去除符号前导零后的绝对值字节（正数）。
pub fn integer(input: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (content, rest) = expect(0x02, input)?;
    if content.is_empty() {
        return Err(Error::InvalidInput);
    }
    // 正整数：首字节高位为 0，或长度 1
    if content[0] & 0x80 != 0 {
        return Err(Error::InvalidInput);
    }
    // 去除多余前导零
    let mut s = 0;
    while s + 1 < content.len() && content[s] == 0 {
        s += 1;
    }
    Ok((&content[s..], rest))
}

/// 解析后的私钥内容（按算法分派给 [`crate::sign`] 各类型）。
#[derive(Debug)]
pub enum ParsedPrivateKey {
    /// P-256：SEC1 OCTET STRING 内的 32 字节标量。
    P256 {
        /// 未压缩 SEC1 公钥点（0x04||X||Y），SEC1 结构中可选携带。
        public_sec1: Option<Vec<u8>>,
    },
    /// P-384：SEC1 内的 48 字节标量。
    P384 {
        /// 未压缩 SEC1 公钥点。
        public_sec1: Option<Vec<u8>>,
    },
    /// RSA PKCS#1 私钥（DER 内容，供 sign::rsa 二次解析）。
    RsaPkcs1(Vec<u8>),
    /// Ed25519：32 字节种子。
    Ed25519(Vec<u8>),
}

/// 解析 PKCS#8 PrivateKeyInfo（RFC 5958/5208）。
///
/// PrivateKeyInfo ::= SEQUENCE {
///   version INTEGER (0),
///   privateKeyAlgorithm AlgorithmIdentifier,
///   privateKey OCTET STRING,
///   attributes [0] IMPLICIT OPTIONAL }
pub fn parse_pkcs8_private_key(der: &[u8]) -> Result<ParsedPrivateKey, Error> {
    let (seq, rest) = sequence(der)?;
    // PKCS#8 后不得有剩余字节
    if !rest.is_empty() {
        return Err(Error::InvalidInput);
    }
    let (version, rest) = integer(seq)?;
    if version.len() != 1 || version[0] != 0 {
        return Err(Error::InvalidInput);
    }
    // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY }
    let (alg_seq, rest) = sequence(rest)?;
    let (oid, alg_rest) = object_identifier(alg_seq)?;
    let (_ptag, _params, _alg_rest_rest) = match read_tlv(alg_rest) {
        Ok(x) => x,
        Err(_) => return Err(Error::InvalidInput),
    };
    let (key_bytes, rest) = octet_string(rest)?;
    // [0] attributes 可选——存在则忽略，但必须是 context-tag 0
    if !rest.is_empty() && rest[0] != 0xa0 {
        return Err(Error::InvalidInput);
    }

    if oid == oid::ED25519 {
        // Ed25519 私钥 = OCTET STRING(32)
        let (seed, inner_rest) = octet_string(key_bytes)?;
        if !inner_rest.is_empty() || seed.len() != 32 {
            return Err(Error::InvalidInput);
        }
        return Ok(ParsedPrivateKey::Ed25519(seed.to_vec()));
    }
    if oid == oid::RSA_ENCRYPTION {
        // 内层 OCTET STRING = PKCS#1 RSAPrivateKey DER
        let (pkcs1, inner_rest) = octet_string(key_bytes)?;
        if !inner_rest.is_empty() {
            return Err(Error::InvalidInput);
        }
        return Ok(ParsedPrivateKey::RsaPkcs1(pkcs1.to_vec()));
    }
    if oid == oid::EC_PUBLIC_KEY {
        // parameters = namedCurve OID
        let (_ptag, params, _alg_rest_rest) = read_tlv(alg_rest)?;
        if params[0] != 0x06 {
            return Err(Error::InvalidInput);
        }
        let curve_oid = &params[2..];
        let curve = if curve_oid == oid::PRIME256V1 {
            32usize
        } else if curve_oid == oid::SECP384R1 {
            48usize
        } else {
            return Err(Error::InvalidInput);
        };
        // SEC1 ECPrivateKey ::= SEQUENCE { version INTEGER(1), privateKey OCTET STRING,
        //   publicKey [1] BIT STRING OPTIONAL }
        let (sec1, sec1_rest) = sequence(key_bytes)?;
        if !sec1_rest.is_empty() {
            return Err(Error::InvalidInput);
        }
        let (sec_ver, sec1_rest) = integer(sec1)?;
        if sec_ver.len() != 1 || sec_ver[0] != 1 {
            return Err(Error::InvalidInput);
        }
        let (priv_key, sec1_rest) = octet_string(sec1_rest)?;
        if priv_key.len() != curve || !sec1_rest.is_empty() && sec1_rest[0] != 0xa1 {
            return Err(Error::InvalidInput);
        }
        // 可选公钥 [1] BIT STRING
        let mut public_sec1 = None;
        if !sec1_rest.is_empty() {
            let (pub_bits, pub_rest) = bit_string(sec1_rest)?;
            if !pub_rest.is_empty() {
                return Err(Error::InvalidInput);
            }
            if pub_bits.len() != 1 + 2 * curve || pub_bits[0] != 0x04 {
                return Err(Error::InvalidInput);
            }
            public_sec1 = Some(pub_bits.to_vec());
        }
        return if curve == 32 {
            Ok(ParsedPrivateKey::P256 { public_sec1 })
        } else {
            Ok(ParsedPrivateKey::P384 { public_sec1 })
        };
    }
    Err(Error::InvalidInput)
}
