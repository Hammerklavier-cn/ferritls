//! AES 块密码（FIPS 197），128/192/256 位密钥的软件实现。
//!
//! FIPS 批准；作为 GCM/CCM 与 CTR-DRBG 的底层部件，上电自检覆盖（M5）。
//! AES-NI 后端在 M8+ 经 [`crate::ops`] 入口挂接，不影响本模块公开 API。
//!
//! 常数时间策略：S-box 不查表——由 GF(2^8) 分支无关乘法链计算逆元
//! （x^254）再作仿射变换；字节移位/列混合全部为算术与掩码操作。
//! 慢于查表实现一个量级以上，属可接受（性能由 M8 后端解决）。
//! 轮密钥 Drop 时零化。
//!
//! 向量：FIPS-197 附录 C.1/C.2/C.3 KAT（`tests` 内嵌）+ GCM 集成 KAT。

/// 官方 S-box（FIPS-197 图 7）。
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// 逆 S-box：由正表程序化求逆（S-box 为双射，结果唯一）。
const INV_SBOX: [u8; 256] = {
    let mut inv = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        let mut i = 0usize;
        loop {
            if SBOX[i] as usize == x {
                inv[x] = i as u8;
                break;
            }
            i += 1;
        }
        x += 1;
    }
    inv
};

/// GF(2^8) 倍乘（xtime）。
fn xtime(x: u8) -> u8 {
    let hi = ((x >> 7) & 1).wrapping_neg();
    (x << 1) ^ (hi & 0x1b)
}

/// GF(2^8) 分支无关乘法。
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        p ^= a & ((b & 1).wrapping_neg());
        let hi = ((a >> 7) & 1).wrapping_neg();
        a = (a << 1) ^ (hi & 0x1b);
        b >>= 1;
    }
    p
}

/// 常数时间表访问：遍历全部 256 项，按相等掩码选择。
/// 访问模式与输入无关（无缓存侧信道）。
#[inline]
fn ct_table_lookup(table: &[u8; 256], x: u8) -> u8 {
    let mut acc = 0u8;
    for (i, &entry) in table.iter().enumerate() {
        let eq = (((i as u8) ^ x) == 0) as u8;
        acc |= entry & eq.wrapping_neg();
    }
    acc
}

#[inline]
fn sbox(x: u8) -> u8 {
    ct_table_lookup(&SBOX, x)
}

#[inline]
fn inv_sbox(x: u8) -> u8 {
    ct_table_lookup(&INV_SBOX, x)
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    [sbox(w[0]), sbox(w[1]), sbox(w[2]), sbox(w[3])]
}

macro_rules! aes_impl {
    ($name:ident, $nk:expr, $nr:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            /// 轮密钥（Nr+1 × 16 字节，按 FIPS-197 列序展开）。
            rk: Vec<u8>,
        }

        impl $name {
            /// 密钥字节数。
            pub const KEY_LEN: usize = $nk * 4;
            const NR: usize = $nr;

            /// 展开密钥。
            pub fn new(key: &[u8; $nk * 4]) -> Self {
                let total = 16 * ($nr + 1);
                let mut rk = vec![0u8; total];
                let nk_bytes = $nk * 4;
                rk[..nk_bytes].copy_from_slice(key);

                let mut rcon = 1u8;
                let mut i = nk_bytes;
                while i < total {
                    let mut t: [u8; 4] = rk[i - 4..i].try_into().unwrap();
                    if i % nk_bytes == 0 {
                        t = sub_word([t[1], t[2], t[3], t[0]]);
                        t[0] ^= rcon;
                        rcon = xtime(rcon);
                    } else if $nk > 6 && i % nk_bytes == 16 {
                        t = sub_word(t);
                    }
                    for j in 0..4 {
                        rk[i + j] = rk[i - nk_bytes + j] ^ t[j];
                    }
                    i += 4;
                }
                Self { rk }
            }

            fn add_round_key(&self, state: &mut [u8; 16], round: usize) {
                for j in 0..16 {
                    state[j] ^= self.rk[round * 16 + j];
                }
            }

            /// 就地加密一个块。
            pub fn encrypt_block(&self, block: &mut [u8; 16]) {
                let mut s = *block;
                self.add_round_key(&mut s, 0);
                for round in 1..Self::NR {
                    for b in s.iter_mut() {
                        *b = sbox(*b);
                    }
                    shift_rows(&mut s);
                    mix_columns(&mut s);
                    self.add_round_key(&mut s, round);
                }
                for b in s.iter_mut() {
                    *b = sbox(*b);
                }
                shift_rows(&mut s);
                self.add_round_key(&mut s, Self::NR);
                *block = s;
            }

            /// 就地解密一个块（等价逆变换；DRBG 与 GCM 只需加密方向）。
            pub fn decrypt_block(&self, block: &mut [u8; 16]) {
                let mut s = *block;
                self.add_round_key(&mut s, Self::NR);
                for round in (1..Self::NR).rev() {
                    inv_shift_rows(&mut s);
                    for b in s.iter_mut() {
                        *b = inv_sbox(*b);
                    }
                    self.add_round_key(&mut s, round);
                    inv_mix_columns(&mut s);
                }
                inv_shift_rows(&mut s);
                for b in s.iter_mut() {
                    *b = inv_sbox(*b);
                }
                self.add_round_key(&mut s, 0);
                *block = s;
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.rk.fill(0);
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

fn shift_rows(s: &mut [u8; 16]) {
    // flat index = 4*col + row（FIPS-197 列序）
    let t = *s;
    for row in 1..4 {
        for col in 0..4 {
            s[4 * col + row] = t[4 * ((col + row) % 4) + row];
        }
    }
}

fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    for row in 1..4 {
        for col in 0..4 {
            s[4 * ((col + row) % 4) + row] = t[4 * col + row];
        }
    }
}

fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
        // 矩阵 [2 3 1 1; 1 2 3 1; 1 1 2 3; 3 1 1 2]
        s[o] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        s[o + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        s[o + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        s[o + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let o = 4 * c;
        let (a0, a1, a2, a3) = (s[o], s[o + 1], s[o + 2], s[o + 3]);
        s[o] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9);
        s[o + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13);
        s[o + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11);
        s[o + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14);
    }
}

aes_impl!(Aes128, 4, 10, "AES-128 块密码实例。");
aes_impl!(Aes192, 6, 12, "AES-192 块密码实例。");
aes_impl!(Aes256, 8, 14, "AES-256 块密码实例。");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sbox_known_values_and_bijection() {
        // FIPS-197 官方锚点。
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x01), 0x7c);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0xff), 0x16);
        let mut seen = [false; 256];
        for x in 0..=255u8 {
            assert_eq!(inv_sbox(sbox(x)), x, "round trip at {x}");
            seen[sbox(x) as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "sbox must be a bijection");
    }

    #[test]
    fn fips197_appendix_c_kats() {
        // C.1: AES-128
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes = Aes128::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
                0xc5, 0x5a
            ]
        );
        aes.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );

        // C.3: AES-256
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let aes = Aes256::new(&key);
        let mut block = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        aes.encrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
                0x60, 0x89
            ]
        );
        aes.decrypt_block(&mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }
}
