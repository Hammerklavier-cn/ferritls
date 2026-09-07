//! CTR-DRBG（NIST SP 800-90A Rev.1 §10.2.1），AES-256 为基、无推导
//! 函数（no df），安全强度 256 位，seedlen = 48 字节。
//!
//! FIPS 批准的随机数发生器：FIPS 模式下所有密钥生成与随机数消费都
//! 必须经由它（OS 熵源直读不构成批准的 RBG）。设计参照 Go 标准库
//! FIPS 模块：生产路径的每次读取都以 128 位内核熵作为 additional
//! input 混入（熵不记入强度，防御熵源退化/状态泄露后的可复制性），
//! 同时保持 2^48 重播种间隔的规范上限。
//!
//! 入口约定：
//! - [`CtrDrbg::new`] / [`CtrDrbg::reseed`] / [`CtrDrbg::generate`] /
//!   [`CtrDrbg::generate_with_ai`] 为 SP 800-90A 的确定性原语
//!   （CAVP DRBGVS 向量可逐字节核对）；
//! - [`CtrDrbg::instantiate_from_os`] + [`CtrDrbg::generate_mixed`]
//!   为生产入口（实例化与健康测试走 OS 熵，每次生成混入 128 位
//!   内核熵）。
//!
//! 安全注意：状态 V/Key `Drop` 零化；生产实例化执行 SP 800-90B
//! 重复计数测试（RCT，C=3）与有界适应性比例测试（APT）。OS 噪声源
//! （getrandom）的连续健康监测属边界外熵源的责任，此处为纵深防御。

use crate::Error;
use crate::aes::Aes256;

/// seedlen：Key（32 字节）+ V（16 字节）。
const SEEDLEN: usize = 48;
/// 单次 Generate 请求上限：2^19 位 = 65536 字节。
const MAX_REQUEST: usize = 65536;
/// 重播种间隔（SP 800-90A 表 3）。
const RESEED_INTERVAL: u64 = 1u64 << 48;

/// SP 800-90A CTR-DRBG（无推导函数，AES-256）。
#[derive(Debug)]
pub struct CtrDrbg {
    aes: Aes256,
    key: [u8; 32],
    v: [u8; 16],
    reseed_counter: u64,
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        self.key.fill(0);
        self.v = [0u8; 16];
    }
}

impl CtrDrbg {
    /// 实例化（SP 800-90A §10.2.1.3.1，无 DF）：`seed_material =
    /// entropy_input || nonce || personalization`；无 DF 的 Update 要求
    /// provided_data 恰为 seedlen 位，超长部分按 seedlen 分块**异或折叠**
    /// （CAVP 中间值证实），不足则末尾补零。初始 Key = 0^256、V = 0^128，
    /// 再以折叠后的 seed_material 做一次 Update。
    pub fn new(entropy_input: &[u8], personalization: &[u8]) -> Result<Self, Error> {
        if entropy_input.len() < SEEDLEN {
            return Err(Error::InvalidInput);
        }
        let mut seed_material = Vec::with_capacity(entropy_input.len() + personalization.len());
        seed_material.extend_from_slice(entropy_input);
        seed_material.extend_from_slice(personalization);
        let seed = xor_fold(&seed_material);
        let mut drbg = Self {
            aes: Aes256::new(&[0u8; 32]),
            key: [0u8; 32],
            v: [0u8; 16],
            reseed_counter: 1,
        };
        drbg.update(&seed);
        Ok(drbg)
    }

    /// 生产实例化：OS 熵 48 字节（经健康测试）+ 个性化串。
    /// 上电自检守卫：未通过则拒绝服务。
    pub fn instantiate_from_os(personalization: &[u8]) -> Result<Self, Error> {
        crate::selftest::ensure_passed()?;
        let mut seed = [0u8; SEEDLEN];
        crate::entropy::fill(&mut seed)?;
        entropy_health_tests(&seed)?;
        Self::new(&seed, personalization)
    }

    /// 重播种（SP 800-90A §10.2.1.4.1，无 DF）：seed_material =
    /// entropy_input || additional_input，按 seedlen 异或折叠。
    pub fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) -> Result<(), Error> {
        if entropy_input.len() < SEEDLEN {
            return Err(Error::InvalidInput);
        }
        let mut seed_material = Vec::with_capacity(entropy_input.len() + additional_input.len());
        seed_material.extend_from_slice(entropy_input);
        seed_material.extend_from_slice(additional_input);
        let seed = xor_fold(&seed_material);
        self.update(&seed);
        self.reseed_counter = 1;
        Ok(())
    }

    /// 生成随机字节（确定性，无 additional input；CAVP 入口）。
    pub fn generate(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.generate_with_ai(out, None)
    }

    /// 生成随机字节（SP 800-90A §10.2.1.2，无 DF）。
    /// `additional_input` 非空时按规范在输出块生成前后各做一次 Update。
    pub fn generate_with_ai(
        &mut self,
        out: &mut [u8],
        additional_input: Option<&[u8]>,
    ) -> Result<(), Error> {
        if out.len() > MAX_REQUEST {
            return Err(Error::RngError);
        }
        if self.reseed_counter > RESEED_INTERVAL {
            return Err(Error::RngError);
        }
        if let Some(ai) = additional_filter(additional_input) {
            let seed = xor_fold(ai);
            self.update(&seed);
        }
        let mut temp = Vec::with_capacity(out.len() + 15);
        while temp.len() < out.len() {
            increment_v(&mut self.v);
            let mut block = self.v;
            self.aes.encrypt_block(&mut block);
            temp.extend_from_slice(&block);
        }
        out.copy_from_slice(&temp[..out.len()]);
        zeroize_vec(&mut temp);
        // §10.2.1.2 末次 Update 无条件执行：provided_data = additional_input
        //（空则 0^seedlen）——CAVP 中间值（Generate 后 Key/V 变化）证实
        let pd = match additional_filter(additional_input) {
            Some(ai) => xor_fold(ai),
            None => [0u8; SEEDLEN],
        };
        self.update(&pd);
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }

    /// 生产生成入口：每次调用先取 128 位内核熵作为 additional input
    /// （Go FIPS 模块策略），输出即使状态泄露/被复制也不可预测。
    pub fn generate_mixed(&mut self, out: &mut [u8]) -> Result<(), Error> {
        crate::selftest::ensure_passed()?;
        let mut ai = [0u8; 16];
        crate::entropy::fill(&mut ai)?;
        self.generate_with_ai(out, Some(&ai))
    }

    /// CTR_DRBG_Update（无 DF，§10.2.1.1）：temp = AES-256-CTR(Key, V++)，
    /// Key/V ← temp ⊕ provided_data。
    fn update(&mut self, provided_data: &[u8]) {
        let mut temp = [0u8; SEEDLEN];
        let mut chunk = [0u8; 16];
        for part in temp.chunks_mut(16) {
            increment_v(&mut self.v);
            chunk.copy_from_slice(&self.v);
            self.aes.encrypt_block(&mut chunk);
            part.copy_from_slice(&chunk);
        }
        for (i, b) in temp.iter_mut().enumerate() {
            *b ^= provided_data[i];
        }
        self.key.copy_from_slice(&temp[..32]);
        self.aes = Aes256::new(&self.key);
        self.v.copy_from_slice(&temp[32..48]);
        temp.fill(0);
    }
}

/// 无 DF 的 seed_material 归约：按 seedlen 分块异或折叠（末块不足
/// 补零）；len ≤ seedlen 时等价于补零截取。
fn xor_fold(seed_material: &[u8]) -> [u8; SEEDLEN] {
    let mut out = [0u8; SEEDLEN];
    for chunk in seed_material.chunks(SEEDLEN) {
        for (i, b) in chunk.iter().enumerate() {
            out[i] ^= b;
        }
    }
    out
}

/// additional_input 语义归一：None 与 Some(空) 等价（规范中 Null）。
fn additional_filter(ai: Option<&[u8]>) -> Option<&[u8]> {
    match ai {
        Some(b) if !b.is_empty() => Some(b),
        _ => None,
    }
}

/// V ← V + 1 (mod 2^128)，大端进位。
fn increment_v(v: &mut [u8; 16]) {
    for i in (0..16).rev() {
        let (nv, ov) = v[i].overflowing_add(1);
        v[i] = nv;
        if !ov {
            break;
        }
    }
}

fn zeroize_vec(v: &mut [u8]) {
    for b in v.iter_mut() {
        *b = 0;
    }
}

/// SP 800-90B 健康测试（对实例化/重播种熵材料的纵深防御检查）：
/// - 重复计数测试（RCT，C = 3）：不允许 3 个连续相同字节；
/// - 有界适应性比例测试（APT）：48 字节窗口内首个字节出现 ≥ 6 次
///   即失败（完整 APT 窗口为 4096 样本，此处为边界内可行的收缩版）。
fn entropy_health_tests(seed: &[u8; SEEDLEN]) -> Result<(), Error> {
    let mut run = 1u8;
    for i in 1..seed.len() {
        if seed[i] == seed[i - 1] {
            run += 1;
            if run >= 3 {
                return Err(Error::EntropyFailed);
            }
        } else {
            run = 1;
        }
    }
    let first = seed[0];
    if seed.iter().filter(|&&b| b == first).count() >= 6 {
        return Err(Error::EntropyFailed);
    }
    Ok(())
}

#[cfg(test)]
mod health_tests {
    use super::*;

    #[test]
    fn rct_rejects_three_identical() {
        let mut seed = [0u8; SEEDLEN];
        (0..48u8).for_each(|i| seed[i as usize] = i);
        seed[10] = 0xAA;
        seed[11] = 0xAA;
        seed[12] = 0xAA;
        assert_eq!(entropy_health_tests(&seed), Err(Error::EntropyFailed));
        // 两个相同可接受
        seed[12] = 0xAB;
        assert!(entropy_health_tests(&seed).is_ok());
        // 48 字节全同必然触发
        let same = [0x11u8; SEEDLEN];
        assert_eq!(entropy_health_tests(&same), Err(Error::EntropyFailed));
    }

    #[test]
    fn apt_rejects_high_repetition_of_first_byte() {
        let mut seed = [0u8; SEEDLEN];
        (0..48u8).for_each(|i| seed[i as usize] = i);
        // 首字节 0x00 共出现 6 次（位置 0 与 1..5）；无 3 连重复
        for s in seed.iter_mut().take(6).skip(1) {
            *s = 0x00;
        }
        assert_eq!(entropy_health_tests(&seed), Err(Error::EntropyFailed));
    }
}
#[cfg(test)]
mod probe2 {
    use super::*;

    fn hx(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // CAVP [AES-256 no df] PS=384 AI=0 COUNT=0
    const EI: &str = "b5e2af38591a9743e5d3e458848a3998536d3b625e1694be847f95c3bfbda267f08624be4bb6aa496e1b596be523e7c4";
    const PS: &str = "0a9a59e7605c0e12fae317bb004aecf1427bda4dca7718801895c38179fd36cd922634c3789a99b9d9c556fe50a41de4";
    const EXP_KEY: &str = "ec777c24fe03afe8b6534712400ba6e2dfb1a112d901e7509ba493917cb309b2";
    const EXP_V: &str = "10c013b7048a1984667cfa1bc081cfae";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn ps_interpretations() {
        let ei = hex(EI);
        let ps = hex(PS);
        // (a) 忽略 PS（规范左截断解释）
        let d = CtrDrbg::new(&ei, &ps).unwrap();
        println!(
            "(a) new(ei, ps)  match: {}",
            hx(&d.key) == EXP_KEY && hx(&d.v) == EXP_V
        );
        // (b) 忽略 PS
        let d = CtrDrbg::new(&ei, b"").unwrap();
        println!(
            "(b) new(ei, '')  match: {}",
            hx(&d.key) == EXP_KEY && hx(&d.v) == EXP_V
        );
        // (c) seed = ei ⊕ ps
        let mut x = ei.clone();
        for (a, b) in x.iter_mut().zip(ps.iter()) {
            *a ^= b;
        }
        let d = CtrDrbg::new(&x, b"").unwrap();
        println!(
            "(c) ei xor ps    match: {}",
            hx(&d.key) == EXP_KEY && hx(&d.v) == EXP_V
        );
        // (d) seed = ps
        let d = CtrDrbg::new(&ps, b"").unwrap();
        println!(
            "(d) ps only      match: {}",
            hx(&d.key) == EXP_KEY && hx(&d.v) == EXP_V
        );
        // (e) update(ei) 后再 update(ps)：手动构造
        let mut d = CtrDrbg::new(&[0u8; 48], b"").unwrap();
        d.update(&{
            let mut s = [0u8; SEEDLEN];
            s[..48].copy_from_slice(&ei);
            s
        });
        d.update(&{
            let mut s = [0u8; SEEDLEN];
            s[..48].copy_from_slice(&ps);
            s
        });
        println!(
            "(e) upd(ei)+upd(ps) match: {}",
            hx(&d.key) == EXP_KEY && hx(&d.v) == EXP_V
        );
        println!("expect Key = {EXP_KEY}");
        println!("expect V   = {EXP_V}");
    }
}
