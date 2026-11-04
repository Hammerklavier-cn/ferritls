//! # ferritls-core
//!
//! Pure-Rust cryptographic primitives, providing everything that
//! [ferritls-rustls](https://docs.rs/ferritls-rustls) (the rustls
//! `CryptoProvider` adapter) needs. No C, no assembly, no `unsafe`.
//!
//! ## FIPS 140-3 module boundary
//!
//! This crate is the **module boundary** intended for future CMVP
//! validation: every algorithm is implemented in-boundary in pure Rust
//! (`#![forbid(unsafe_code)]`), and the dependency whitelist is exactly
//! [`subtle`], [`zeroize`] and [`getrandom`] (OS entropy input). New
//! dependencies require updating the whitelist and audit rationale in
//! `docs/FIPS.md` first (AGENTS.md hard rule 2).
//!
//! Note that the module is **not yet CMVP-validated**; the `fips` cargo
//! feature selects the approved-algorithm mode, it is not a
//! certification claim.
//!
//! ## Default feature `simd`
//!
//! The default `simd` feature uses the standard library's `core::simd`
//! (portable_simd) for explicit vectorization of the AES and ChaCha20
//! hot paths — `std` code, not a third-party dependency, so the
//! whitelist is unchanged. On the **stable toolchain** it compiles via
//! `RUSTC_BOOTSTRAP=1` (provided by this repository's
//! `.cargo/config.toml`; downstream users set the env themselves or opt
//! out with `default-features = false`, which keeps the scalar fallback
//! path). Vector width follows the compile target (SSE2/NEON baseline,
//! widening to AVX2/AVX-512 with the corresponding `target-feature`
//! RUSTFLAGS); there is no runtime dispatch and no `unsafe`.
//!
//! ## Usage
//!
//! Hashing:
//!
//! ```
//! use ferritls_core::sha2::Sha256;
//!
//! let digest = Sha256::one_shot(b"abc");
//! assert_eq!(&digest[..4], &[0xba, 0x78, 0x16, 0xbf]); // FIPS 180-4 example
//! ```
//!
//! Authenticated encryption (AES-128-GCM; the same shape exists for
//! [`gcm::Aes256Gcm`], [`ccm`] and [`chacha20poly1305`]):
//!
//! ```
//! use ferritls_core::gcm::Aes128Gcm;
//!
//! let cipher = Aes128Gcm::new(&[7u8; 16]);
//! let nonce = [9u8; 12]; // unique per key — never repeat a (key, nonce) pair
//!
//! let ct_and_tag = cipher.seal(&nonce, b"aad", b"plaintext");
//! let plaintext = cipher.open(&nonce, b"aad", &ct_and_tag).expect("authentic");
//! assert_eq!(plaintext, b"plaintext");
//!
//! // Tampered ciphertexts fail verification before any plaintext is returned:
//! let mut tampered = ct_and_tag.clone();
//! tampered[0] ^= 0x01;
//! assert!(cipher.open(&nonce, b"aad", &tampered).is_err());
//! ```
//!
//! Key agreement, signatures, KEMs and the DRBG follow the same pattern:
//! typed keys, explicit errors (no panics on attacker-controlled input),
//! and zeroization of secret material on drop.
//!
//! ## Module map
//!
//! | Module | Contents | FIPS approval |
//! |---|---|---|
//! | [`sha2`] | SHA-256/384/512 | approved |
//! | [`sha3`] | SHA3-224/256/384/512, SHAKE-128/256 (full FIPS 202 family) | approved |
//! | [`hmac`] / [`hkdf`] | HMAC, HKDF | approved |
//! | [`aes`] / [`gcm`] / [`ccm`] | AES, AES-GCM, AES-CCM | approved |
//! | [`chacha20poly1305`] | ChaCha20-Poly1305 | not approved |
//! | [`ecdh`] | X25519 (not approved), P-256/384 (approved) | mixed |
//! | [`mlkem`] | ML-KEM-512/768/1024 (FIPS 203) | approved |
//! | [`sign`] | ECDSA, RSA (approved), Ed25519 (not approved) | mixed |
//! | [`drbg`] / [`entropy`] | SP 800-90A CTR-DRBG, OS entropy | approved |
//! | [`selftest`] | Power-on self-tests (KATs) | required |
//! | [`der`] | Minimal DER/PKCS#8/SEC1 parsing | — |
//! | [`ct`] / [`policy`] / [`ops`] | Constant-time utilities, approval policy, backend dispatch | — |
//!
//! All modules are fully implemented and covered by official
//! NIST/RFC/CAVP vectors, Wycheproof and the RFC 8448 key schedule (see
//! `docs/VECTOR-PROVENANCE.md` for sources). AES-GCM and SHA-256 public
//! types dispatch through [`ops`]: the default is a zero-overhead direct
//! software path, and an optional out-of-boundary hardware backend crate
//! can be installed to replace the execution core (see [`ops`]).

#![forbid(unsafe_code)]
// Default feature `simd`: explicit core::simd (portable_simd) paths — std
// code, entirely safe. On stable toolchains the feature gate compiles via
// RUSTC_BOOTSTRAP=1 (repo .cargo/config.toml [env] / CI env; downstream
// users provide the env or opt out with default-features = false, which
// keeps the scalar fallback). Constraints and lane-width selection rules:
// AGENTS.md §5.5. Remove the bootstrap dependency once portable_simd
// stabilizes.
#![cfg_attr(feature = "simd", feature(portable_simd))]
// Future hardware backends (AES-NI/SHA extensions) inevitably need unsafe;
// they must not enter this crate — they live in separate out-of-boundary
// backend crates hooked up through the ops module traits (see the ops
// module docs and docs/ARCHITECTURE.md). Whether such a backend ever joins
// the FIPS boundary is a phase-C decision.

/// Compile canary for the `simd` feature: ensures portable_simd is truly
/// available in the current configuration (the hot paths live in the
/// [`aes`] and [`chacha20poly1305`] modules).
#[cfg(feature = "simd")]
#[allow(dead_code)]
fn _portable_simd_canary(v: std::simd::u32x4) -> std::simd::u32x4 {
    v + std::simd::u32x4::splat(1)
}

pub mod aes;
pub mod ccm;
pub mod chacha20poly1305;
pub mod ct;
pub mod der;
pub mod drbg;
pub mod ecdh;
pub mod entropy;
mod fields;
pub mod gcm;
pub mod hkdf;
pub mod hmac;
pub mod mlkem;
pub mod ops;
pub mod policy;
mod rsabig;
pub mod selftest;
pub mod sha2;
pub mod sha3;
pub mod sign;

pub use policy::Approval;

/// The unified error type of the module boundary.
///
/// Rule: attacker-controlled input (network data, certificates, key
/// files) must never panic — every failure is returned as this error
/// (AGENTS.md hard rule 4). `non_exhaustive`: variants may be added as
/// milestones land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Input length or format does not satisfy the algorithm's requirements.
    InvalidInput,
    /// Verification of a key/IV/tag failed (AEAD open, signature
    /// verification, etc.). Comparisons are constant-time; the error must
    /// not distinguish failure reasons.
    VerificationFailed,
    /// The requested algorithm or curve is unavailable in this build
    /// (approved mode).
    Unsupported,
    /// Entropy source failure (OS randomness unavailable).
    EntropyFailed,
    /// DRBG failure (health test failed, generation limit exceeded, etc.).
    RngError,
    /// Power-on self-test failed: the module is in an error state and
    /// refuses service until re-initialized.
    SelfTestFailed(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "invalid input length or format"),
            Error::VerificationFailed => write!(f, "verification failed"),
            Error::Unsupported => write!(f, "algorithm unavailable in this build/mode"),
            Error::EntropyFailed => write!(f, "OS entropy source failed"),
            Error::RngError => write!(f, "DRBG failure"),
            Error::SelfTestFailed(which) => {
                write!(f, "power-up self-test failed: {which}")
            }
        }
    }
}

impl std::error::Error for Error {}
