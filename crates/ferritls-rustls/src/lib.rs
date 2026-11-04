//! # ferritls-rustls
//!
//! A [rustls](https://docs.rs/rustls) 0.23 `CryptoProvider` backed by
//! [`ferritls_core`]: a pure-Rust cryptographic core with no C, no
//! assembly and no `unsafe` code, organized as a FIPS 140-3 module
//! boundary.
//!
//! This crate sits **outside** the FIPS boundary: it only assembles
//! rustls traits from core primitives and contains no cryptography
//! itself, which isolates rustls version churn to this layer.
//!
//! ## Getting started
//!
//! Install the provider once per process, then use rustls as usual:
//!
//! ```no_run
//! ferritls_rustls::default_provider()
//!     .install_default()
//!     .expect("ferritls is the first CryptoProvider installed");
//!
//! // `ClientConfig::builder()` / `ServerConfig::builder()` now pick up
//! // the process-default provider:
//! let config = rustls::ClientConfig::builder()
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth();
//! ```
//!
//! `install_default()` fails if another provider has already claimed the
//! process default (for example a `ring`/`aws-lc-rs` default pulled in
//! by another dependency — see the [reqwest notes](#using-with-reqwest)
//! below).
//!
//! To avoid process-global state, pass the provider explicitly:
//!
//! ```no_run
//! use std::sync::Arc;
//!
//! let provider = Arc::new(ferritls_rustls::default_provider());
//!
//! let client_config = rustls::ClientConfig::builder_with_provider(provider.clone())
//!     .with_safe_default_protocol_versions()
//!     .expect("rustls defaults")
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth();
//! ```
//!
//! Server side (certificate chain and private key loaded from your own
//! storage; PKCS#8 / SEC1 DER and PEM via `rustls::pki_types`):
//!
//! ```no_run
//! # use std::sync::Arc;
//! # fn example(
//! #     certs: Vec<rustls::pki_types::CertificateDer<'static>>,
//! #     key: rustls::pki_types::PrivateKeyDer<'static>,
//! # ) {
//! let provider = Arc::new(ferritls_rustls::default_provider());
//!
//! let server_config = rustls::ServerConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()
//!     .expect("rustls defaults")
//!     .with_no_client_auth()
//!     .with_single_cert(certs, key)
//!     .expect("valid server certificate chain");
//! # }
//! ```
//!
//! Signing keys are loaded through the provider's `key_provider`; the
//! supported private-key formats are ECDSA (SEC1/PKCS#8), RSA (PKCS#8)
//! and Ed25519 (PKCS#8).
//!
//! ## Capabilities
//!
//! **Cipher suites (TLS 1.3 only)** — order equals preference:
//!
//! | Suite | Default mode | Approved mode | QUIC |
//! |---|---|---|---|
//! | `TLS_AES_128_GCM_SHA256` | yes | yes | yes |
//! | `TLS_AES_256_GCM_SHA384` | yes | yes | yes |
//! | `TLS_CHACHA20_POLY1305_SHA256` | yes | no (not NIST-approved) | yes |
//! | `TLS_AES_128_CCM_SHA256` | yes | yes | no |
//! | `TLS_AES_128_CCM_8_SHA256` | yes | no (8-byte tag outside SP 800-52r2) | no |
//!
//! **Key exchange groups**: X25519, secp256r1, secp384r1, the
//! X25519MLKEM768 hybrid (0x11EC, draft-ietf-tls-ecdhe-mlkem) and the
//! pure ML-KEM groups MLKEM512/768/1024 (0x0200–0x0202,
//! draft-ietf-tls-mlkem-key-agreement). Approved mode offers the
//! SP 800-52r2 approved subset (P-256/384 + X25519MLKEM768 + ML-KEM).
//!
//! **Signature verification**: ECDSA P-256/384 (SHA-256/384/512),
//! RSA-PSS and RSA PKCS#1 v1.5 (SHA-256/384/512), Ed25519 (default
//! mode only — EdDSA is not a FIPS-approved signature algorithm).
//!
//! ## Approved ("FIPS") mode
//!
//! [`fips_mode_provider()`] returns a provider restricted to
//! NIST-approved algorithms: AES-GCM/CCM suites, P-256/384 + ML-KEM key
//! exchange, ECDSA/RSA verification, an SP 800-90A CTR-DRBG random
//! source (reseeded with OS entropy on every generate) and power-on
//! self-test KATs. The same restriction is available at compile time
//! via the `fips` cargo feature.
//!
//! ```no_run
//! let provider = ferritls_rustls::fips_mode_provider();
//! ```
//!
//! **`fips()` semantics (important)**: ferritls is **not yet
//! CMVP-validated**, so every `fips()` hook on this provider returns
//! `false`. [`fips_mode_provider()`] means "runs in the approved
//! algorithm mode", not a certification claim. Once validation lands, a
//! separate `fips-validated` feature on a locked source snapshot will
//! flip that semantics (see `docs/FIPS.md`, phase C).
//!
//! ## QUIC
//!
//! The AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 suites implement
//! `rustls::quic::Algorithm` (RFC 9001 packet protection: packet keys,
//! header protection and multipath `for_path`), so they can be used
//! with QUIC stacks such as quinn:
//!
//! ```no_run
//! let provider = std::sync::Arc::new(ferritls_rustls::default_provider());
//! let mut config = rustls::ClientConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()
//!     .expect("rustls defaults")
//!     .with_root_certificates(rustls::RootCertStore::empty())
//!     .with_no_client_auth();
//! config.alpn_protocols = vec![b"h3".to_vec()];
//! // Feed `config` to your QUIC stack (e.g. quinn::crypto::rustls).
//! ```
//!
//! The CCM suites report `quic: None` (RFC 9001 §5.1 mandates AES-GCM
//! as the baseline; rustls has no CCM traffic-secrets variant either).
//!
//! ## Using with reqwest
//!
//! reqwest 0.12 and 0.13 both depend on `rustls ^0.23` — the same
//! version line as ferritls — so Cargo unifies everything into a single
//! rustls instance and both generations work out of the box. Pick the
//! **no-provider feature variants**; otherwise reqwest compiles in
//! ring/aws-lc, which may claim the process default provider first
//! (after which `install_default()` fails):
//!
//! ```toml
//! # reqwest 0.13 (rustls is the default TLS backend; system roots via
//! # rustls-platform-verifier)
//! reqwest = { version = "0.13", default-features = false,
//!             features = ["rustls-no-provider", "http2", "charset"] }
//!
//! # reqwest 0.12 (rustls is opt-in; bundled webpki root store)
//! reqwest = { version = "0.12", default-features = false,
//!             features = ["rustls-tls-webpki-roots-no-provider", "http2", "charset"] }
//! # For system root stores use rustls-tls-native-roots-no-provider.
//! ```
//!
//! ```ignore
//! // Install before creating the first Client:
//! ferritls_rustls::default_provider().install_default()?;
//! let client = reqwest::Client::new();
//! ```
//!
//! To avoid process-global state, build a `ClientConfig` explicitly and
//! inject it via `use_preconfigured_tls` (supported in both 0.12 and
//! 0.13). The trust roots and **ALPN** must then be set on the
//! `ClientConfig` yourself: reqwest does not modify a preconfigured
//! config, and a missing ALPN list silently disables HTTP/2. Note that
//! ferritls currently ships TLS 1.3 suites only.
//!
//! ## Build requirements (`simd` default feature)
//!
//! The default `simd` feature of `ferritls-core` uses the standard
//! library's `core::simd` (portable_simd) for explicit vectorization of
//! the AES and ChaCha20 hot paths. It is safe code from `std` (no new
//! dependencies), but on the **stable toolchain** it requires the
//! `RUSTC_BOOTSTRAP=1` environment variable to compile the feature gate:
//!
//! ```bash
//! export RUSTC_BOOTSTRAP=1                                     # (a) keep simd
//! # or, in your Cargo.toml:                                    # (b) scalar fallback
//! # ferritls-core = { version = "0.9", default-features = false }
//! ```
//!
//! Vector width follows the compile target (SSE2/NEON baseline; build
//! with `RUSTFLAGS="-C target-feature=+avx2"` or `-C target-cpu=native`
//! to widen to AVX2/AVX-512). Nightly toolchains need no variable, and
//! the requirement disappears once portable_simd stabilizes.
//!
//! ## Hardware acceleration (optional)
//!
//! [`ferritls-backend-x86_64`](https://docs.rs/ferritls-backend-x86_64)
//! is a separate, out-of-boundary crate (x86_64 only) providing AES-NI +
//! CLMUL whole-message AES-GCM kernels and SHA-NI SHA-256, with runtime
//! CPU detection and install-time KATs. It is opt-in from the
//! application side via `ferritls_core::ops::install()`; nothing changes
//! if it is not installed, and approved mode always stays on the
//! software path.
//!
//! ## Crate layout
//!
//! | Module | Contents |
//! |---|---|
//! | [`provider`] | [`default_provider`] / [`fips_mode_provider`] assembly |
//! | [`cipher`] | TLS 1.3 suite adapters (AEAD, hash, HKDF, QUIC wiring) |
//! | [`kx`] | `SupportedKxGroup` adapters (ECDH, ML-KEM, hybrid) |
//! | [`verify`] | webpki signature-verification algorithms |
//! | [`sign`] | `SigningKey`/`Signer` adapters and the rustls key provider |
//! | [`random`] | `SecureRandom` implementations (OS entropy / CTR-DRBG) |
//! | [`quic`] | `rustls::quic::Algorithm` packet/header protection |

#![forbid(unsafe_code)]

pub mod cipher;
pub mod kx;
pub mod provider;
pub mod quic;
pub mod random;
pub mod sign;
pub mod verify;

pub use provider::{default_provider, fips_mode_provider};
