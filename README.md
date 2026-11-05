# ferritls

[English](README.md) | [简体中文](README.zh.md)

ferritls is a pure-Rust [rustls](https://github.com/rustls/rustls)
`CryptoProvider`: no C, no assembly, no `unsafe` in the cryptographic
core, organized as a FIPS 140-3 cryptographic module boundary. It is a
maintained, fully auditable alternative to `aws-lc-rs` (C/assembly,
cmake, slow builds) and the unmaintained `rustls-rustcrypto`.

## Highlights

- **TLS 1.3** cipher suites: AES-128/256-GCM, AES-128-CCM (and CCM_8),
  ChaCha20-Poly1305
- **Key exchange**: X25519, secp256r1, secp384r1, post-quantum
  **ML-KEM** 512/768/1024 (FIPS 203) and the X25519MLKEM768 hybrid
- **Certificate signatures**: ECDSA P-256/384, RSA-PSS / PKCS#1 v1.5,
  Ed25519
- **QUIC** packet protection (RFC 9001) for the GCM and ChaCha suites
- **Approved mode** (`fips` feature): NIST-approved algorithms only,
  SP 800-90A CTR-DRBG, power-on self-tests
- Optional **x86_64 hardware backend** (AES-NI / SHA-NI):
  [`ferritls-backend-x86_64`](https://crates.io/crates/ferritls-backend-x86_64),
  a separate crate registered at runtime (outside the FIPS boundary)
- Tested against NIST/RFC/CAVP vectors, 2,300+ Wycheproof cases,
  cross-interop with rustls-ring, and continuous fuzzing

## Usage

```toml
[dependencies]
ferritls-rustls = "0.9"
```

```rust
// Once per process, before building any TLS config:
ferritls_rustls::default_provider().install_default()?;

// rustls now uses ferritls by default:
let config = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();
```

Prefer to avoid process-global state? Pass the provider explicitly:

```rust
use std::sync::Arc;

let provider = Arc::new(ferritls_rustls::default_provider());
let config = rustls::ClientConfig::builder_with_provider(provider)
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
```

Detailed usage — server configuration, approved mode, QUIC, reqwest
integration — lives in the **[API documentation](https://docs.rs/ferritls-rustls)**.

### Hardware backend (x86_64, optional)

```toml
[dependencies]
ferritls-backend-x86_64 = "0.9"
```

```rust
// Once per process, before constructing any key object (x86_64 only;
// elsewhere this crate is empty and the block compiles away):
#[cfg(target_arch = "x86_64")]
ferritls_backend_x86_64::install()?;
```

Details — probe/KAT failure modes, the `fips`-build refusal, and
performance numbers — are in the
[`ferritls-backend-x86_64` README](crates/ferritls-backend-x86_64/README.md).

## Build requirements

The default `simd` feature uses the standard library's `core::simd`
(portable_simd), which on the **stable toolchain** requires
`RUSTC_BOOTSTRAP=1` (this repository's `.cargo/config.toml` already
sets it):

```bash
export RUSTC_BOOTSTRAP=1                                     # (a) keep simd
# or, in your Cargo.toml:                                    # (b) scalar fallback
# ferritls-core = { version = "0.9", default-features = false }
```

Nightly toolchains need no variable; the requirement goes away once
portable_simd stabilizes.

## FIPS 140-3 status

ferritls is organized as a FIPS 140-3 cryptographic module boundary
(the `ferritls-core` crate); it is **not yet CMVP-validated**. Every
`fips()` hook returns `false`, and the `fips` feature means "runs in
the approved-algorithm mode", not a certification claim. Roadmap:
[docs/FIPS.md](docs/FIPS.md).

## License

Apache-2.0 OR MIT (see [LICENSE-APACHE](LICENSE-APACHE) and
[LICENSE-MIT](LICENSE-MIT)). Contributors — human or AI agents — should
read [AGENTS.md](AGENTS.md) first.
