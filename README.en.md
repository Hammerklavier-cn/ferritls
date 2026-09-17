# ferritls

[English](README.en.md) | [简体中文](README.md)

A pure-Rust [rustls](https://github.com/rustls/rustls) `CryptoProvider`
backend: no C, no assembly, no `unsafe`, organized as a FIPS 140-3
cryptographic module boundary.

## Why

| Instead of | Pain point | ferritls |
|---|---|---|
| rustls-rustcrypto | Unmaintained (last release 2024-04; README carries a "do not use in production" banner) | Actively maintained; interface pinned to rustls 0.23 |
| aws-lc-rs | C/assembly, cmake, slow builds, bound to AWS-LC | Pure Rust — a plain `cargo build` suffices, and the whole boundary is auditable |

## Capabilities

- **TLS 1.3 suites**: `TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`,
  `TLS_AES_128_CCM_SHA256`
- **Key exchange**: X25519, secp256r1, secp384r1, X25519MLKEM768 hybrid
- **Post-quantum**: FIPS 202 SHA-3/SHAKE and all three FIPS 203
  ML-KEM parameter sets (512/768/1024; implemented in-boundary, zero
  new dependencies, anchored on NIST ACVP vectors); key exchange
  covers the X25519MLKEM768 hybrid (draft-ietf-tls-ecdhe-mlkem,
  codepoint 0x11EC, the channel through which X25519 enters approved
  mode) and the three pure ML-KEM groups
  (draft-ietf-tls-mlkem-key-agreement, codepoints 0x0200-0x0202)
- **QUIC** (RFC 9001, M8.5): QUIC packet protection for the three
  AES-GCM/ChaCha20-Poly1305 suites (`quic::Algorithm`: packet keys +
  header protection + multipath), byte-anchored on RFC 9001 Appendix A
  samples, cross-tested against rustls-ring
- **Signatures / verification**: ECDSA P-256/384,
  RSA-PSS/PKCS#1 (SHA-256/384/512), Ed25519
- **Approved mode** (`fips` feature): NIST-approved algorithms only +
  SP 800-90A CTR-DRBG (reseeded with OS entropy on every generate) +
  power-on self-test KATs
- **Testing surface**: official RFC/NIST/CAVP vectors, NIST ACVP
  ML-KEM-768 vectors, RFC 8448 key schedule, 2,349 Wycheproof cases,
  rustls-ring cross-interop, webpki certificate chains, seven
  cargo-fuzz targets
  ([vector provenance](docs/VECTOR-PROVENANCE.md))
- **Performance** (P1 autovectorization + P2 explicit `std::simd`, on
  by default, still zero `unsafe`): bitsliced AES + grouped GHASH
  tables + batched ChaCha20 — roughly 19-21x faster AES-GCM record
  processing versus the masked-scalar baseline (baseline ISA); building
  with `RUSTFLAGS="-C target-cpu=native"` automatically widens the
  vector channels to AVX2/AVX-512; see the P1/P2 sections of
  [docs/ROADMAP.md](docs/ROADMAP.md)
- **Optional hardware backend** (`ferritls-backend-x86_64`, a separate
  out-of-boundary crate, x86_64 only): whole-message AES-GCM kernels on
  AES-NI + CLMUL and SHA-256 dispatch on SHA-NI, with runtime CPU
  detection and an install-time KAT; approved mode stays on the
  software path — roughly 750-980x faster GCM primitives than the
  software path; see [docs/BENCHMARKS.md](docs/BENCHMARKS.md) §5

```rust
let provider = ferritls_rustls::default_provider();
provider.install_default()?;
// ClientConfig::builder() / ServerConfig::builder() now use it by default.
```

## Using with reqwest

Both reqwest 0.12 and 0.13 depend on `rustls ^0.23` — the same version
line as ferritls, so Cargo unifies them into a single rustls instance
and both generations work out of the box (interop `tests/reqwest.rs`
keeps a loopback-handshake regression guard on the 0.12 line). Pick the
**no-provider feature variants**: otherwise reqwest compiles in
ring/aws-lc, which may claim the process default provider first (after
which `install_default()` fails):

```toml
# reqwest 0.13 (rustls is the default TLS backend; system roots via rustls-platform-verifier)
reqwest = { version = "0.13", default-features = false,
            features = ["rustls-no-provider", "http2", "charset"] }

# reqwest 0.12 (rustls is opt-in; bundled webpki root store)
reqwest = { version = "0.12", default-features = false,
            features = ["rustls-tls-webpki-roots-no-provider", "http2", "charset"] }
# For system root stores use rustls-tls-native-roots-no-provider instead.
```

```rust
// Install before creating the first Client:
ferritls_rustls::default_provider().install_default()?;
let client = reqwest::Client::new();
```

To avoid process-global state, build a `ClientConfig` explicitly and
inject it via `use_preconfigured_tls` (supported in both 0.12 and
0.13); the trust roots and **ALPN** must then be set on the
`ClientConfig` yourself — reqwest does not modify a preconfigured
config, and a missing ALPN list silently disables HTTP/2. Note that
ferritls currently ships TLS 1.3 suites only (TLS 1.2 is an M8
remainder); both reqwest generations behave identically here.

## Build requirements (default `simd` feature)

The default `simd` feature of `ferritls-core` uses the standard
library's `core::simd` (portable_simd), which on the **stable
toolchain** requires the `RUSTC_BOOTSTRAP=1` environment variable
(this repository ships a `.cargo/config.toml` that sets it, so a
cloned checkout builds out of the box):

```bash
# When depending on this crate (crates.io / path / git) — pick one:
export RUSTC_BOOTSTRAP=1                      # (a) keep simd
ferritls-core = { version = "0.6", default-features = false }  # (b) scalar fallback
```

- Vector width follows the compile target: the default x86-64/aarch64
  baselines (SSE2/NEON); building with
  `RUSTFLAGS="-C target-feature=+avx2"` or `-C target-cpu=native`
  automatically widens the same source to AVX2/AVX-512 channels.
- Once portable_simd stabilizes on a Rust release, this environment
  variable requirement goes away.
- Nightly toolchains need no variable (feature gates are native).

## FIPS 140-3 statement

ferritls is organized as a FIPS 140-3 cryptographic module boundary
(the boundary is the `ferritls-core` crate), and is **not yet
CMVP-validated**: every `fips()` hook returns `false` until
certification lands, and the `fips` feature means "runs in the approved
algorithm mode", not a certification claim. No pure-Rust module has yet
passed CMVP; the roadmap and costs are documented in
[docs/FIPS.md](docs/FIPS.md).

## Repository layout

| crate | role |
|---|---|
| `ferritls-core` | Cryptographic core = the FIPS module boundary (`#![forbid(unsafe_code)]`) |
| `ferritls-rustls` | rustls `CryptoProvider` adapter layer |
| `ferritls-backend-x86_64` | AES-NI/SHA-NI hardware backend (out of boundary, x86_64 only, registered via `ops`) |
| `ferritls-interop` | Interop / end-to-end test host |

Contributors — human or AI agents — should read [AGENTS.md](AGENTS.md)
first.

## License

Apache-2.0 OR MIT (see [LICENSE-APACHE](LICENSE-APACHE) and
[LICENSE-MIT](LICENSE-MIT)).
