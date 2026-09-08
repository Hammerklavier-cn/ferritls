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
- **Key exchange**: X25519, secp256r1, secp384r1
- **Signatures / verification**: ECDSA P-256/384,
  RSA-PSS/PKCS#1 (SHA-256/384/512), Ed25519
- **Approved mode** (`fips` feature): NIST-approved algorithms only +
  SP 800-90A CTR-DRBG (reseeded with OS entropy on every generate) +
  power-on self-test KATs
- **Testing surface**: official RFC/NIST/CAVP vectors, RFC 8448 key
  schedule, 2,349 Wycheproof cases, rustls-ring cross-interop, webpki
  certificate chains, six cargo-fuzz targets
  ([vector provenance](docs/VECTOR-PROVENANCE.md))
- **Performance** (P1 autovectorization + P2 explicit `std::simd`, on
  by default, still zero `unsafe`): bitsliced AES + grouped GHASH
  tables + batched ChaCha20 — roughly 19-21x faster AES-GCM record
  processing versus the masked-scalar baseline (baseline ISA); building
  with `RUSTFLAGS="-C target-cpu=native"` automatically widens the
  vector channels to AVX2/AVX-512; see the P1/P2 sections of
  [docs/ROADMAP.md](docs/ROADMAP.md)

```rust
let provider = ferritls_rustls::default_provider();
provider.install_default()?;
// ClientConfig::builder() / ServerConfig::builder() now use it by default.
```

## Build requirements (default `simd` feature)

The default `simd` feature of `ferritls-core` uses the standard
library's `core::simd` (portable_simd), which on the **stable
toolchain** requires the `RUSTC_BOOTSTRAP=1` environment variable
(this repository ships a `.cargo/config.toml` that sets it, so a
cloned checkout builds out of the box):

```bash
# When depending on this crate (crates.io / path / git) — pick one:
export RUSTC_BOOTSTRAP=1                      # (a) keep simd
ferritls-core = { version = "0.1", default-features = false }  # (b) scalar fallback
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
| `ferritls-interop` | Interop / end-to-end test host |

Contributors — human or AI agents — should read [AGENTS.md](AGENTS.md)
first.

## License

Apache-2.0 OR MIT (see [LICENSE-APACHE](LICENSE-APACHE) and
[LICENSE-MIT](LICENSE-MIT)).
