# ferritls-backend-x86_64

x86_64 hardware execution core (AES-NI + CLMUL GHASH + SHA-NI) for
[`ferritls-core`](https://crates.io/crates/ferritls-core). It contains
no cryptography policy of its own: it only supplies faster execution
cores that [`ferritls-core::ops`](https://docs.rs/ferritls-core) swaps
in at runtime.

- **Outside the FIPS boundary.** The boundary is the `ferritls-core`
  crate snapshot; this crate is never part of it. Under the `fips`
  feature build, `ferritls-core` refuses every installation and the
  software path stays fixed. Publishing this crate changes nothing
  about that.
- **x86_64 only.** On any other target it compiles to an empty crate,
  so it is safe to depend on unconditionally.
- **Zero dependencies** besides `ferritls-core` itself.

## Usage

```toml
[dependencies]
ferritls-rustls = "0.9"
ferritls-backend-x86_64 = "0.9"
```

```rust
// Once per process, before constructing any key object:
#[cfg(target_arch = "x86_64")]
ferritls_backend_x86_64::install()?;

ferritls_rustls::default_provider().install_default()?;
```

After installation, newly created `ferritls_core::gcm::{Aes128Gcm,
Aes256Gcm}` instances run on the AES-NI/CLMUL path and SHA-256
compression runs on SHA-NI; instances created before installation are
unaffected.

Install semantics:

- Probes `aes` + `pclmulqdq`; if either is missing, returns
  `Error::Unsupported` — no silent fallback, nothing is installed.
- Runs a known-answer self-test (McGrew–Viega TC5/TC16) on its own
  execution core first; on failure returns `Error::SelfTestFailed`
  and refuses to install.
- Under the approved-mode (`fips` feature) build of `ferritls-core`,
  installation is refused by core.
- Process-wide, exactly once; a second install is refused by core.

`detect()` exposes the raw capability probe for callers that need
custom wiring or diagnostics; the normal path is `install()`.

## `unsafe` discipline

Crate root is `#![deny(unsafe_code)]`. `unsafe` exists only in the
single private leaf module plus one trampoline per kernel entry point;
each kernel carries `#[target_feature(...)]` and calls its intrinsic
directly in-context (the fearless_simd pattern, reimplemented here
with zero dependencies). Everything else is safe code. AES/GCM
instructions are fixed-latency and data-independent; tag comparison
stays in `ferritls-core`.

## Performance

Representative numbers (same-machine comparisons, details in
`docs/BENCHMARKS.md` §5.1): streaming SHA-256 ~6×, HKDF ~5×, and a
dual-Ni X25519 handshake ~2.35× versus the software path.

## Versioning

Released in lockstep with `ferritls-core` / `ferritls-rustls` (same
version number, same tag). Not yet CMVP-validated — same as the rest
of ferritls (see `docs/FIPS.md`).
