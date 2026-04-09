# zmls

A Zig implementation of the Messaging Layer Security (MLS) protocol,
[RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html).

Zero external dependencies. All cryptographic primitives from `std.crypto`
or implemented in-tree.

## Requirements

- Zig `0.16.0-dev.3039+b490412cd` or compatible.

## Build and Test

```sh
zig build          # build the library
make test          # fetch test vectors + run all tests
make all           # fmt + check + build + test
```

Test vectors are fetched from GitHub on first run (pinned commit).
To force re-download:

```sh
rm -rf tests/vectors && make fetch-vectors
```

Filter tests by name:

```sh
make test-filter TEST_FILTER="tree_math"
```

### Available Makefile Targets

| Target | Description |
|--------|-------------|
| `all` | fmt + check + build + test (default) |
| `fmt` | Format all Zig sources |
| `check` | Check formatting (CI) |
| `build` | Build library (debug) |
| `build-safe` | Build library (ReleaseSafe) |
| `build-fast` | Build library (ReleaseFast) |
| `test` | Fetch vectors + run all tests |
| `test-filter` | Run tests with `TEST_FILTER=` name filter |
| `bench` | Run benchmarks (ReleaseFast) |
| `bench-filter` | Run benchmarks with `BENCH_FILTER=` filter |
| `clean` | Remove all build artifacts |

## Architecture

Hexagonal (ports and adapters). The core library has no dependency on I/O,
transport, or storage.

### Core Library Ports

| Port | Kind | Purpose |
|------|------|---------|
| `CryptoProvider` | comptime generic | DH, AEAD, HKDF, HPKE, signatures |
| `CredentialValidator` | runtime interface | Application-defined credential trust |
| `PskLookup` | runtime interface | External PSK resolution |

```
                    +---------------------------+
                    |     Application Layer     |
                    +---------------------------+
                             |
                    +---------------------------+
                    |     zmls: core library    |
                    |  (pure computation, no IO)|
                    +---------------------------+
                    |              |            |
               +----+-----+   +----+-----+  +---+-------+
               |CryptoP   |   |Credential|  |KeySchedule|
               |(comptime)|   |Validator |  |SecretTree |
               +----------+   +----------+  +-----------+
```

### Cipher Suites

| Suite | ID | DH | AEAD | Hash | Signature |
|-------|---:|-----|------|------|-----------|
| MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | 0x0001 | X25519 | AES-128-GCM | SHA-256 | Ed25519 |
| MLS_128_DHKEMP256_AES128GCM_SHA256_P256 | 0x0002 | P-256 | AES-128-GCM | SHA-256 | ECDSA P-256 |
| MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 | 0x0003 | X25519 | ChaCha20-Poly1305 | SHA-256 | Ed25519 |
| MLS_256_DHKEMP256_CHACHA20POLY1305_SHA256_P256 | 0x0004 | P-256 | ChaCha20-Poly1305 | SHA-256 | ECDSA P-256 |
| MLS_256_DHKEMP384_AES256GCM_SHA384_P384 | 0x0006 | P-384 | AES-256-GCM | SHA-384 | ECDSA P-384 |

Suites 0x0005 (`MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448`) and
0x0007 (`MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448`) are
**not supported**. X448 and Ed448 are not available in Zig's
standard library, and these suites see negligible adoption in
practice.

### Source Layout

```
src/                          core library (no I/O)
  zmls.zig                    root API re-exports
  common/                     types, errors
  codec/                      wire codec (slice-based, u32 position)
  crypto/                     provider trait, HPKE, primitives,
                              backends (default, p256, p384,
                              chacha20, p256_chacha20)
  tree/                       tree math, ratchet tree, tree hashes,
                              path ops
  key_schedule/               key schedule, secret tree, PSK,
                              transcript, exporter
  framing/                    content types, public/private message
  group/                      group state, evolution, commit,
                              welcome, external join
  messages/                   proposal, commit, welcome, key package,
                              group info
  credential/                 credential types, validator trait
tests/
  integration_test.zig        full group lifecycle tests (7 tests)
  interop_test.zig            RFC test vector validation (16 categories)
  fuzz_*.zig                  fuzz targets (4 files)
benchmarks/
  bench.zig                   performance benchmarks
```

## License

MIT. See [LICENSE](LICENSE).