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

## Benchmarks

```sh
make bench                              # all benchmarks (ReleaseFast)
make bench-filter BENCH_FILTER="hash"   # filtered
```

Results (ReleaseFast, Apple M-series, 200 iterations, median):

### Crypto Primitives

| Operation | ops/s | median |
|-----------|------:|-------:|
| SHA-256 1KB | 2,178,649 | 459 ns |
| KDF extract+expand | 4,807,692 | 208 ns |
| AEAD seal 1KB | 2,183,406 | 458 ns |
| AEAD open 1KB | 1,043,841 | 958 ns |
| Ed25519 sign 256B | 11,029 | 90 us |
| Ed25519 verify 256B | 5,973 | 167 us |
| X25519 DH | 10,914 | 91 us |
| HPKE encrypt 256B | 10,714 | 93 us |
| HPKE decrypt 256B | 8,261 | 121 us |

### Key Schedule

| Operation | ops/s |
|-----------|------:|
| deriveEpochSecrets | 615,384 |
| SecretTree init 16 leaves | 82,754 |
| SecretTree init 256 leaves | 9,002 |
| SecretTree init 1024 leaves | 2,338 |

### Group Operations

| Operation | ops/s |
|-----------|------:|
| createGroup | 11,776 |
| createCommit (empty) | 5,664 |
| createCommit (add) | 2,080 |
| createCommit (remove) | 1,814 |
| processCommit (add, 2-member) | 1,736 |
| processWelcome (2-member) | 1,700 |
| createExternalCommit | 6,541 |
| processExternalCommit | 6,312 |

### Message Protection

| Operation | ops/s |
|-----------|------:|
| encryptContent 64B | 1,715,265 |
| decryptContent 64B | 1,333,333 |
| encryptContent 1KB | 1,090,512 |
| decryptContent 1KB | 705,716 |

### Tree Operations

| Operation | ops/s |
|-----------|------:|
| generateUpdatePath (16-member) | 96 |
| addLeaf (15->16) | 902 |
| addLeaf (255->256) | 54 |
| removeLeaf (16) | 858 |
| removeLeaf (256) | 54 |
| treeHash (16) | 864 |
| treeHash (256) | 54 |
| verifyParentHashes (16) | 874 |

### Serialization

| Operation | ops/s |
|-----------|------:|
| GroupState serialize | 11,168 |
| GroupState deserialize | 8,673 |

### Multi-cipher Suite Comparison (ops/s)

| Suite | DH | Sign | createGroup |
|-------|---:|-----:|------------:|
| 0x0001 (X25519/Ed25519) | 10,923 | 12,611 | 11,571 |
| 0x0003 (X25519/Ed25519/ChaCha20) | -- | -- | 12,339 |
| 0x0002 (P-256) | 1,919 | 2,053 | 2,854 |
| 0x0006 (P-384) | 479 | 501 | 706 |

## Architecture

Hexagonal (ports and adapters). The core library has no dependency on I/O,
transport, or storage. Three extension ports:

| Port | Kind | Purpose |
|------|------|---------|
| `CryptoProvider` | comptime generic | DH, AEAD, HKDF, HPKE, signatures |
| `CredentialValidator` | runtime interface | Application-defined credential trust |
| `KeyStore` | runtime interface | Application-provided key storage |

### Source Layout

```
src/
  zmls.zig              root API re-exports
  common/               types, errors
  codec/                wire codec (slice-based, u32 position tracking)
  crypto/               provider trait, HPKE, primitives, default backend
  tree/                 tree math, ratchet tree, tree hashes, path ops
  key_schedule/         key schedule, secret tree, PSK, transcript, exporter
  framing/              content types, public/private message framing
  group/                group state, evolution, commit, welcome, external join
  messages/             proposal, commit, welcome, key package, group info
  credential/           credential types, validator trait
tests/
  integration_test.zig  full group lifecycle tests
  interop_test.zig      RFC test vector validation
  fuzz_*.zig            fuzz targets for codec, crypto, tree, framing
benchmarks/
  bench.zig             performance benchmarks
```

## License

MIT. See [LICENSE](LICENSE).
