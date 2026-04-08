# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-04-08

### Added

- **CI workflow** -- added `make test-cli` step to GitHub Actions.
- **README** -- added Quick Start code example, Group Lifecycle,
  Custom Cipher Suite section, cipher suites table, test coverage
  table, and ASCII architecture diagram.
- **Makefile targets** -- `build-client`, `test-cli`, `fmt-client`,
  `check-client`, `test-client`, `clean-client` for zmls-client
  integration.

### Removed

- **Root CLI** -- deleted `examples/cli/main.zig` and
  `examples/cli/test_e2e.sh` (superseded by zmls-client CLI).
- **Root CLI build target** -- removed CLI executable target from
  root `build.zig`.

## [0.1.0] - 2026-04-07

Initial release. Complete implementation of RFC 9420 (Messaging Layer
Security).

### Added

- **Core protocol** -- full RFC 9420 implementation covering group
  creation, commit, welcome, external join, proposal validation, and
  epoch advancement.
- **Five cipher suites** -- 0x0001 (X25519/AES-128-GCM/SHA-256/Ed25519),
  0x0002 (P-256/AES-128-GCM), 0x0003 (X25519/ChaCha20-Poly1305),
  0x0004 (P-256/ChaCha20-Poly1305), 0x0006 (P-384/AES-256-GCM).
- **Hexagonal architecture** -- core library has zero I/O dependency.
  CryptoProvider (comptime), CredentialValidator (runtime), and
  PskLookup (runtime) ports.
- **TLS codec** -- slice-based encode/decode with varint support.
- **Ratchet tree** -- array-based binary tree with add/remove, tree
  hash, parent hash, UpdatePath generation and application.
- **Key schedule** -- epoch secret derivation, secret tree, PSK
  chaining, transcript hashes, MLS exporter, epoch key ring.
- **Message framing** -- PublicMessage and PrivateMessage with AEAD
  encryption, sender data encryption, membership tags.
- **Interop tests** -- 16 categories against official RFC 9420 test
  vectors (fetched from GitHub at pinned commit).
- **Integration tests** -- 7 end-to-end protocol flow tests.
- **Fuzz targets** -- codec, tree, proposals, and message decoding.
- **CLI example** -- zmls-cli with init, key-package, add, remove,
  commit, export, info subcommands.
- **Benchmarks** -- crypto primitives, key schedule, group operations,
  message protection, tree operations, serialization, multi-suite
  comparison.
