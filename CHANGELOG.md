# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- **Welcome path_secret per RFC 9420 §12.4.3.1** -- `buildWelcome` now
  computes and includes the per-member `path_secret` in GroupSecrets.
  Previously hardcoded to `null`, new members can now receive the path
  secret for the lowest node in the committer's filtered direct path
  that is also in the new member's direct path.
- **processWelcome derives path keys from path_secret** --
  `processWelcome` now returns `WelcomeJoinResult` containing the
  `GroupState` plus derived parent node private keys from the Welcome's
  `path_secret`. The joiner can use these keys for future UpdatePath
  decryption where they are matched via a parent node.
- **processWelcome validates signer key against tree** --
  `processWelcome` now verifies that the caller-provided
  `signer_verify_key` matches the `signature_key` of the leaf at
  `GroupInfo.signer` in the ratchet tree (constant-time compare).
  Previously the key was trusted entirely from caller input.
- **HPKE public key validation for encryption_key** --
  `LeafNode.validateEncryptionKey(P)` validates that `encryption_key`
  is a valid HPKE public key via `P.validateDhPublicKey`. Called from
  `KeyPackage.validate`, Update leaf validation, and Welcome tree
  validation per RFC 9420 §7.3.
- **LeafNode capabilities.versions must include mls10** --
  `LeafNode.validate()` now checks that `capabilities.versions`
  contains `mls10` per RFC 9420 §7.2.
- **External commit Remove count enforced** --
  `validateExternalProposals` now enforces at most one Remove
  proposal in external commits per RFC 9420 §12.4.3.2. Previously
  multiple Removes were silently accepted. Credential matching
  between joiner and removed leaf is documented as application-level
  policy per the RFC.
- **PSK resumption usage validation explicit** --
  `validatePskProposals` now uses an explicit switch on
  `.application`, `.reinit`, `.branch`, `.reserved`, and unknown
  values instead of a negated comparison. Behavior is unchanged
  but the code now clearly documents which usages are valid in a
  normal commit context per RFC 9420 §12.2.
- **encodeVarVector returns error instead of assert** --
  `encodeVarVector` now returns `error.VectorTooLarge` when
  `data.len > max_vec_length` instead of using a debug-only
  `assert`. Prevents silent corrupt wire data in release builds.

## [0.1.2] - 2026-04-10

### Fixed

- **PublicMessage membership tag validation** -- reject invalid-length
  membership tags on decode instead of silently setting to null.
  Encode now errors when a member sender has no tag.
- **MLSMessage protocol version validation** -- reject unsupported
  protocol versions on decode; encode uses unconditional check
  instead of debug-only assert.
- **X.509 external sender credentials** -- external sender decoding
  now supports X.509 credentials (previously only Basic).
- **Secret key zeroing in all backends** -- `defer secureZero` added
  for KeyPair/SecretKey locals in `sign()` and `signKeypairFromSeed`
  across all five crypto backends.
- **HPKE exporter_secret zeroing** -- `sealBase`/`openBase` now zero
  the unused `exporter_secret` via `defer secureZero`.
- **CryptoProvider signature validation** -- `assertValid` now
  validates function signatures (parameter counts, return types) and
  all required constants (`nt`, `npk`, `nsk`, `sign_pk_len`,
  `sign_sk_len`, `sig_len`, `seed_len`).
- **P-384 native 48-byte seeds** -- seed size changed from 32 to 48
  bytes for P-384 backends, matching 192-bit security level.
  `encapDeterministic` accepts suite-appropriate seed sizes.
- **Epoch overflow** -- returns `error.EpochOverflow` instead of
  `@panic` at u64 boundary.
- **GroupState ownership** -- `buildWelcomeGroupState` clones
  `group_id` and `extensions` to avoid dangling pointers.
- **truncateTree invariant** -- on allocation failure, preserves
  original `leaf_count` to maintain `nodes.len == nodeWidth(leaf_count)`.
- **OutOfMemory propagation** -- `OutOfMemory` no longer erased to
  `IndexOutOfRange` in `hashes.zig` and `path.zig`.
- **resolveWelcomePskSecret** -- returns error union instead of
  optional null for consistency with `resolvePskSecret`.
- **CipherSuite IANA compliance** -- aligned enum values 0x0004--0x0007
  with the IANA MLS Cipher Suites registry. P-384/AES-256 moved from
  0x0006 to 0x0007 (correct IANA value). P-256/ChaCha20 moved to
  private-use value 0xF001.
- **DER ECDSA signature support** -- `verifyWithLabel` now accepts
  both IEEE P1363 (raw r||s) and DER-encoded ECDSA signatures,
  enabling interoperability with other MLS implementations.

### Changed

- **Heap-allocate ValidatedProposals** -- `ValidatedProposals`
  (~120 KiB) is now heap-allocated. `validateProposalList` takes an
  allocator parameter and returns `*ValidatedProposals`; callers use
  `defer validated.destroy(allocator)`.
- **processCommit/stageCommit opts struct** -- internal 17-parameter
  functions refactored to accept `ProcessCommitOpts` / context
  structs.
- **hasResolution()** -- new bool-returning method avoids allocating
  256 KiB resolution buffer just to check emptiness.
- **LeafNode.decode split** -- 123-line decode split into
  `decodeIdentityFields` and `decodeSourceFields` sub-decoders.
- **path.zig split** -- extracted `update_path.zig` (wire types +
  codec) and `path_secrets.zig` (derivation + encryption).
- **encodeVarPrefixedList** -- generic helper replaces 3 duplicated
  gap-then-shift encoding patterns.
- **consumeKey/deriveKeyNonce deduplication** -- `consumeKey` now
  delegates to `deriveKeyNonce`.
- **buildConfirmedHash deduplication** -- single shared function
  replaces identical logic in `commit.zig` and `external.zig`.
- **encryptContent single-serialize** -- content serialized once with
  padding appended in-place, eliminating double serialization.
- **resolution iterative** -- `resolutionInner` converted from
  recursion to explicit stack per RULES.md.
- **Cipher suite constants** -- all suites reference provider
  constants instead of hardcoded magic numbers.
- **Test extraction** -- 13 test files extracted from source modules
  to dedicated `*_test.zig` files for cleaner separation.

### Performance

- **treeHash O(n)** -- stride-based level enumeration replaces
  O(n log n) level-scanning approach.
- **verifyParentHashes** -- precomputed base tree hashes eliminate
  redundant O(k x d x width) allocation cost.

### Added

- **Crypto fuzz targets** -- 6 new fuzz targets in
  `tests/fuzz_crypto.zig` for HPKE seal/open, sign/verify,
  DeriveKeyPair, and tree hash.
- **Commit fuzz targets** -- 2 new fuzz targets in
  `tests/fuzz_commit.zig` for `processCommit` with random proposals
  and PrivateMessage encrypt/decrypt round-trip with corruption.
- **Add proposal fuzzing** -- `tests/fuzz_proposals.zig` now includes
  Add proposals with KeyPackage.
- **Integration tests** -- 7 new end-to-end tests: PSK through commit
  pipeline, mixed Add+Remove in same commit, concurrent commit
  rejection, GroupContextExtensions proposal, ReInit proposal
  end-to-end, out-of-order stale-epoch rejection, and 257-member
  group.
- **Multi-suite interop tests** -- PSK, Welcome, and tree-validation
  test vectors verified for suites 2 (P-256) and 7 (P-384) in
  addition to suites 1 and 3.
- **Adversarial tests** -- tampered commit signature, replay
  protection, forward secrecy verification.

### Documented

- GCE intentional over-restriction vs RFC 9420 (commit.zig).
- Unknown proposal zero-length body limitation (proposal.zig).
- `encapDeterministic` seed reuse risk (hpke.zig).
- `n_secret == nh` coincidence (hpke.zig).
- Auth verification security contract (auth.zig).
- `forwardRatchet` lost generation behavior (secret_tree.zig).
- P-384 non-standard HKDF seed expansion labels (p384.zig).
- Stack usage for HPKE labeled buffers and EncryptContextBuf.
- X448/Ed448 and P-521 suites as explicitly out-of-scope (DESIGN.md).

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
  0xF001 (P-256/ChaCha20-Poly1305, non-standard), 0x0007
  (P-384/AES-256-GCM).
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
