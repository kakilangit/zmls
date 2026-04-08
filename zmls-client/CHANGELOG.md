# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-04-08

Initial release. Client and Delivery Service framework for zmls.

### Added

- **Hexagonal port interfaces** -- `GroupStore`, `KeyStore(P)`,
  `Transport`, `GroupDirectory`, `KeyPackageDirectory`,
  `GroupInfoDirectory`. All vtable-based with `std.Io` for async I/O.
- **In-memory adapters** -- bounded, fixed-capacity implementations
  for all six ports. Secret material is `secureZero`'d on removal
  and deinit.
- **Client(P)** -- high-level MLS client parameterized over
  `CryptoProvider`. 18 public methods covering group creation,
  membership (invite, join, external join, remove, leave, self-update),
  messaging (send, receive, processIncoming), proposals (proposeAdd,
  proposeRemove, commitPending, cancelPending), staged commits
  (stageCommit, confirm, discard), and queries (epoch, ownLeafIndex,
  memberCount, listMembers, exportSecret, epochAuthenticator,
  groupInfo, freshKeyPackage).
- **Credential validation** -- validates credentials at four critical
  points: `inviteMember`, `processAndPersistWelcome`,
  `processPublicCommit`, `executeExternalJoin`. Custom validators via
  `CredentialValidator` interface from zmls core.
- **Staged commit conflict detection** -- `StagedCommitHandle.confirm()`
  checks epoch freshness and returns `error.ConflictingCommit` if the
  group advanced while the commit was staged.
- **DeliveryService** -- opaque byte relay (dumb delivery service).
  Message routing via `GroupDirectory`, `KeyPackageDirectory` and
  `GroupInfoDirectory` with size limit enforcement.
- **Wire protocol** -- versioned binary envelope framing with
  validation (`writeEnvelope` / `readEnvelope`).
- **CLI** -- fully working command-line tool at
  `examples/cli/main.zig` (~1390 lines) with 13 subcommands:
  `init`, `info`, `key-package`, `add`, `join`, `send`, `recv`,
  `remove`, `commit`, `export`, `group-info`, `external-join`,
  `process`.
- **CLI end-to-end tests** -- 18 tests in `examples/cli/test_e2e.sh`
  covering group creation, member add/join, message exchange, MLS
  exporter, external join, key update, and member removal with
  message isolation.
- **Integration tests** -- 12 tests: full lifecycle, external join,
  staged commit confirm/discard, member removal, key update,
  persistence, error paths, three-party, proposal batching.
- **Unit tests** -- 81 tests across client (37), adapters (16),
  ports (6), wire (8), delivery service (4), pending (4),
  group bundle (3), and other modules.
