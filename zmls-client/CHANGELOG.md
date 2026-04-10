# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-04-10

### Fixed

- **Welcome path_secret in inviteMember** -- `buildInviteResult` now
  passes path secrets, filtered direct path nodes, and the new member's
  leaf index through to `buildWelcome` per RFC 9420 §12.4.3.1.
- **joinGroup adapts to WelcomeJoinResult** -- `joinGroup` now handles
  the `WelcomeJoinResult` return type from `joinViaWelcome`, extracting
  the group state from the result.
- **Proposal cache on failed commit** -- `commitPending` no longer
  clears cached proposals when the commit fails. Proposals are only
  cleared on the success path.
- **Allocator usage** -- replaced all `std.heap.page_allocator`
  occurrences in `client.zig` with the function's allocator parameter,
  fixing leak detection in tests.
- **PendingProposalStore group matching** -- replaced 64-bit Wyhash
  with full group_id byte comparison to eliminate hash collision risk.

### Changed

- **joinGroup no longer requires `my_leaf_index`** -- the leaf index
  is now derived internally by searching the tree for the matching
  signature key. The parameter has been removed from the public API.
- **processPublicProposal** -- removed unused `io` parameter.
- **processPublicCommit extraction** -- validation, credential
  checking, and secret tree initialization extracted into helpers,
  reducing the function from 91 to 55 lines.
- **Single-pass tree decode** -- two-pass tree decode replaced with
  `skipNode`-based counting that advances position without allocating.
- **KeyStore port** -- added `deleteEncryptionKey(group_id, leaf)`
  method; called during `leaveGroup` for best-effort key cleanup.
- **Test extraction** -- client tests moved to dedicated
  `client_test.zig`.

### Added

- **PSK support** -- `Client.Options` accepts an optional `psk_lookup`
  field (`zmls.PskLookup`) for external PSK resolution.
  `proposeExternalPsk` method creates standalone PSK proposals.
  `PskResolver` is threaded through all commit creation paths
  (`commitWithProposals`, `commitWithPath`, `stageCommit`,
  `inviteMember`) and incoming commit processing
  (`processPublicCommit`).
- **Bundle blob cache** -- in-memory `BlobCache` (HashMap-based, LRU
  eviction at 16 entries) eliminates redundant GroupStore I/O for
  repeated loads of the same group.
- **Client-level tests** -- multiple groups simultaneously, receiving
  commits for unknown groups, malformed Welcome with wrong keys,
  credential validation rejection at joinGroup, PSK proposal
  end-to-end flow.

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
