# zmls-client

Client and Delivery Service framework for
[zmls](https://github.com/kakilangit/zmls), the Zig MLS (RFC 9420)
protocol library.

Hexagonal architecture: applications bring their own adapters for
storage, transport, and directory ports. The library ships in-memory
adapters as defaults for testing and development.

## Requirements

- Zig `0.16.0-dev.3039+b490412cd` or compatible.
- The `zmls` protocol core (resolved automatically via `build.zig.zon`).

## Build and Test

```sh
cd zmls-client
zig build          # build the library + CLI
zig build test     # run all tests (unit + integration)
make test-cli      # run CLI end-to-end tests (18 tests)
make all           # fmt + check + build + test
```

### Available Makefile Targets

| Target | Description |
|--------|-------------|
| `all` | fmt + check + build + test (default) |
| `fmt` | Format all sources (src + examples) |
| `check` | Check formatting (CI) |
| `build` | Build library + CLI (debug) |
| `build-safe` | Build (ReleaseSafe) |
| `build-fast` | Build (ReleaseFast) |
| `test` | Run all tests (81 unit + 12 integration) |
| `test-filter` | Run tests with `TEST_FILTER=` name filter |
| `test-cli` | Build CLI + run 18 end-to-end tests |
| `clean` | Remove build artifacts |

## Quick Start

The `Client(P)` API handles key management, state persistence, and wire encoding.
For a full working CLI example, see
[`examples/cli/main.zig`](examples/cli/main.zig).

```zig
const zmls = @import("zmls");
const zmls_client = @import("zmls-client");

const P = zmls.DefaultCryptoProvider;
const Client = zmls_client.Client(P);

// Create a client with in-memory stores.
var group_store = zmls_client.MemoryGroupStore(8).init();
var key_store = zmls_client.MemoryKeyStore(P, 8).init();
defer group_store.deinit();
defer key_store.deinit();

var alice = try Client.init(allocator, "alice",
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    &signing_seed, .{
        .group_store = group_store.groupStore(),
        .key_store = key_store.keyStore(),
        .credential_validator =
            zmls.credential_validator.AcceptAllValidator.validator(),
    });
defer alice.deinit();

// Create a group — returns the group_id.
const group_id = try alice.createGroup(io);

// Generate a key package for another member.
const kp = try bob.freshKeyPackage(allocator, io);

// Add Bob — produces commit + welcome bytes.
var invite = try alice.inviteMember(
    allocator, io, group_id, kp.data,
);
defer invite.deinit();
// invite.commit  — send to existing members
// invite.welcome — send to the new member

// Bob joins via Welcome.
const join = try bob.joinGroup(
    allocator, io, invite.welcome, join_opts,
);
defer join.deinit();

// Send an encrypted application message.
const ct = try alice.sendMessage(
    allocator, io, group_id, "hello",
);
defer allocator.free(ct);

// Receive and decrypt.
var msg = try bob.receiveMessage(
    allocator, io, join.group_id, ct,
);
defer msg.deinit();
// msg.data contains "hello"
```

### Group Lifecycle

```zig
// Key update (self-update with new leaf keys).
const commit = try alice.selfUpdate(
    allocator, io, group_id,
);

// Remove a member by leaf index.
const remove = try alice.removeMember(
    allocator, io, group_id, 1,
);

// External join via GroupInfo.
const gi_bytes = try alice.groupInfo(allocator, io, group_id);
var ej = try carol.externalJoin(allocator, io, gi_bytes.data);
// ej.commit — existing members must process this
// ej.group_id — Carol's new group membership

// Process incoming commit/proposal/message.
var result = try bob.processIncoming(
    allocator, io, group_id, incoming_data,
);
// result is a tagged union: .commit_applied, .application,
// or .proposal_cached
```

### Custom Cipher Suite

The `P` parameter is a comptime struct satisfying the
`CryptoProvider` interface. Switch cipher suites by
changing the type:

```zig
// P-256 / AES-128-GCM (suite 0x0002)
const P256 = zmls.P256CryptoProvider;
var client = try zmls_client.Client(P256).init(...);

// X25519 / ChaCha20-Poly1305 (suite 0x0003)
const ChaCha = zmls.ChaCha20CryptoProvider;
var client = try zmls_client.Client(ChaCha).init(...);
```

To implement a custom provider, define a struct with the
required comptime fields (`nh`, `nsk`, `npk`, `sign_sk_len`,
`sign_pk_len`) and functions (`dhKeypairFromSeed`, `hkdfExtract`,
`hkdfExpand`, `aeadSeal`, `aeadOpen`, `hpkeEncrypt`,
`hpkeDecrypt`, `sign`, `verify`). See the zmls core library's
`src/crypto/provider.zig` for the full interface contract.

## Client(P) API

`Client(P)` is the main entry point. It wraps the zmls protocol core
with persistent storage, key management, and credential validation.
Parameterized over `CryptoProvider` at comptime.

### Group Management

| Method | Description |
|--------|-------------|
| `createGroup(io)` | Create a new group with random ID |
| `createGroupWithId(io, id, exts)` | Create a group with specific ID |
| `inviteMember(alloc, io, group_id, kp)` | Add a member, returns commit + welcome |
| `joinGroup(alloc, io, welcome, opts)` | Join via Welcome message |
| `externalJoin(alloc, io, group_info)` | Join via external commit |
| `removeMember(alloc, io, group_id, leaf)` | Remove a member by leaf index |
| `leaveGroup(io, group_id)` | Delete local group state |
| `selfUpdate(alloc, io, group_id)` | Key rotation (empty commit with path) |

### Messaging

| Method | Description |
|--------|-------------|
| `sendMessage(alloc, io, group_id, pt)` | Encrypt application message |
| `receiveMessage(alloc, io, group_id, ct)` | Decrypt application message |
| `processIncoming(alloc, io, group_id, data)` | Dispatch commit/proposal/app message |

### Proposals and Staged Commits

| Method | Description |
|--------|-------------|
| `proposeAdd(alloc, io, group_id, kp)` | Cache an Add proposal |
| `proposeRemove(alloc, io, group_id, leaf)` | Cache a Remove proposal |
| `commitPendingProposals(alloc, io, group_id)` | Commit all cached proposals |
| `cancelPendingProposals(alloc, io, group_id)` | Discard cached proposals |
| `stageCommit(alloc, io, group_id)` | Create commit without persisting |
| `StagedCommitHandle.confirm(io)` | Persist staged commit |
| `StagedCommitHandle.discard()` | Abandon staged commit |

### Queries

| Method | Description |
|--------|-------------|
| `epoch(io, group_id)` | Current epoch number |
| `ownLeafIndex(io, group_id)` | Own leaf index in the tree |
| `memberCount(io, group_id)` | Number of non-blank leaves |
| `listMembers(alloc, io, group_id)` | List all members |
| `exportSecret(io, group_id, label, ctx, out)` | MLS exporter |
| `epochAuthenticator(io, group_id, out)` | Epoch authenticator secret |
| `groupInfo(alloc, io, group_id)` | Export signed GroupInfo |
| `freshKeyPackage(alloc, io)` | Generate a KeyPackage |

## Architecture

Hexagonal (ports and adapters) architecture. The client layer orchestrates
the core zmls protocol library with I/O, state management, and application
integration.

```
                    +---------------------------+
                    |       Application         |
                    +---------------------------+
                             |
                    +---------------------------+
                    |   zmls-client: Client(P)  |
                    |  (orchestrator + state)   |
                    +---------------------------+
                      |          |            |
               +------+---+ +----+------+  +--+--------+
               |GroupStore| |KeyStore(P)|  | Transport |  <- ports
               +------+---+ +----+------+  +--+--------+
                      |          |            |
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

### Ports (interfaces)

| Port | Generic | Purpose |
|------|---------|---------|
| `GroupStore` | no | Persist serialized `GroupState` blobs |
| `KeyStore(P)` | yes (comptime P) | Store/load private signing and encryption keys |
| `Transport` | no | Send/receive MLS messages |
| `GroupDirectory` | no | Server-side group membership and message queues |
| `KeyPackageDirectory` | no | Server-side single-use KeyPackage registry |
| `GroupInfoDirectory` | no | Server-side GroupInfo blob registry |

All ports are vtable-based (`*anyopaque` + `*const VTable`). Every
method that performs I/O takes `io: std.Io` by value.

### Adapters (in-memory defaults)

| Adapter | Port | Notes |
|---------|------|-------|
| `MemoryGroupStore(cap)` | `GroupStore` | `secureZero` on removal |
| `MemoryKeyStore(P, cap)` | `KeyStore(P)` | Fixed-size key arrays |
| `LoopbackTransport(cap)` | `Transport` | FIFO queue for testing |
| `MemoryGroupDirectory(g, m, q)` | `GroupDirectory` | Per-member queues |
| `MemoryKeyPackageDirectory(cap)` | `KeyPackageDirectory` | Single-use consume |
| `MemoryGroupInfoDirectory(cap)` | `GroupInfoDirectory` | Overwrite semantics |

### Client and DeliveryService

- **`Client(P)`** wraps `GroupState(P)` from the zmls protocol core with
  persistent storage, key management, credential validation, and
  transport. Parameterized over `CryptoProvider` at comptime.
  37 unit tests + 12 integration tests.
- **`DeliveryService`** is an opaque byte relay. Not parameterized by
  `CryptoProvider` -- it never interprets MLS content. Routes messages
  via `GroupDirectory`, manages `KeyPackageDirectory` and
  `GroupInfoDirectory`.

### Wire Protocol

`wire.writeEnvelope` / `wire.readEnvelope` provide versioned binary
framing for messages on the wire.

## CLI

A fully working CLI at `examples/cli/main.zig` demonstrating the
`Client(P)` API over file-based persistence.

### Subcommands

| Command | Description |
|---------|-------------|
| `init <group-id>` | Create a new group |
| `info <state-file>` | Print group info (epoch, members, tree) |
| `key-package <identity>` | Generate a KeyPackage |
| `add <state> <kp>` | Add a member (commit + welcome) |
| `join <welcome> <secrets>` | Join via Welcome |
| `send <state> <message>` | Encrypt and output ciphertext |
| `recv <state> <ct-file>` | Decrypt and output plaintext |
| `remove <state> <leaf>` | Remove a member |
| `commit <state>` | Key update (empty commit with path) |
| `export <state> <label> <len>` | MLS exporter |
| `group-info <state>` | Export signed GroupInfo |
| `external-join <gi> <identity>` | Join via external commit |
| `process <state> <msg-file>` | Process incoming commit |


## Source Layout

```
zmls-client/
  build.zig               build system
  build.zig.zon           package manifest (depends on zmls)
  src/
    root.zig              public API re-exports
    ports/                port interfaces (6 files)
      group_store.zig     GroupStore
      key_store.zig       KeyStore(P)
      transport.zig       Transport, MessageType, ReceivedEnvelope
      group_directory.zig GroupDirectory
      kp_directory.zig    KeyPackageDirectory
      gi_directory.zig    GroupInfoDirectory
    adapters/             in-memory adapters (6 files)
      memory_group_store.zig
      memory_key_store.zig
      loopback_transport.zig
      memory_group_directory.zig
      memory_kp_directory.zig
      memory_gi_directory.zig
    wire/                 envelope framing
      envelope.zig
    client/               Client(P) orchestrator (8 files)
      client.zig          main Client(P) struct + methods
      types.zig           result types, MemberInfo
      pending.zig         PendingKeyPackageMap
      group_bundle.zig    GroupBundle serialize/deserialize
      message_protect.zig encrypt/decrypt helpers
      commit_process.zig  incoming commit processing
      proposal_encode.zig standalone proposal encoding
      proposal_store.zig  PendingProposalStore
    delivery_service/     DeliveryService relay (2 files)
      delivery_service.zig
      types.zig
  tests/
    integration_test.zig  12 Client + DeliveryService tests
  examples/
    cli/
      main.zig            CLI tool (~1390 lines)
      test_e2e.sh         18 end-to-end tests
```

## License

MIT. See [LICENSE](LICENSE).
