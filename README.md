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
| `fmt` | Format all Zig sources (core + client) |
| `check` | Check formatting (CI) |
| `build` | Build library (debug) |
| `build-safe` | Build library (ReleaseSafe) |
| `build-fast` | Build library (ReleaseFast) |
| `test` | Fetch vectors + run all tests (core + client) |
| `test-filter` | Run tests with `TEST_FILTER=` name filter |
| `test-cli` | Run CLI end-to-end tests |
| `bench` | Run benchmarks (ReleaseFast) |
| `bench-filter` | Run benchmarks with `BENCH_FILTER=` filter |
| `clean` | Remove all build artifacts |

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

## Quick Start

The `zmls-client` package provides a high-level `Client(P)` API
that handles key management, state persistence, and wire encoding.
For the full working CLI example, see
[`zmls-client/examples/cli/main.zig`](zmls-client/examples/cli/main.zig).

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
`hpkeDecrypt`, `sign`, `verify`). See `src/crypto/provider.zig`
for the full interface contract.

## Architecture

Hexagonal (ports and adapters). The core library has no dependency on I/O,
transport, or storage.

### Core Library Ports

| Port | Kind | Purpose |
|------|------|---------|
| `CryptoProvider` | comptime generic | DH, AEAD, HKDF, HPKE, signatures |
| `CredentialValidator` | runtime interface | Application-defined credential trust |
| `PskLookup` | runtime interface | External PSK resolution |

### Client Layer Ports

| Port | Kind | Purpose |
|------|------|---------|
| `GroupStore` | runtime interface | Persist serialized group state |
| `KeyStore(P)` | runtime interface | Store/load private keys |
| `Transport` | runtime interface | Send/receive MLS messages |

### Server Layer Ports

| Port | Kind | Purpose |
|------|------|---------|
| `GroupDirectory` | runtime interface | Group membership + message queues |
| `KeyPackageDirectory` | runtime interface | Single-use KeyPackage registry |
| `GroupInfoDirectory` | runtime interface | GroupInfo blob registry |

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

### Cipher Suites

| Suite | ID | DH | AEAD | Hash | Signature |
|-------|---:|-----|------|------|-----------|
| MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 | 0x0001 | X25519 | AES-128-GCM | SHA-256 | Ed25519 |
| MLS_128_DHKEMP256_AES128GCM_SHA256_P256 | 0x0002 | P-256 | AES-128-GCM | SHA-256 | ECDSA P-256 |
| MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 | 0x0003 | X25519 | ChaCha20-Poly1305 | SHA-256 | Ed25519 |
| MLS_256_DHKEMP256_CHACHA20POLY1305_SHA256_P256 | 0x0004 | P-256 | ChaCha20-Poly1305 | SHA-256 | ECDSA P-256 |
| MLS_256_DHKEMP384_AES256GCM_SHA384_P384 | 0x0006 | P-384 | AES-256-GCM | SHA-384 | ECDSA P-384 |

### Test Coverage

| Category | Count |
|----------|------:|
| Core library unit tests | 80+ |
| RFC 9420 test vectors | 16/16 categories |
| Core integration tests | 7 |
| zmls-client unit tests | 81 |
| zmls-client integration tests | 12 |
| CLI end-to-end tests | 18 |
| Fuzz targets | 4 (codec, tree, proposals, messages) |

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
zmls-client/                  client + server layer (I/O, state)
  src/client/                 Client(P) orchestrator (8 files)
  src/delivery_service/       DeliveryService relay (2 files)
  src/ports/                  port interfaces (6 files)
  src/adapters/               in-memory adapters (6 files)
  src/wire/                   envelope framing
  examples/cli/               CLI tool (main.zig + test_e2e.sh)
  tests/                      integration tests (12 tests)
tests/
  integration_test.zig        full group lifecycle tests (7 tests)
  interop_test.zig            RFC test vector validation (16 categories)
  fuzz_*.zig                  fuzz targets (4 files)
benchmarks/
  bench.zig                   performance benchmarks
```

## License

MIT. See [LICENSE](LICENSE).
