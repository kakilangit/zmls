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
```

## Quick Start

```zig
const zmls_client = @import("zmls-client");
const zmls = @import("zmls");
const P = zmls.DefaultCryptoProvider;

// Set up in-memory adapters.
var gs = zmls_client.MemoryGroupStore(8).init();
defer gs.deinit();
var ks = zmls_client.MemoryKeyStore(P, 8).init();
defer ks.deinit();

const seed: [32]u8 = .{0x42} ** 32;
var client = try zmls_client.Client(P).init(
    allocator,
    "alice",
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    &seed,
    .{
        .group_store = gs.groupStore(),
        .key_store = ks.keyStore(),
        .credential_validator = zmls.credential_validator
            .AcceptAllValidator.validator(),
    },
);
defer client.deinit();

const group_id = try client.createGroup(io);
defer allocator.free(group_id);
```

## Architecture

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
  persistent storage, key management, and transport. Parameterized over
  `CryptoProvider` at comptime.
- **`DeliveryService`** is an opaque byte relay. Not parameterized by
  `CryptoProvider` — it never interprets MLS content.

### Wire Protocol

`wire.writeEnvelope` / `wire.readEnvelope` provide versioned binary
framing for messages on the wire.

## Source Layout

```
zmls-client/
  build.zig               build system
  build.zig.zon           package manifest (depends on zmls)
  src/
    root.zig              public API re-exports
    ports/                port interfaces (6 files)
    adapters/             in-memory adapters (6 files)
    wire/                 envelope framing
    client/               Client(P), types, pending KP map
    delivery_service/     DeliveryService, types
  tests/
    integration_test.zig  Client + DeliveryService lifecycle tests
  examples/
    cli/main.zig          CLI placeholder
```

## License

MIT. See [LICENSE](../LICENSE).
