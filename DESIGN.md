# zmls -- Design Document

A Zig implementation of the Messaging Layer Security (MLS) protocol
(RFC 9420).

## Goals

Design priorities, in order: **correct, simple, foolproof, fast**.

- Correct, readable implementation of RFC 9420.
- Simple APIs that are hard to misuse. The caller must not juggle
  pointers, call fixup methods, or satisfy invisible prerequisites.
  If a struct is valid after construction, it stays valid without
  manual intervention.
- Hexagonal architecture: core logic has zero dependency on I/O,
  transport, or storage.
- Shared primitives (codec, tree math, crypto) written once, reused
  everywhere.
- Explicit over clever. Flat over nested. Small files over large.
- No published version exists. Every breaking change is free. When
  a better design is found, delete the old implementation and
  replace it entirely. Workarounds, compatibility shims, and
  incremental patches on flawed foundations are not acceptable.

## Non-Goals

- Delivery Service or Authentication Service (application concerns).
- Transport layer (HTTP, WebSocket, QUIC).
- Persistent storage engine.
- Backwards compatibility with any prior version of this library.
  There are no external consumers. Any struct, function, file, or
  module may be rewritten or deleted at any time.

---

## Architecture

### Hexagonal (Ports & Adapters)

```
                +-----------------------------------------+
                |            Application                  |
                |  (DS adapter, AS adapter, CLI,          |
                |   tests, fuzz harness, ...)             |
                +--------+-----------------------+--------+
                         |  Ports                |
                +--------v-----------------------v--------+
                |              Core Library               |
                |                                         |
                |  +----------+  +--------------------+   |
                |  |  Group   |  |   Key Schedule     |   |
                |  |  State   |  |   & Secrets        |   |
                |  +----+-----+  +---------+----------+   |
                |       |                  |              |
                |  +----v------------------v-----------+  |
                |  |         Ratchet Tree              |  |
                |  +----+------------------------------+  |
                |       |                                 |
                |  +----v------------------------------+  |
                |  |     Message Framing & Codec       |  |
                |  +----+------------------------------+  |
                |       |                                 |
                |  +----v------------------------------+  |
                |  |     Crypto Provider (port)        |  |
                |  +-----------------------------------+  |
                +-----------------------------------------+
                         |  Adapters
                +--------v--------------------------------+
                |   Concrete Crypto Backend               |
                |   (Zig std.crypto, in-tree HPKE)        |
                +-----------------------------------------+
```

**Ports** are comptime interfaces that the core defines but does
not implement:

| Port | Purpose |
|---|---|
| `CryptoProvider` | HPKE, signatures, AEAD, KDF, hash -- one impl per cipher suite |
| `CredentialValidator` | Application-specific credential verification |
| `PskLookup` | External PSK secret resolution (application-provided storage) |
| `KeyStore` | Optional persistence of secrets, key packages, group state |

**Adapters** are concrete implementations supplied by the
application or by the default backend.

### Layer Dependency Rule

Each layer depends only on layers below it. No layer depends on
the Application layer.

```
Application
   |
Group State / Key Schedule / Proposals & Commits
   |
Ratchet Tree
   |
Message Framing & Codec
   |
Crypto Provider (port)
```

---

## Project Structure

```
zmls/
+-- build.zig                  Build system entry point
+-- build.zig.zon              Package manifest
+-- Makefile                   fmt / check / build / test targets
|
+-- src/
|   +-- zmls.zig               Root API -- re-exports public surface
|   |
|   +-- crypto/
|   |   +-- provider.zig       CryptoProvider comptime interface
|   |   +-- primitives.zig     Labeled operations, secureZero
|   |   +-- hpke.zig           HPKE base mode (RFC 9180)
|   |   +-- default.zig        Default backend (X25519/AES-128-GCM/SHA-256/Ed25519)
|   |
|   +-- codec/
|   |   +-- codec.zig          TLS-style encode/decode (slice-based, u32 position)
|   |   +-- varint.zig         Variable-length integer (RFC 9000 variant)
|   |
|   +-- tree/
|   |   +-- math.zig           Array-based tree index arithmetic (Appendix C)
|   |   +-- node.zig           LeafNode, ParentNode, Node types
|   |   +-- ratchet_tree.zig   RatchetTree: resolution, paths, add/remove
|   |   +-- hashes.zig         Tree hashes and parent hashes
|   |   +-- path.zig           UpdatePath generation, encryption, application
|   |
|   +-- key_schedule/
|   |   +-- schedule.zig       Epoch key derivation chain
|   |   +-- secret_tree.zig    Per-sender encryption ratchets
|   |   +-- psk.zig            PSK secret chaining
|   |   +-- transcript.zig     Confirmed & interim transcript hashes
|   |   +-- exporter.zig       MLS-Exporter function
|   |
|   +-- framing/
|   |   +-- content_type.zig   ContentType, SenderType, WireFormat enums
|   |   +-- framed_content.zig FramedContent, FramedContentTBS
|   |   +-- auth.zig           Signing, verification, confirmation tag
|   |   +-- public_msg.zig     PublicMessage encode/decode/verify
|   |   +-- private_msg.zig    PrivateMessage encrypt/decrypt
|   |   +-- mls_message.zig    Top-level MLSMessage wrapper
|   |
|   +-- group/
|   |   +-- context.zig        GroupContext struct and serialization
|   |   +-- state.zig          GroupState, createGroup
|   |   +-- evolution.zig      Proposal validation and application
|   |   +-- commit.zig         Commit creation and processing
|   |   +-- welcome.zig        Welcome processing
|   |   +-- external.zig       External join (Section 3.3)
|   |
|   +-- messages/
|   |   +-- proposal.zig       Proposal types (Add, Update, Remove, ...)
|   |   +-- commit.zig         Commit, ProposalOrRef
|   |   +-- welcome.zig        Welcome, GroupSecrets, EncryptedGroupSecrets
|   |   +-- key_package.zig    KeyPackage, KeyPackageTBS
|   |   +-- group_info.zig     GroupInfo, GroupInfoTBS
|   |
|   +-- credential/
|   |   +-- credential.zig     Credential, CredentialType
|   |   +-- validator.zig      CredentialValidator interface
|   |
|   +-- common/
|       +-- types.zig          Type aliases (Epoch, LeafIndex, NodeIndex, ...)
|       +-- errors.zig         Unified error set
|
+-- tests/
    +-- integration_test.zig   7 end-to-end protocol tests
    +-- interop_test.zig       13 tests against RFC 9420 test vectors
    +-- fuzz_codec.zig         Fuzz: codec decode
    +-- fuzz_tree.zig          Fuzz: tree operations
    +-- fuzz_proposals.zig     Fuzz: proposal validation
    +-- fuzz_messages.zig      Fuzz: message decode
```

---

## Building Blocks

Each block maps to one or more RFC 9420 sections. Listed
bottom-up.

### 1. Common Types & Errors (`common/`)

Shared type aliases and a unified error set.

| Type | Description |
|---|---|
| `Epoch` | `u64` -- group epoch counter |
| `LeafIndex` | `enum(u32)` -- leaf position in ratchet tree |
| `NodeIndex` | `enum(u32)` -- position in array-based tree |
| `Generation` | `u32` -- secret tree ratchet counter |
| `ProtocolVersion` | `enum { mls10 = 1 }` |
| `CipherSuite` | `enum(u16)` -- wire value |

Error set: `DecodeError`, `CryptoError`, `TreeError`,
`ValidationError`, `GroupError`.

### 2. Codec (`codec/`) -- RFC Section 2.1

TLS presentation language serialization using a slice-based API
with explicit `u32` position tracking. Functions take
`(buf: []u8, pos: u32, ...)` and return the new position.

Features:
- Big-endian integer encoding (u8, u16, u32, u64).
- Variable-length integer (1, 2, or 4 bytes, RFC 9000 variant).
- Length-prefixed vectors with variable headers.
- Optional presence byte.

### 3. Crypto Provider (`crypto/`) -- RFC Section 5

A comptime interface that abstracts all cryptographic operations.
The provider is passed as `comptime P: type` -- duck-typed at
compile time, zero runtime dispatch.

```zig
// Required constants
P.nh    // hash output length
P.nk    // AEAD key length
P.nn    // AEAD nonce length
P.nt    // AEAD tag length
P.npk   // DH public key length
P.nsk   // DH secret key length

// Required functions
P.hash(data) -> [nh]u8
P.kdfExtract(salt, ikm) -> [nh]u8
P.kdfExpand(prk, info, out)
P.aeadSeal(key, nonce, aad, pt, ct, tag)
P.aeadOpen(key, nonce, aad, ct, tag, pt) -> !void
P.sign(sk, msg) -> ![sig_len]u8
P.verify(pk, msg, sig) -> !void
P.dhKeypairFromSeed(seed) -> !{ sk, pk }
P.dh(sk, pk) -> ![shared_len]u8
P.validateDhPublicKey(pk) -> !void
```

**Default backend** (`default.zig`): cipher suite 0x0001
(DHKEM-X25519 + AES-128-GCM + SHA-256 + Ed25519) using
`std.crypto`. Includes X25519 low-order point rejection.

**HPKE** (`hpke.zig`): base mode (RFC 9180) built from the
provider primitives. Provides `encapDeterministic`, `decap`,
`sealBase`, `openBase`.

**Labeled operations** (`primitives.zig`): `expandWithLabel`,
`deriveSecret`, `encryptWithLabel`, `decryptWithLabel`,
`signWithLabel`, `verifyWithLabel`, `refHash`, `secureZero`.

### 4. Tree Math (`tree/math.zig`) -- RFC Appendix C

Pure arithmetic on array-based binary tree indices. No
allocations, no state.

| Function | Description |
|---|---|
| `level(x)` | Level of node (leaves = 0) |
| `nodeWidth(n)` | Total nodes for `n` leaves |
| `root(n)` | Root index |
| `left(x)` | Left child |
| `right(x)` | Right child |
| `parent(x, n)` | Parent |
| `sibling(x, n)` | Sibling |
| `directPath(x, n)` | Path from node to root |
| `copath(x, n)` | Copath |
| `commonAncestor(x, y)` | Lowest common ancestor |

### 5. Ratchet Tree (`tree/`) -- RFC Sections 4, 7

Array of `?Node` (null = blank). Managed struct -- stores its
allocator.

**Node types** (Section 7.1, 7.2):
- `LeafNode` -- encryption key, signature key, credential,
  capabilities, extensions, signature.
- `ParentNode` -- encryption key, parent hash, unmerged leaves.

**Operations** (Sections 7.4-7.9):
- `resolution(node_index)` -- non-blank node enumeration.
- `filteredDirectPath(leaf_index)` -- path excluding blanks.
- `addLeaf(LeafNode)` -- leftmost blank or extend.
- `removeLeaf(LeafIndex)` -- blank leaf + ancestors, truncate.
- `treeHash(node_index)` -- iterative subtree hash.
- `parentHash(node_index)` -- chain for tree integrity.

**Path secret evolution** (Section 7.4):
```
path_secret[0] = random
path_secret[n] = DeriveSecret(path_secret[n-1], "path")
node_secret[n] = DeriveSecret(path_secret[n], "node")
node_priv[n], node_pub[n] = DeriveKeyPair(node_secret[n])
commit_secret = path_secret[n+1]
```

### 6. Credentials (`credential/`) -- RFC Section 5.3

`Credential` is a tagged union: `basic` (opaque identity) or
`x509` (certificate chain). `CredentialValidator` is a port --
the application decides how to validate.

### 7. Key Schedule (`key_schedule/`) -- RFC Section 8

```
init_secret[n-1]
       |
  commit_secret --+
       |          |
  KDF.Extract <---+
       |
  ExpandWithLabel(., "joiner", GroupContext[n])
       |
  joiner_secret
       |        psk_secret
  KDF.Extract <-------------
       |
  +-- DeriveSecret(., "welcome") --> welcome_secret
  |
  ExpandWithLabel(., "epoch", GroupContext[n])
       |
  epoch_secret
       |
  +-- DeriveSecret(., "sender data")    -> sender_data_secret
  +-- DeriveSecret(., "encryption")     -> encryption_secret
  +-- DeriveSecret(., "exporter")       -> exporter_secret
  +-- DeriveSecret(., "external")       -> external_secret
  +-- DeriveSecret(., "confirm")        -> confirmation_key
  +-- DeriveSecret(., "membership")     -> membership_key
  +-- DeriveSecret(., "resumption")     -> resumption_psk
  +-- DeriveSecret(., "authentication") -> epoch_authenticator
  +-- DeriveSecret(., "init")           -> init_secret[n]
```

Sub-modules:
- `transcript.zig` -- confirmed and interim transcript hashes.
- `psk.zig` -- PSK secret chaining over PreSharedKeyIDs.
- `exporter.zig` -- `MLS-Exporter(Label, Context, Length)`.
- `secret_tree.zig` -- per-member encryption ratchets with
  generation overflow guard.

### 8. Message Framing (`framing/`) -- RFC Section 6

Two wire formats:

**PublicMessage** (Section 6.2) -- signed, unencrypted. Used for
handshake messages.

**PrivateMessage** (Section 6.3) -- signed and encrypted via
AEAD with keys from the secret tree. Sender data encrypted
separately.

**MLSMessage** -- top-level wrapper discriminated by WireFormat.

### 9. Messages (`messages/`) -- RFC Sections 10, 12

- **KeyPackage** -- version, cipher suite, init key, leaf node,
  extensions, signature.
- **Proposals** -- Add, Update, Remove, PreSharedKey, ReInit,
  ExternalInit, GroupContextExtensions.
- **Commit** -- list of ProposalOrRef + optional UpdatePath.
- **Welcome** -- cipher suite, encrypted group secrets per new
  member, encrypted GroupInfo.
- **GroupInfo** -- GroupContext, extensions, confirmation tag,
  signer, signature.

### 10. Group State & Operations (`group/`) -- RFC Sections 8.1, 11, 12

`GroupState` holds the combined mutable state for a member:
context, tree, epoch secrets, secret tree, transcript hashes,
leaf index.

- **createGroup** -- single-member group at epoch 0.
- **createCommit** -- validate proposals, apply to tree, generate
  UpdatePath, derive epoch secrets, sign, build Welcome.
- **processCommit** -- verify signature, apply proposals, decrypt
  path, derive secrets, verify confirmation tag.
- **processWelcome** -- decrypt group secrets, decrypt GroupInfo,
  verify signature, initialize tree, derive secrets.
- **createExternalCommit / processExternalCommit** -- external
  join via ExternalInit proposal + HPKE against external_pub.

---

## Cross-Cutting Concerns

### Memory Management

- Zig allocator interface everywhere. Caller controls strategy
  (arena, GPA, fixed-buffer).
- Managed structs (e.g. `RatchetTree`) store their allocator.
- Secrets zeroed via `secureZero` (volatile writes, not
  optimizable) before deallocation.

### Error Handling

- Per-module error sets unioned as needed.
- All fallible functions return `Error!T`.
- No panics in library code. `unreachable` only for
  proven-impossible states.

### Testing

- 310 unit tests (in-file `test` blocks).
- 7 integration tests (end-to-end protocol flows).
- 13 interop tests against RFC 9420 official test vectors.
- 4 fuzz target files (codec, tree, proposals, messages).
- Zero external test dependencies.


### Code Quality References

Two Zig codebases serve as examples of the quality bar this project
targets:

- **[ghostty](https://github.com/ghostty-org/ghostty)** --
  GPU-accelerated terminal emulator.
- **[tigerbeetle](https://github.com/tigerbeetle/tigerbeetle)** --
  Distributed financial transactions database (origin of Tiger Style).

When the two conflict, TigerBeetle takes precedence — it is
the origin of Tiger Style, which is the foundation of RULES.md.
Ghostty is a secondary reference for module layout and error handling.
