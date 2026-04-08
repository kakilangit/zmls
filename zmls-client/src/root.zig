//! zmls-client — Client & Delivery Service framework for zmls.
//!
//! High-level `Client(P)` and `Server` types on top of the zmls
//! protocol core. Hexagonal architecture: applications supply
//! adapters for storage, transport, and directory ports.
//!
//! ## Quick start
//!
//! ```zig
//! const zmls_client = @import("zmls-client");
//! const zmls = @import("zmls");
//! const P = zmls.DefaultCryptoProvider;
//!
//! var client = try zmls_client.Client(P).init(
//!     allocator, identity, .x25519_aes128gcm_sha256_ed25519,
//!     &seed, .{},
//! );
//! defer client.deinit();
//! ```

// ── Ports ──────────────────────────────────────────────────

/// Group state persistence port.
pub const GroupStore = @import("ports/group_store.zig").GroupStore;

/// Private key persistence port (comptime-generic over P).
pub const KeyStore = @import("ports/key_store.zig").KeyStore;

/// Message delivery transport port.
pub const transport = @import("ports/transport.zig");
pub const Transport = transport.Transport;
pub const MessageType = transport.MessageType;
pub const ReceivedEnvelope = transport.ReceivedEnvelope;

/// Server-side group membership and message queue port.
pub const GroupDirectory =
    @import("ports/group_directory.zig").GroupDirectory;

/// Server-side KeyPackage registry port.
pub const KeyPackageDirectory =
    @import("ports/kp_directory.zig").KeyPackageDirectory;

/// Server-side GroupInfo registry port.
pub const GroupInfoDirectory =
    @import("ports/gi_directory.zig").GroupInfoDirectory;

// ── Adapters ───────────────────────────────────────────────

/// In-memory bounded group state store.
pub const MemoryGroupStore =
    @import("adapters/memory_group_store.zig").MemoryGroupStore;

/// In-memory bounded private key store.
pub const MemoryKeyStore =
    @import("adapters/memory_key_store.zig").MemoryKeyStore;

/// In-process loopback message transport.
pub const LoopbackTransport =
    @import("adapters/loopback_transport.zig").LoopbackTransport;

/// In-memory bounded group directory.
pub const MemoryGroupDirectory =
    @import("adapters/memory_group_directory.zig")
        .MemoryGroupDirectory;

/// In-memory bounded KeyPackage directory.
pub const MemoryKeyPackageDirectory =
    @import("adapters/memory_kp_directory.zig")
        .MemoryKeyPackageDirectory;

/// In-memory bounded GroupInfo directory.
pub const MemoryGroupInfoDirectory =
    @import("adapters/memory_gi_directory.zig")
        .MemoryGroupInfoDirectory;

// ── Wire Protocol ──────────────────────────────────────────

/// Envelope framing for the wire protocol.
pub const wire = @import("wire/envelope.zig");

// ── Client ─────────────────────────────────────────────────

/// High-level MLS client parameterized over CryptoProvider.
pub const Client = @import("client/client.zig").Client;

/// Client result and configuration types.
pub const client_types = @import("client/types.zig");
pub const WireFormatPolicy = client_types.WireFormatPolicy;
pub const InviteResult = client_types.InviteResult;
pub const ExternalJoinResult = client_types.ExternalJoinResult;
pub const ReceivedMessage = client_types.ReceivedMessage;
pub const ProcessingResult = client_types.ProcessingResult;
pub const MemberInfo = client_types.MemberInfo;

/// Pending KeyPackage map (bounded, secureZero on removal).
pub const PendingKeyPackageMap =
    @import("client/pending.zig").PendingKeyPackageMap;

// ── Delivery Service ───────────────────────────────────────

/// Delivery service (dumb relay).
pub const DeliveryService =
    @import("delivery_service/delivery_service.zig")
        .DeliveryService;

test {
    // Pull in tests from all submodules.
    @import("std").testing.refAllDecls(@This());
}
