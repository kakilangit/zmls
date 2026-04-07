//! Zig MLS (RFC 9420) library.
//!
//! This is the root module. Public API is re-exported here
//! as each layer is implemented.

// ── Foundation ──────────────────────────────────────────────

/// Common protocol types (LeafIndex, NodeIndex, Epoch,
/// ProtocolVersion, CipherSuite, SenderType, ContentType,
/// ExtensionType, ProposalType, CredentialType, WireFormat).
pub const types = @import("common/types.zig");

/// Error sets for all modules (CryptoError, TreeError,
/// ValidationError, GroupError, DecodeError).
pub const errors = @import("common/errors.zig");

/// GREASE (Generate Random Extensions And Sustain
/// Extensibility) -- RFC 9420 Section 13.4.
pub const grease = @import("common/grease.zig");

// ── Codec ───────────────────────────────────────────────────

/// TLS presentation language serialization/deserialization.
/// Slice-based API: `encode(buf, pos, ...)` -> new position.
pub const codec = @import("codec/codec.zig");

/// Variable-length integer encoding (RFC 9420 Section 2.1.2).
pub const varint = @import("codec/varint.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
