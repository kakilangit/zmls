//! Common type aliases (Epoch, LeafIndex, NodeIndex, CipherSuite, etc.)
//! used across the library to prevent accidental mixing of semantically
//! distinct values.
// Common type aliases used across the zmls library.
//
// Per RULES.md Section 3: use explicitly sized types and named wrappers
// to prevent accidental mixing of semantically distinct values.

const std = @import("std");
const assert = std.debug.assert;

/// Group epoch counter. Incremented on every Commit. Per RFC 9420 Section 8.1.
pub const Epoch = u64;

/// Leaf position in the ratchet tree. Per RFC 9420 Section 4.1.1.
pub const LeafIndex = enum(u32) {
    _,

    /// Convert a leaf index to the corresponding node index in the
    /// array-based tree representation. Per RFC 9420 Appendix C:
    /// leaf n is at array index 2*n.
    pub fn toNodeIndex(self: LeafIndex) NodeIndex {
        const v = @as(u32, @intFromEnum(self));
        if (v > 0x7FFFFFFF) @panic("LeafIndex overflow");
        return @enumFromInt(v * 2);
    }

    pub fn toU32(self: LeafIndex) u32 {
        return @intFromEnum(self);
    }

    pub fn fromU32(value: u32) LeafIndex {
        return @enumFromInt(value);
    }
};

/// Position in the array-based binary tree. Includes both leaf and parent nodes.
/// Per RFC 9420 Appendix C.
pub const NodeIndex = enum(u32) {
    _,

    pub fn toU32(self: NodeIndex) u32 {
        return @intFromEnum(self);
    }

    pub fn toUsize(self: NodeIndex) usize {
        return @intCast(@intFromEnum(self));
    }

    pub fn fromU32(value: u32) NodeIndex {
        return @enumFromInt(value);
    }

    pub fn fromUsize(value: usize) NodeIndex {
        assert(value <= std.math.maxInt(u32));
        return @enumFromInt(@as(u32, @intCast(value)));
    }
};

/// AEAD encryption generation counter. Per RFC 9420 Section 9.1.
pub const Generation = u32;

/// Protocol version. Per RFC 9420 Section 6.
pub const ProtocolVersion = enum(u16) {
    reserved = 0,
    mls10 = 1,
    _,
};

/// Wire-level cipher suite identifier. Per RFC 9420 Section 5.1.
///
/// Values 0x0001–0x0007 follow the IANA MLS Cipher Suites registry.
/// Suites 0x0004–0x0006 (X448/Ed448, P-521) are not implemented.
/// The P256/ChaCha20 combination is non-standard and uses a
/// private-use value (0xF001).
pub const CipherSuite = enum(u16) {
    reserved = 0x0000,
    mls_128_dhkemx25519_aes128gcm_sha256_ed25519 = 0x0001,
    mls_128_dhkemp256_aes128gcm_sha256_p256 = 0x0002,
    mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 = 0x0003,
    mls_256_dhkemx448_aes256gcm_sha512_ed448 = 0x0004,
    mls_256_dhkemp521_aes256gcm_sha512_p521 = 0x0005,
    mls_256_dhkemx448_chacha20poly1305_sha512_ed448 = 0x0006,
    mls_256_dhkemp384_aes256gcm_sha384_p384 = 0x0007,
    /// Non-standard: P-256/ChaCha20Poly1305/SHA-256/P-256.
    /// Uses a private-use value per RFC 9420 Section 17.1.
    mls_128_dhkemp256_chacha20poly1305_sha256_p256 = 0xF001,
    _,
};

/// Content type discriminator for framed messages. Per RFC 9420 Section 6.
pub const ContentType = enum(u8) {
    reserved = 0,
    application = 1,
    proposal = 2,
    commit = 3,
    _,
};

/// Sender type discriminator. Per RFC 9420 Section 6.
pub const SenderType = enum(u8) {
    reserved = 0,
    member = 1,
    external = 2,
    new_member_proposal = 3,
    new_member_commit = 4,
    _,
};

/// Wire format discriminator for top-level MLS messages. Per RFC 9420 Section 6.
pub const WireFormat = enum(u16) {
    reserved = 0,
    mls_public_message = 1,
    mls_private_message = 2,
    mls_welcome = 3,
    mls_group_info = 4,
    mls_key_package = 5,
    _,
};

/// Wire format policy for outgoing messages.
///
/// Per RFC 9420 Section 6.2, application data MUST be sent as
/// PrivateMessage. Handshake messages MAY be sent as either.
pub const WireFormatPolicy = enum(u8) {
    /// All messages (handshake + application) encrypted.
    always_encrypt = 0,
    /// Application data encrypted; handshake may be public.
    encrypt_application_only = 1,
};

/// Proposal type discriminator. Per RFC 9420 Section 12.1.
pub const ProposalType = enum(u16) {
    reserved = 0,
    add = 1,
    update = 2,
    remove = 3,
    psk = 4,
    reinit = 5,
    external_init = 6,
    group_context_extensions = 7,
    _,
};

/// Credential type discriminator. Per RFC 9420 Section 5.3.
pub const CredentialType = enum(u16) {
    reserved = 0,
    basic = 1,
    x509 = 2,
    _,
};

/// Extension type discriminator. Per RFC 9420 Section 13.4.
pub const ExtensionType = enum(u16) {
    reserved = 0,
    application_id = 1,
    ratchet_tree = 2,
    required_capabilities = 3,
    external_pub = 4,
    external_senders = 5,
    last_resort = 10,
    _,
};

/// Leaf node source discriminator. Per RFC 9420 Section 7.2.
pub const LeafNodeSource = enum(u8) {
    reserved = 0,
    key_package = 1,
    update = 2,
    commit = 3,
    _,
};

/// Maximum size for variable-length vectors in bytes.
///
/// RFC 9420 §6 uses a varint encoding that supports vectors up to 2^30-1
/// bytes (~1 GiB). This implementation intentionally uses a much smaller
/// limit as a security hardening measure to prevent memory exhaustion from
/// malicious or malformed input.
///
/// NOTE: deployments that use very large ratchet_tree extensions, long
/// certificate chains, or other large payloads may need to increase this
/// value. Doing so trades memory-safety margin for interoperability with
/// peers that produce large vectors.
pub const max_vec_length: u32 = 1 << 20; // 1 MiB.

/// Per-field decode limits for known-bounded MLS fields.
pub const max_public_key_length: u32 = 256;
pub const max_signature_length: u32 = 512;
pub const max_hash_length: u32 = 128;
pub const max_credential_length: u32 = 1 << 16; // 64 KiB.
pub const max_extension_data_length: u32 = 1 << 18; // 256 KiB.

// Compile-time assertions on type sizes.
comptime {
    std.debug.assert(@sizeOf(Epoch) == 8);
    std.debug.assert(@sizeOf(LeafIndex) == 4);
    std.debug.assert(@sizeOf(NodeIndex) == 4);
    std.debug.assert(@sizeOf(ProtocolVersion) == 2);
    std.debug.assert(@sizeOf(CipherSuite) == 2);
    std.debug.assert(@sizeOf(ContentType) == 1);
    std.debug.assert(@sizeOf(SenderType) == 1);
    std.debug.assert(@sizeOf(WireFormat) == 2);
    std.debug.assert(@sizeOf(ProposalType) == 2);
    std.debug.assert(@sizeOf(CredentialType) == 2);
    std.debug.assert(@sizeOf(ExtensionType) == 2);
    std.debug.assert(@sizeOf(LeafNodeSource) == 1);
}

test "LeafIndex to NodeIndex conversion" {
    const testing = std.testing;

    // Leaf 0 → node 0.
    try testing.expectEqual(@as(u32, 0), LeafIndex.fromU32(0).toNodeIndex().toU32());
    // Leaf 1 → node 2.
    try testing.expectEqual(@as(u32, 2), LeafIndex.fromU32(1).toNodeIndex().toU32());
    // Leaf 3 → node 6.
    try testing.expectEqual(@as(u32, 6), LeafIndex.fromU32(3).toNodeIndex().toU32());
}
