//! Proposal types (Add, Update, Remove, PSK, ReInit, ExternalInit,
//! GroupContextExtensions) per RFC 9420 Section 12.1 with tagged
//! union encode/decode.
// Proposal types per RFC 9420 Section 12.1.
//
//   struct {
//       ProposalType msg_type;
//       select (Proposal.msg_type) {
//           case add:                      Add;
//           case update:                   Update;
//           case remove:                   Remove;
//           case psk:                      PreSharedKey;
//           case reinit:                   ReInit;
//           case external_init:            ExternalInit;
//           case group_context_extensions: GroupContextExtensions;
//       };
//   } Proposal;

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const kp_mod = @import("key_package.zig");
const prim = @import("../crypto/primitives.zig");
const psk_mod = @import("../key_schedule/psk.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const ProposalType = types.ProposalType;
const CipherSuite = types.CipherSuite;
const ProtocolVersion = types.ProtocolVersion;
const Extension = node_mod.Extension;
const LeafNode = node_mod.LeafNode;
const KeyPackage = kp_mod.KeyPackage;
const PreSharedKeyId = psk_mod.PreSharedKeyId;

// -- Individual proposal structs ------------------------------------------

/// Add: proposes adding a new member via their KeyPackage.
///   struct { KeyPackage key_package; } Add;
pub const Add = struct {
    key_package: KeyPackage,

    pub fn encode(
        self: *const Add,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return self.key_package.encode(buf, pos);
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Add,
        pos: u32,
    } {
        const r = try KeyPackage.decode(allocator, data, pos);
        return .{
            .value = .{ .key_package = r.value },
            .pos = r.pos,
        };
    }

    pub fn deinit(
        self: *Add,
        allocator: std.mem.Allocator,
    ) void {
        self.key_package.deinit(allocator);
        self.* = undefined;
    }
};

/// Update: proposes updating the sender's own leaf node.
///   struct { LeafNode leaf_node; } Update;
pub const Update = struct {
    leaf_node: LeafNode,

    pub fn encode(
        self: *const Update,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return self.leaf_node.encode(buf, pos);
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Update,
        pos: u32,
    } {
        const r = try LeafNode.decode(allocator, data, pos);
        return .{
            .value = .{ .leaf_node = r.value },
            .pos = r.pos,
        };
    }

    pub fn deinit(
        self: *Update,
        allocator: std.mem.Allocator,
    ) void {
        self.leaf_node.deinit(allocator);
        self.* = undefined;
    }
};

/// Remove: proposes removing a member by leaf index.
///   struct { uint32 removed; } Remove;
pub const Remove = struct {
    removed: u32,

    pub fn encode(
        self: *const Remove,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return codec.encodeUint32(buf, pos, self.removed);
    }

    pub fn decode(
        data: []const u8,
        pos: u32,
    ) DecodeError!struct { value: Remove, pos: u32 } {
        const r = try codec.decodeUint32(data, pos);
        return .{
            .value = .{ .removed = r.value },
            .pos = r.pos,
        };
    }
};

/// PreSharedKey: proposes injecting a PSK.
///   struct { PreSharedKeyID psk; } PreSharedKey;
pub const PreSharedKey = struct {
    psk: PreSharedKeyId,

    pub fn encode(
        self: *const PreSharedKey,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return self.psk.encode(buf, pos);
    }

    pub fn decode(
        data: []const u8,
        pos: u32,
    ) DecodeError!struct { value: PreSharedKey, pos: u32 } {
        const r = try PreSharedKeyId.decode(data, pos);
        return .{
            .value = .{ .psk = r.value },
            .pos = r.pos,
        };
    }
};

/// ReInit: proposes reinitializing the group with new parameters.
///   struct {
///       opaque group_id<V>;
///       ProtocolVersion version;
///       CipherSuite cipher_suite;
///       Extension extensions<V>;
///   } ReInit;
pub const ReInit = struct {
    group_id: []const u8,
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    extensions: []const Extension,

    pub fn encode(
        self: *const ReInit,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        p = try codec.encodeVarVector(buf, p, self.group_id);
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.version),
        );
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.cipher_suite),
        );
        p = try encodeExtensionList(buf, p, self.extensions);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: ReInit,
        pos: u32,
    } {
        var p = pos;
        const gid_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_public_key_length,
        );
        p = gid_r.pos;
        const ver_r = try codec.decodeUint16(data, p);
        p = ver_r.pos;
        const cs_r = try codec.decodeUint16(data, p);
        p = cs_r.pos;
        const ext_r = try decodeExtensionList(
            allocator,
            data,
            p,
        );
        p = ext_r.pos;
        return .{
            .value = .{
                .group_id = gid_r.value,
                .version = @enumFromInt(ver_r.value),
                .cipher_suite = @enumFromInt(cs_r.value),
                .extensions = @as(
                    []const Extension,
                    ext_r.value,
                ),
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *ReInit,
        allocator: std.mem.Allocator,
    ) void {
        if (self.group_id.len > 0) {
            allocator.free(self.group_id);
        }
        for (self.extensions) |*ext| {
            @constCast(ext).deinit(allocator);
        }
        if (self.extensions.len > 0) {
            allocator.free(self.extensions);
        }
        self.* = undefined;
    }
};

/// ExternalInit: proposes an external join.
///   struct { opaque kem_output<V>; } ExternalInit;
pub const ExternalInit = struct {
    kem_output: []const u8,

    pub fn encode(
        self: *const ExternalInit,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return codec.encodeVarVector(buf, pos, self.kem_output);
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: ExternalInit,
        pos: u32,
    } {
        const r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_public_key_length,
        );
        return .{
            .value = .{ .kem_output = r.value },
            .pos = r.pos,
        };
    }

    pub fn deinit(
        self: *ExternalInit,
        allocator: std.mem.Allocator,
    ) void {
        if (self.kem_output.len > 0) {
            allocator.free(self.kem_output);
        }
        self.* = undefined;
    }
};

/// GroupContextExtensions: proposes changing group extensions.
///   struct { Extension extensions<V>; } GroupContextExtensions;
pub const GroupContextExtensions = struct {
    extensions: []const Extension,

    pub fn encode(
        self: *const GroupContextExtensions,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return encodeExtensionList(buf, pos, self.extensions);
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: GroupContextExtensions,
        pos: u32,
    } {
        const ext_r = try decodeExtensionList(
            allocator,
            data,
            pos,
        );
        return .{
            .value = .{
                .extensions = @as(
                    []const Extension,
                    ext_r.value,
                ),
            },
            .pos = ext_r.pos,
        };
    }

    pub fn deinit(
        self: *GroupContextExtensions,
        allocator: std.mem.Allocator,
    ) void {
        for (self.extensions) |*ext| {
            @constCast(ext).deinit(allocator);
        }
        if (self.extensions.len > 0) {
            allocator.free(self.extensions);
        }
        self.* = undefined;
    }
};

// -- Proposal tagged union ------------------------------------------------

/// Proposal payload union.
pub const ProposalPayload = union {
    add: Add,
    update: Update,
    remove: Remove,
    psk: PreSharedKey,
    reinit: ReInit,
    external_init: ExternalInit,
    group_context_extensions: GroupContextExtensions,
    /// Opaque payload for unknown/GREASE proposal types.
    /// RFC 9420 Section 13 requires tolerance of unknown values.
    unknown: []const u8,
};

/// The top-level Proposal struct, tagged by ProposalType.
pub const Proposal = struct {
    tag: ProposalType,
    payload: ProposalPayload,

    // -- Encode -----------------------------------------------------------

    pub fn encode(
        self: *const Proposal,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint16(
            buf,
            pos,
            @intFromEnum(self.tag),
        );
        switch (self.tag) {
            .add => {
                p = try self.payload.add.encode(buf, p);
            },
            .update => {
                p = try self.payload.update.encode(buf, p);
            },
            .remove => {
                p = try self.payload.remove.encode(buf, p);
            },
            .psk => {
                p = try self.payload.psk.encode(buf, p);
            },
            .reinit => {
                p = try self.payload.reinit.encode(buf, p);
            },
            .external_init => {
                p = try self.payload
                    .external_init.encode(buf, p);
            },
            .group_context_extensions => {
                p = try self.payload
                    .group_context_extensions.encode(buf, p);
            },
            else => {
                // Unknown/GREASE: write opaque body bytes.
                const body = self.payload.unknown;
                const blen: u32 = @intCast(body.len);
                if (p + blen > buf.len) {
                    return error.BufferTooSmall;
                }
                @memcpy(buf[p..][0..blen], body);
                p += blen;
            },
        }
        return p;
    }

    // -- Decode -----------------------------------------------------------

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Proposal,
        pos: u32,
    } {
        const type_r = try codec.decodeUint16(data, pos);
        const tag: ProposalType = @enumFromInt(type_r.value);
        var p = type_r.pos;

        switch (tag) {
            .add => {
                const r = try Add.decode(allocator, data, p);
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .add = r.value },
                    },
                    .pos = p,
                };
            },
            .update => {
                const r = try Update.decode(
                    allocator,
                    data,
                    p,
                );
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .update = r.value },
                    },
                    .pos = p,
                };
            },
            .remove => {
                const r = try Remove.decode(data, p);
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .remove = r.value },
                    },
                    .pos = p,
                };
            },
            .psk => {
                const r = try PreSharedKey.decode(data, p);
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .psk = r.value },
                    },
                    .pos = p,
                };
            },
            .reinit => {
                const r = try ReInit.decode(
                    allocator,
                    data,
                    p,
                );
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .reinit = r.value },
                    },
                    .pos = p,
                };
            },
            .external_init => {
                const r = try ExternalInit.decode(
                    allocator,
                    data,
                    p,
                );
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{
                            .external_init = r.value,
                        },
                    },
                    .pos = p,
                };
            },
            .group_context_extensions => {
                const r = try GroupContextExtensions.decode(
                    allocator,
                    data,
                    p,
                );
                p = r.pos;
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{
                            .group_context_extensions = r.value,
                        },
                    },
                    .pos = p,
                };
            },
            else => {
                // Unknown/GREASE proposal type (RFC 9420 S13).
                // Assume zero-length body: the TLS select
                // construct provides no length prefix for
                // unknown variants, so we cannot determine the
                // body boundary. GREASE proposals have empty
                // bodies by convention.
                return .{
                    .value = .{
                        .tag = tag,
                        .payload = .{ .unknown = &.{} },
                    },
                    .pos = p,
                };
            },
        }
    }

    // -- makeRef ----------------------------------------------------------

    /// Compute the ProposalRef for this Proposal.
    ///
    ///   ProposalRef = RefHash("MLS 1.0 Proposal Reference",
    ///                         Proposal)
    pub fn makeRef(
        self: *const Proposal,
        comptime P: type,
    ) CryptoError![P.nh]u8 {
        const max_encode: u32 = 65536;
        var buf: [max_encode]u8 = undefined;
        const end = self.encode(
            &buf,
            0,
        ) catch return error.KdfOutputTooLong;
        return prim.refHash(
            P,
            "MLS 1.0 Proposal Reference",
            buf[0..end],
        );
    }

    // -- Skip decode ------------------------------------------------------

    /// Advance past an encoded Proposal without allocating.
    /// Returns the position after the Proposal.
    pub fn skipDecode(
        data: []const u8,
        pos: u32,
    ) DecodeError!u32 {
        const type_r = try codec.decodeUint16(data, pos);
        const tag: ProposalType = @enumFromInt(type_r.value);
        var p = type_r.pos;
        switch (tag) {
            .add => {
                p = try skipKeyPackage(data, p);
            },
            .update => {
                p = try skipLeafNode(data, p);
            },
            .remove => {
                if (p + 4 > data.len) return error.Truncated;
                p += 4; // uint32 removed
            },
            .psk => {
                p = try skipPreSharedKeyId(data, p);
            },
            .reinit => {
                // group_id<V>, version u16, cipher_suite u16,
                // extensions<V>
                p = try codec.skipVarVector(data, p);
                if (p + 4 > data.len) return error.Truncated;
                p += 4; // version + cipher_suite
                p = try codec.skipVarVector(data, p);
            },
            .external_init => {
                p = try codec.skipVarVector(data, p);
            },
            .group_context_extensions => {
                p = try codec.skipVarVector(data, p);
            },
            else => {
                // Unknown/GREASE: assume zero-length body.
                // See Proposal.decode comment.
            },
        }
        return p;
    }

    // -- Cleanup ----------------------------------------------------------

    pub fn deinit(
        self: *Proposal,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.tag) {
            .add => self.payload.add.deinit(allocator),
            .update => self.payload.update.deinit(allocator),
            .reinit => self.payload.reinit.deinit(allocator),
            .external_init => {
                self.payload.external_init.deinit(allocator);
            },
            .group_context_extensions => {
                self.payload
                    .group_context_extensions.deinit(allocator);
            },
            // Remove and psk have no heap allocations.
            .remove, .psk => {},
            else => {
                // Unknown/GREASE: free opaque body if allocated.
                const body = self.payload.unknown;
                if (body.len > 0) {
                    allocator.free(body);
                }
            },
        }
        self.* = undefined;
    }
};

// -- Extension list codec helpers (same pattern as key_package.zig) --------

const max_extensions: u32 = 64;

fn encodeExtensionList(
    buf: []u8,
    pos: u32,
    exts: []const Extension,
) EncodeError!u32 {
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;
    for (exts) |*ext| {
        p = try ext.encode(buf, p);
    }
    const inner_len: u32 = p - start;
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(
        &len_buf,
        0,
        inner_len,
    );
    const dest_start = pos + len_end;
    if (dest_start != start) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[start..][0..inner_len],
        );
    }
    @memcpy(buf[pos..][0..len_end], len_buf[0..len_end]);
    return dest_start + inner_len;
}

/// Free extension data slices allocated during decode.
fn freeDecodedExts(
    allocator: std.mem.Allocator,
    exts: []Extension,
) void {
    for (exts) |ext| allocator.free(ext.data);
}

fn decodeExtensionList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []Extension,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;
    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;
    const end = p + total_len;
    var temp: [max_extensions]Extension = undefined;
    var count: u32 = 0;
    while (p < end) {
        if (count >= max_extensions) {
            return error.VectorTooLarge;
        }
        const ext_r = try Extension.decode(
            allocator,
            data,
            p,
        );
        temp[count] = ext_r.value;
        count += 1;
        p = ext_r.pos;
    }
    if (p != end) return error.Truncated;

    // RFC 9420 S13.4: reject duplicate extension types.
    var di: u32 = 0;
    while (di < count) : (di += 1) {
        var dj: u32 = di + 1;
        while (dj < count) : (dj += 1) {
            if (temp[di].extension_type ==
                temp[dj].extension_type)
            {
                freeDecodedExts(allocator, temp[0..count]);
                return error.DuplicateExtensionType;
            }
        }
    }
    const exts = allocator.alloc(
        Extension,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(exts, temp[0..count]);
    return .{ .value = exts, .pos = p };
}

// -- Skip-decode helpers (advance position without allocating) ----------

/// Skip over an encoded Credential.
/// Credential = u16 tag + (basic: <V>) | (x509: <V>).
fn skipCredential(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    // u16 credential_type, then variant body.
    // Both basic and x509 bodies are a single <V> vector.
    const ct = try codec.decodeUint16(data, pos);
    return codec.skipVarVector(data, ct.pos);
}

/// Skip over encoded Capabilities.
/// Capabilities = 5 x <V> (versions, cipher_suites, extensions,
///                          proposals, credentials).
fn skipCapabilities(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    var p = pos;
    // Five varint-prefixed lists.
    p = try codec.skipVarVector(data, p);
    p = try codec.skipVarVector(data, p);
    p = try codec.skipVarVector(data, p);
    p = try codec.skipVarVector(data, p);
    p = try codec.skipVarVector(data, p);
    return p;
}

/// Skip over an encoded LeafNode.
/// LeafNode = encryption_key<V> + signature_key<V> + Credential
///          + Capabilities + u8 source + [Lifetime if key_package]
///          + extensions<V> + signature<V>.
pub fn skipLeafNode(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    var p = pos;
    p = try codec.skipVarVector(data, p); // encryption_key
    p = try codec.skipVarVector(data, p); // signature_key
    p = try skipCredential(data, p);
    p = try skipCapabilities(data, p);
    const src = try codec.decodeUint8(data, p);
    p = src.pos;
    if (src.value == 0x01) {
        // key_package source: Lifetime = u64 + u64.
        if (p + 16 > data.len) return error.Truncated;
        p += 16;
    } else if (src.value == 0x03) {
        // Commit source: parent_hash<V>.
        p = try codec.skipVarVector(data, p);
    }
    // update(0x02) has no extra fields.
    p = try codec.skipVarVector(data, p); // extensions
    p = try codec.skipVarVector(data, p); // signature
    return p;
}

/// Skip over an encoded KeyPackage.
/// KeyPackage = u16 version + u16 cipher_suite + init_key<V>
///            + LeafNode + extensions<V> + signature<V>.
fn skipKeyPackage(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    var p = pos;
    if (p + 4 > data.len) return error.Truncated;
    p += 4; // version + cipher_suite
    p = try codec.skipVarVector(data, p); // init_key
    p = try skipLeafNode(data, p);
    p = try codec.skipVarVector(data, p); // extensions
    p = try codec.skipVarVector(data, p); // signature
    return p;
}

/// Skip over an encoded PreSharedKeyId.
/// PreSharedKeyId = u8 psk_type + variant + psk_nonce<V>.
fn skipPreSharedKeyId(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    var p = pos;
    const psk_type = try codec.decodeUint8(data, p);
    p = psk_type.pos;
    switch (psk_type.value) {
        0x01 => { // external
            p = try codec.skipVarVector(data, p); // psk_id
        },
        0x02 => { // resumption
            if (p + 1 > data.len) return error.Truncated;
            p += 1; // usage u8
            p = try codec.skipVarVector(data, p); // group_id
            if (p + 8 > data.len) return error.Truncated;
            p += 8; // epoch u64
        },
        else => return error.InvalidEnumValue,
    }
    p = try codec.skipVarVector(data, p); // psk_nonce
    return p;
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import("../crypto/default.zig")
    .DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import("../credential/credential.zig")
    .Credential;
const CredentialType = types.CredentialType;
const ExtensionType = types.ExtensionType;
const Capabilities = node_mod.Capabilities;
const Lifetime = node_mod.Lifetime;

test "Proposal Add round-trip" {
    const alloc = testing.allocator;

    // Build a minimal KeyPackage for the Add proposal.
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]ExtensionType{};
    const prop_types = comptime [_]ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

    const kp = KeyPackage{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .init_key = &[_]u8{0x01} ** 32,
        .leaf_node = .{
            .encryption_key = &[_]u8{0x02} ** 32,
            .signature_key = &[_]u8{0x03} ** 32,
            .credential = Credential.initBasic("bob"),
            .capabilities = .{
                .versions = &versions,
                .cipher_suites = &suites,
                .extensions = &ext_types,
                .proposals = &prop_types,
                .credentials = &cred_types,
            },
            .source = .key_package,
            .lifetime = .{
                .not_before = 100,
                .not_after = 200,
            },
            .parent_hash = null,
            .extensions = &.{},
            .signature = &[_]u8{0xAA} ** 4,
        },
        .extensions = &.{},
        .signature = &[_]u8{0xBB} ** 4,
    };

    const prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = kp } },
    };

    var buf: [4096]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(ProposalType.add, dec_r.value.tag);
    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.payload.add.key_package.version,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Proposal Remove round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 42 } },
    };

    var buf: [64]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.remove,
        dec_r.value.tag,
    );
    try testing.expectEqual(
        @as(u32, 42),
        dec_r.value.payload.remove.removed,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Proposal PreSharedKey round-trip" {
    const alloc = testing.allocator;

    const psk_id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "nonce123",
    };

    const prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = psk_id } },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(ProposalType.psk, dec_r.value.tag);
    try testing.expectEqual(
        psk_mod.PskType.external,
        dec_r.value.payload.psk.psk.psk_type,
    );
}

test "Proposal ExternalInit round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .external_init,
        .payload = .{
            .external_init = .{
                .kem_output = "kem-out-data",
            },
        },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.external_init,
        dec_r.value.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "kem-out-data",
        dec_r.value.payload.external_init.kem_output,
    );
}

test "Proposal ReInit round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };

    var buf: [256]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.reinit,
        dec_r.value.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "new-group",
        dec_r.value.payload.reinit.group_id,
    );
    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.payload.reinit.version,
    );
}

test "Proposal GroupContextExtensions round-trip" {
    const alloc = testing.allocator;

    const prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = &.{},
            },
        },
    };

    var buf: [64]u8 = undefined;
    const end = try prop.encode(&buf, 0);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProposalType.group_context_extensions,
        dec_r.value.tag,
    );
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload
            .group_context_extensions.extensions.len,
    );
}

test "Proposal makeRef is deterministic" {
    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 7 } },
    };

    const ref1 = try prop.makeRef(Default);
    const ref2 = try prop.makeRef(Default);
    try testing.expectEqualSlices(u8, &ref1, &ref2);
    try testing.expectEqual(@as(usize, 32), ref1.len);
}

test "Proposal decode accepts unknown/GREASE type" {
    const alloc = testing.allocator;
    var buf: [4]u8 = undefined;
    _ = try codec.encodeUint16(&buf, 0, 0xFFFF);
    var dec_r = try Proposal.decode(alloc, &buf, 0);
    defer dec_r.value.deinit(alloc);

    // Tag preserves the raw value.
    try testing.expectEqual(
        @as(u16, 0xFFFF),
        @intFromEnum(dec_r.value.tag),
    );
    // Payload is the unknown variant with empty body.
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload.unknown.len,
    );
    // Position advanced past the 2-byte tag only.
    try testing.expectEqual(@as(u32, 2), dec_r.pos);
}

test "Proposal unknown/GREASE encode round-trip" {
    const alloc = testing.allocator;
    const grease_tag: ProposalType = @enumFromInt(0x0A0A);
    const prop = Proposal{
        .tag = grease_tag,
        .payload = .{ .unknown = &.{} },
    };

    var buf: [4]u8 = undefined;
    const end = try prop.encode(&buf, 0);
    try testing.expectEqual(@as(u32, 2), end);

    var dec_r = try Proposal.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(grease_tag, dec_r.value.tag);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.payload.unknown.len,
    );
}

test "Proposal skipDecode handles unknown type" {
    var buf: [4]u8 = undefined;
    _ = try codec.encodeUint16(&buf, 0, 0x0A0A);
    const p = try Proposal.skipDecode(&buf, 0);
    // Advances past 2-byte tag, zero-length body.
    try testing.expectEqual(@as(u32, 2), p);
}
