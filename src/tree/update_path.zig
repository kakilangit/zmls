//! UpdatePath wire format types (HPKECiphertext, UpdatePathNode,
//! UpdatePath) and list codec helpers per RFC 9420 Section 7.5-7.6.

const std = @import("std");
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("node.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const LeafNode = node_mod.LeafNode;

/// Maximum number of HPKE ciphertexts per UpdatePathNode.
pub const max_ciphertexts: u32 = 1024;

/// Maximum number of UpdatePathNodes in an UpdatePath.
pub const max_path_nodes: u32 = 32;

/// Maximum encoded size for HPKE ciphertext components.
const max_ct_data: u32 = 8192;

// -- HPKECiphertext (Section 7.6) -------------------------------------------

/// An HPKE ciphertext: KEM output + encrypted payload.
///
///   struct {
///       opaque kem_output<V>;
///       opaque ciphertext<V>;
///   } HPKECiphertext;
pub const HPKECiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,

    pub fn encode(
        self: *const HPKECiphertext,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeVarVector(
            buf,
            pos,
            self.kem_output,
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.ciphertext,
        );
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: HPKECiphertext,
        pos: u32,
    } {
        const kem_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_public_key_length,
        );
        const ct_r = try codec.decodeVarVector(
            allocator,
            data,
            kem_r.pos,
        );
        return .{
            .value = .{
                .kem_output = kem_r.value,
                .ciphertext = ct_r.value,
            },
            .pos = ct_r.pos,
        };
    }

    pub fn deinit(
        self: *HPKECiphertext,
        allocator: std.mem.Allocator,
    ) void {
        if (self.kem_output.len > 0) {
            allocator.free(self.kem_output);
        }
        if (self.ciphertext.len > 0) {
            allocator.free(self.ciphertext);
        }
        self.* = undefined;
    }
};

// -- UpdatePathNode (Section 7.6) -------------------------------------------

/// A node in an UpdatePath: new encryption key + encrypted path
/// secrets for the copath resolution.
///
///   struct {
///       HPKEPublicKey encryption_key;
///       HPKECiphertext encrypted_path_secret<V>;
///   } UpdatePathNode;
pub const UpdatePathNode = struct {
    encryption_key: []const u8,
    encrypted_path_secret: []const HPKECiphertext,

    pub fn encode(
        self: *const UpdatePathNode,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeVarVector(
            buf,
            pos,
            self.encryption_key,
        );
        // encrypted_path_secret<V>: varint-prefixed list.
        p = try encodeHpkeCiphertextList(
            buf,
            p,
            self.encrypted_path_secret,
        );
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: UpdatePathNode,
        pos: u32,
    } {
        const ek_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_public_key_length,
        );
        const ct_r = try decodeHpkeCiphertextList(
            allocator,
            data,
            ek_r.pos,
        );
        return .{
            .value = .{
                .encryption_key = ek_r.value,
                .encrypted_path_secret = ct_r.value,
            },
            .pos = ct_r.pos,
        };
    }

    pub fn deinit(
        self: *UpdatePathNode,
        allocator: std.mem.Allocator,
    ) void {
        if (self.encryption_key.len > 0) {
            allocator.free(self.encryption_key);
        }
        for (self.encrypted_path_secret) |*ct| {
            @constCast(ct).deinit(allocator);
        }
        if (self.encrypted_path_secret.len > 0) {
            allocator.free(self.encrypted_path_secret);
        }
        self.* = undefined;
    }
};

// -- UpdatePath (Section 7.5) -----------------------------------------------

/// An update path: new leaf + path nodes along the filtered direct
/// path.
///
///   struct {
///       LeafNode leaf_node;
///       UpdatePathNode nodes<V>;
///   } UpdatePath;
pub const UpdatePath = struct {
    leaf_node: LeafNode,
    nodes: []const UpdatePathNode,

    pub fn encode(
        self: *const UpdatePath,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try self.leaf_node.encode(buf, pos);
        p = try encodeUpdatePathNodeList(buf, p, self.nodes);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: UpdatePath,
        pos: u32,
    } {
        const leaf_r = try LeafNode.decode(
            allocator,
            data,
            pos,
        );
        const nodes_r = try decodeUpdatePathNodeList(
            allocator,
            data,
            leaf_r.pos,
        );
        return .{
            .value = .{
                .leaf_node = leaf_r.value,
                .nodes = nodes_r.value,
            },
            .pos = nodes_r.pos,
        };
    }

    pub fn deinit(
        self: *UpdatePath,
        allocator: std.mem.Allocator,
    ) void {
        self.leaf_node.deinit(allocator);
        for (self.nodes) |*n| {
            @constCast(n).deinit(allocator);
        }
        if (self.nodes.len > 0) {
            allocator.free(self.nodes);
        }
        self.* = undefined;
    }
};

// -- Codec helpers for list types -------------------------------------------

/// Encode a slice of HPKECiphertext into a varint-length-prefixed
/// byte vector.
pub fn encodeHpkeCiphertextList(
    buf: []u8,
    pos: u32,
    items: []const HPKECiphertext,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        HPKECiphertext,
        buf,
        pos,
        items,
    );
}

pub fn decodeHpkeCiphertextList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const HPKECiphertext,
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
    var temp: [max_ciphertexts]HPKECiphertext = undefined;
    var count: u32 = 0;
    errdefer for (temp[0..count]) |*ct| ct.deinit(allocator);

    while (p < end) {
        if (count >= max_ciphertexts) {
            return error.VectorTooLarge;
        }
        const ct_r = try HPKECiphertext.decode(
            allocator,
            data,
            p,
        );
        temp[count] = ct_r.value;
        count += 1;
        p = ct_r.pos;
    }

    if (p != end) return error.Truncated;

    const items = allocator.alloc(
        HPKECiphertext,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

/// Encode a slice of UpdatePathNode into a varint-length-prefixed
/// byte vector.
pub fn encodeUpdatePathNodeList(
    buf: []u8,
    pos: u32,
    items: []const UpdatePathNode,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        UpdatePathNode,
        buf,
        pos,
        items,
    );
}

pub fn decodeUpdatePathNodeList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const UpdatePathNode,
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
    var temp: [max_path_nodes]UpdatePathNode = undefined;
    var count: u32 = 0;
    errdefer for (temp[0..count]) |*n| n.deinit(allocator);

    while (p < end) {
        if (count >= max_path_nodes) {
            return error.VectorTooLarge;
        }
        const n_r = try UpdatePathNode.decode(
            allocator,
            data,
            p,
        );
        temp[count] = n_r.value;
        count += 1;
        p = n_r.pos;
    }

    if (p != end) return error.Truncated;

    const items = allocator.alloc(
        UpdatePathNode,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}
