//! Commit message struct (ProposalOrRef list + optional UpdatePath)
//! per RFC 9420 Section 12.4, with wire format encode/decode.
// Commit struct per RFC 9420 Section 12.4.
//
//   enum {
//       reserved(0), proposal(1), reference(2), (255)
//   } ProposalOrRefType;
//
//   struct {
//       ProposalOrRefType type;
//       select (ProposalOrRef.type) {
//           case proposal:  Proposal proposal;
//           case reference: ProposalRef reference;
//       };
//   } ProposalOrRef;
//
//   struct {
//       ProposalOrRef proposals<V>;
//       optional<UpdatePath> path;
//   } Commit;

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const path_mod = @import("../tree/path.zig");
const proposal_mod = @import("proposal.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const Proposal = proposal_mod.Proposal;
const UpdatePath = path_mod.UpdatePath;
const skipLeafNode = proposal_mod.skipLeafNode;

/// Maximum number of proposals in a Commit.
const max_proposals: u32 = 256;

// -- ProposalOrRefType -------------------------------------------------------

pub const ProposalOrRefType = enum(u8) {
    reserved = 0,
    proposal = 1,
    reference = 2,
    _,
};

// -- ProposalOrRef -----------------------------------------------------------

/// Payload union for ProposalOrRef.
pub const ProposalOrRefPayload = union {
    proposal: Proposal,
    reference: []const u8,
};

/// A proposal can be included inline or by reference (hash).
pub const ProposalOrRef = struct {
    tag: ProposalOrRefType,
    payload: ProposalOrRefPayload,

    pub fn initProposal(p: Proposal) ProposalOrRef {
        return .{
            .tag = .proposal,
            .payload = .{ .proposal = p },
        };
    }

    pub fn initReference(ref: []const u8) ProposalOrRef {
        return .{
            .tag = .reference,
            .payload = .{ .reference = ref },
        };
    }

    pub fn encode(
        self: *const ProposalOrRef,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint8(
            buf,
            pos,
            @intFromEnum(self.tag),
        );
        switch (self.tag) {
            .proposal => {
                p = try self.payload.proposal.encode(buf, p);
            },
            .reference => {
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.payload.reference,
                );
            },
            else => return error.BufferTooSmall,
        }
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: ProposalOrRef,
        pos: u32,
    } {
        const type_r = try codec.decodeUint8(data, pos);
        const tag: ProposalOrRefType = @enumFromInt(
            type_r.value,
        );
        const p = type_r.pos;

        switch (tag) {
            .proposal => {
                const r = try Proposal.decode(
                    allocator,
                    data,
                    p,
                );
                return .{
                    .value = .{
                        .tag = .proposal,
                        .payload = .{ .proposal = r.value },
                    },
                    .pos = r.pos,
                };
            },
            .reference => {
                const r = try codec.decodeVarVectorLimited(
                    allocator,
                    data,
                    p,
                    types.max_hash_length,
                );
                return .{
                    .value = .{
                        .tag = .reference,
                        .payload = .{ .reference = r.value },
                    },
                    .pos = r.pos,
                };
            },
            else => return error.InvalidEnumValue,
        }
    }

    pub fn deinit(
        self: *ProposalOrRef,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.tag) {
            .proposal => {
                self.payload.proposal.deinit(allocator);
            },
            .reference => {
                const ref = self.payload.reference;
                if (ref.len > 0) {
                    allocator.free(ref);
                }
            },
            else => {},
        }
        self.* = undefined;
    }
};

// -- Commit ------------------------------------------------------------------

/// The Commit message. Contains a list of proposals (inline or by
/// reference) and an optional UpdatePath.
///
///   struct {
///       ProposalOrRef proposals<V>;
///       optional<UpdatePath> path;
///   } Commit;
pub const Commit = struct {
    proposals: []const ProposalOrRef,
    path: ?UpdatePath,

    pub fn encode(
        self: *const Commit,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        // proposals<V> — varint-prefixed list.
        p = try encodeProposalOrRefList(buf, p, self.proposals);
        // optional<UpdatePath> path.
        if (self.path) |*up| {
            p = try codec.encodeUint8(buf, p, 1);
            p = try up.encode(buf, p);
        } else {
            p = try codec.encodeUint8(buf, p, 0);
        }
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Commit,
        pos: u32,
    } {
        var p = pos;
        // proposals<V>
        const props_r = try decodeProposalOrRefList(
            allocator,
            data,
            p,
        );
        p = props_r.pos;

        // optional<UpdatePath>
        const opt_r = try codec.decodeUint8(data, p);
        p = opt_r.pos;

        var path: ?UpdatePath = null;
        if (opt_r.value == 1) {
            const up_r = try UpdatePath.decode(
                allocator,
                data,
                p,
            );
            path = up_r.value;
            p = up_r.pos;
        } else if (opt_r.value != 0) {
            return error.InvalidOptionalPrefix;
        }

        return .{
            .value = .{
                .proposals = @as(
                    []const ProposalOrRef,
                    props_r.value,
                ),
                .path = path,
            },
            .pos = p,
        };
    }

    /// Advance past an encoded Commit without allocating.
    /// Returns the position after the Commit.
    ///
    /// Commit = proposals<V> + optional<UpdatePath>.
    /// The proposals<V> vector is self-delimiting (varint +
    /// payload). The optional path is u8 presence + UpdatePath.
    /// UpdatePath = LeafNode + nodes<V>, both self-delimiting.
    pub fn skipDecode(
        data: []const u8,
        pos: u32,
    ) DecodeError!u32 {
        var p = pos;
        // proposals<V> — skip entire vector.
        p = try codec.skipVarVector(data, p);
        // optional<UpdatePath>
        const opt = try codec.decodeUint8(data, p);
        p = opt.pos;
        if (opt.value == 1) {
            // UpdatePath: LeafNode + nodes<V>.
            p = try skipLeafNode(data, p);
            p = try codec.skipVarVector(data, p); // nodes
        } else if (opt.value != 0) {
            return error.InvalidOptionalPrefix;
        }
        return p;
    }

    pub fn deinit(
        self: *Commit,
        allocator: std.mem.Allocator,
    ) void {
        for (self.proposals) |*por| {
            @constCast(por).deinit(allocator);
        }
        if (self.proposals.len > 0) {
            allocator.free(self.proposals);
        }
        if (self.path) |*up| {
            up.deinit(allocator);
        }
        self.* = undefined;
    }
};

// -- ProposalOrRef list codec helpers ----------------------------------------

fn encodeProposalOrRefList(
    buf: []u8,
    pos: u32,
    items: []const ProposalOrRef,
) EncodeError!u32 {
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;
    for (items) |*item| {
        p = try item.encode(buf, p);
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

fn decodeProposalOrRefList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []ProposalOrRef,
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
    var temp: [max_proposals]ProposalOrRef = undefined;
    var count: u32 = 0;
    errdefer for (temp[0..count]) |*r| r.deinit(allocator);

    while (p < end) {
        if (count >= max_proposals) {
            return error.VectorTooLarge;
        }
        const r = try ProposalOrRef.decode(
            allocator,
            data,
            p,
        );
        temp[count] = r.value;
        count += 1;
        p = r.pos;
    }
    if (p != end) return error.Truncated;
    const items = allocator.alloc(
        ProposalOrRef,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);
    return .{ .value = items, .pos = p };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const ProposalType = types.ProposalType;
const Credential = @import("../credential/credential.zig")
    .Credential;
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const CredentialType = types.CredentialType;
const ExtensionType = types.ExtensionType;
const KeyPackage = @import("key_package.zig").KeyPackage;
const LeafNode = node_mod.LeafNode;

test "Commit with inline Remove proposals, no path" {
    const alloc = testing.allocator;

    const remove1 = ProposalOrRef.initProposal(.{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1 } },
    });
    const remove2 = ProposalOrRef.initProposal(.{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 5 } },
    });

    const proposals = [_]ProposalOrRef{ remove1, remove2 };
    const commit = Commit{
        .proposals = &proposals,
        .path = null,
    };

    var buf: [1024]u8 = undefined;
    const end = try commit.encode(&buf, 0);

    var dec_r = try Commit.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 2),
        dec_r.value.proposals.len,
    );
    try testing.expect(dec_r.value.path == null);
    try testing.expectEqual(
        ProposalType.remove,
        dec_r.value.proposals[0].payload.proposal.tag,
    );
    try testing.expectEqual(
        @as(u32, 1),
        dec_r.value.proposals[0]
            .payload.proposal.payload.remove.removed,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Commit with reference proposals" {
    const alloc = testing.allocator;

    const ref1 = ProposalOrRef.initReference(
        "hash-of-proposal-1-32bytes!!!!??",
    );
    const ref2 = ProposalOrRef.initReference(
        "hash-of-proposal-2-32bytes!!!!??",
    );

    const proposals = [_]ProposalOrRef{ ref1, ref2 };
    const commit = Commit{
        .proposals = &proposals,
        .path = null,
    };

    var buf: [512]u8 = undefined;
    const end = try commit.encode(&buf, 0);

    var dec_r = try Commit.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 2),
        dec_r.value.proposals.len,
    );
    try testing.expectEqual(
        ProposalOrRefType.reference,
        dec_r.value.proposals[0].tag,
    );
    try testing.expectEqualSlices(
        u8,
        "hash-of-proposal-1-32bytes!!!!??",
        dec_r.value.proposals[0].payload.reference,
    );
}

test "Commit empty proposals, no path" {
    const alloc = testing.allocator;

    const commit = Commit{
        .proposals = &.{},
        .path = null,
    };

    var buf: [64]u8 = undefined;
    const end = try commit.encode(&buf, 0);

    var dec_r = try Commit.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.proposals.len,
    );
    try testing.expect(dec_r.value.path == null);
}

test "Commit with UpdatePath present" {
    const alloc = testing.allocator;

    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]ExtensionType{};
    const prop_types = comptime [_]ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

    const up = UpdatePath{
        .leaf_node = .{
            .encryption_key = &[_]u8{0x01} ** 32,
            .signature_key = &[_]u8{0x02} ** 32,
            .credential = Credential.initBasic("alice"),
            .capabilities = .{
                .versions = &versions,
                .cipher_suites = &suites,
                .extensions = &ext_types,
                .proposals = &prop_types,
                .credentials = &cred_types,
            },
            .source = .commit,
            .lifetime = null,
            .parent_hash = null,
            .extensions = &.{},
            .signature = &[_]u8{0xAA} ** 4,
        },
        .nodes = &.{},
    };

    const commit = Commit{
        .proposals = &.{},
        .path = up,
    };

    var buf: [4096]u8 = undefined;
    const end = try commit.encode(&buf, 0);

    var dec_r = try Commit.decode(alloc, buf[0..end], 0);
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path != null);
    try testing.expectEqualSlices(
        u8,
        "alice",
        dec_r.value.path.?.leaf_node
            .credential.payload.basic,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "ProposalOrRef decode rejects unknown type" {
    const alloc = testing.allocator;
    var buf: [1]u8 = undefined;
    _ = try codec.encodeUint8(&buf, 0, 0xFF);
    const result = ProposalOrRef.decode(alloc, &buf, 0);
    try testing.expectError(error.InvalidEnumValue, result);
}
