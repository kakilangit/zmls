//! Core framing types: Sender, ContentType, and WireFormat enums
//! with encode/decode per RFC 9420 Section 6.
// Core framing types per RFC 9420 Section 6.
//
// Defines the Sender struct used in FramedContent, along with
// encode/decode for all framing enums and the Sender.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");

const DecodeError = errors.DecodeError;
const EncodeError = codec.EncodeError;

const SenderType = types.SenderType;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const LeafIndex = types.LeafIndex;

/// Sender of a framed message per RFC 9420 Section 6.
///
/// struct {
///   SenderType sender_type;
///   select (Sender.sender_type) {
///     case member:              uint32 leaf_index;
///     case external:            uint32 sender_index;
///     case new_member_commit:   (empty)
///     case new_member_proposal: (empty)
///   };
/// } Sender;
pub const Sender = struct {
    sender_type: SenderType,
    /// For member: the leaf index. For external: the sender
    /// index. Zero for new_member_* types.
    leaf_index: u32,

    /// Create a member sender.
    pub fn member(idx: LeafIndex) Sender {
        return .{
            .sender_type = .member,
            .leaf_index = idx.toU32(),
        };
    }

    /// Create an external sender.
    pub fn external(idx: u32) Sender {
        return .{
            .sender_type = .external,
            .leaf_index = idx,
        };
    }

    /// Create a new_member_commit sender.
    pub fn newMemberCommit() Sender {
        return .{
            .sender_type = .new_member_commit,
            .leaf_index = 0,
        };
    }

    /// Create a new_member_proposal sender.
    pub fn newMemberProposal() Sender {
        return .{
            .sender_type = .new_member_proposal,
            .leaf_index = 0,
        };
    }

    /// Encode this Sender into `buf` at `pos`.
    pub fn encode(
        self: *const Sender,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint8(
            buf,
            pos,
            @intFromEnum(self.sender_type),
        );

        switch (self.sender_type) {
            .member, .external => {
                p = try codec.encodeUint32(
                    buf,
                    p,
                    self.leaf_index,
                );
            },
            .new_member_commit, .new_member_proposal => {
                // No payload.
            },
            else => {
                // Unknown sender type — encode the u32 anyway
                // for forward compatibility.
                p = try codec.encodeUint32(
                    buf,
                    p,
                    self.leaf_index,
                );
            },
        }

        return p;
    }

    /// Decode a Sender from `buf` at `pos`.
    pub fn decode(
        buf: []const u8,
        pos: u32,
    ) DecodeError!struct { value: Sender, pos: u32 } {
        const st_raw = try codec.decodeUint8(buf, pos);
        const st: SenderType = @enumFromInt(st_raw.value);
        const p = st_raw.pos;

        switch (st) {
            .member, .external => {
                const idx = try codec.decodeUint32(buf, p);
                return .{
                    .value = .{
                        .sender_type = st,
                        .leaf_index = idx.value,
                    },
                    .pos = idx.pos,
                };
            },
            .new_member_commit, .new_member_proposal => {
                return .{
                    .value = .{
                        .sender_type = st,
                        .leaf_index = 0,
                    },
                    .pos = p,
                };
            },
            else => {
                return error.InvalidEnumValue;
            },
        }
    }
};

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "Sender.member encode/decode round-trip" {
    var buf: [16]u8 = undefined;
    const sender = Sender.member(LeafIndex.fromU32(42));
    const end = try sender.encode(&buf, 0);

    const result = try Sender.decode(&buf, 0);
    try testing.expectEqual(SenderType.member, result.value.sender_type);
    try testing.expectEqual(@as(u32, 42), result.value.leaf_index);
    try testing.expectEqual(end, result.pos);
}

test "Sender.external encode/decode round-trip" {
    var buf: [16]u8 = undefined;
    const sender = Sender.external(7);
    const end = try sender.encode(&buf, 0);

    const result = try Sender.decode(&buf, 0);
    try testing.expectEqual(SenderType.external, result.value.sender_type);
    try testing.expectEqual(@as(u32, 7), result.value.leaf_index);
    try testing.expectEqual(end, result.pos);
}

test "Sender.newMemberCommit encode/decode round-trip" {
    var buf: [16]u8 = undefined;
    const sender = Sender.newMemberCommit();
    const end = try sender.encode(&buf, 0);

    const result = try Sender.decode(&buf, 0);
    try testing.expectEqual(
        SenderType.new_member_commit,
        result.value.sender_type,
    );
    try testing.expectEqual(end, result.pos);
}

test "Sender.newMemberProposal encode/decode round-trip" {
    var buf: [16]u8 = undefined;
    const sender = Sender.newMemberProposal();
    const end = try sender.encode(&buf, 0);

    const result = try Sender.decode(&buf, 0);
    try testing.expectEqual(
        SenderType.new_member_proposal,
        result.value.sender_type,
    );
    try testing.expectEqual(end, result.pos);
}

test "Sender member size is 5 bytes" {
    var buf: [16]u8 = undefined;
    const sender = Sender.member(LeafIndex.fromU32(0));
    const end = try sender.encode(&buf, 0);
    // 1 byte sender_type + 4 bytes leaf_index.
    try testing.expectEqual(@as(u32, 5), end);
}

test "Sender new_member_commit size is 1 byte" {
    var buf: [16]u8 = undefined;
    const sender = Sender.newMemberCommit();
    const end = try sender.encode(&buf, 0);
    // 1 byte sender_type only.
    try testing.expectEqual(@as(u32, 1), end);
}

test "Sender decode truncated returns error" {
    const buf = [_]u8{};
    const result = Sender.decode(&buf, 0);
    try testing.expectError(error.Truncated, result);
}
