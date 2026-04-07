//! FramedContent and FramedContentTBS structs wrapping message
//! content (application data, proposal, or commit) with
//! group/epoch/sender metadata per RFC 9420 Section 6.
// FramedContent and FramedContentTBS per RFC 9420 Section 6.
//
// FramedContent wraps the actual message content (application data,
// proposal, or commit) along with group/epoch/sender metadata.
//
// FramedContentTBS is the to-be-signed structure used for content
// authentication.
//
// At this layer we treat proposals and commits as opaque byte
// vectors — the inner structures are parsed in Phase 9.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const content_type_mod = @import("content_type.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_mod = @import("../messages/commit.zig");

const DecodeError = errors.DecodeError;
const EncodeError = codec.EncodeError;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const ProtocolVersion = types.ProtocolVersion;
const Sender = content_type_mod.Sender;
const Proposal = proposal_mod.Proposal;
const Commit = commit_mod.Commit;

/// FramedContent per RFC 9420 Section 6.
///
/// The content payload is stored as raw bytes regardless of
/// content_type. Higher layers interpret it as application data,
/// a Proposal, or a Commit.
pub const FramedContent = struct {
    /// Group identifier.
    group_id: []const u8,
    /// Epoch number.
    epoch: types.Epoch,
    /// Sender information.
    sender: Sender,
    /// Application-supplied authenticated data (included in AAD
    /// but not encrypted).
    authenticated_data: []const u8,
    /// Content type discriminator.
    content_type: ContentType,
    /// The content payload (application_data, serialized Proposal,
    /// or serialized Commit).
    content: []const u8,

    /// Encode this FramedContent into `buf` at `pos`.
    pub fn encode(
        self: *const FramedContent,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;

        // opaque group_id<V>
        p = try codec.encodeVarVector(buf, p, self.group_id);

        // uint64 epoch
        p = try codec.encodeUint64(buf, p, self.epoch);

        // Sender sender
        p = try self.sender.encode(buf, p);

        // opaque authenticated_data<V>
        p = try codec.encodeVarVector(
            buf,
            p,
            self.authenticated_data,
        );

        // ContentType content_type
        p = try codec.encodeUint8(
            buf,
            p,
            @intFromEnum(self.content_type),
        );

        // Content payload.
        // RFC 9420 Section 6: application_data is opaque<V>
        // (varint-prefixed). Proposal and Commit are encoded
        // directly (no length prefix).
        switch (self.content_type) {
            .application => {
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.content,
                );
            },
            .proposal, .commit => {
                const clen: u32 = @intCast(
                    self.content.len,
                );
                if (p + clen > buf.len) {
                    return error.BufferTooSmall;
                }
                @memcpy(
                    buf[p..][0..clen],
                    self.content,
                );
                p += clen;
            },
            else => return error.BufferTooSmall,
        }

        return p;
    }

    /// Decode a FramedContent from `buf` at `pos`.
    ///
    /// The returned FramedContent borrows slices into `buf`. The
    /// caller must ensure `buf` outlives the returned value.
    pub fn decode(
        buf: []const u8,
        pos: u32,
    ) DecodeError!struct { value: FramedContent, pos: u32 } {
        var p = pos;

        // opaque group_id<V>
        const gid = try codec.decodeVarVectorSlice(buf, p);
        p = gid.pos;

        // uint64 epoch
        const ep = try codec.decodeUint64(buf, p);
        p = ep.pos;

        // Sender
        const sender = try Sender.decode(buf, p);
        p = sender.pos;

        // opaque authenticated_data<V>
        const ad = try codec.decodeVarVectorSlice(buf, p);
        p = ad.pos;

        // ContentType
        const ct_raw = try codec.decodeUint8(buf, p);
        p = ct_raw.pos;
        const ct: ContentType = @enumFromInt(ct_raw.value);

        // Content payload.
        // RFC 9420 Section 6: application_data is opaque<V>
        // (varint-prefixed). Proposal and Commit are encoded
        // directly — skip-parse to find the end.
        var content: []const u8 = undefined;
        switch (ct) {
            .application => {
                const cv = try codec.decodeVarVectorSlice(
                    buf,
                    p,
                );
                content = cv.value;
                p = cv.pos;
            },
            .proposal => {
                const start = p;
                p = try Proposal.skipDecode(buf, p);
                content = buf[start..p];
            },
            .commit => {
                const start = p;
                p = try Commit.skipDecode(buf, p);
                content = buf[start..p];
            },
            else => return error.InvalidEnumValue,
        }

        return .{
            .value = .{
                .group_id = gid.value,
                .epoch = ep.value,
                .sender = sender.value,
                .authenticated_data = ad.value,
                .content_type = ct,
                .content = content,
            },
            .pos = p,
        };
    }
};

/// FramedContentTBS — the to-be-signed wrapper per RFC 9420 Section 6.1.
///
/// struct {
///   ProtocolVersion version = mls10;
///   WireFormat wire_format;
///   FramedContent content;
///   select (FramedContentTBS.sender.sender_type) {
///     case member: GroupContext context;
///   };
/// } FramedContentTBS;
///
/// We encode this as a helper that prepends the version and
/// wire_format before the FramedContent, and appends the
/// GroupContext for member senders.
pub const FramedContentTBS = struct {
    wire_format: WireFormat,
    content: FramedContent,
    /// Serialized GroupContext — only included when sender is
    /// a member. Empty otherwise.
    group_context: []const u8,

    /// Encode the TBS structure into `buf` at `pos`.
    pub fn encode(
        self: *const FramedContentTBS,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;

        // ProtocolVersion version = mls10 (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(ProtocolVersion.mls10),
        );

        // WireFormat wire_format (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.wire_format),
        );

        // FramedContent content
        p = try self.content.encode(buf, p);

        // GroupContext (for member and new_member_commit senders).
        const st = self.content.sender.sender_type;
        if (st == .member or st == .new_member_commit) {
            if (self.group_context.len > 0) {
                const end: u32 = @intCast(
                    p + self.group_context.len,
                );
                if (end > buf.len) return error.BufferTooSmall;
                @memcpy(
                    buf[p..][0..self.group_context.len],
                    self.group_context,
                );
                p = end;
            }
        }

        return p;
    }
};

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "FramedContent encode/decode round-trip (application)" {
    const fc = FramedContent{
        .group_id = "test-group",
        .epoch = 5,
        .sender = Sender.member(types.LeafIndex.fromU32(3)),
        .authenticated_data = "aad",
        .content_type = .application,
        .content = "hello world",
    };

    var buf: [256]u8 = undefined;
    const end = try fc.encode(&buf, 0);

    const result = try FramedContent.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqualSlices(
        u8,
        "test-group",
        result.value.group_id,
    );
    try testing.expectEqual(@as(u64, 5), result.value.epoch);
    try testing.expectEqual(
        types.SenderType.member,
        result.value.sender.sender_type,
    );
    try testing.expectEqual(
        @as(u32, 3),
        result.value.sender.leaf_index,
    );
    try testing.expectEqualSlices(
        u8,
        "aad",
        result.value.authenticated_data,
    );
    try testing.expectEqual(ContentType.application, result.value.content_type);
    try testing.expectEqualSlices(
        u8,
        "hello world",
        result.value.content,
    );
}

test "FramedContent encode/decode round-trip (proposal)" {
    // A valid Remove proposal: ProposalType(u16=3) + uint32(2).
    const remove_bytes = [_]u8{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x02 };

    const fc = FramedContent{
        .group_id = "grp",
        .epoch = 0,
        .sender = Sender.member(types.LeafIndex.fromU32(0)),
        .authenticated_data = "",
        .content_type = .proposal,
        .content = &remove_bytes,
    };

    var buf: [256]u8 = undefined;
    const end = try fc.encode(&buf, 0);

    const result = try FramedContent.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqual(
        ContentType.proposal,
        result.value.content_type,
    );
    try testing.expectEqualSlices(
        u8,
        &remove_bytes,
        result.value.content,
    );
}

test "FramedContent with external sender" {
    // A valid empty Commit: proposals<V>=varint(0) + optional=0.
    const commit_bytes = [_]u8{ 0x00, 0x00 };

    const fc = FramedContent{
        .group_id = "g",
        .epoch = 100,
        .sender = Sender.external(2),
        .authenticated_data = "",
        .content_type = .commit,
        .content = &commit_bytes,
    };

    var buf: [256]u8 = undefined;
    const end = try fc.encode(&buf, 0);

    const result = try FramedContent.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqual(
        types.SenderType.external,
        result.value.sender.sender_type,
    );
    try testing.expectEqual(@as(u32, 2), result.value.sender.leaf_index);
}

test "FramedContentTBS encode includes version and wire_format" {
    const fc = FramedContent{
        .group_id = "g",
        .epoch = 1,
        .sender = Sender.member(types.LeafIndex.fromU32(0)),
        .authenticated_data = "",
        .content_type = .application,
        .content = "data",
    };

    const tbs = FramedContentTBS{
        .wire_format = .mls_public_message,
        .content = fc,
        .group_context = "serialized group context",
    };

    var buf: [512]u8 = undefined;
    const end = try tbs.encode(&buf, 0);

    // First 2 bytes: ProtocolVersion.mls10 = 0x0001
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 0x01), buf[1]);

    // Next 2 bytes: WireFormat.mls_public_message = 0x0001
    try testing.expectEqual(@as(u8, 0x00), buf[2]);
    try testing.expectEqual(@as(u8, 0x01), buf[3]);

    // The buffer should end after the group context.
    try testing.expect(end > 4);
}

test "FramedContentTBS omits context for external sender" {
    // A valid empty Commit: proposals<V>=varint(0) + optional=0.
    const commit_bytes = [_]u8{ 0x00, 0x00 };

    const fc = FramedContent{
        .group_id = "g",
        .epoch = 1,
        .sender = Sender.external(0),
        .authenticated_data = "",
        .content_type = .commit,
        .content = &commit_bytes,
    };

    const tbs_with_ctx = FramedContentTBS{
        .wire_format = .mls_public_message,
        .content = fc,
        .group_context = "some context bytes",
    };

    const tbs_no_ctx = FramedContentTBS{
        .wire_format = .mls_public_message,
        .content = fc,
        .group_context = "",
    };

    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;
    const end1 = try tbs_with_ctx.encode(&buf1, 0);
    const end2 = try tbs_no_ctx.encode(&buf2, 0);

    // For external sender, group context is NOT appended,
    // so both should produce the same encoding.
    try testing.expectEqual(end1, end2);
    try testing.expectEqualSlices(
        u8,
        buf1[0..end1],
        buf2[0..end2],
    );
}

test "FramedContent decode truncated returns error" {
    const buf = [_]u8{ 0x01, 0x02 };
    const result = FramedContent.decode(&buf, 0);
    try testing.expectError(error.Truncated, result);
}
