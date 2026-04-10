//! MLSMessage top-level wire format wrapper. Dispatches over
//! PublicMessage, PrivateMessage, Welcome, GroupInfo, and
//! KeyPackage per RFC 9420 Section 6.
// MLSMessage top-level wrapper per RFC 9420 Section 6.
//
// This is the outermost structure for all MLS wire messages:
//
//   struct {
//     ProtocolVersion version = mls10;
//     WireFormat wire_format;
//     select (MLSMessage.wire_format) {
//       case mls_public_message:  PublicMessage;
//       case mls_private_message: PrivateMessage;
//       case mls_welcome:         Welcome;
//       case mls_group_info:      GroupInfo;
//       case mls_key_package:     KeyPackage;
//     };
//   } MLSMessage;
//
// Welcome, GroupInfo, and KeyPackage are defined in Phase 9.
// For now, those variants store the inner bytes opaquely.

const std = @import("std");
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const private_msg_mod = @import("private_msg.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const WireFormat = types.WireFormat;
const ProtocolVersion = types.ProtocolVersion;
const PrivateMessage = private_msg_mod.PrivateMessage;

/// Payload of an MLSMessage. We distinguish the wire formats
/// we can parse (public, private) from those we store opaquely.
pub const MessageBody = union(enum) {
    /// Raw encoded PublicMessage bytes (parsed by caller with
    /// the appropriate crypto provider type).
    public_message: []const u8,
    /// Parsed PrivateMessage.
    private_message: PrivateMessage,
    /// Opaque Welcome bytes (Phase 9).
    welcome: []const u8,
    /// Opaque GroupInfo bytes (Phase 9).
    group_info: []const u8,
    /// Opaque KeyPackage bytes (Phase 9).
    key_package: []const u8,
};

/// MLSMessage — the top-level MLS protocol message.
pub const MLSMessage = struct {
    version: ProtocolVersion,
    wire_format: WireFormat,
    body: MessageBody,

    /// Encode this MLSMessage into `buf` at `pos`.
    ///
    /// For public and private messages, the body is the raw
    /// encoded bytes (the caller is responsible for encoding
    /// the inner message first). For opaque variants, the raw
    /// bytes are written directly.
    pub fn encode(
        self: *const MLSMessage,
        buf: []u8,
        pos: u32,
    ) (EncodeError || DecodeError)!u32 {
        if (self.version != .mls10) {
            return error.UnsupportedProtocolVersion;
        }
        var p = pos;

        // ProtocolVersion (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.version),
        );

        // WireFormat (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.wire_format),
        );

        // Body — write the raw bytes.
        const body_bytes = switch (self.body) {
            .public_message => |b| b,
            .private_message => |pm| {
                // Encode PrivateMessage inline.
                return pm.encode(buf, p) catch
                    error.BufferTooSmall;
            },
            .welcome => |b| b,
            .group_info => |b| b,
            .key_package => |b| b,
        };

        const blen: u32 = @intCast(body_bytes.len);
        if (p + blen > buf.len) return error.BufferTooSmall;
        @memcpy(buf[p..][0..blen], body_bytes);
        return p + blen;
    }

    /// Decode an MLSMessage header (version + wire_format) and
    /// the body. For private messages, the body is fully parsed.
    /// For other types, the body is stored as a slice into the
    /// input buffer (remaining bytes after the header).
    ///
    /// WARNING: non-private variants consume the entire buffer
    /// remainder as the body. Use `decodeExact` when the buffer
    /// is expected to contain exactly one message.
    pub fn decode(
        buf: []const u8,
        pos: u32,
    ) DecodeError!struct { value: MLSMessage, pos: u32 } {
        var p = pos;

        // ProtocolVersion (u16)
        const ver = try codec.decodeUint16(buf, p);
        p = ver.pos;

        // WireFormat (u16)
        const wf_raw = try codec.decodeUint16(buf, p);
        p = wf_raw.pos;

        const version: ProtocolVersion = @enumFromInt(ver.value);
        if (version != .mls10) {
            return error.UnsupportedProtocolVersion;
        }
        const wf: WireFormat = @enumFromInt(wf_raw.value);

        switch (wf) {
            .mls_private_message => {
                const pm = try PrivateMessage.decode(buf, p);
                return .{
                    .value = .{
                        .version = version,
                        .wire_format = wf,
                        .body = .{ .private_message = pm.value },
                    },
                    .pos = pm.pos,
                };
            },
            .mls_public_message => {
                // Store remaining bytes as the public message
                // body. The caller decodes with their P type.
                return .{
                    .value = .{
                        .version = version,
                        .wire_format = wf,
                        .body = .{
                            .public_message = buf[p..],
                        },
                    },
                    .pos = @intCast(buf.len),
                };
            },
            .mls_welcome => {
                return .{
                    .value = .{
                        .version = version,
                        .wire_format = wf,
                        .body = .{ .welcome = buf[p..] },
                    },
                    .pos = @intCast(buf.len),
                };
            },
            .mls_group_info => {
                return .{
                    .value = .{
                        .version = version,
                        .wire_format = wf,
                        .body = .{ .group_info = buf[p..] },
                    },
                    .pos = @intCast(buf.len),
                };
            },
            .mls_key_package => {
                return .{
                    .value = .{
                        .version = version,
                        .wire_format = wf,
                        .body = .{ .key_package = buf[p..] },
                    },
                    .pos = @intCast(buf.len),
                };
            },
            else => return error.InvalidEnumValue,
        }
    }

    /// Decode an MLSMessage and reject trailing bytes.
    ///
    /// Callers that receive a single message per buffer (e.g.,
    /// from a length-framed transport) should use this instead
    /// of `decode` to prevent trailing garbage from being
    /// silently absorbed into the body.
    pub fn decodeExact(
        buf: []const u8,
    ) DecodeError!MLSMessage {
        const r = try decode(buf, 0);
        if (r.pos != buf.len) return error.TrailingData;
        return r.value;
    }
};

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "MLSMessage encode/decode private message" {
    const pm = PrivateMessage{
        .group_id = "g",
        .epoch = 1,
        .content_type = .application,
        .authenticated_data = "",
        .encrypted_sender_data = "esd",
        .ciphertext = "ct",
    };

    const msg = MLSMessage{
        .version = .mls10,
        .wire_format = .mls_private_message,
        .body = .{ .private_message = pm },
    };

    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    const result = try MLSMessage.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqual(
        ProtocolVersion.mls10,
        result.value.version,
    );
    try testing.expectEqual(
        WireFormat.mls_private_message,
        result.value.wire_format,
    );

    switch (result.value.body) {
        .private_message => |parsed_pm| {
            try testing.expectEqualSlices(
                u8,
                "g",
                parsed_pm.group_id,
            );
            try testing.expectEqual(
                @as(u64, 1),
                parsed_pm.epoch,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MLSMessage encode/decode public message (opaque)" {
    const pub_body = "raw public message bytes here";
    const msg = MLSMessage{
        .version = .mls10,
        .wire_format = .mls_public_message,
        .body = .{ .public_message = pub_body },
    };

    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    // Decode from a slice trimmed to the encoded length so
    // that the opaque body covers exactly the right bytes.
    const result = try MLSMessage.decode(buf[0..end], 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqual(
        WireFormat.mls_public_message,
        result.value.wire_format,
    );

    switch (result.value.body) {
        .public_message => |body| {
            try testing.expectEqualSlices(
                u8,
                pub_body,
                body,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MLSMessage welcome variant (opaque)" {
    const welcome_body = "welcome data";
    const msg = MLSMessage{
        .version = .mls10,
        .wire_format = .mls_welcome,
        .body = .{ .welcome = welcome_body },
    };

    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    const result = try MLSMessage.decode(buf[0..end], 0);
    try testing.expectEqual(end, result.pos);
    switch (result.value.body) {
        .welcome => |body| {
            try testing.expectEqualSlices(
                u8,
                welcome_body,
                body,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "MLSMessage header is 4 bytes" {
    // version (2) + wire_format (2) = 4 bytes header.
    const pm = PrivateMessage{
        .group_id = "",
        .epoch = 0,
        .content_type = .application,
        .authenticated_data = "",
        .encrypted_sender_data = "",
        .ciphertext = "",
    };
    const msg = MLSMessage{
        .version = .mls10,
        .wire_format = .mls_private_message,
        .body = .{ .private_message = pm },
    };

    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    // Version: 0x00 0x01, WireFormat: 0x00 0x02
    try testing.expectEqual(@as(u8, 0x00), buf[0]);
    try testing.expectEqual(@as(u8, 0x01), buf[1]);
    try testing.expectEqual(@as(u8, 0x00), buf[2]);
    try testing.expectEqual(@as(u8, 0x02), buf[3]);
    try testing.expect(end > 4);
}

test "MLSMessage decode truncated returns error" {
    const buf = [_]u8{ 0x00, 0x01 }; // Only version, no wire_format
    const result = MLSMessage.decode(&buf, 0);
    try testing.expectError(error.Truncated, result);
}

test "decodeExact rejects trailing bytes" {
    // Encode a valid private message.
    const pm = PrivateMessage{
        .group_id = "",
        .epoch = 0,
        .content_type = .application,
        .authenticated_data = "",
        .encrypted_sender_data = "",
        .ciphertext = "",
    };
    const msg = MLSMessage{
        .version = .mls10,
        .wire_format = .mls_private_message,
        .body = .{ .private_message = pm },
    };
    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);
    // Exact buffer: should succeed.
    const ok = try MLSMessage.decodeExact(buf[0..end]);
    try testing.expectEqual(WireFormat.mls_private_message, ok.wire_format);
    // Buffer with one trailing byte: should fail.
    buf[end] = 0xFF;
    const bad = MLSMessage.decodeExact(buf[0 .. end + 1]);
    try testing.expectError(error.TrailingData, bad);
}

test "MLSMessage decode rejects unsupported version" {
    // Version 0xFFFF, WireFormat mls_public_message (0x0001),
    // followed by some body bytes.
    const buf = [_]u8{
        0xFF, 0xFF, // version = 0xFFFF
        0x00, 0x01, // wire_format = mls_public_message
        0x00, // body byte
    };
    const result = MLSMessage.decode(&buf, 0);
    try testing.expectError(
        error.UnsupportedProtocolVersion,
        result,
    );
}

test "MLSMessage encode rejects unsupported version" {
    const msg = MLSMessage{
        .version = @enumFromInt(0xFFFF),
        .wire_format = .mls_public_message,
        .body = .{ .public_message = "data" },
    };
    var buf: [64]u8 = undefined;
    const result = msg.encode(&buf, 0);
    try testing.expectError(
        error.UnsupportedProtocolVersion,
        result,
    );
}
