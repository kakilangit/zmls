//! PublicMessage (cleartext FramedContent + auth data + membership
//! tag) per RFC 9420 Section 6.2.
// PublicMessage per RFC 9420 Section 6.2.
//
// A PublicMessage is a FramedContent + authentication data sent
// in the clear (no content encryption). For member senders, a
// membership tag is appended to prevent forgery by non-members.
//
//   struct {
//     FramedContent content;
//     FramedContentAuthData auth;
//     select (PublicMessage.content.sender.sender_type) {
//       case member: opaque membership_tag<V>;
//     };
//   } PublicMessage;
//
// The membership tag covers the AuthenticatedContentTBM:
//
//   struct {
//     ProtocolVersion version = mls10;
//     WireFormat wire_format;
//     FramedContent content;
//     FramedContentAuthData auth;
//   } AuthenticatedContentTBM;
//
//   membership_tag = MAC(membership_key, AuthenticatedContentTBM)
//
// MAC is KDF.Extract (per RFC 9420 Section 5.1).
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const primitives = @import("../crypto/primitives.zig");
const errors = @import("../common/errors.zig");
const framed_content_mod = @import("framed_content.zig");
const auth_mod = @import("auth.zig");
const content_type_mod = @import("content_type.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const ProtocolVersion = types.ProtocolVersion;
const FramedContent = framed_content_mod.FramedContent;
const Sender = content_type_mod.Sender;

/// PublicMessage per RFC 9420 Section 6.2.
pub fn PublicMessage(comptime P: type) type {
    const AuthData = auth_mod.FramedContentAuthData(P);

    return struct {
        content: FramedContent,
        auth: AuthData,
        membership_tag: ?[P.nh]u8,

        const Self = @This();

        /// Encode this PublicMessage into `buf` at `pos`.
        pub fn encode(
            self: *const Self,
            buf: []u8,
            pos: u32,
        ) EncodeError!u32 {
            var p = pos;

            // FramedContent
            p = try self.content.encode(buf, p);

            // FramedContentAuthData
            p = try self.auth.encode(
                buf,
                p,
                self.content.content_type,
            );

            // membership_tag (only for member senders)
            if (self.content.sender.sender_type == .member) {
                if (self.membership_tag) |tag| {
                    p = try codec.encodeVarVector(
                        buf,
                        p,
                        &tag,
                    );
                }
            }

            return p;
        }

        /// Decode a PublicMessage from `buf` at `pos`.
        pub fn decode(
            buf: []const u8,
            pos: u32,
        ) DecodeError!struct { value: Self, pos: u32 } {
            var p = pos;

            // FramedContent
            const fc = try FramedContent.decode(buf, p);
            p = fc.pos;

            // FramedContentAuthData
            const ad = try AuthData.decode(
                buf,
                p,
                fc.value.content_type,
            );
            p = ad.pos;

            // membership_tag
            var tag: ?[P.nh]u8 = null;
            if (fc.value.sender.sender_type == .member) {
                const tag_data = try codec.decodeVarVectorSlice(
                    buf,
                    p,
                );
                p = tag_data.pos;
                if (tag_data.value.len == P.nh) {
                    var t: [P.nh]u8 = undefined;
                    @memcpy(&t, tag_data.value);
                    tag = t;
                }
            }

            return .{
                .value = .{
                    .content = fc.value,
                    .auth = ad.value,
                    .membership_tag = tag,
                },
                .pos = p,
            };
        }
    };
}

/// Compute a membership tag for a PublicMessage.
///
///   membership_tag = MAC(membership_key, AuthenticatedContentTBM)
///
/// AuthenticatedContentTBM = FramedContentTBS || AuthData
///
/// FramedContentTBS for member senders includes the GroupContext
/// after the FramedContent (RFC 9420 Section 6.1).
pub fn computeMembershipTag(
    comptime P: type,
    membership_key: *const [P.nh]u8,
    content: *const FramedContent,
    auth: *const auth_mod.FramedContentAuthData(P),
    group_context: []const u8,
) EncodeError![P.nh]u8 {
    // 128KB buffer: content + GroupContext + auth data.
    // Overflow returns EncodeError via try below.
    var tbm_buf: [131072]u8 = undefined;
    var p: u32 = 0;

    // FramedContentTBS: version || wire_format || content
    //                   || GroupContext (for member senders)
    const tbs = framed_content_mod.FramedContentTBS{
        .wire_format = .mls_public_message,
        .content = content.*,
        .group_context = group_context,
    };
    p = try tbs.encode(&tbm_buf, p);

    // FramedContentAuthData
    p = try auth.encode(
        &tbm_buf,
        p,
        content.content_type,
    );

    // MAC = KDF.Extract(key, data)
    return P.kdfExtract(membership_key, tbm_buf[0..p]);
}

/// Verify a membership tag.
pub fn verifyMembershipTag(
    comptime P: type,
    membership_key: *const [P.nh]u8,
    content: *const FramedContent,
    auth: *const auth_mod.FramedContentAuthData(P),
    tag: *const [P.nh]u8,
    group_context: []const u8,
) (EncodeError || errors.ValidationError)!void {
    const expected = try computeMembershipTag(
        P,
        membership_key,
        content,
        auth,
        group_context,
    );
    if (!primitives.constantTimeEql(P.nh, &expected, tag)) {
        return error.MembershipTagMismatch;
    }
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

fn makeTestContent() FramedContent {
    return .{
        .group_id = "test-group",
        .epoch = 1,
        .sender = Sender.member(types.LeafIndex.fromU32(0)),
        .authenticated_data = "",
        .content_type = .application,
        .content = "hello",
    };
}

test "PublicMessage encode/decode round-trip" {
    const Pub = PublicMessage(Default);
    const AuthData = auth_mod.FramedContentAuthData(Default);

    const content = makeTestContent();
    const sig = [_]u8{0xAA} ** Default.sig_len;
    const tag = [_]u8{0xBB} ** Default.nh;

    const msg = Pub{
        .content = content,
        .auth = AuthData{
            .signature = sig,
            .confirmation_tag = null,
        },
        .membership_tag = tag,
    };

    var buf: [512]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    const result = try Pub.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqualSlices(
        u8,
        "test-group",
        result.value.content.group_id,
    );
    try testing.expectEqualSlices(
        u8,
        &sig,
        &result.value.auth.signature,
    );
    try testing.expect(result.value.membership_tag != null);
    try testing.expectEqualSlices(
        u8,
        &tag,
        &result.value.membership_tag.?,
    );
}

test "membership tag computation and verification" {
    const mk = [_]u8{0x42} ** Default.nh;
    const content = makeTestContent();
    const AuthData = auth_mod.FramedContentAuthData(Default);
    const auth = AuthData{
        .signature = [_]u8{0xCC} ** Default.sig_len,
        .confirmation_tag = null,
    };

    const tag = try computeMembershipTag(
        Default,
        &mk,
        &content,
        &auth,
        "",
    );

    // Should be non-zero.
    var all_zero = true;
    for (tag) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    // Verification should pass.
    try verifyMembershipTag(
        Default,
        &mk,
        &content,
        &auth,
        &tag,
        "",
    );
}

test "membership tag rejects wrong key" {
    const mk1 = [_]u8{0x11} ** Default.nh;
    const mk2 = [_]u8{0x22} ** Default.nh;
    const content = makeTestContent();
    const AuthData = auth_mod.FramedContentAuthData(Default);
    const auth = AuthData{
        .signature = [_]u8{0xDD} ** Default.sig_len,
        .confirmation_tag = null,
    };

    const tag = try computeMembershipTag(
        Default,
        &mk1,
        &content,
        &auth,
        "",
    );

    const result = verifyMembershipTag(
        Default,
        &mk2,
        &content,
        &auth,
        &tag,
        "",
    );
    try testing.expectError(
        error.MembershipTagMismatch,
        result,
    );
}

test "membership tag is deterministic" {
    const mk = [_]u8{0x55} ** Default.nh;
    const content = makeTestContent();
    const AuthData = auth_mod.FramedContentAuthData(Default);
    const auth = AuthData{
        .signature = [_]u8{0xEE} ** Default.sig_len,
        .confirmation_tag = null,
    };

    const tag1 = try computeMembershipTag(
        Default,
        &mk,
        &content,
        &auth,
        "",
    );
    const tag2 = try computeMembershipTag(
        Default,
        &mk,
        &content,
        &auth,
        "",
    );
    try testing.expectEqualSlices(u8, &tag1, &tag2);
}

test "PublicMessage without membership tag for external sender" {
    const Pub = PublicMessage(Default);
    const AuthData = auth_mod.FramedContentAuthData(Default);

    // Valid empty Commit: proposals<V>=varint(0) + optional=0.
    const commit_bytes = [_]u8{ 0x00, 0x00 };

    const content = FramedContent{
        .group_id = "g",
        .epoch = 0,
        .sender = Sender.external(0),
        .authenticated_data = "",
        .content_type = .commit,
        .content = &commit_bytes,
    };
    const sig = [_]u8{0xFF} ** Default.sig_len;
    const conf_tag = [_]u8{0x11} ** Default.nh;

    const msg = Pub{
        .content = content,
        .auth = AuthData{
            .signature = sig,
            .confirmation_tag = conf_tag,
        },
        .membership_tag = null,
    };

    var buf: [512]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    const result = try Pub.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expect(result.value.membership_tag == null);
}
