//! Content authentication (signing/verification of FramedContent)
//! and confirmation tag computation per RFC 9420 Section 6.1.
//!
//! ## Security contract
//!
//! `verifyFramedContent` **must** be called on every incoming
//! `FramedContent` before the content is applied to group
//! state. The core commit processing pipeline (`processCommit`
//! in commit.zig and external.zig) enforces this invariant
//! internally — callers that go through `GroupState.processCommit`
//! or `processExternalCommit` do not need to verify separately.
//!
//! If you process `FramedContent` through any other path (e.g.,
//! decoding a PublicMessage and inspecting its payload directly),
//! you **must** call `verifyFramedContent` yourself before
//! acting on the content. Failure to do so allows signature
//! forgery attacks.
// Content authentication per RFC 9420 Section 6.1.
//
// Provides signing and verification of FramedContent, plus
// confirmation tag computation. The authentication data is:
//
//   struct {
//     opaque signature<V>;
//     select (FramedContent.content_type) {
//       case commit: opaque confirmation_tag<V>;
//     };
//   } FramedContentAuthData;
//
// Signing uses SignWithLabel with label "FramedContentTBS".
//
// Confirmation tag:
//   MAC(confirmation_key, confirmed_transcript_hash)
// where MAC is HMAC via KDF.Extract (RFC 9420 Section 5.1).
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const primitives = @import("../crypto/primitives.zig");
const framed_content_mod = @import("framed_content.zig");
const content_type_mod = @import("content_type.zig");

const CryptoError = errors.CryptoError;
const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const FramedContent = framed_content_mod.FramedContent;
const FramedContentTBS = framed_content_mod.FramedContentTBS;
const Sender = content_type_mod.Sender;

/// FramedContentAuthData per RFC 9420 Section 6.1.
pub fn FramedContentAuthData(comptime P: type) type {
    return struct {
        /// Signature over FramedContentTBS.
        signature: [P.sig_len]u8,
        /// Confirmation tag — present only for commit content.
        confirmation_tag: ?[P.nh]u8,

        const Self = @This();

        /// Encode this auth data into `buf` at `pos`.
        pub fn encode(
            self: *const Self,
            buf: []u8,
            pos: u32,
            content_type: ContentType,
        ) EncodeError!u32 {
            var p = pos;

            // opaque signature<V>
            p = try codec.encodeVarVector(
                buf,
                p,
                &self.signature,
            );

            // For commits, confirmation_tag is mandatory.
            // A null tag indicates a programming error:
            // the caller built auth data without setting it.
            if (content_type == .commit) {
                const tag = self.confirmation_tag orelse
                    return error.MissingConfirmationTag;
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    &tag,
                );
            }

            return p;
        }

        /// Decode auth data from `buf` at `pos`.
        pub fn decode(
            buf: []const u8,
            pos: u32,
            content_type: ContentType,
        ) DecodeError!struct { value: Self, pos: u32 } {
            var p = pos;

            // opaque signature<V>
            const sig_data = try codec.decodeVarVectorSlice(
                buf,
                p,
            );
            p = sig_data.pos;

            if (sig_data.value.len != P.sig_len) {
                return error.Truncated;
            }
            var sig: [P.sig_len]u8 = undefined;
            @memcpy(&sig, sig_data.value);

            // Optional confirmation_tag for commits.
            var tag: ?[P.nh]u8 = null;
            if (content_type == .commit) {
                const tag_data = try codec.decodeVarVectorSlice(
                    buf,
                    p,
                );
                p = tag_data.pos;
                if (tag_data.value.len != P.nh) {
                    return error.Truncated;
                }
                var t: [P.nh]u8 = undefined;
                @memcpy(&t, tag_data.value);
                tag = t;
            }

            return .{
                .value = .{
                    .signature = sig,
                    .confirmation_tag = tag,
                },
                .pos = p,
            };
        }
    };
}

/// Sign a FramedContent, producing a FramedContentAuthData.
///
/// Uses SignWithLabel(sign_key, "FramedContentTBS", tbs_bytes).
///
/// For commit content, also computes the confirmation tag.
pub fn signFramedContent(
    comptime P: type,
    content: *const FramedContent,
    wire_format: WireFormat,
    group_context: []const u8,
    sign_key: *const [P.sign_sk_len]u8,
    confirmation_key: ?*const [P.nh]u8,
    confirmed_transcript_hash: ?*const [P.nh]u8,
) CryptoError!FramedContentAuthData(P) {
    assert(content.content_type != .reserved);
    // Encode FramedContentTBS.
    const tbs = FramedContentTBS{
        .wire_format = wire_format,
        .content = content.*,
        .group_context = group_context,
    };

    var tbs_buf: [65536]u8 = undefined;
    const tbs_len = tbs.encode(&tbs_buf, 0) catch {
        return error.KdfOutputTooLong;
    };

    // Sign.
    const sig = try primitives.signWithLabel(
        P,
        sign_key,
        "FramedContentTBS",
        tbs_buf[0..tbs_len],
    );

    // Confirmation tag for commits.
    var tag: ?[P.nh]u8 = null;
    if (content.content_type == .commit) {
        if (confirmation_key) |ck| {
            if (confirmed_transcript_hash) |cth| {
                tag = computeConfirmationTag(P, ck, cth);
            }
        }
    }

    return .{
        .signature = sig,
        .confirmation_tag = tag,
    };
}

/// Verify the signature on a FramedContent.
pub fn verifyFramedContent(
    comptime P: type,
    content: *const FramedContent,
    wire_format: WireFormat,
    group_context: []const u8,
    verify_key: *const [P.sign_pk_len]u8,
    auth: *const FramedContentAuthData(P),
) CryptoError!void {
    // Encode FramedContentTBS.
    const tbs = FramedContentTBS{
        .wire_format = wire_format,
        .content = content.*,
        .group_context = group_context,
    };

    var tbs_buf: [65536]u8 = undefined;
    const tbs_len = tbs.encode(&tbs_buf, 0) catch {
        return error.KdfOutputTooLong;
    };

    return primitives.verifyWithLabel(
        P,
        verify_key,
        "FramedContentTBS",
        tbs_buf[0..tbs_len],
        auth.signature[0..],
    );
}

/// Compute a confirmation tag:
///   MAC(confirmation_key, confirmed_transcript_hash)
///
/// MAC is defined as HMAC via KDF.Extract (Section 5.1):
///   MAC(key, data) = KDF.Extract(key, data)
pub fn computeConfirmationTag(
    comptime P: type,
    confirmation_key: *const [P.nh]u8,
    confirmed_transcript_hash: *const [P.nh]u8,
) [P.nh]u8 {
    return P.kdfExtract(confirmation_key, confirmed_transcript_hash);
}

/// Verify a confirmation tag.
pub fn verifyConfirmationTag(
    comptime P: type,
    confirmation_key: *const [P.nh]u8,
    confirmed_transcript_hash: *const [P.nh]u8,
    tag: *const [P.nh]u8,
) errors.ValidationError!void {
    const expected = computeConfirmationTag(
        P,
        confirmation_key,
        confirmed_transcript_hash,
    );
    if (!primitives.constantTimeEql(P.nh, &expected, tag)) {
        return error.ConfirmationTagMismatch;
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

test "sign and verify round-trip" {
    const seed = [_]u8{0x42} ** 32;
    const kp = try Default.signKeypairFromSeed(&seed);
    const content = makeTestContent();

    const auth = try signFramedContent(
        Default,
        &content,
        .mls_public_message,
        "group context",
        &kp.sk,
        null,
        null,
    );

    try verifyFramedContent(
        Default,
        &content,
        .mls_public_message,
        "group context",
        &kp.pk,
        &auth,
    );
}

test "verify rejects wrong key" {
    const seed1 = [_]u8{0x01} ** 32;
    const seed2 = [_]u8{0x02} ** 32;
    const kp1 = try Default.signKeypairFromSeed(&seed1);
    const kp2 = try Default.signKeypairFromSeed(&seed2);
    const content = makeTestContent();

    const auth = try signFramedContent(
        Default,
        &content,
        .mls_public_message,
        "",
        &kp1.sk,
        null,
        null,
    );

    const result = verifyFramedContent(
        Default,
        &content,
        .mls_public_message,
        "",
        &kp2.pk,
        &auth,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "verify rejects tampered content" {
    const seed = [_]u8{0x03} ** 32;
    const kp = try Default.signKeypairFromSeed(&seed);
    const content = makeTestContent();

    const auth = try signFramedContent(
        Default,
        &content,
        .mls_public_message,
        "",
        &kp.sk,
        null,
        null,
    );

    // Tamper with content.
    var tampered = content;
    tampered.epoch = 999;

    const result = verifyFramedContent(
        Default,
        &tampered,
        .mls_public_message,
        "",
        &kp.pk,
        &auth,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "confirmation tag computation" {
    const conf_key = [_]u8{0x11} ** Default.nh;
    const hash_val = [_]u8{0x22} ** Default.nh;

    const tag = computeConfirmationTag(
        Default,
        &conf_key,
        &hash_val,
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
    try verifyConfirmationTag(
        Default,
        &conf_key,
        &hash_val,
        &tag,
    );
}

test "confirmation tag verification rejects wrong tag" {
    const conf_key = [_]u8{0x33} ** Default.nh;
    const hash_val = [_]u8{0x44} ** Default.nh;
    const wrong_tag = [_]u8{0x55} ** Default.nh;

    const result = verifyConfirmationTag(
        Default,
        &conf_key,
        &hash_val,
        &wrong_tag,
    );
    try testing.expectError(
        error.ConfirmationTagMismatch,
        result,
    );
}

test "sign commit includes confirmation tag" {
    const seed = [_]u8{0x66} ** 32;
    const kp = try Default.signKeypairFromSeed(&seed);
    const conf_key = [_]u8{0x77} ** Default.nh;
    const cth = [_]u8{0x88} ** Default.nh;

    var content = makeTestContent();
    content.content_type = .commit;
    content.content = "commit data";

    const auth = try signFramedContent(
        Default,
        &content,
        .mls_public_message,
        "context",
        &kp.sk,
        &conf_key,
        &cth,
    );

    try testing.expect(auth.confirmation_tag != null);
}

test "FramedContentAuthData encode/decode round-trip" {
    const Auth = FramedContentAuthData(Default);
    const sig = [_]u8{0xAA} ** Default.sig_len;
    const tag = [_]u8{0xBB} ** Default.nh;

    const auth = Auth{
        .signature = sig,
        .confirmation_tag = tag,
    };

    var buf: [256]u8 = undefined;
    const end = try auth.encode(&buf, 0, .commit);

    const result = try Auth.decode(&buf, 0, .commit);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqualSlices(
        u8,
        &sig,
        &result.value.signature,
    );
    try testing.expect(result.value.confirmation_tag != null);
    try testing.expectEqualSlices(
        u8,
        &tag,
        &result.value.confirmation_tag.?,
    );
}

test "FramedContentAuthData decode rejects wrong-length commit tag" {
    const Auth = FramedContentAuthData(Default);
    const sig = [_]u8{0xAA} ** Default.sig_len;

    // Encode a commit auth with a truncated tag (1 byte).
    var buf: [256]u8 = undefined;
    var p: u32 = 0;

    // Encode signature as var_vector.
    p = try codec.encodeVarVector(&buf, p, &sig);
    // Encode a 1-byte confirmation_tag (wrong length).
    p = try codec.encodeVarVector(&buf, p, &[_]u8{0x42});

    const result = Auth.decode(&buf, 0, .commit);
    try testing.expectError(error.Truncated, result);
}

test "FramedContentAuthData decode rejects missing commit tag" {
    const Auth = FramedContentAuthData(Default);
    const sig = [_]u8{0xAA} ** Default.sig_len;

    // Encode only a signature, no confirmation_tag.
    var buf: [256]u8 = undefined;
    const p = try codec.encodeVarVector(&buf, 0, &sig);

    // Decode as commit: should fail because tag is missing.
    const result = Auth.decode(buf[0..p], 0, .commit);
    try testing.expectError(error.Truncated, result);
}

test "FramedContentAuthData encode rejects commit with null tag" {
    const Auth = FramedContentAuthData(Default);
    const auth = Auth{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    var buf: [512]u8 = undefined;
    const result = auth.encode(&buf, 0, .commit);
    try testing.expectError(
        error.MissingConfirmationTag,
        result,
    );
}
