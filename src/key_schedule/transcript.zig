//! Confirmed and interim transcript hash computation per RFC 9420
//! Section 8.2. Forms a chain binding each epoch's Commit to
//! all prior history.
// Transcript hash computation per RFC 9420 Section 8.2.
//
// The confirmed and interim transcript hashes form a chain that
// binds each epoch's Commit to all prior history:
//
//   confirmed_transcript_hash[0] = ""
//   interim_transcript_hash[0] = ""
//
//   confirmed_transcript_hash[n] =
//     Hash(interim_transcript_hash[n-1] ||
//          ConfirmedTranscriptHashInput[n])
//
//   interim_transcript_hash[n] =
//     Hash(confirmed_transcript_hash[n] ||
//          InterimTranscriptHashInput[n])
//
// ConfirmedTranscriptHashInput contains the wire format, framed
// content, and signature of the Commit. InterimTranscriptHashInput
// contains the confirmation tag.
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");

const EncodeError = codec.EncodeError;

/// Update the confirmed transcript hash for a new epoch.
///
/// Computes:
///   confirmed_transcript_hash[n] =
///     Hash(interim_transcript_hash[n-1] ||
///          ConfirmedTranscriptHashInput)
///
/// Where ConfirmedTranscriptHashInput is the serialized
/// concatenation of (wire_format, framed_content, signature),
/// already provided as `confirmed_input`.
///
/// For epoch 0, `interim_hash_prev` should be an empty slice.
pub fn updateConfirmedTranscriptHash(
    comptime P: type,
    interim_hash_prev: []const u8,
    confirmed_input: []const u8,
) EncodeError![P.nh]u8 {
    return hashConcat(P, interim_hash_prev, confirmed_input);
}

/// Update the interim transcript hash for the current epoch.
///
/// Computes:
///   interim_transcript_hash[n] =
///     Hash(confirmed_transcript_hash[n] ||
///          InterimTranscriptHashInput)
///
/// Where InterimTranscriptHashInput is the serialized
/// confirmation_tag (a varint-prefixed opaque vector).
///
/// `confirmation_tag` is the raw MAC value; this function
/// encodes it as `opaque confirmation_tag<V>` per the spec.
pub fn updateInterimTranscriptHash(
    comptime P: type,
    confirmed_hash: *const [P.nh]u8,
    confirmation_tag: []const u8,
) EncodeError![P.nh]u8 {
    // Encode InterimTranscriptHashInput:
    //   struct { opaque confirmation_tag<V>; }
    // 512B: confirmation_tag is bounded by P.nh (<=64).
    var input_buf: [512]u8 = undefined;
    const pos = try codec.encodeVarVector(
        &input_buf,
        0,
        confirmation_tag,
    );

    return hashConcat(P, confirmed_hash, input_buf[0..pos]);
}

/// Hash the concatenation of two byte slices:
///   Hash(a || b)
///
/// Uses a stack buffer for concatenation. Returns
/// `BufferTooSmall` if `a.len + b.len` exceeds the limit.
fn hashConcat(
    comptime P: type,
    a: []const u8,
    b: []const u8,
) EncodeError![P.nh]u8 {
    const max_len = 65536;
    const total = a.len + b.len;
    if (total > max_len) return error.BufferTooSmall;

    var buf: [max_len]u8 = undefined;
    @memcpy(buf[0..a.len], a);
    @memcpy(buf[a.len..][0..b.len], b);

    return P.hash(buf[0..total]);
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "epoch 0: empty interim produces valid confirmed hash" {
    // At epoch 0, interim_transcript_hash[-1] = ""
    const confirmed_input = "fake wire_format || content || sig";

    const confirmed = try updateConfirmedTranscriptHash(
        Default,
        "", // empty for first epoch
        confirmed_input,
    );

    // Should be Hash("" || confirmed_input) = Hash(confirmed_input)
    const expected = Default.hash(confirmed_input);
    try testing.expectEqualSlices(u8, &expected, &confirmed);
}

test "confirmed then interim hash chain" {
    const confirmed_input = "commit content bytes";
    const confirmation_tag = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // Step 1: confirmed hash from empty interim.
    const confirmed = try updateConfirmedTranscriptHash(
        Default,
        "",
        confirmed_input,
    );

    // Step 2: interim hash from confirmed hash.
    const interim = try updateInterimTranscriptHash(
        Default,
        &confirmed,
        &confirmation_tag,
    );

    // Verify interim is non-zero and different from confirmed.
    var all_zero = true;
    for (interim) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
    try testing.expect(
        !std.mem.eql(u8, &confirmed, &interim),
    );
}

test "two-epoch chain produces distinct hashes" {
    const tag_0 = [_]u8{0x01} ** 16;
    const tag_1 = [_]u8{0x02} ** 16;

    // Epoch 0.
    const confirmed_0 = try updateConfirmedTranscriptHash(
        Default,
        "",
        "commit epoch 0",
    );
    const interim_0 = try updateInterimTranscriptHash(
        Default,
        &confirmed_0,
        &tag_0,
    );

    // Epoch 1: uses interim_0 as the previous interim hash.
    const confirmed_1 = try updateConfirmedTranscriptHash(
        Default,
        &interim_0,
        "commit epoch 1",
    );
    const interim_1 = try updateInterimTranscriptHash(
        Default,
        &confirmed_1,
        &tag_1,
    );

    // All four hashes should be distinct.
    const hashes = [_]*const [Default.nh]u8{
        &confirmed_0,
        &interim_0,
        &confirmed_1,
        &interim_1,
    };
    for (hashes, 0..) |a, i| {
        var j: u32 = @intCast(i + 1);
        while (j < hashes.len) : (j += 1) {
            try testing.expect(
                !std.mem.eql(u8, a, hashes[j]),
            );
        }
    }
}

test "transcript hash is deterministic" {
    const input = "deterministic commit content";
    const tag = [_]u8{0xFF} ** 8;

    const c1 = try updateConfirmedTranscriptHash(Default, "", input);
    const c2 = try updateConfirmedTranscriptHash(Default, "", input);
    try testing.expectEqualSlices(u8, &c1, &c2);

    const it1 = try updateInterimTranscriptHash(Default, &c1, &tag);
    const it2 = try updateInterimTranscriptHash(Default, &c2, &tag);
    try testing.expectEqualSlices(u8, &it1, &it2);
}

test "different confirmed inputs produce different hashes" {
    const c1 = try updateConfirmedTranscriptHash(
        Default,
        "",
        "commit A",
    );
    const c2 = try updateConfirmedTranscriptHash(
        Default,
        "",
        "commit B",
    );
    try testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "different confirmation tags produce different interim hashes" {
    const confirmed = try updateConfirmedTranscriptHash(
        Default,
        "",
        "some commit",
    );

    const tag_a = [_]u8{0x11} ** 16;
    const tag_b = [_]u8{0x22} ** 16;

    const i_a = try updateInterimTranscriptHash(
        Default,
        &confirmed,
        &tag_a,
    );
    const i_b = try updateInterimTranscriptHash(
        Default,
        &confirmed,
        &tag_b,
    );
    try testing.expect(!std.mem.eql(u8, &i_a, &i_b));
}

test "oversized input returns error instead of panic" {
    // hashConcat uses a 65536-byte buffer; exceeding it must
    // return BufferTooSmall, not panic.
    const big = [_]u8{0xAA} ** 65536;
    const result = updateConfirmedTranscriptHash(
        Default,
        &big,
        "x",
    );
    try testing.expectError(error.BufferTooSmall, result);
}
