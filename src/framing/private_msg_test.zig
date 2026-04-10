const std = @import("std");
const testing = std.testing;

const private_msg = @import("private_msg.zig");
const auth_mod = @import("auth.zig");

const SenderData = private_msg.SenderData;
const PrivateMessage = private_msg.PrivateMessage;
const ContentType = @import("../common/types.zig").ContentType;

const buildSenderDataAad = private_msg.buildSenderDataAad;
const encryptSenderData = private_msg.encryptSenderData;
const decryptSenderData = private_msg.decryptSenderData;
const applyReuseGuard = private_msg.applyReuseGuard;
const buildPrivateContentAad = private_msg.buildPrivateContentAad;
const paddedLength = private_msg.paddedLength;
const encodePrivateMessageContent = private_msg.encodePrivateMessageContent;
const decodePrivateMessageContent = private_msg.decodePrivateMessageContent;
const encryptContent = private_msg.encryptContent;
const decryptContent = private_msg.decryptContent;
const validateSenderLeafIndex = private_msg.validateSenderLeafIndex;
const default_padding_block = private_msg.default_padding_block;

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

// -- Codec round-trips ---------------------------------------------------

test "SenderData encode/decode round-trip" {
    const sd = SenderData{
        .leaf_index = 42,
        .generation = 7,
        .reuse_guard = .{ 0xDE, 0xAD, 0xBE, 0xEF },
    };

    var buf: [16]u8 = undefined;
    const end = try sd.encode(&buf, 0);
    try testing.expectEqual(
        @as(u32, SenderData.encoded_size),
        end,
    );

    const result = try SenderData.decode(&buf, 0);
    try testing.expectEqual(@as(u32, 42), result.value.leaf_index);
    try testing.expectEqual(@as(u32, 7), result.value.generation);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
        &result.value.reuse_guard,
    );
}

test "PrivateMessage encode/decode round-trip" {
    const msg = PrivateMessage{
        .group_id = "test-group",
        .epoch = 5,
        .content_type = .application,
        .authenticated_data = "aad",
        .encrypted_sender_data = "enc-sd",
        .ciphertext = "ct-bytes",
    };

    var buf: [256]u8 = undefined;
    const end = try msg.encode(&buf, 0);

    const result = try PrivateMessage.decode(&buf, 0);
    try testing.expectEqual(end, result.pos);
    try testing.expectEqualSlices(
        u8,
        "test-group",
        result.value.group_id,
    );
    try testing.expectEqual(@as(u64, 5), result.value.epoch);
    try testing.expectEqual(
        ContentType.application,
        result.value.content_type,
    );
    try testing.expectEqualSlices(
        u8,
        "enc-sd",
        result.value.encrypted_sender_data,
    );
    try testing.expectEqualSlices(
        u8,
        "ct-bytes",
        result.value.ciphertext,
    );
}

// -- Sender data crypto --------------------------------------------------

test "sender data encrypt/decrypt round-trip" {
    const sd = SenderData{
        .leaf_index = 3,
        .generation = 10,
        .reuse_guard = .{ 0x01, 0x02, 0x03, 0x04 },
    };
    const sds = [_]u8{0x55} ** Default.nh;
    const ct_sample = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    // Build SenderDataAAD.
    var aad_buf: [256]u8 = undefined;
    const aad_len = buildSenderDataAad(
        &aad_buf,
        "test-group",
        1,
        .application,
        // Safe: aad_buf is 256 bytes, AAD is ~30 bytes.
    ) catch unreachable;
    const aad = aad_buf[0..aad_len];

    var enc_buf: [SenderData.encoded_size]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    encryptSenderData(
        Default,
        &sd,
        &sds,
        &ct_sample,
        aad,
        &enc_buf,
        &tag,
    );

    // Concatenate ciphertext + tag for decryption.
    var combined: [SenderData.encoded_size + Default.nt]u8 = undefined;
    @memcpy(combined[0..SenderData.encoded_size], &enc_buf);
    @memcpy(combined[SenderData.encoded_size..], &tag);

    const decrypted = try decryptSenderData(
        Default,
        &combined,
        &sds,
        &ct_sample,
        aad,
    );

    try testing.expectEqual(@as(u32, 3), decrypted.leaf_index);
    try testing.expectEqual(@as(u32, 10), decrypted.generation);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
        &decrypted.reuse_guard,
    );
}

test "sender data decryption rejects wrong secret" {
    const sd = SenderData{
        .leaf_index = 0,
        .generation = 0,
        .reuse_guard = .{ 0, 0, 0, 0 },
    };
    const sds1 = [_]u8{0x11} ** Default.nh;
    const sds2 = [_]u8{0x22} ** Default.nh;
    const ct_sample = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    var aad_buf: [256]u8 = undefined;
    const aad_len = buildSenderDataAad(
        &aad_buf,
        "g",
        0,
        .application,
        // Safe: aad_buf is 256 bytes, AAD is ~20 bytes.
    ) catch unreachable;
    const aad = aad_buf[0..aad_len];

    var enc_buf: [SenderData.encoded_size]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    encryptSenderData(
        Default,
        &sd,
        &sds1,
        &ct_sample,
        aad,
        &enc_buf,
        &tag,
    );

    var combined: [SenderData.encoded_size + Default.nt]u8 = undefined;
    @memcpy(combined[0..SenderData.encoded_size], &enc_buf);
    @memcpy(combined[SenderData.encoded_size..], &tag);

    const result = decryptSenderData(
        Default,
        &combined,
        &sds2,
        &ct_sample,
        aad,
    );
    try testing.expectError(error.AeadError, result);
}

// -- Helpers -------------------------------------------------------------

test "reuse guard XOR application" {
    var nonce = [_]u8{ 0x00, 0x00, 0x00, 0x00 } ++
        [_]u8{0xFF} ** (Default.nn - 4);
    const guard = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    applyReuseGuard(Default, &nonce, &guard);
    try testing.expectEqual(@as(u8, 0xDE), nonce[0]);
    try testing.expectEqual(@as(u8, 0xAD), nonce[1]);
    try testing.expectEqual(@as(u8, 0xBE), nonce[2]);
    try testing.expectEqual(@as(u8, 0xEF), nonce[3]);
}

test "buildPrivateContentAad encodes correctly" {
    var buf: [256]u8 = undefined;
    const end = try buildPrivateContentAad(
        &buf,
        "group-1",
        42,
        .application,
        "extra",
    );
    try testing.expect(end > 0);
}

test "paddedLength rounds up to block boundary" {
    // Exact multiple stays the same.
    try testing.expectEqual(@as(u32, 32), paddedLength(32, 32));
    // Round up to next block.
    try testing.expectEqual(@as(u32, 32), paddedLength(1, 32));
    try testing.expectEqual(@as(u32, 32), paddedLength(31, 32));
    try testing.expectEqual(@as(u32, 64), paddedLength(33, 32));
    // Zero block means no padding.
    try testing.expectEqual(@as(u32, 17), paddedLength(17, 0));
    // Zero length.
    try testing.expectEqual(@as(u32, 0), paddedLength(0, 32));
}

// -- Content encode/decode -----------------------------------------------

test "encodePrivateMessageContent round-trip" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const sig = [_]u8{0xAA} ** Default.sig_len;
    const auth = Auth{
        .signature = sig,
        .confirmation_tag = null,
    };

    var buf: [512]u8 = undefined;
    const end = try encodePrivateMessageContent(
        Default,
        &buf,
        0,
        "hello",
        .application,
        &auth,
        10, // 10 bytes of padding
    );

    // Should decode back with padding stripped.
    const result = try decodePrivateMessageContent(
        Default,
        buf[0..end],
        .application,
    );
    try testing.expectEqualSlices(u8, "hello", result.content);
    try testing.expectEqualSlices(
        u8,
        &sig,
        &result.auth.signature,
    );
    try testing.expect(result.auth.confirmation_tag == null);
}

test "content ending with 0x00 round-trips correctly" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const sig = [_]u8{0xAA} ** Default.sig_len;
    const auth = Auth{
        .signature = sig,
        .confirmation_tag = null,
    };

    // Application content that ends with 0x00.
    const content = "data\x00";

    var buf: [512]u8 = undefined;
    const end = try encodePrivateMessageContent(
        Default,
        &buf,
        0,
        content,
        .application,
        &auth,
        10,
    );

    const result = try decodePrivateMessageContent(
        Default,
        buf[0..end],
        .application,
    );
    try testing.expectEqualSlices(u8, content, result.content);
}

test "non-zero padding bytes rejected" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const sig = [_]u8{0xBB} ** Default.sig_len;
    const auth = Auth{
        .signature = sig,
        .confirmation_tag = null,
    };

    var buf: [512]u8 = undefined;
    const end = try encodePrivateMessageContent(
        Default,
        &buf,
        0,
        "test",
        .application,
        &auth,
        10,
    );

    // Corrupt a padding byte (last byte before end).
    buf[end - 1] = 0xFF;

    const result = decodePrivateMessageContent(
        Default,
        buf[0..end],
        .application,
    );
    try testing.expectError(error.InvalidPadding, result);
}

// -- Encrypt / decrypt content -------------------------------------------

test "encryptContent/decryptContent round-trip (application)" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const sig = [_]u8{0xBB} ** Default.sig_len;
    const auth = Auth{
        .signature = sig,
        .confirmation_tag = null,
    };

    const key = [_]u8{0x42} ** Default.nk;
    const nonce = [_]u8{0x13} ** Default.nn;

    // Build AAD.
    var aad_buf: [256]u8 = undefined;
    const aad_len = try buildPrivateContentAad(
        &aad_buf,
        "test-group",
        1,
        .application,
        "",
    );

    // Encrypt.
    var ct_buf: [1024]u8 = undefined;
    const ct_len = try encryptContent(
        Default,
        "secret message",
        .application,
        &auth,
        default_padding_block,
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &ct_buf,
    );
    try testing.expect(ct_len > 0);

    // Decrypt.
    var pt_buf: [1024]u8 = undefined;
    const result = try decryptContent(
        Default,
        ct_buf[0..ct_len],
        .application,
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &pt_buf,
    );

    try testing.expectEqualSlices(
        u8,
        "secret message",
        result.content,
    );
    try testing.expectEqualSlices(
        u8,
        &sig,
        &result.auth.signature,
    );
}

test "encryptContent/decryptContent round-trip (commit)" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const sig = [_]u8{0xCC} ** Default.sig_len;
    const tag = [_]u8{0xDD} ** Default.nh;
    const auth = Auth{
        .signature = sig,
        .confirmation_tag = tag,
    };

    const key = [_]u8{0x55} ** Default.nk;
    const nonce = [_]u8{0x66} ** Default.nn;

    var aad_buf: [256]u8 = undefined;
    const aad_len = try buildPrivateContentAad(
        &aad_buf,
        "grp",
        0,
        .commit,
        "",
    );

    // Valid empty Commit: proposals<V>=varint(0) + optional=0.
    const commit_bytes = [_]u8{ 0x00, 0x00 };

    var ct_buf: [1024]u8 = undefined;
    const ct_len = try encryptContent(
        Default,
        &commit_bytes,
        .commit,
        &auth,
        default_padding_block,
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &ct_buf,
    );

    var pt_buf: [1024]u8 = undefined;
    const result = try decryptContent(
        Default,
        ct_buf[0..ct_len],
        .commit,
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &pt_buf,
    );

    try testing.expectEqualSlices(
        u8,
        &commit_bytes,
        result.content,
    );
    try testing.expect(result.auth.confirmation_tag != null);
    try testing.expectEqualSlices(
        u8,
        &tag,
        &result.auth.confirmation_tag.?,
    );
}

test "decryptContent rejects wrong key" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const auth = Auth{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };

    const key1 = [_]u8{0x11} ** Default.nk;
    const key2 = [_]u8{0x22} ** Default.nk;
    const nonce = [_]u8{0x33} ** Default.nn;

    var aad_buf: [256]u8 = undefined;
    const aad_len = try buildPrivateContentAad(
        &aad_buf,
        "g",
        0,
        .application,
        "",
    );

    var ct_buf: [1024]u8 = undefined;
    const ct_len = try encryptContent(
        Default,
        "msg",
        .application,
        &auth,
        0,
        &key1,
        &nonce,
        aad_buf[0..aad_len],
        &ct_buf,
    );

    var pt_buf: [1024]u8 = undefined;
    const result = decryptContent(
        Default,
        ct_buf[0..ct_len],
        .application,
        &key2,
        &nonce,
        aad_buf[0..aad_len],
        &pt_buf,
    );
    try testing.expectError(error.AeadError, result);
}

test "encryptContent with no padding" {
    const Auth = auth_mod.FramedContentAuthData(Default);
    const auth = Auth{
        .signature = [_]u8{0xEE} ** Default.sig_len,
        .confirmation_tag = null,
    };

    const key = [_]u8{0x77} ** Default.nk;
    const nonce = [_]u8{0x88} ** Default.nn;

    var aad_buf: [256]u8 = undefined;
    const aad_len = try buildPrivateContentAad(
        &aad_buf,
        "g",
        0,
        .application,
        "",
    );

    var ct_buf: [1024]u8 = undefined;
    const ct_len = try encryptContent(
        Default,
        "no-pad",
        .application,
        &auth,
        0, // padding_block = 0 → no padding
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &ct_buf,
    );

    var pt_buf: [1024]u8 = undefined;
    const result = try decryptContent(
        Default,
        ct_buf[0..ct_len],
        .application,
        &key,
        &nonce,
        aad_buf[0..aad_len],
        &pt_buf,
    );

    try testing.expectEqualSlices(
        u8,
        "no-pad",
        result.content,
    );
}

// -- Sender validation ---------------------------------------------------

test "validateSenderLeafIndex rejects out-of-bounds" {
    const sd = SenderData{
        .leaf_index = 5,
        .generation = 0,
        .reuse_guard = .{ 0, 0, 0, 0 },
    };
    const result = validateSenderLeafIndex(sd, 4);
    try testing.expectError(error.IndexOutOfRange, result);
}

test "validateSenderLeafIndex accepts valid index" {
    const sd = SenderData{
        .leaf_index = 3,
        .generation = 0,
        .reuse_guard = .{ 0, 0, 0, 0 },
    };
    try validateSenderLeafIndex(sd, 4);
}
