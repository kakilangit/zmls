//! PrivateMessage encryption/decryption per RFC 9420 Section 6.3.
//! Sender data and content ciphertext are encrypted separately
//! using secret tree keys.
// PrivateMessage per RFC 9420 Section 6.3.
//
// A PrivateMessage encrypts both the sender identity and the
// content. The sender data is encrypted separately using a key
// derived from the sender_data_secret and a sample of the
// content ciphertext. The content itself is encrypted with a
// key/nonce from the secret tree.
//
// Wire format:
//   struct {
//     opaque group_id<V>;
//     uint64 epoch;
//     ContentType content_type;
//     opaque authenticated_data<V>;
//     opaque encrypted_sender_data<V>;
//     opaque ciphertext<V>;
//   } PrivateMessage;
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const primitives = @import("../crypto/primitives.zig");
const framed_content_mod = @import("framed_content.zig");
const auth_mod = @import("auth.zig");
const content_type_mod = @import("content_type.zig");
const node_mod = @import("../tree/node.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const ContentType = types.ContentType;

const proposal_mod = @import("../messages/proposal.zig");
const commit_mod = @import("../messages/commit.zig");
const Proposal = proposal_mod.Proposal;
const Commit = commit_mod.Commit;
const FramedContent = framed_content_mod.FramedContent;
const Sender = content_type_mod.Sender;

/// SenderData per RFC 9420 Section 6.3.1.
///
/// struct {
///   uint32 leaf_index;
///   uint32 generation;
///   opaque reuse_guard[4];
/// } SenderData;
pub const SenderData = struct {
    leaf_index: u32,
    generation: types.Generation,
    reuse_guard: [4]u8,

    pub fn encode(
        self: *const SenderData,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        p = try codec.encodeUint32(buf, p, self.leaf_index);
        p = try codec.encodeUint32(buf, p, self.generation);
        if (p + 4 > buf.len) return error.BufferTooSmall;
        @memcpy(buf[p..][0..4], &self.reuse_guard);
        return p + 4;
    }

    pub fn decode(
        buf: []const u8,
        pos: u32,
    ) DecodeError!struct { value: SenderData, pos: u32 } {
        var p = pos;
        const li = try codec.decodeUint32(buf, p);
        p = li.pos;
        const gen = try codec.decodeUint32(buf, p);
        p = gen.pos;
        if (p + 4 > buf.len) return error.Truncated;
        var rg: [4]u8 = undefined;
        @memcpy(&rg, buf[p..][0..4]);
        return .{
            .value = .{
                .leaf_index = li.value,
                .generation = gen.value,
                .reuse_guard = rg,
            },
            .pos = p + 4,
        };
    }

    pub const encoded_size: u32 = 4 + 4 + 4; // 12 bytes
};

/// PrivateMessage wire format.
pub const PrivateMessage = struct {
    group_id: []const u8,
    epoch: types.Epoch,
    content_type: ContentType,
    authenticated_data: []const u8,
    encrypted_sender_data: []const u8,
    ciphertext: []const u8,

    /// Encode this PrivateMessage into `buf` at `pos`.
    pub fn encode(
        self: *const PrivateMessage,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        p = try codec.encodeVarVector(
            buf,
            p,
            self.group_id,
        );
        p = try codec.encodeUint64(buf, p, self.epoch);
        p = try codec.encodeUint8(
            buf,
            p,
            @intFromEnum(self.content_type),
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.authenticated_data,
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.encrypted_sender_data,
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.ciphertext,
        );
        return p;
    }

    /// Decode a PrivateMessage from `buf` at `pos`.
    pub fn decode(
        buf: []const u8,
        pos: u32,
    ) DecodeError!struct { value: PrivateMessage, pos: u32 } {
        var p = pos;
        const gid = try codec.decodeVarVectorSlice(buf, p);
        p = gid.pos;
        const ep = try codec.decodeUint64(buf, p);
        p = ep.pos;
        const ct = try codec.decodeUint8(buf, p);
        p = ct.pos;
        const ad = try codec.decodeVarVectorSlice(buf, p);
        p = ad.pos;
        const esd = try codec.decodeVarVectorSlice(buf, p);
        p = esd.pos;
        const ciph = try codec.decodeVarVectorSlice(buf, p);
        p = ciph.pos;

        return .{
            .value = .{
                .group_id = gid.value,
                .epoch = ep.value,
                .content_type = @enumFromInt(ct.value),
                .authenticated_data = ad.value,
                .encrypted_sender_data = esd.value,
                .ciphertext = ciph.value,
            },
            .pos = p,
        };
    }
};

/// Derive sender data key and nonce from sender_data_secret
/// and a ciphertext sample per RFC 9420 Section 6.3.2.
///
///   sample = ciphertext[0..min(Nh, len)]
///   key    = ExpandWithLabel(sds, "key",   sample, Nk)
///   nonce  = ExpandWithLabel(sds, "nonce", sample, Nn)
pub fn deriveSenderDataKeyNonce(
    comptime P: type,
    sender_data_secret: *const [P.nh]u8,
    ciphertext_sample: []const u8,
) struct { key: [P.nk]u8, nonce: [P.nn]u8 } {
    // Sample is first min(Nh, len(ciphertext)) bytes.
    const sample_len = @min(P.nh, ciphertext_sample.len);
    const sample = ciphertext_sample[0..sample_len];

    var key: [P.nk]u8 = undefined;
    var nonce: [P.nn]u8 = undefined;

    primitives.expandWithLabel(
        P,
        sender_data_secret,
        "key",
        sample,
        &key,
    );
    primitives.expandWithLabel(
        P,
        sender_data_secret,
        "nonce",
        sample,
        &nonce,
    );

    return .{ .key = key, .nonce = nonce };
}

/// Build the SenderDataAAD: the first three fields of
/// PrivateMessage (group_id, epoch, content_type).
///
/// RFC 9420 Section 6.3.2:
///   The AAD for the SenderData ciphertext is the first
///   three fields of PrivateMessage.
pub fn buildSenderDataAad(
    buf: []u8,
    group_id: []const u8,
    epoch: types.Epoch,
    content_type: ContentType,
) EncodeError!u32 {
    var p: u32 = 0;
    p = try codec.encodeVarVector(buf, p, group_id);
    p = try codec.encodeUint64(buf, p, epoch);
    p = try codec.encodeUint8(buf, p, @intFromEnum(content_type));
    return p;
}

/// Encrypt sender data.
///
/// `sender_data_aad` is the pre-built SenderDataAAD (first 3
/// fields of PrivateMessage: group_id, epoch, content_type).
///
/// Returns encrypted sender data (ciphertext + tag).
pub fn encryptSenderData(
    comptime P: type,
    sender_data: *const SenderData,
    sender_data_secret: *const [P.nh]u8,
    ciphertext_sample: []const u8,
    sender_data_aad: []const u8,
    out: []u8,
    tag_out: *[P.nt]u8,
) void {
    var kn = deriveSenderDataKeyNonce(
        P,
        sender_data_secret,
        ciphertext_sample,
    );
    defer primitives.secureZero(&kn.key);
    defer primitives.secureZero(&kn.nonce);

    // Encode SenderData.
    var sd_buf: [SenderData.encoded_size]u8 = undefined;
    const sd_len = sender_data.encode(
        &sd_buf,
        0,
    ) catch unreachable;

    P.aeadSeal(
        &kn.key,
        &kn.nonce,
        sender_data_aad,
        sd_buf[0..sd_len],
        out,
        tag_out,
    );
}

/// Decrypt sender data.
///
/// `sender_data_aad` is the pre-built SenderDataAAD (first 3
/// fields of PrivateMessage: group_id, epoch, content_type).
pub fn decryptSenderData(
    comptime P: type,
    encrypted_sender_data: []const u8,
    sender_data_secret: *const [P.nh]u8,
    ciphertext_sample: []const u8,
    sender_data_aad: []const u8,
) CryptoError!SenderData {
    var kn = deriveSenderDataKeyNonce(
        P,
        sender_data_secret,
        ciphertext_sample,
    );
    defer primitives.secureZero(&kn.key);
    defer primitives.secureZero(&kn.nonce);

    // Split into ciphertext and tag.
    if (encrypted_sender_data.len < P.nt) {
        return error.AeadError;
    }
    const ct_len = encrypted_sender_data.len - P.nt;
    const ct = encrypted_sender_data[0..ct_len];
    var tag: [P.nt]u8 = undefined;
    @memcpy(&tag, encrypted_sender_data[ct_len..]);

    var pt: [SenderData.encoded_size]u8 = undefined;
    if (ct_len > SenderData.encoded_size) {
        return error.AeadError;
    }

    P.aeadOpen(
        &kn.key,
        &kn.nonce,
        sender_data_aad,
        ct,
        &tag,
        pt[0..ct_len],
    ) catch return error.AeadError;

    const result = SenderData.decode(
        &pt,
        0,
    ) catch return error.AeadError;
    return result.value;
}

/// Validate that the decrypted sender leaf_index is within the
/// tree bounds and refers to a non-blank leaf. RFC §6.3.2
/// requires that the sender leaf index identifies a non-blank
/// member. Call this after decryptSenderData.
pub fn validateSenderLeafIndex(
    sender: SenderData,
    leaf_count: u32,
    nodes: []const ?node_mod.Node,
) errors.TreeError!void {
    if (sender.leaf_index >= leaf_count)
        return error.IndexOutOfRange;
    // The leaf's node index = 2 * leaf_index.
    const ni = @as(usize, sender.leaf_index) * 2;
    if (ni >= nodes.len)
        return error.IndexOutOfRange;
    if (nodes[ni] == null)
        return error.BlankNode;
}

/// Apply a reuse guard to a nonce by XOR-ing the guard bytes
/// into the first 4 bytes of the nonce.
pub fn applyReuseGuard(
    comptime P: type,
    nonce: *[P.nn]u8,
    reuse_guard: *const [4]u8,
) void {
    nonce[0] ^= reuse_guard[0];
    nonce[1] ^= reuse_guard[1];
    nonce[2] ^= reuse_guard[2];
    nonce[3] ^= reuse_guard[3];
}

/// Build the PrivateContentAAD for content encryption.
///
///   struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///   } PrivateContentAAD;
pub fn buildPrivateContentAad(
    buf: []u8,
    group_id: []const u8,
    epoch: types.Epoch,
    content_type: ContentType,
    authenticated_data: []const u8,
) EncodeError!u32 {
    var p: u32 = 0;
    p = try codec.encodeVarVector(buf, p, group_id);
    p = try codec.encodeUint64(buf, p, epoch);
    p = try codec.encodeUint8(buf, p, @intFromEnum(content_type));
    p = try codec.encodeVarVector(buf, p, authenticated_data);
    return p;
}

/// Maximum plaintext buffer for PrivateMessageContent encoding.
/// content (varint + data) + auth (varint + sig + opt tag) + padding.
const max_content_buf: u32 = 65536;

/// Default padding block size. Content is padded to a multiple of
/// this value to limit ciphertext length as a metadata channel.
pub const default_padding_block: u32 = 32;

/// Compute the padded length for a given content length.
///
/// Returns the smallest multiple of `block` that is >= `len`.
/// If `block` is 0, returns `len` unchanged (no padding).
pub fn paddedLength(len: u32, block: u32) u32 {
    if (block == 0) return len;
    return ((len + block - 1) / block) * block;
}

/// Encode PrivateMessageContent into `buf` at `pos`.
///
///   struct {
///     select (content_type) {
///       case application: opaque application_data<V>;
///       case proposal:    Proposal proposal;
///       case commit:      Commit commit;
///     };
///     FramedContentAuthData auth;
///     opaque padding[length_of_padding];
///   } PrivateMessageContent;
///
/// Returns the position after the last padding byte.
pub fn encodePrivateMessageContent(
    comptime P: type,
    buf: []u8,
    pos: u32,
    content: []const u8,
    content_type: ContentType,
    auth: *const auth_mod.FramedContentAuthData(P),
    padding_len: u32,
) EncodeError!u32 {
    var p = pos;

    // Content payload: varint-prefixed for application,
    // raw bytes for proposal/commit.
    switch (content_type) {
        .application => {
            p = try codec.encodeVarVector(buf, p, content);
        },
        .proposal, .commit => {
            const clen: u32 = @intCast(content.len);
            if (p + clen > buf.len) {
                return error.BufferTooSmall;
            }
            @memcpy(buf[p..][0..clen], content);
            p += clen;
        },
        else => return error.BufferTooSmall,
    }

    // FramedContentAuthData (signature + optional tag).
    p = try auth.encode(buf, p, content_type);

    // Zero-padding.
    if (padding_len > 0) {
        const end: u32 = p + padding_len;
        if (end > buf.len) return error.BufferTooSmall;
        @memset(buf[p..][0..padding_len], 0);
        p = end;
    }

    return p;
}

/// Result of decoding a PrivateMessageContent after decryption.
pub fn DecryptedContent(comptime P: type) type {
    return struct {
        /// The inner content payload bytes.
        content: []const u8,
        /// The decoded auth data.
        auth: auth_mod.FramedContentAuthData(P),
    };
}

/// Decode PrivateMessageContent from decrypted plaintext.
///
/// Decodes content and auth data from the front, then verifies
/// all remaining bytes are zero (padding per RFC 9420 Section
/// 6.3.1).
pub fn decodePrivateMessageContent(
    comptime P: type,
    plaintext: []const u8,
    content_type: ContentType,
) DecodeError!DecryptedContent(P) {
    // Decode content payload.
    var content: []const u8 = undefined;
    var p: u32 = 0;
    switch (content_type) {
        .application => {
            const cv = try codec.decodeVarVectorSlice(
                plaintext,
                0,
            );
            content = cv.value;
            p = cv.pos;
        },
        .proposal => {
            const start = p;
            p = try Proposal.skipDecode(plaintext, p);
            content = plaintext[start..p];
        },
        .commit => {
            const start = p;
            p = try Commit.skipDecode(plaintext, p);
            content = plaintext[start..p];
        },
        else => return error.InvalidEnumValue,
    }

    // Decode auth data.
    const auth_result = try auth_mod.FramedContentAuthData(
        P,
    ).decode(plaintext, p, content_type);

    // Verify remaining bytes are all zeros (padding).
    for (plaintext[auth_result.pos..]) |b| {
        if (b != 0) return error.InvalidPadding;
    }

    return .{
        .content = content,
        .auth = auth_result.value,
    };
}

/// Encrypt a PrivateMessageContent.
///
/// Serializes the content + auth data with padding, then AEAD-seals
/// using the provided key and nonce (already XOR'd with reuse guard
/// by the caller).
///
/// `aad` is the pre-built PrivateContentAAD.
///
/// Returns: ciphertext || tag concatenated into `out`. The caller
/// must provide a buffer of at least `plaintext_len + P.nt` bytes.
///
/// Returns the total output length (ciphertext + tag).
/// Per-call options for `encryptContent`.
pub fn EncryptContentOpts(comptime P: type) type {
    return struct {
        /// Plaintext content to encrypt.
        content: []const u8,
        /// Content type (application, proposal, commit).
        content_type: ContentType,
        /// Authentication data (signature + confirmation_tag).
        auth: *const auth_mod.FramedContentAuthData(P),
        /// Padding block size (0 = no padding).
        padding_block: u32 = 0,
        /// Encryption key.
        key: *const [P.nk]u8,
        /// Nonce.
        nonce: *const [P.nn]u8,
        /// Additional authenticated data.
        aad: []const u8,
    };
}

pub fn encryptContent(
    comptime P: type,
    content: []const u8,
    content_type: ContentType,
    auth: *const auth_mod.FramedContentAuthData(P),
    padding_block: u32,
    key: *const [P.nk]u8,
    nonce: *const [P.nn]u8,
    aad: []const u8,
    out: []u8,
) CryptoError!u32 {
    // Serialize PrivateMessageContent without padding.
    var pt_buf: [max_content_buf]u8 = undefined;
    defer primitives.secureZero(&pt_buf);
    const raw_len = encodePrivateMessageContent(
        P,
        &pt_buf,
        0,
        content,
        content_type,
        auth,
        0,
    ) catch return error.KdfOutputTooLong;

    // Compute and append zero padding in-place.
    const padded_len = paddedLength(raw_len, padding_block);
    const pad_bytes = padded_len - raw_len;
    if (raw_len + pad_bytes > pt_buf.len) {
        return error.KdfOutputTooLong;
    }
    if (pad_bytes > 0) {
        @memset(pt_buf[raw_len..][0..pad_bytes], 0);
    }
    const total_pt = raw_len + pad_bytes;

    // Output must hold ciphertext + tag.
    const required: u32 = total_pt + P.nt;
    if (required > out.len) return error.KdfOutputTooLong;

    var tag: [P.nt]u8 = undefined;
    P.aeadSeal(
        key,
        nonce,
        aad,
        pt_buf[0..total_pt],
        out[0..total_pt],
        &tag,
    );

    // Append tag.
    @memcpy(out[total_pt..][0..P.nt], &tag);

    return required;
}

/// Decrypt a PrivateMessageContent.
///
/// `ciphertext_with_tag` contains ciphertext || tag (as produced
/// by encryptContent). The key and nonce should already have the
/// reuse guard applied.
///
/// `aad` is the pre-built PrivateContentAAD.
///
/// Returns the decrypted content and auth data. The returned
/// slices point into `pt_out`, which the caller must provide
/// with length >= `ciphertext_with_tag.len - P.nt`.
pub fn decryptContent(
    comptime P: type,
    ciphertext_with_tag: []const u8,
    content_type: ContentType,
    key: *const [P.nk]u8,
    nonce: *const [P.nn]u8,
    aad: []const u8,
    pt_out: []u8,
) CryptoError!DecryptedContent(P) {
    if (ciphertext_with_tag.len < P.nt) {
        return error.AeadError;
    }

    const ct_len: u32 = @intCast(
        ciphertext_with_tag.len - P.nt,
    );
    const ct = ciphertext_with_tag[0..ct_len];
    var tag: [P.nt]u8 = undefined;
    @memcpy(&tag, ciphertext_with_tag[ct_len..]);

    if (pt_out.len < ct_len) return error.AeadError;

    P.aeadOpen(
        key,
        nonce,
        aad,
        ct,
        &tag,
        pt_out[0..ct_len],
    ) catch return error.AeadError;

    return decodePrivateMessageContent(
        P,
        pt_out[0..ct_len],
        content_type,
    ) catch return error.AeadError;
}
