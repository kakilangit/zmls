//! GroupInfo struct per RFC 9420 Section 12.4.3.1. Contains
//! GroupContext, extensions, confirmation tag, signer index,
//! and signature with encode/decode.
// GroupInfo per RFC 9420 Section 12.4.3.1.
//
//   struct {
//       GroupContext group_context;
//       Extension extensions<V>;
//       opaque confirmation_tag<V>;
//       uint32 signer;
//       /* SignWithLabel(., "GroupInfoTBS", GroupInfoTBS) */
//       opaque signature<V>;
//   } GroupInfo;
//
// The GroupInfoTBS is everything except the signature.
// GroupInfo is signed by a group member and then AEAD-encrypted
// using the welcome_key/welcome_nonce derived from welcome_secret.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const primitives = @import("../crypto/primitives.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const Extension = node_mod.Extension;

/// Maximum encoded GroupInfo size for stack buffers.
const max_gi_encode: u32 = 65536;

// -- GroupInfo ---------------------------------------------------------------

/// A GroupInfo message: signed group state shared with new members
/// (via Welcome) or external joiners.
///
/// The `group_context` field holds the serialized GroupContext.
/// Extensions may include `ratchet_tree` or `external_pub`.
pub const GroupInfo = struct {
    group_context: []const u8,
    extensions: []const Extension,
    confirmation_tag: []const u8,
    signer: u32,
    signature: []const u8,

    pub fn encode(
        self: *const GroupInfo,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try encodeTbs(
            buf,
            pos,
            self.group_context,
            self.extensions,
            self.confirmation_tag,
            self.signer,
        );

        // opaque signature<V>.
        p = try codec.encodeVarVector(buf, p, self.signature);

        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: GroupInfo,
        pos: u32,
    } {
        var p = pos;

        // GroupContext — inline struct. Skip-parse to find end,
        // then slice the raw bytes for round-trip fidelity.
        const gc_start = p;
        p = try skipGroupContext(data, p);
        const gc_bytes = try copySlice(
            allocator,
            data[gc_start..p],
        );

        // Extension extensions<V>.
        const ext_r = try decodeExtensionList(
            allocator,
            data,
            p,
        );
        p = ext_r.pos;

        // opaque confirmation_tag<V>.
        const ct_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_hash_length,
        );
        p = ct_r.pos;

        // uint32 signer.
        const s_r = try codec.decodeUint32(data, p);
        p = s_r.pos;

        // opaque signature<V>.
        const sig_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_signature_length,
        );
        p = sig_r.pos;

        return .{
            .value = .{
                .group_context = gc_bytes,
                .extensions = ext_r.value,
                .confirmation_tag = ct_r.value,
                .signer = s_r.value,
                .signature = sig_r.value,
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *GroupInfo,
        allocator: std.mem.Allocator,
    ) void {
        if (self.group_context.len > 0) {
            allocator.free(self.group_context);
        }
        for (self.extensions) |*ext| {
            @constCast(ext).deinit(allocator);
        }
        if (self.extensions.len > 0) {
            allocator.free(self.extensions);
        }
        if (self.confirmation_tag.len > 0) {
            allocator.free(self.confirmation_tag);
        }
        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
        self.* = undefined;
    }
};

// -- Sign / Verify -----------------------------------------------------------

/// Sign a GroupInfo. Returns the signature bytes.
///
/// Computes SignWithLabel(sign_key, "GroupInfoTBS", tbs_bytes)
/// where tbs_bytes encodes: group_context || extensions ||
///   confirmation_tag || signer.
pub fn signGroupInfo(
    comptime P: type,
    group_context: []const u8,
    extensions: []const Extension,
    confirmation_tag: []const u8,
    signer: u32,
    sign_key: *const [P.sign_sk_len]u8,
) CryptoError![P.sig_len]u8 {
    var tbs_buf: [max_gi_encode]u8 = undefined;
    const tbs_end = encodeTbs(
        &tbs_buf,
        0,
        group_context,
        extensions,
        confirmation_tag,
        signer,
    ) catch return error.KdfOutputTooLong;

    return primitives.signWithLabel(
        P,
        sign_key,
        "GroupInfoTBS",
        tbs_buf[0..tbs_end],
    );
}

/// Verify a GroupInfo signature.
pub fn verifyGroupInfo(
    comptime P: type,
    gi: *const GroupInfo,
    verify_key: *const [P.sign_pk_len]u8,
) CryptoError!void {
    var tbs_buf: [max_gi_encode]u8 = undefined;
    const tbs_end = encodeTbs(
        &tbs_buf,
        0,
        gi.group_context,
        gi.extensions,
        gi.confirmation_tag,
        gi.signer,
    ) catch return error.KdfOutputTooLong;

    if (gi.signature.len != P.sig_len) {
        return error.SignatureVerifyFailed;
    }
    const sig: *const [P.sig_len]u8 = gi.signature[0..P.sig_len];

    return primitives.verifyWithLabel(
        P,
        verify_key,
        "GroupInfoTBS",
        tbs_buf[0..tbs_end],
        sig,
    );
}

// -- AEAD encrypt/decrypt (welcome_key/welcome_nonce) ------------------------

/// Derive welcome_key and welcome_nonce from welcome_secret.
///
/// welcome_key = ExpandWithLabel(welcome_secret, "key", "", Nk)
/// welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", Nn)
fn deriveWelcomeKeyNonce(
    comptime P: type,
    welcome_secret: *const [P.nh]u8,
) struct { key: [P.nk]u8, nonce: [P.nn]u8 } {
    var key: [P.nk]u8 = undefined;
    primitives.expandWithLabel(
        P,
        welcome_secret,
        "key",
        "",
        &key,
    );

    var nonce: [P.nn]u8 = undefined;
    primitives.expandWithLabel(
        P,
        welcome_secret,
        "nonce",
        "",
        &nonce,
    );

    return .{ .key = key, .nonce = nonce };
}

/// Encrypt a serialized GroupInfo using AEAD with welcome_key.
///
/// Returns ciphertext || tag.
pub fn encryptGroupInfo(
    comptime P: type,
    welcome_secret: *const [P.nh]u8,
    plaintext: []const u8,
    ct_out: []u8,
    tag_out: *[P.nt]u8,
) void {
    var kn = deriveWelcomeKeyNonce(P, welcome_secret);
    defer primitives.secureZeroArr(P.nk, &kn.key);
    defer primitives.secureZeroArr(P.nn, &kn.nonce);
    P.aeadSeal(
        &kn.key,
        &kn.nonce,
        "",
        plaintext,
        ct_out,
        tag_out,
    );
}

/// Decrypt encrypted_group_info using AEAD with welcome_key.
///
/// The input `data` must be ciphertext || tag (tag is last
/// P.nt bytes).
pub fn decryptGroupInfo(
    comptime P: type,
    welcome_secret: *const [P.nh]u8,
    data: []const u8,
    pt_out: []u8,
) CryptoError!void {
    if (data.len < P.nt) return error.AeadError;

    const ct_len: u32 = @intCast(data.len - P.nt);
    const ct = data[0..ct_len];
    const tag: *const [P.nt]u8 = data[ct_len..][0..P.nt];
    var kn = deriveWelcomeKeyNonce(P, welcome_secret);
    defer primitives.secureZeroArr(P.nk, &kn.key);
    defer primitives.secureZeroArr(P.nn, &kn.nonce);

    try P.aeadOpen(
        &kn.key,
        &kn.nonce,
        "",
        ct,
        tag,
        pt_out,
    );
}

// -- TBS encoder helper ------------------------------------------------------

/// Encode the GroupInfoTBS (everything except the signature):
///   GroupContext || extensions<V> || confirmation_tag<V>
///   || uint32 signer
///
/// GroupContext is an inline struct per RFC 9420 Section 12.4.3.1,
/// NOT varint-prefixed. The `group_context` slice must already be
/// a valid TLS-serialized GroupContext.
fn encodeTbs(
    buf: []u8,
    pos: u32,
    group_context: []const u8,
    extensions: []const Extension,
    confirmation_tag: []const u8,
    signer: u32,
) EncodeError!u32 {
    var p = pos;

    // GroupContext group_context — inline struct, raw bytes.
    const gc_len: u32 = @intCast(group_context.len);
    if (p + gc_len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[p..][0..gc_len], group_context);
    p += gc_len;

    // Extension extensions<V>.
    p = try encodeExtensionList(buf, p, extensions);

    // opaque confirmation_tag<V>.
    p = try codec.encodeVarVector(buf, p, confirmation_tag);

    // uint32 signer.
    p = try codec.encodeUint32(buf, p, signer);

    return p;
}

// -- Extension list codec helpers --------------------------------------------

fn encodeExtensionList(
    buf: []u8,
    pos: u32,
    items: []const Extension,
) EncodeError!u32 {
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;

    for (items) |*ext| {
        p = try ext.encode(buf, p);
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

/// Free extension data slices allocated during decode.
fn freeDecodedExts(
    allocator: std.mem.Allocator,
    exts: []Extension,
) void {
    for (exts) |ext| allocator.free(ext.data);
}

fn decodeExtensionList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const Extension,
    pos: u32,
} {
    const max_extensions: u32 = 256;

    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;
    var temp: [256]Extension = undefined;
    var count: u32 = 0;

    while (p < end) {
        if (count >= max_extensions) {
            return error.VectorTooLarge;
        }
        const r = try Extension.decode(
            allocator,
            data,
            p,
        );
        temp[count] = r.value;
        count += 1;
        p = r.pos;
    }

    if (p != end) return error.Truncated;

    // RFC 9420 S13.4: reject duplicate extension types.
    var di: u32 = 0;
    while (di < count) : (di += 1) {
        var dj: u32 = di + 1;
        while (dj < count) : (dj += 1) {
            if (temp[di].extension_type ==
                temp[dj].extension_type)
            {
                freeDecodedExts(allocator, temp[0..count]);
                return error.DuplicateExtensionType;
            }
        }
    }

    const items = allocator.alloc(
        Extension,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

// -- GroupContext skip-parse -------------------------------------------------

/// Skip past a TLS-serialized GroupContext without allocating.
///
/// GroupContext layout:
///   uint16 version | uint16 cipher_suite | group_id<V>
///   | uint64 epoch | tree_hash<V>
///   | confirmed_transcript_hash<V> | extensions<V>
fn skipGroupContext(
    data: []const u8,
    pos: u32,
) DecodeError!u32 {
    var p = pos;

    // uint16 version + uint16 cipher_suite.
    if (p + 4 > data.len) return error.Truncated;
    p += 4;

    // opaque group_id<V>.
    p = try codec.skipVarVector(data, p);

    // uint64 epoch.
    if (p + 8 > data.len) return error.Truncated;
    p += 8;

    // opaque tree_hash<V>.
    p = try codec.skipVarVector(data, p);

    // opaque confirmed_transcript_hash<V>.
    p = try codec.skipVarVector(data, p);

    // Extension extensions<V>.
    p = try codec.skipVarVector(data, p);

    return p;
}

/// Copy a slice into an allocator-owned buffer.
fn copySlice(
    allocator: std.mem.Allocator,
    src: []const u8,
) (DecodeError || error{OutOfMemory})![]const u8 {
    const buf = allocator.alloc(
        u8,
        src.len,
    ) catch return error.OutOfMemory;
    @memcpy(buf, src);
    return buf;
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const ExtensionType = types.ExtensionType;
const GC = @import("../group/context.zig").GroupContext;

/// Build a minimal valid serialized GroupContext for tests.
fn testGroupContext(gid: []const u8) [256]u8 {
    const gc = GC(Default.nh){
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = gid,
        .epoch = 0,
        .tree_hash = [_]u8{0} ** Default.nh,
        .confirmed_transcript_hash = [_]u8{0} ** Default.nh,
        .extensions = &.{},
    };
    var buf: [256]u8 = [_]u8{0} ** 256;
    _ = gc.encode(&buf, 0) catch unreachable;
    return buf;
}

fn testGroupContextLen(gid: []const u8) u32 {
    const gc = GC(Default.nh){
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = gid,
        .epoch = 0,
        .tree_hash = [_]u8{0} ** Default.nh,
        .confirmed_transcript_hash = [_]u8{0} ** Default.nh,
        .extensions = &.{},
    };
    var buf: [256]u8 = undefined;
    return gc.encode(&buf, 0) catch unreachable;
}

test "GroupInfo encode/decode round-trip" {
    const alloc = testing.allocator;

    const gc_buf = testGroupContext("test-group");
    const gc_len = testGroupContextLen("test-group");
    const gc = gc_buf[0..gc_len];

    const gi = GroupInfo{
        .group_context = gc,
        .extensions = &.{},
        .confirmation_tag = &[_]u8{0xCC} ** 32,
        .signer = 0,
        .signature = &[_]u8{0xDD} ** 64,
    };

    var buf: [512]u8 = undefined;
    const end = try gi.encode(&buf, 0);

    var dec_r = try GroupInfo.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        gc,
        dec_r.value.group_context,
    );
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.extensions.len,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xCC} ** 32,
        dec_r.value.confirmation_tag,
    );
    try testing.expectEqual(@as(u32, 0), dec_r.value.signer);
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xDD} ** 64,
        dec_r.value.signature,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "GroupInfo with extensions round-trip" {
    const alloc = testing.allocator;

    const gc_buf = testGroupContext("g");
    const gc_len = testGroupContextLen("g");
    const gc = gc_buf[0..gc_len];

    const ext = Extension{
        .extension_type = @enumFromInt(0xFE01),
        .data = "some-ext-data",
    };
    const exts = [_]Extension{ext};

    const gi = GroupInfo{
        .group_context = gc,
        .extensions = &exts,
        .confirmation_tag = "tag",
        .signer = 42,
        .signature = "sig",
    };

    var buf: [512]u8 = undefined;
    const end = try gi.encode(&buf, 0);

    var dec_r = try GroupInfo.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.extensions.len,
    );
    try testing.expectEqualSlices(
        u8,
        "some-ext-data",
        dec_r.value.extensions[0].data,
    );
    try testing.expectEqual(
        @as(u32, 42),
        dec_r.value.signer,
    );
}

test "signGroupInfo and verifyGroupInfo round-trip" {
    const alloc = testing.allocator;

    // Generate signing key pair.
    const sign_seed = [_]u8{0x01} ** 32;
    const sign_kp = try Default.signKeypairFromSeed(&sign_seed);

    const gc_buf = testGroupContext("sign-test");
    const gc_len = testGroupContextLen("sign-test");
    const gc = gc_buf[0..gc_len];
    const conf_tag = [_]u8{0xAA} ** 32;

    const sig = try signGroupInfo(
        Default,
        gc,
        &.{},
        &conf_tag,
        0,
        &sign_kp.sk,
    );

    const gi = GroupInfo{
        .group_context = gc,
        .extensions = &.{},
        .confirmation_tag = &conf_tag,
        .signer = 0,
        .signature = &sig,
    };

    // Verify should succeed.
    try verifyGroupInfo(Default, &gi, &sign_kp.pk);

    // Verify with wrong key should fail.
    const wrong_seed = [_]u8{0x02} ** 32;
    const wrong_kp = try Default.signKeypairFromSeed(&wrong_seed);
    const result = verifyGroupInfo(Default, &gi, &wrong_kp.pk);
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
    _ = alloc;
}

test "encryptGroupInfo and decryptGroupInfo round-trip" {
    const welcome_secret = [_]u8{0x42} ** Default.nh;
    const plaintext = "serialized-group-info-tbs-data!!";

    // Encrypt.
    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    encryptGroupInfo(
        Default,
        &welcome_secret,
        plaintext,
        &ct,
        &tag,
    );

    // Build ciphertext || tag.
    var data: [plaintext.len + Default.nt]u8 = undefined;
    @memcpy(data[0..plaintext.len], &ct);
    @memcpy(data[plaintext.len..], &tag);

    // Decrypt.
    var decrypted: [plaintext.len]u8 = undefined;
    try decryptGroupInfo(
        Default,
        &welcome_secret,
        &data,
        &decrypted,
    );
    try testing.expectEqualSlices(
        u8,
        plaintext,
        &decrypted,
    );
}

test "decryptGroupInfo rejects wrong welcome_secret" {
    const welcome_secret = [_]u8{0x42} ** Default.nh;
    const plaintext = "test-plaintext";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    encryptGroupInfo(
        Default,
        &welcome_secret,
        plaintext,
        &ct,
        &tag,
    );

    var data: [plaintext.len + Default.nt]u8 = undefined;
    @memcpy(data[0..plaintext.len], &ct);
    @memcpy(data[plaintext.len..], &tag);

    // Wrong welcome_secret.
    const wrong = [_]u8{0xFF} ** Default.nh;
    var out: [plaintext.len]u8 = undefined;
    const result = decryptGroupInfo(
        Default,
        &wrong,
        &data,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "full GroupInfo sign, encrypt, decrypt, verify flow" {
    const alloc = testing.allocator;

    // Signing key.
    const sign_seed = [_]u8{0x10} ** 32;
    const sign_kp = try Default.signKeypairFromSeed(&sign_seed);

    const gc_buf = testGroupContext("full-flow");
    const gc_len = testGroupContextLen("full-flow");
    const gc = gc_buf[0..gc_len];
    const conf_tag = [_]u8{0xBB} ** 32;

    // 1. Sign.
    const sig = try signGroupInfo(
        Default,
        gc,
        &.{},
        &conf_tag,
        0,
        &sign_kp.sk,
    );

    // 2. Encode the full GroupInfo.
    const gi = GroupInfo{
        .group_context = gc,
        .extensions = &.{},
        .confirmation_tag = &conf_tag,
        .signer = 0,
        .signature = &sig,
    };

    var gi_buf: [2048]u8 = undefined;
    const gi_end = try gi.encode(&gi_buf, 0);
    const gi_bytes = gi_buf[0..gi_end];

    // 3. Encrypt with welcome_secret.
    const welcome_secret = [_]u8{0x55} ** Default.nh;
    var egi_ct: [2048]u8 = undefined;
    var egi_tag: [Default.nt]u8 = undefined;
    encryptGroupInfo(
        Default,
        &welcome_secret,
        gi_bytes,
        egi_ct[0..gi_end],
        &egi_tag,
    );

    // 4. Decrypt.
    var egi_data: [2048 + Default.nt]u8 = undefined;
    @memcpy(egi_data[0..gi_end], egi_ct[0..gi_end]);
    @memcpy(egi_data[gi_end..][0..Default.nt], &egi_tag);

    var dec_pt: [2048]u8 = undefined;
    try decryptGroupInfo(
        Default,
        &welcome_secret,
        egi_data[0 .. gi_end + Default.nt],
        dec_pt[0..gi_end],
    );

    // 5. Decode GroupInfo.
    var dec_gi = try GroupInfo.decode(
        alloc,
        dec_pt[0..gi_end],
        0,
    );
    defer dec_gi.value.deinit(alloc);

    // 6. Verify signature.
    try verifyGroupInfo(
        Default,
        &dec_gi.value,
        &sign_kp.pk,
    );

    try testing.expectEqualSlices(
        u8,
        gc,
        dec_gi.value.group_context,
    );
    try testing.expectEqual(
        @as(u32, 0),
        dec_gi.value.signer,
    );
}
