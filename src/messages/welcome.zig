//! Welcome message structs (GroupSecrets, EncryptedGroupSecrets,
//! Welcome) per RFC 9420 Section 12.4.3.1 with wire format
//! encode/decode.
// Welcome message per RFC 9420 Section 12.4.3.1.
//
//   struct {
//       opaque path_secret<V>;
//   } PathSecret;
//
//   struct {
//       opaque joiner_secret<V>;
//       optional<PathSecret> path_secret;
//       PreSharedKeyID psks<V>;
//   } GroupSecrets;
//
//   struct {
//       KeyPackageRef new_member;
//       HPKECiphertext encrypted_group_secrets;
//   } EncryptedGroupSecrets;
//
//   struct {
//       CipherSuite cipher_suite;
//       EncryptedGroupSecrets secrets<V>;
//       opaque encrypted_group_info<V>;
//   } Welcome;
//
// A new member finds their EncryptedGroupSecrets entry by
// matching KeyPackageRef, then decrypts the GroupSecrets using
// HPKE with their init_key private key.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const psk_mod = @import("../key_schedule/psk.zig");
const path_mod = @import("../tree/path.zig");
const primitives = @import("../crypto/primitives.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const CipherSuite = types.CipherSuite;
const PreSharedKeyId = psk_mod.PreSharedKeyId;
const HPKECiphertext = path_mod.HPKECiphertext;

/// Maximum number of EncryptedGroupSecrets entries.
const max_secrets: u32 = 256;

/// Maximum number of PSK IDs in GroupSecrets.
const max_psks: u32 = 256;

/// Maximum encoded GroupSecrets size for stack buffers.
const max_gs_encode: u32 = 65536;

// -- GroupSecrets ------------------------------------------------------------

/// The secrets shared with a new member via Welcome.
pub const GroupSecrets = struct {
    joiner_secret: []const u8,
    path_secret: ?[]const u8,
    psks: []const PreSharedKeyId,

    pub fn encode(
        self: *const GroupSecrets,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;

        // opaque joiner_secret<V>.
        p = try codec.encodeVarVector(
            buf,
            p,
            self.joiner_secret,
        );

        // optional<PathSecret> path_secret.
        if (self.path_secret) |ps| {
            p = try codec.encodeUint8(buf, p, 1);
            p = try codec.encodeVarVector(buf, p, ps);
        } else {
            p = try codec.encodeUint8(buf, p, 0);
        }

        // PreSharedKeyID psks<V> — varint-prefixed list.
        p = try encodePskIdList(buf, p, self.psks);

        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: GroupSecrets,
        pos: u32,
    } {
        var p = pos;

        // joiner_secret<V>.
        const js_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_hash_length,
        );
        p = js_r.pos;

        // optional<PathSecret>.
        const opt_r = try codec.decodeUint8(data, p);
        p = opt_r.pos;

        var path_secret: ?[]const u8 = null;
        if (opt_r.value == 1) {
            const ps_r = try codec.decodeVarVectorLimited(
                allocator,
                data,
                p,
                types.max_hash_length,
            );
            path_secret = ps_r.value;
            p = ps_r.pos;
        } else if (opt_r.value != 0) {
            return error.InvalidOptionalPrefix;
        }

        // PreSharedKeyID psks<V>.
        const psks_r = try decodePskIdList(
            allocator,
            data,
            p,
        );
        p = psks_r.pos;

        return .{
            .value = .{
                .joiner_secret = js_r.value,
                .path_secret = path_secret,
                .psks = psks_r.value,
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *GroupSecrets,
        allocator: std.mem.Allocator,
    ) void {
        if (self.joiner_secret.len > 0) {
            primitives.secureZeroConst(self.joiner_secret);
            allocator.free(self.joiner_secret);
        }
        if (self.path_secret) |ps| {
            if (ps.len > 0) {
                primitives.secureZeroConst(ps);
                allocator.free(ps);
            }
        }
        if (self.psks.len > 0) {
            allocator.free(self.psks);
        }
        self.* = undefined;
    }
};

// -- EncryptedGroupSecrets ---------------------------------------------------

/// An entry binding a new member (by KeyPackageRef) to their
/// HPKE-encrypted GroupSecrets.
pub const EncryptedGroupSecrets = struct {
    new_member: []const u8,
    encrypted_group_secrets: HPKECiphertext,

    pub fn encode(
        self: *const EncryptedGroupSecrets,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;

        // opaque new_member<V> (KeyPackageRef).
        p = try codec.encodeVarVector(
            buf,
            p,
            self.new_member,
        );

        // HPKECiphertext encrypted_group_secrets.
        p = try self.encrypted_group_secrets.encode(buf, p);

        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: EncryptedGroupSecrets,
        pos: u32,
    } {
        const nm_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_hash_length,
        );
        const ct_r = try HPKECiphertext.decode(
            allocator,
            data,
            nm_r.pos,
        );
        return .{
            .value = .{
                .new_member = nm_r.value,
                .encrypted_group_secrets = ct_r.value,
            },
            .pos = ct_r.pos,
        };
    }

    pub fn deinit(
        self: *EncryptedGroupSecrets,
        allocator: std.mem.Allocator,
    ) void {
        if (self.new_member.len > 0) {
            allocator.free(self.new_member);
        }
        self.encrypted_group_secrets
            .deinit(allocator);
        self.* = undefined;
    }
};

// -- Welcome -----------------------------------------------------------------

/// The Welcome message sent to new members.
///
///   struct {
///       CipherSuite cipher_suite;
///       EncryptedGroupSecrets secrets<V>;
///       opaque encrypted_group_info<V>;
///   } Welcome;
pub const Welcome = struct {
    cipher_suite: CipherSuite,
    secrets: []const EncryptedGroupSecrets,
    encrypted_group_info: []const u8,

    pub fn encode(
        self: *const Welcome,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;

        // CipherSuite cipher_suite (u16).
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.cipher_suite),
        );

        // EncryptedGroupSecrets secrets<V>.
        p = try encodeEncryptedSecretsList(
            buf,
            p,
            self.secrets,
        );

        // opaque encrypted_group_info<V>.
        p = try codec.encodeVarVector(
            buf,
            p,
            self.encrypted_group_info,
        );

        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Welcome,
        pos: u32,
    } {
        var p = pos;

        // CipherSuite (u16).
        const cs_r = try codec.decodeUint16(data, p);
        p = cs_r.pos;

        // EncryptedGroupSecrets secrets<V>.
        const sec_r = try decodeEncryptedSecretsList(
            allocator,
            data,
            p,
        );
        p = sec_r.pos;

        // opaque encrypted_group_info<V>.
        const egi_r = try codec.decodeVarVector(
            allocator,
            data,
            p,
        );
        p = egi_r.pos;

        return .{
            .value = .{
                .cipher_suite = @enumFromInt(cs_r.value),
                .secrets = sec_r.value,
                .encrypted_group_info = egi_r.value,
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *Welcome,
        allocator: std.mem.Allocator,
    ) void {
        for (self.secrets) |*egs| {
            @constCast(egs).deinit(allocator);
        }
        if (self.secrets.len > 0) {
            allocator.free(self.secrets);
        }
        if (self.encrypted_group_info.len > 0) {
            allocator.free(self.encrypted_group_info);
        }
        self.* = undefined;
    }
};

// -- HPKE encrypt/decrypt GroupSecrets per member ----------------------------

/// Encrypt GroupSecrets for a single new member.
///
/// Uses EncryptWithLabel(init_key, "Welcome",
///                       encrypted_group_info, group_secrets)
/// per RFC 9420 Section 12.4.3.1.
///
/// Returns the EncryptedGroupSecrets entry containing the
/// KeyPackageRef and the HPKE ciphertext.
pub fn encryptGroupSecrets(
    comptime P: type,
    group_secrets: *const GroupSecrets,
    kp_ref: []const u8,
    init_key: *const [P.npk]u8,
    encrypted_group_info: []const u8,
    eph_seed: *const [P.seed_len]u8,
) CryptoError!EncryptedGroupSecrets {
    // Encode GroupSecrets.
    var gs_buf: [max_gs_encode]u8 = undefined;
    const gs_end = group_secrets.encode(
        &gs_buf,
        0,
    ) catch return error.KdfOutputTooLong;
    const gs_bytes = gs_buf[0..gs_end];

    // EncryptWithLabel(init_key, "Welcome",
    //                  encrypted_group_info, gs_bytes)
    var ct: [max_gs_encode]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    const kem_output = try primitives.encryptWithLabel(
        P,
        init_key,
        "Welcome",
        encrypted_group_info,
        gs_bytes,
        eph_seed,
        ct[0..gs_end],
        &tag,
    );

    // Build the ciphertext blob: ciphertext || tag.
    var ct_with_tag: [max_gs_encode + P.nt]u8 = undefined;
    @memcpy(ct_with_tag[0..gs_end], ct[0..gs_end]);
    @memcpy(ct_with_tag[gs_end..][0..P.nt], &tag);

    return .{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = &kem_output,
            .ciphertext = ct_with_tag[0 .. gs_end + P.nt],
        },
    };
}

/// Decrypt GroupSecrets from a Welcome message.
///
/// Searches for matching KeyPackageRef, then decrypts using
/// DecryptWithLabel(init_sk, "Welcome",
///                  encrypted_group_info, kem_output, ciphertext).
pub fn decryptGroupSecrets(
    comptime P: type,
    allocator: std.mem.Allocator,
    welcome: *const Welcome,
    kp_ref: []const u8,
    init_sk: *const [P.nsk]u8,
    init_pk: *const [P.npk]u8,
) (CryptoError || DecodeError || error{OutOfMemory})!GroupSecrets {
    // Find matching entry.
    for (welcome.secrets) |*entry| {
        if (!std.mem.eql(
            u8,
            entry.new_member,
            kp_ref,
        )) continue;

        // Found our entry. Decrypt it.
        const ct_data = entry.encrypted_group_secrets.ciphertext;
        if (ct_data.len < P.nt) return error.Truncated;

        const ct_len: u32 = @intCast(ct_data.len - P.nt);
        const ct_slice = ct_data[0..ct_len];
        const tag: *const [P.nt]u8 = ct_data[ct_len..][0..P.nt];

        const kem_out = entry.encrypted_group_secrets.kem_output;
        if (kem_out.len != P.npk) return error.Truncated;
        const kem_ptr: *const [P.npk]u8 = kem_out[0..P.npk];

        var pt_buf: [max_gs_encode]u8 = undefined;
        try primitives.decryptWithLabel(
            P,
            init_sk,
            init_pk,
            "Welcome",
            welcome.encrypted_group_info,
            kem_ptr,
            ct_slice,
            tag,
            pt_buf[0..ct_len],
        );

        // Decode GroupSecrets from plaintext.
        const gs_r = GroupSecrets.decode(
            allocator,
            pt_buf[0..ct_len],
            0,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Truncated,
        };

        return gs_r.value;
    }

    // No matching entry found.
    return error.KeyPackageNotFound;
}

// -- Codec helpers for list types -------------------------------------------

fn encodePskIdList(
    buf: []u8,
    pos: u32,
    items: []const PreSharedKeyId,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        PreSharedKeyId,
        buf,
        pos,
        items,
    );
}

fn decodePskIdList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const PreSharedKeyId,
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
    var temp: [max_psks]PreSharedKeyId = undefined;
    var count: u32 = 0;

    while (p < end) {
        if (count >= max_psks) return error.VectorTooLarge;
        // PreSharedKeyId.decode is zero-copy (no allocator).
        const r = try PreSharedKeyId.decode(data, p);
        temp[count] = r.value;
        count += 1;
        p = r.pos;
    }

    if (p != end) return error.Truncated;

    const items = allocator.alloc(
        PreSharedKeyId,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

fn encodeEncryptedSecretsList(
    buf: []u8,
    pos: u32,
    items: []const EncryptedGroupSecrets,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        EncryptedGroupSecrets,
        buf,
        pos,
        items,
    );
}

fn decodeEncryptedSecretsList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const EncryptedGroupSecrets,
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
    var temp: [max_secrets]EncryptedGroupSecrets = undefined;
    var count: u32 = 0;

    while (p < end) {
        if (count >= max_secrets) return error.VectorTooLarge;
        const r = try EncryptedGroupSecrets.decode(
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
        EncryptedGroupSecrets,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(items, temp[0..count]);

    return .{ .value = items, .pos = p };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "GroupSecrets encode/decode round-trip, no path, no PSKs" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x42} ** 32;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    var buf: [256]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        &joiner,
        dec_r.value.joiner_secret,
    );
    try testing.expect(dec_r.value.path_secret == null);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.psks.len,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "GroupSecrets with path_secret round-trip" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x11} ** 32;
    const path = [_]u8{0x22} ** 32;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = &path,
        .psks = &.{},
    };

    var buf: [256]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path_secret != null);
    try testing.expectEqualSlices(
        u8,
        &path,
        dec_r.value.path_secret.?,
    );
}

test "GroupSecrets with PSKs round-trip" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x33} ** 32;
    const psk_id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-external-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "nonce123",
    };
    const psks = [_]PreSharedKeyId{psk_id};
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &psks,
    };

    var buf: [512]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.psks.len,
    );
    try testing.expectEqualSlices(
        u8,
        "my-external-psk",
        dec_r.value.psks[0].external_psk_id,
    );
    try testing.expectEqualSlices(
        u8,
        "nonce123",
        dec_r.value.psks[0].psk_nonce,
    );
}

test "EncryptedGroupSecrets encode/decode round-trip" {
    const alloc = testing.allocator;

    const egs = EncryptedGroupSecrets{
        .new_member = "kp-ref-hash-32-bytes!!!!!!!!????",
        .encrypted_group_secrets = .{
            .kem_output = &[_]u8{0xAA} ** 32,
            .ciphertext = &[_]u8{0xBB} ** 64,
        },
    };

    var buf: [512]u8 = undefined;
    const end = try egs.encode(&buf, 0);

    var dec_r = try EncryptedGroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        "kp-ref-hash-32-bytes!!!!!!!!????",
        dec_r.value.new_member,
    );
    try testing.expectEqual(
        @as(usize, 32),
        dec_r.value.encrypted_group_secrets.kem_output.len,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "Welcome encode/decode round-trip" {
    const alloc = testing.allocator;

    const egs = EncryptedGroupSecrets{
        .new_member = "ref1",
        .encrypted_group_secrets = .{
            .kem_output = &[_]u8{0x01} ** 8,
            .ciphertext = &[_]u8{0x02} ** 16,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = &[_]u8{0xFF} ** 48,
    };

    var buf: [512]u8 = undefined;
    const end = try welcome.encode(&buf, 0);

    var dec_r = try Welcome.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        CipherSuite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        dec_r.value.cipher_suite,
    );
    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.secrets.len,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xFF} ** 48,
        dec_r.value.encrypted_group_info,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "encrypt and decrypt GroupSecrets round-trip" {
    const alloc = testing.allocator;

    // Generate recipient init key pair.
    const init_seed = [_]u8{0xAA} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    // Create GroupSecrets.
    const joiner = [_]u8{0x42} ** Default.nh;
    const path_s = [_]u8{0x77} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = &path_s,
        .psks = &.{},
    };

    const kp_ref = "test-kp-ref-32-bytes!!!!????????";
    const egi = "encrypted-group-info-placeholder";
    const eph_seed = [_]u8{0xBB} ** 32;

    // Encrypt.
    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    // Build a Welcome with this entry.
    // We need to copy the kem_output and ciphertext from the
    // stack-returned egs into heap-allocated slices for the
    // Welcome to be decodable after encode/decode.
    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt.
    var dec_gs = try decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        kp_ref,
        &init_kp.sk,
        &init_kp.pk,
    );
    defer dec_gs.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        &joiner,
        dec_gs.joiner_secret,
    );
    try testing.expect(dec_gs.path_secret != null);
    try testing.expectEqualSlices(
        u8,
        &path_s,
        dec_gs.path_secret.?,
    );
}

test "decryptGroupSecrets fails with wrong key" {
    const alloc = testing.allocator;

    // Correct recipient.
    const init_seed = [_]u8{0xCC} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    // Wrong recipient.
    const wrong_seed = [_]u8{0xDD} ** 32;
    const wrong_kp = try Default.dhKeypairFromSeed(&wrong_seed);

    const joiner = [_]u8{0x55} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    const kp_ref = "ref-for-wrong-key-test!!!!!!!???";
    const egi = "egi-placeholder";
    const eph_seed = [_]u8{0xEE} ** 32;

    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt with wrong key should fail.
    const result = decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        kp_ref,
        &wrong_kp.sk,
        &wrong_kp.pk,
    );
    try testing.expectError(error.AeadError, result);
}

test "decryptGroupSecrets fails with wrong ref" {
    const alloc = testing.allocator;

    const init_seed = [_]u8{0x11} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    const joiner = [_]u8{0x66} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    const kp_ref = "correct-ref-32-bytes!!!!!!!!!???";
    const egi = "egi-data";
    const eph_seed = [_]u8{0x22} ** 32;

    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt with wrong ref should fail.
    const result = decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        "wrong-ref-32-bytes!!!!!!!!!!!???",
        &init_kp.sk,
        &init_kp.pk,
    );
    try testing.expectError(error.KeyPackageNotFound, result);
}
