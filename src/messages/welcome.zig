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
