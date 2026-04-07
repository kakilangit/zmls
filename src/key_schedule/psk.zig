//! PSK chaining per RFC 9420 Section 8.4. Iteratively folds
//! pre-shared keys into a running psk_secret via Extract and
//! ExpandWithLabel.
// PSK chaining per RFC 9420 Section 8.4.
//
// Pre-shared keys are injected into the key schedule via iterative
// chaining. Each PSK is folded into a running secret:
//
//   psk_secret[0] = 0  (all-zero vector of Nh bytes)
//   For i = 0..n-1:
//     psk_extracted[i] = KDF.Extract(0, psk[i])
//     psk_input[i] = ExpandWithLabel(psk_extracted[i],
//                      "derived psk", PSKLabel[i], Nh)
//     psk_secret[i+1] = KDF.Extract(psk_input[i],
//                         psk_secret[i])
//
// PSKLabel is:
//   struct {
//     PreSharedKeyID id;
//     uint16 index;
//     uint16 count;
//   }
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const primitives = @import("../crypto/primitives.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");

const DecodeError = errors.DecodeError;
const ValidationError = errors.ValidationError;

/// Maximum PSK count (fits in u16 per RFC 9420 PSKLabel).
const max_psk_count: u32 = 65535;

/// PSK type discriminator per RFC 9420 Section 8.4.
pub const PskType = enum(u8) {
    reserved = 0,
    external = 1,
    resumption = 2,
    _,
};

/// Resumption PSK usage per RFC 9420 Section 8.4.
pub const ResumptionPskUsage = enum(u8) {
    reserved = 0,
    application = 1,
    reinit = 2,
    branch = 3,
    _,
};

/// Pre-shared key identifier per RFC 9420 Section 8.4.
///
/// struct {
///   PSKType psktype;
///   select (PreSharedKeyID.psktype) {
///     case external: opaque psk_id<V>;
///     case resumption: {
///       ResumptionPSKUsage usage;
///       opaque group_id<V>;
///       uint64 epoch;
///     };
///   };
///   opaque psk_nonce<V>;
/// } PreSharedKeyID;
pub const PreSharedKeyId = struct {
    psk_type: PskType,

    // External PSK fields.
    external_psk_id: []const u8,

    // Resumption PSK fields.
    resumption_usage: ResumptionPskUsage,
    resumption_group_id: []const u8,
    resumption_epoch: types.Epoch,

    // Common field.
    psk_nonce: []const u8,

    /// Encode this PreSharedKeyID into `buf` starting at `pos`.
    /// Returns the new position after encoding.
    pub fn encode(
        self: *const PreSharedKeyId,
        buf: []u8,
        pos: u32,
    ) !u32 {
        var p = pos;

        // PSKType (u8).
        p = try codec.encodeUint8(buf, p, @intFromEnum(self.psk_type));

        switch (self.psk_type) {
            .external => {
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.external_psk_id,
                );
            },
            .resumption => {
                p = try codec.encodeUint8(
                    buf,
                    p,
                    @intFromEnum(self.resumption_usage),
                );
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.resumption_group_id,
                );
                p = try codec.encodeUint64(
                    buf,
                    p,
                    self.resumption_epoch,
                );
            },
            else => unreachable,
        }

        // psk_nonce<V>.
        p = try codec.encodeVarVector(buf, p, self.psk_nonce);

        return p;
    }

    /// Decode a PreSharedKeyID from `data` starting at `pos`.
    /// Uses zero-copy slices into the source buffer.
    pub fn decode(
        data: []const u8,
        pos: u32,
    ) DecodeError!struct { value: PreSharedKeyId, pos: u32 } {
        var p = pos;

        // PSKType (u8).
        const pt_r = try codec.decodeUint8(data, p);
        const psk_type: PskType = @enumFromInt(pt_r.value);
        p = pt_r.pos;

        var result = PreSharedKeyId{
            .psk_type = psk_type,
            .external_psk_id = "",
            .resumption_usage = .reserved,
            .resumption_group_id = "",
            .resumption_epoch = 0,
            .psk_nonce = "",
        };

        switch (psk_type) {
            .external => {
                const id_r = try codec.decodeVarVectorSlice(
                    data,
                    p,
                );
                result.external_psk_id = id_r.value;
                p = id_r.pos;
            },
            .resumption => {
                const usage_r = try codec.decodeUint8(data, p);
                result.resumption_usage = @enumFromInt(
                    usage_r.value,
                );
                p = usage_r.pos;
                const gid_r = try codec.decodeVarVectorSlice(
                    data,
                    p,
                );
                result.resumption_group_id = gid_r.value;
                p = gid_r.pos;
                const ep_r = try codec.decodeUint64(data, p);
                result.resumption_epoch = ep_r.value;
                p = ep_r.pos;
            },
            else => return error.InvalidEnumValue,
        }

        // psk_nonce<V>.
        const nonce_r = try codec.decodeVarVectorSlice(
            data,
            p,
        );
        result.psk_nonce = nonce_r.value;
        p = nonce_r.pos;

        return .{ .value = result, .pos = p };
    }
};

/// A single PSK entry for chaining: the identifier and the raw
/// secret bytes.
pub const PskEntry = struct {
    id: PreSharedKeyId,
    secret: []const u8,
};

/// Derive the psk_secret by chaining a list of PSKs.
///
/// If the list is empty, returns an all-zero vector (the initial
/// psk_secret[0]).
///
/// The `count` parameter is the total number of PSKs. Each PSK's
/// label includes its index and the count.
pub fn derivePskSecret(
    comptime P: type,
    psks: []const PskEntry,
) ValidationError![P.nh]u8 {
    const zero = [_]u8{0} ** P.nh;

    if (psks.len == 0) return zero;
    if (psks.len > max_psk_count)
        return error.InvalidProposalList;

    var psk_secret: [P.nh]u8 = zero;
    const count: u16 = @intCast(psks.len);

    for (psks, 0..) |psk, idx| {
        // RFC 9420 S8.4: psk_nonce length must equal Nh.
        if (psk.id.psk_nonce.len != P.nh)
            return error.InvalidKeyPackage;

        // psk_extracted = KDF.Extract(0, psk[i])
        var psk_extracted = P.kdfExtract(&zero, psk.secret);
        defer primitives.secureZero(&psk_extracted);

        // Build PSKLabel:
        //   struct {
        //     PreSharedKeyID id;
        //     uint16 index;
        //     uint16 count;
        //   }
        // 1024B for PSKLabel. Overflow caught below.
        var label_buf: [1024]u8 = undefined;
        var pos: u32 = 0;

        pos = psk.id.encode(&label_buf, pos) catch
            return error.InvalidKeyPackage;
        pos = codec.encodeUint16(
            &label_buf,
            pos,
            @intCast(idx),
        ) catch return error.InvalidKeyPackage;
        pos = codec.encodeUint16(
            &label_buf,
            pos,
            count,
        ) catch return error.InvalidKeyPackage;

        const label_bytes = label_buf[0..pos];

        // psk_input = ExpandWithLabel(psk_extracted,
        //               "derived psk", PSKLabel, Nh)
        var psk_input: [P.nh]u8 = undefined;
        defer primitives.secureZero(&psk_input);
        primitives.expandWithLabel(
            P,
            &psk_extracted,
            "derived psk",
            label_bytes,
            &psk_input,
        );

        // psk_secret[i+1] = KDF.Extract(psk_input, psk_secret[i])
        const new_secret = P.kdfExtract(&psk_input, &psk_secret);
        primitives.secureZero(&psk_secret);
        psk_secret = new_secret;
    }

    return psk_secret;
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

fn makeExternalPsk(
    psk_id: []const u8,
    nonce: []const u8,
    secret: []const u8,
) PskEntry {
    return .{
        .id = .{
            .psk_type = .external,
            .external_psk_id = psk_id,
            .resumption_usage = .reserved,
            .resumption_group_id = "",
            .resumption_epoch = 0,
            .psk_nonce = nonce,
        },
        .secret = secret,
    };
}

test "zero PSKs produces all-zero secret" {
    const empty: []const PskEntry = &.{};
    const result = try derivePskSecret(Default, empty);
    const expected = [_]u8{0} ** Default.nh;
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "single external PSK produces non-zero secret" {
    const secret = [_]u8{0xAA} ** 32;
    const nonce = [_]u8{0x01} ** Default.nh;
    const psks = [_]PskEntry{
        makeExternalPsk("my-psk-id", &nonce, &secret),
    };

    const result = try derivePskSecret(Default, &psks);

    // Should be non-zero.
    var all_zero = true;
    for (result) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "PSK chaining is deterministic" {
    const secret = [_]u8{0xBB} ** 32;
    const nonce = [_]u8{0x02} ** Default.nh;
    const psks = [_]PskEntry{
        makeExternalPsk("psk-1", &nonce, &secret),
    };

    const r1 = try derivePskSecret(Default, &psks);
    const r2 = try derivePskSecret(Default, &psks);
    try testing.expectEqualSlices(u8, &r1, &r2);
}

test "multiple PSKs produce different result than single" {
    const s1 = [_]u8{0x11} ** 32;
    const s2 = [_]u8{0x22} ** 32;
    const nonce = [_]u8{0x00} ** Default.nh;

    const single = [_]PskEntry{
        makeExternalPsk("psk-a", &nonce, &s1),
    };
    const multi = [_]PskEntry{
        makeExternalPsk("psk-a", &nonce, &s1),
        makeExternalPsk("psk-b", &nonce, &s2),
    };

    const result_single = try derivePskSecret(Default, &single);
    const result_multi = try derivePskSecret(Default, &multi);

    try testing.expect(
        !std.mem.eql(u8, &result_single, &result_multi),
    );
}

test "PSK order matters" {
    const s1 = [_]u8{0x11} ** 32;
    const s2 = [_]u8{0x22} ** 32;
    const nonce = [_]u8{0x00} ** Default.nh;

    const order_ab = [_]PskEntry{
        makeExternalPsk("psk-a", &nonce, &s1),
        makeExternalPsk("psk-b", &nonce, &s2),
    };
    const order_ba = [_]PskEntry{
        makeExternalPsk("psk-b", &nonce, &s2),
        makeExternalPsk("psk-a", &nonce, &s1),
    };

    const r_ab = try derivePskSecret(Default, &order_ab);
    const r_ba = try derivePskSecret(Default, &order_ba);

    try testing.expect(!std.mem.eql(u8, &r_ab, &r_ba));
}

test "resumption PSK encoding works" {
    const secret = [_]u8{0xCC} ** 32;
    const nonce = [_]u8{0x03} ** Default.nh;
    const psks = [_]PskEntry{
        .{
            .id = .{
                .psk_type = .resumption,
                .external_psk_id = "",
                .resumption_usage = .application,
                .resumption_group_id = "group-id-1",
                .resumption_epoch = 42,
                .psk_nonce = &nonce,
            },
            .secret = &secret,
        },
    };

    const result = try derivePskSecret(Default, &psks);

    // Should be non-zero and deterministic.
    var all_zero = true;
    for (result) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);

    // Verify determinism.
    const r2 = try derivePskSecret(Default, &psks);
    try testing.expectEqualSlices(u8, &result, &r2);
}

test "PSK nonce length must equal Nh" {
    const secret = [_]u8{0xAA} ** 32;
    const short_nonce = [_]u8{0x01} ** 16;
    const psks = [_]PskEntry{
        makeExternalPsk("psk-id", &short_nonce, &secret),
    };
    const result = derivePskSecret(Default, &psks);
    try testing.expectError(error.InvalidKeyPackage, result);
}
