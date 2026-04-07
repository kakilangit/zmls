//! Credential types (basic and x509) for asserting group member
//! identity per RFC 9420 Section 5.3, with encode/decode support.
// Credential types for MLS per RFC 9420 Section 5.3.
//
// A Credential asserts the identity of a group member. Two types are
// defined by the base spec:
//   - basic: an opaque identity string (application-defined).
//   - x509: a chain of DER-encoded X.509 certificates.
//
// Additional credential types may be defined by extensions. Unknown
// types are rejected at decode time.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");

const CredentialType = types.CredentialType;
const DecodeError = errors.DecodeError;
const EncodeError = codec.EncodeError;

/// Maximum identity / cert_data size in bytes.
const max_identity_len: u32 = 65535;
/// Maximum number of certificates in an X.509 chain.
const max_cert_chain_len: u32 = 32;

// -- Certificate -------------------------------------------------------------

/// A single DER-encoded X.509 certificate.
///
///   struct { opaque cert_data<V>; } Certificate;
pub const Certificate = struct {
    /// Raw DER bytes. Owned by the caller (or the allocator used in decode).
    data: []const u8,

    /// Serialize this Credential into buf at the given position.
    pub fn encode(
        self: *const Certificate,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        return codec.encodeVarVector(buf, pos, self.data);
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Certificate,
        pos: u32,
    } {
        const r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            pos,
            types.max_credential_length,
        );
        return .{
            .value = .{ .data = r.value },
            .pos = r.pos,
        };
    }

    /// Free all heap-allocated payload data owned by this
    /// Credential.
    pub fn deinit(self: *Certificate, allocator: std.mem.Allocator) void {
        if (self.data.len > 0) {
            allocator.free(self.data);
        }
        self.data = &.{};
        self.* = undefined;
    }
};

// -- Credential --------------------------------------------------------------

/// MLS Credential tagged union.
///
///   struct {
///       CredentialType credential_type;
///       select (credential_type) {
///           case basic: opaque identity<V>;
///           case x509:  Certificate certificates<V>;
///       };
///   } Credential;
///
/// We use a non-exhaustive enum tag so the union carries the
/// CredentialType discriminator directly. Unsupported types
/// are rejected at decode time (not representable in the union).
pub const Credential = struct {
    tag: CredentialType,
    payload: Payload,

    pub const Payload = union {
        /// Basic credential: an opaque identity blob.
        basic: []const u8,
        /// X.509 credential: a chain of certificates.
        x509: []Certificate,
        /// Unknown/GREASE credential type: opaque bytes.
        unknown: []const u8,
    };

    /// Create a basic credential.
    pub fn initBasic(identity: []const u8) Credential {
        return .{
            .tag = .basic,
            .payload = .{ .basic = identity },
        };
    }

    /// Create an X.509 credential.
    pub fn initX509(certs: []Certificate) Credential {
        return .{
            .tag = .x509,
            .payload = .{ .x509 = certs },
        };
    }

    // -- Encode --------------------------------------------------------------

    pub fn encode(
        self: *const Credential,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        // Write credential_type as u16.
        var p = try codec.encodeUint16(
            buf,
            pos,
            @intFromEnum(self.tag),
        );

        switch (self.tag) {
            .basic => {
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.payload.basic,
                );
            },
            .x509 => {
                p = try encodeCertChain(
                    buf,
                    p,
                    self.payload.x509,
                );
            },
            else => {
                p = try codec.encodeVarVector(
                    buf,
                    p,
                    self.payload.unknown,
                );
            },
        }
        return p;
    }

    // -- Decode --------------------------------------------------------------

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Credential,
        pos: u32,
    } {
        const type_r = try codec.decodeUint16(data, pos);
        const cred_type: CredentialType = @enumFromInt(
            type_r.value,
        );

        switch (cred_type) {
            .basic => {
                const id_r = try codec.decodeVarVectorLimited(
                    allocator,
                    data,
                    type_r.pos,
                    types.max_credential_length,
                );
                return .{
                    .value = .{
                        .tag = .basic,
                        .payload = .{ .basic = id_r.value },
                    },
                    .pos = id_r.pos,
                };
            },
            .x509 => {
                const chain_r = try decodeCertChain(
                    allocator,
                    data,
                    type_r.pos,
                );
                return .{
                    .value = .{
                        .tag = .x509,
                        .payload = .{ .x509 = chain_r.value },
                    },
                    .pos = chain_r.pos,
                };
            },
            else => {
                const raw_r = try codec.decodeVarVectorLimited(
                    allocator,
                    data,
                    type_r.pos,
                    types.max_credential_length,
                );
                return .{
                    .value = .{
                        .tag = cred_type,
                        .payload = .{ .unknown = raw_r.value },
                    },
                    .pos = raw_r.pos,
                };
            },
        }
    }

    pub fn deinit(
        self: *Credential,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.tag) {
            .basic => {
                const identity = self.payload.basic;
                if (identity.len > 0) {
                    allocator.free(identity);
                }
            },
            .x509 => {
                const certs = self.payload.x509;
                for (certs) |*c| {
                    c.deinit(allocator);
                }
                if (certs.len > 0) {
                    allocator.free(certs);
                }
            },
            else => {
                const raw = self.payload.unknown;
                if (raw.len > 0) allocator.free(raw);
            },
        }
        self.* = undefined;
    }

    /// Deep-copy this credential. Caller owns the returned value.
    pub fn clone(
        self: *const Credential,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!Credential {
        switch (self.tag) {
            .basic => {
                const id = self.payload.basic;
                if (id.len > 0) {
                    const copy = allocator.alloc(
                        u8,
                        id.len,
                    ) catch return error.OutOfMemory;
                    @memcpy(copy, id);
                    return .{
                        .tag = .basic,
                        .payload = .{ .basic = copy },
                    };
                }
                return .{
                    .tag = .basic,
                    .payload = .{ .basic = &.{} },
                };
            },
            .x509 => {
                const src = self.payload.x509;
                if (src.len == 0) {
                    return .{
                        .tag = .x509,
                        .payload = .{ .x509 = &.{} },
                    };
                }
                const dst = allocator.alloc(
                    Certificate,
                    src.len,
                ) catch return error.OutOfMemory;
                var i: usize = 0;
                errdefer {
                    var j: usize = 0;
                    while (j < i) : (j += 1) {
                        dst[j].deinit(allocator);
                    }
                    allocator.free(dst);
                }
                while (i < src.len) : (i += 1) {
                    if (src[i].data.len > 0) {
                        const d = allocator.alloc(
                            u8,
                            src[i].data.len,
                        ) catch return error.OutOfMemory;
                        @memcpy(d, src[i].data);
                        dst[i] = .{ .data = d };
                    } else {
                        dst[i] = .{ .data = &.{} };
                    }
                }
                return .{
                    .tag = .x509,
                    .payload = .{ .x509 = dst },
                };
            },
            else => {
                const raw = self.payload.unknown;
                if (raw.len > 0) {
                    const copy = allocator.alloc(
                        u8,
                        raw.len,
                    ) catch return error.OutOfMemory;
                    @memcpy(copy, raw);
                    return .{
                        .tag = self.tag,
                        .payload = .{ .unknown = copy },
                    };
                }
                return .{
                    .tag = self.tag,
                    .payload = .{ .unknown = &.{} },
                };
            },
        }
    }
};

// -- Cert chain codec helpers ------------------------------------------------

/// Encode a chain of certificates as a varint-prefixed list.
/// Each certificate is varint-prefixed internally as well.
fn encodeCertChain(
    buf: []u8,
    pos: u32,
    certs: []const Certificate,
) EncodeError!u32 {
    // First encode certs into a temp area to get the total
    // byte length, then write the length prefix + data.
    // We encode into buf starting after a gap for the varint.
    // Max varint is 4 bytes, so leave space.
    const gap: u32 = 4;
    const start = pos + gap;
    var p = start;

    for (certs) |*cert| {
        p = try cert.encode(buf, p);
    }

    const inner_len: u32 = p - start;

    // Now write the varint length at pos, then shift data
    // if varint was smaller than 4 bytes.
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(&len_buf, 0, inner_len);

    // Move encoded certs to be adjacent to the length prefix.
    const dest_start = pos + len_end;
    if (dest_start != start) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[start..][0..inner_len],
        );
    }

    // Write the length bytes.
    @memcpy(buf[pos..][0..len_end], len_buf[0..len_end]);

    return dest_start + inner_len;
}

/// Decode a chain of certificates from a varint-prefixed blob.
fn decodeCertChain(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []Certificate,
    pos: u32,
} {
    // Read the outer vector length.
    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;

    // Parse individual certificates. We collect into a bounded
    // temporary array, then copy to an allocated slice.
    var temp: [max_cert_chain_len]Certificate = undefined;
    var count: u32 = 0;

    errdefer for (temp[0..count]) |*cert| cert.deinit(allocator);
    while (p < end) {
        if (count >= max_cert_chain_len) {
            return error.VectorTooLarge;
        }
        const cert_r = try Certificate.decode(
            allocator,
            data,
            p,
        );
        temp[count] = cert_r.value;
        count += 1;
        p = cert_r.pos;
    }

    // Must have consumed exactly the declared bytes.
    if (p != end) return error.Truncated;

    // Allocate final slice.
    const certs = allocator.alloc(
        Certificate,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(certs, temp[0..count]);

    return .{ .value = certs, .pos = p };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;

test "basic credential round-trip" {
    const alloc = testing.allocator;

    const cred = Credential.initBasic("alice@example.com");

    // Encode.
    var buf: [256]u8 = undefined;
    const end = try cred.encode(&buf, 0);

    // Decode.
    var decoded_r = try Credential.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        CredentialType.basic,
        decoded_r.value.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "alice@example.com",
        decoded_r.value.payload.basic,
    );
    try testing.expectEqual(end, decoded_r.pos);
}

test "x509 credential round-trip" {
    const alloc = testing.allocator;

    const cert_data_1 = "fake-cert-der-1";
    const cert_data_2 = "fake-cert-der-2";

    var certs = [_]Certificate{
        .{ .data = cert_data_1 },
        .{ .data = cert_data_2 },
    };

    const cred = Credential.initX509(&certs);

    // Encode.
    var buf: [512]u8 = undefined;
    const end = try cred.encode(&buf, 0);

    // Decode.
    var decoded_r = try Credential.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        CredentialType.x509,
        decoded_r.value.tag,
    );
    const dec_certs = decoded_r.value.payload.x509;
    try testing.expectEqual(@as(usize, 2), dec_certs.len);
    try testing.expectEqualSlices(
        u8,
        cert_data_1,
        dec_certs[0].data,
    );
    try testing.expectEqualSlices(
        u8,
        cert_data_2,
        dec_certs[1].data,
    );
}

test "decode accepts unknown credential type" {
    const alloc = testing.allocator;

    // Write a credential with type = 0xFFFF and empty body.
    var buf: [8]u8 = undefined;
    var p = try codec.encodeUint16(&buf, 0, 0xFFFF);
    p = try codec.encodeVarVector(&buf, p, "");

    const dec_r = try Credential.decode(alloc, buf[0..p], 0);
    var decoded = dec_r.value;
    defer decoded.deinit(alloc);

    try testing.expectEqual(
        @as(u16, 0xFFFF),
        @intFromEnum(decoded.tag),
    );
    try testing.expectEqual(@as(usize, 0), decoded.payload.unknown.len);
}

test "basic credential with empty identity" {
    const alloc = testing.allocator;

    const cred = Credential.initBasic("");

    var buf: [64]u8 = undefined;
    const end = try cred.encode(&buf, 0);

    var decoded_r = try Credential.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        "",
        decoded_r.value.payload.basic,
    );
}

test "x509 credential with single certificate" {
    const alloc = testing.allocator;

    var certs = [_]Certificate{
        .{ .data = "single-cert" },
    };

    const cred = Credential.initX509(&certs);

    var buf: [256]u8 = undefined;
    const end = try cred.encode(&buf, 0);

    var decoded_r = try Credential.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer decoded_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        decoded_r.value.payload.x509.len,
    );
    try testing.expectEqualSlices(
        u8,
        "single-cert",
        decoded_r.value.payload.x509[0].data,
    );
}

test "Credential unknown type round-trips correctly" {
    const alloc = testing.allocator;

    // Encode a credential with unknown type 0x0F0F.
    const cred = Credential{
        .tag = @enumFromInt(0x0F0F),
        .payload = .{ .unknown = "opaque-data" },
    };

    var buf: [256]u8 = undefined;
    const end = try cred.encode(&buf, 0);

    const dec_r = try Credential.decode(
        alloc,
        buf[0..end],
        0,
    );
    var decoded = dec_r.value;
    defer decoded.deinit(alloc);

    try testing.expectEqual(dec_r.pos, end);
    try testing.expectEqual(
        @as(u16, 0x0F0F),
        @intFromEnum(decoded.tag),
    );
    try testing.expectEqualSlices(
        u8,
        "opaque-data",
        decoded.payload.unknown,
    );
}
