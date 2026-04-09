//! KeyPackage per RFC 9420 Section 10. Bundles protocol version,
//! cipher suite, init key, leaf node, extensions, and signature
//! with KeyPackageRef computation.
// KeyPackage per RFC 9420 Section 10.
//
//   struct {
//       ProtocolVersion version;
//       CipherSuite cipher_suite;
//       HPKEPublicKey init_key;
//       LeafNode leaf_node;
//       Extension extensions<V>;
//       opaque signature<V>;
//   } KeyPackage;
//
// KeyPackageTBS is the same struct without the signature field.
// A KeyPackageRef is RefHash("MLS 1.0 KeyPackage Reference",
//                            KeyPackage).

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const prim = @import("../crypto/primitives.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const LeafNodeSource = types.LeafNodeSource;
const Extension = node_mod.Extension;
const LeafNode = node_mod.LeafNode;

/// Maximum encoded KeyPackage size used for stack buffers.
const max_kp_encode: u32 = 65536;

// -- KeyPackage --------------------------------------------------------------

/// A KeyPackage advertises a client's willingness to join a group.
pub const KeyPackage = struct {
    version: ProtocolVersion,
    cipher_suite: CipherSuite,
    init_key: []const u8,
    leaf_node: LeafNode,
    extensions: []const Extension,
    signature: []const u8,

    // -- Encode (full, signed KeyPackage) ---------------------------------

    pub fn encode(
        self: *const KeyPackage,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try self.encodeTbs(buf, pos);
        // signature<V>
        p = try codec.encodeVarVector(buf, p, self.signature);
        return p;
    }

    /// Encode the to-be-signed portion (everything except signature).
    pub fn encodeTbs(
        self: *const KeyPackage,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        // ProtocolVersion (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.version),
        );
        // CipherSuite (u16)
        p = try codec.encodeUint16(
            buf,
            p,
            @intFromEnum(self.cipher_suite),
        );
        // init_key<V>
        p = try codec.encodeVarVector(buf, p, self.init_key);
        // leaf_node
        p = try self.leaf_node.encode(buf, p);
        // extensions<V> — varint-prefixed list of Extension
        p = try encodeExtensionList(buf, p, self.extensions);
        return p;
    }

    // -- Decode -----------------------------------------------------------

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: KeyPackage,
        pos: u32,
    } {
        var p = pos;

        // ProtocolVersion (u16)
        const ver_r = try codec.decodeUint16(data, p);
        p = ver_r.pos;

        // CipherSuite (u16)
        const cs_r = try codec.decodeUint16(data, p);
        p = cs_r.pos;

        // init_key<V>
        const ik_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_public_key_length,
        );
        p = ik_r.pos;

        // leaf_node
        const ln_r = try LeafNode.decode(allocator, data, p);
        p = ln_r.pos;

        // extensions<V>
        const ext_r = try decodeExtensionList(
            allocator,
            data,
            p,
        );
        p = ext_r.pos;

        // signature<V>
        const sig_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_signature_length,
        );
        p = sig_r.pos;

        return .{
            .value = .{
                .version = @enumFromInt(ver_r.value),
                .cipher_suite = @enumFromInt(cs_r.value),
                .init_key = ik_r.value,
                .leaf_node = ln_r.value,
                .extensions = @as(
                    []const Extension,
                    ext_r.value,
                ),
                .signature = sig_r.value,
            },
            .pos = p,
        };
    }

    // -- Sign / Verify ----------------------------------------------------

    /// Sign this KeyPackage. Fills in `self.signature`.
    /// The sign key must correspond to the leaf_node.signature_key.
    pub fn signKeyPackage(
        self: *KeyPackage,
        comptime P: type,
        sk: *const [P.sign_sk_len]u8,
        sig_buf: []u8,
    ) CryptoError!void {
        // Encode KeyPackageTBS.
        var tbs_buf: [max_kp_encode]u8 = undefined;
        const tbs_end = self.encodeTbs(
            &tbs_buf,
            0,
        ) catch return error.KdfOutputTooLong;

        const sig = try prim.signWithLabel(
            P,
            sk,
            "KeyPackageTBS",
            tbs_buf[0..tbs_end],
        );

        if (sig_buf.len < P.sig_len) {
            return error.KdfOutputTooLong;
        }
        @memcpy(sig_buf[0..P.sig_len], &sig);
        self.signature = sig_buf[0..P.sig_len];
    }

    /// Verify the signature on this KeyPackage.
    pub fn verifySignature(
        self: *const KeyPackage,
        comptime P: type,
    ) CryptoError!void {
        // Extract public key from leaf_node.signature_key.
        if (self.leaf_node.signature_key.len != P.sign_pk_len) {
            return error.InvalidPublicKey;
        }
        const pk: *const [P.sign_pk_len]u8 = @ptrCast(
            self.leaf_node.signature_key[0..P.sign_pk_len],
        );

        // Encode KeyPackageTBS.
        var tbs_buf: [max_kp_encode]u8 = undefined;
        const tbs_end = self.encodeTbs(
            &tbs_buf,
            0,
        ) catch return error.KdfOutputTooLong;

        if (self.signature.len == 0) {
            return error.SignatureVerifyFailed;
        }

        try prim.verifyWithLabel(
            P,
            pk,
            "KeyPackageTBS",
            tbs_buf[0..tbs_end],
            self.signature,
        );
    }

    // -- Validate ---------------------------------------------------------

    /// Validate a KeyPackage per RFC 9420 Section 10.1.
    ///
    /// Checks:
    ///  1. version == mls10
    ///  2. cipher_suite is the expected suite
    ///  3. leaf_node.source == key_package
    ///  4. init_key != leaf_node.encryption_key
    ///  5. Signature is valid
    ///
    /// The caller should also perform application-level credential
    /// validation via the CredentialValidator port.
    pub fn validate(
        self: *const KeyPackage,
        comptime P: type,
        expected_suite: CipherSuite,
        current_time: ?u64,
    ) (ValidationError || CryptoError)!void {
        // 1. Protocol version.
        if (self.version != .mls10) {
            return error.VersionMismatch;
        }
        // 2. Cipher suite.
        if (self.cipher_suite != expected_suite) {
            return error.CipherSuiteMismatch;
        }
        // 3. Leaf node source must be key_package.
        if (self.leaf_node.source != .key_package) {
            return error.InvalidKeyPackage;
        }
        // 4. init_key must differ from encryption_key.
        if (std.mem.eql(
            u8,
            self.init_key,
            self.leaf_node.encryption_key,
        )) {
            return error.InvalidKeyPackage;
        }
        // 5. Verify signature.
        try self.verifySignature(P);

        // 6. Validate LeafNode (RFC 9420 Section 7.3).
        try self.leaf_node.validate(expected_suite, current_time);
    }

    // -- KeyPackageRef ----------------------------------------------------

    /// Compute the KeyPackageRef for this KeyPackage.
    ///
    ///   KeyPackageRef = RefHash("MLS 1.0 KeyPackage Reference",
    ///                           KeyPackage)
    pub fn makeRef(
        self: *const KeyPackage,
        comptime P: type,
    ) CryptoError![P.nh]u8 {
        var buf: [max_kp_encode]u8 = undefined;
        const end = self.encode(
            &buf,
            0,
        ) catch return error.KdfOutputTooLong;
        return prim.refHash(
            P,
            "MLS 1.0 KeyPackage Reference",
            buf[0..end],
        );
    }

    // -- Cleanup ----------------------------------------------------------

    pub fn deinit(
        self: *KeyPackage,
        allocator: std.mem.Allocator,
    ) void {
        if (self.init_key.len > 0) {
            allocator.free(self.init_key);
        }
        self.leaf_node.deinit(allocator);
        for (self.extensions) |*ext| {
            @constCast(ext).deinit(allocator);
        }
        if (self.extensions.len > 0) {
            allocator.free(self.extensions);
        }
        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
        self.* = undefined;
    }

    // -- LastResort -------------------------------------------------------

    /// Check whether this KeyPackage carries the last_resort
    /// extension (type 10, empty payload).
    ///
    /// A last-resort KeyPackage is reusable: it should not be
    /// consumed after use and should only be selected when no
    /// other KeyPackages are available.
    pub fn isLastResort(self: *const KeyPackage) bool {
        for (self.extensions) |ext| {
            if (ext.extension_type == .last_resort) return true;
        }
        return false;
    }
};

// -- Extension list codec helpers (reused from node.zig pattern) ----------

/// Maximum extensions per KeyPackage.
const max_extensions: u32 = 64;

/// Create a last_resort extension (type 10, empty payload).
///
/// A KeyPackage carrying this extension is reusable: the
/// application should not delete it after use, and should prefer
/// non-last-resort packages when available.
pub const last_resort_extension = Extension{
    .extension_type = .last_resort,
    .data = &.{},
};

fn encodeExtensionList(
    buf: []u8,
    pos: u32,
    exts: []const Extension,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        Extension,
        buf,
        pos,
        exts,
    );
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
    value: []Extension,
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
    var temp: [max_extensions]Extension = undefined;
    var count: u32 = 0;
    while (p < end) {
        if (count >= max_extensions) {
            return error.VectorTooLarge;
        }
        const ext_r = try Extension.decode(
            allocator,
            data,
            p,
        );
        temp[count] = ext_r.value;
        count += 1;
        p = ext_r.pos;
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
    const exts = allocator.alloc(
        Extension,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(exts, temp[0..count]);
    return .{ .value = exts, .pos = p };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import("../crypto/default.zig")
    .DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import("../credential/credential.zig")
    .Credential;
const CredentialType = types.CredentialType;
const Capabilities = node_mod.Capabilities;
const Lifetime = node_mod.Lifetime;

const TestKeyPackage = struct {
    kp: KeyPackage,
    sign_sk: [Default.sign_sk_len]u8,
    sig_buf: [Default.sig_len]u8,
    // Backing storage for keys so slices remain valid.
    init_pk: [Default.npk]u8,
    enc_pk: [Default.npk]u8,
    sign_pk: [Default.sign_pk_len]u8,
};

/// Build a minimal valid KeyPackage for testing.
fn makeTestKeyPackage() CryptoError!TestKeyPackage {
    // Generate signing key pair.
    const sign_seed = [_]u8{0x01} ** 32;
    const sign_kp = try Default.signKeypairFromSeed(&sign_seed);

    // Generate DH key pairs for init_key and encryption_key.
    const init_seed = [_]u8{0x02} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);
    const enc_seed = [_]u8{0x03} ** 32;
    const enc_kp = try Default.dhKeypairFromSeed(&enc_seed);

    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]CredentialType{.basic};

    var result = TestKeyPackage{
        .sign_sk = sign_kp.sk,
        .sig_buf = undefined,
        .init_pk = init_kp.pk,
        .enc_pk = enc_kp.pk,
        .sign_pk = sign_kp.pk,
        .kp = .{
            .version = .mls10,
            .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            .init_key = undefined,
            .leaf_node = .{
                .encryption_key = undefined,
                .signature_key = undefined,
                .credential = Credential.initBasic("alice"),
                .capabilities = .{
                    .versions = &versions,
                    .cipher_suites = &suites,
                    .extensions = &ext_types,
                    .proposals = &prop_types,
                    .credentials = &cred_types,
                },
                .source = .key_package,
                .lifetime = .{
                    .not_before = 1000,
                    .not_after = 2000,
                },
                .parent_hash = null,
                .extensions = &.{},
                .signature = &[_]u8{0xAA} ** 4,
            },
            .extensions = &.{},
            .signature = &.{},
        },
    };

    // Point slices at the owned backing storage.
    result.kp.init_key = &result.init_pk;
    result.kp.leaf_node.encryption_key = &result.enc_pk;
    result.kp.leaf_node.signature_key = &result.sign_pk;

    return result;
}

/// Fix internal slice pointers after makeTestKeyPackage returns.
/// Must be called on the result in the caller's stack frame.
fn fixTestKeyPackage(t: *TestKeyPackage) CryptoError!void {
    t.kp.init_key = &t.init_pk;
    t.kp.leaf_node.encryption_key = &t.enc_pk;
    t.kp.leaf_node.signature_key = &t.sign_pk;

    // Sign the KeyPackage (signature stored in t.sig_buf).
    try t.kp.signKeyPackage(
        Default,
        &t.sign_sk,
        &t.sig_buf,
    );
}

test "KeyPackage encode/decode round-trip" {
    const alloc = testing.allocator;
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    const kp = &t.kp;

    // Encode.
    var buf: [4096]u8 = undefined;
    const end = try kp.encode(&buf, 0);
    try testing.expect(end > 4);

    // Decode.
    var dec_r = try KeyPackage.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        ProtocolVersion.mls10,
        dec_r.value.version,
    );
    try testing.expectEqual(
        kp.cipher_suite,
        dec_r.value.cipher_suite,
    );
    try testing.expectEqualSlices(
        u8,
        kp.init_key,
        dec_r.value.init_key,
    );
    try testing.expectEqualSlices(
        u8,
        kp.signature,
        dec_r.value.signature,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "KeyPackage sign and verify round-trip" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    const kp = &t.kp;

    // Verify succeeds.
    try kp.verifySignature(Default);
}

test "KeyPackage validate succeeds for valid package" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    const kp = &t.kp;
    try kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
}

test "KeyPackage validate rejects wrong protocol version" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    t.kp.version = .reserved;

    // Re-sign with modified version.
    try t.kp.signKeyPackage(Default, &t.sign_sk, &t.sig_buf);

    const result = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
    try testing.expectError(error.VersionMismatch, result);
}

test "KeyPackage validate rejects init_key == encryption_key" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);

    // Make init_key equal to encryption_key.
    t.kp.init_key = t.kp.leaf_node.encryption_key;

    // Re-sign.
    try t.kp.signKeyPackage(Default, &t.sign_sk, &t.sig_buf);

    const result = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
    try testing.expectError(error.InvalidKeyPackage, result);
}

test "KeyPackage validate rejects wrong cipher suite" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    const result = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519,
        null,
    );
    try testing.expectError(error.CipherSuiteMismatch, result);
}

test "KeyPackage makeRef produces deterministic hash" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    const ref1 = try t.kp.makeRef(Default);
    const ref2 = try t.kp.makeRef(Default);
    try testing.expectEqualSlices(u8, &ref1, &ref2);
    try testing.expectEqual(@as(usize, 32), ref1.len);

    // Verify it's non-zero.
    var all_zero = true;
    for (ref1) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "KeyPackage validate rejects non-key_package source" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    t.kp.leaf_node.source = .update;
    t.kp.leaf_node.lifetime = null;

    // Re-sign.
    try t.kp.signKeyPackage(Default, &t.sign_sk, &t.sig_buf);

    const result = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
    try testing.expectError(error.InvalidKeyPackage, result);
}

test "KeyPackage validate rejects expired lifetime" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);

    // Set lifetime to [1000, 2000].
    t.kp.leaf_node.lifetime = .{
        .not_before = 1000,
        .not_after = 2000,
    };

    // Re-sign.
    try t.kp.signKeyPackage(Default, &t.sign_sk, &t.sig_buf);

    // Time before not_before => rejected.
    const r1 = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        999,
    );
    try testing.expectError(error.InvalidLeafNode, r1);

    // Time after not_after => rejected.
    const r2 = t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        2001,
    );
    try testing.expectError(error.InvalidLeafNode, r2);

    // Time within range => accepted.
    try t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        1500,
    );

    // No time source => accepted (lifetime not checked).
    try t.kp.validate(
        Default,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        null,
    );
}

test "KeyPackage isLastResort false by default" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);
    try testing.expect(!t.kp.isLastResort());
}

test "KeyPackage isLastResort true with extension" {
    var t = try makeTestKeyPackage();
    try fixTestKeyPackage(&t);

    const lr_ext = [_]Extension{last_resort_extension};
    t.kp.extensions = &lr_ext;

    try testing.expect(t.kp.isLastResort());
}

test "last_resort_extension encodes empty data" {
    try testing.expectEqual(
        types.ExtensionType.last_resort,
        last_resort_extension.extension_type,
    );
    try testing.expectEqual(
        @as(usize, 0),
        last_resort_extension.data.len,
    );
}
