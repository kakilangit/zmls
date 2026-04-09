//! MLS labeled cryptographic operations (ExpandWithLabel,
//! DeriveSecret, SignWithLabel, VerifyWithLabel) per RFC 9420
//! Section 5. Prepends the "MLS 1.0 " prefix to all labels.
// MLS labeled cryptographic operations per RFC 9420 Section 5.
//
// These functions prepend the label prefix "MLS 1.0 " to various
// cryptographic inputs as required by the protocol. They are generic
// over any CryptoProvider backend.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const errors = @import("../common/errors.zig");
const CryptoError = errors.CryptoError;

const label_prefix = "MLS 1.0 ";

// -- ExpandWithLabel / DeriveSecret (Section 5.1.2) -----------------------

/// ExpandWithLabel(Secret, Label, Context, Length)
///
/// Constructs a KDFLabel:
///   struct { u16 length; opaque label<V>; opaque context<V>; }
/// where label = "MLS 1.0 " || Label
///
/// Then calls KDF-Expand(Secret, KDFLabel, Length).
///
/// `P` is the CryptoProvider type. `out` receives the derived bytes.
pub fn expandWithLabel(
    comptime P: type,
    secret: *const [P.nh]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) void {
    assert(label.len > 0 and label.len <= 255);
    assert(out.len > 0);
    // Build KDFLabel into a stack buffer.
    // Max size: 2 (length) + 1 (varint) + 8 (prefix) + 255 (label)
    //         + 4 (varint) + 65535 (context) — but we cap at a
    //         practical size. Label is always short in MLS.
    var buf: [512]u8 = undefined;
    const info = buildKdfLabel(
        &buf,
        @intCast(out.len),
        label,
        context,
    );
    P.kdfExpand(secret, info, out);
}

/// DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Nh)
pub fn deriveSecret(
    comptime P: type,
    secret: *const [P.nh]u8,
    label: []const u8,
) [P.nh]u8 {
    var out: [P.nh]u8 = undefined;
    expandWithLabel(P, secret, label, "", &out);
    return out;
}

/// Build the KDFLabel struct into `buf`, return the filled slice.
///
///   struct {
///       uint16 length;
///       opaque label<V>;     // "MLS 1.0 " || Label
///       opaque context<V>;
///   } KDFLabel;
fn buildKdfLabel(
    buf: []u8,
    length: u16,
    label: []const u8,
    context: []const u8,
) []const u8 {
    assert(buf.len >= 2 + 4 + label_prefix.len + label.len + 4 + context.len);
    assert(length > 0);
    var pos: u32 = 0;

    // uint16 length.
    pos = codec.encodeUint16(buf, pos, length) catch unreachable;

    // opaque label<V> — "MLS 1.0 " || Label, varint-prefixed.
    const full_label_len: u32 = @intCast(
        label_prefix.len + label.len,
    );
    pos = varint.encode(buf, pos, full_label_len) catch {
        unreachable;
    };
    @memcpy(buf[pos..][0..label_prefix.len], label_prefix);
    pos += @intCast(label_prefix.len);
    @memcpy(buf[pos..][0..label.len], label);
    pos += @intCast(label.len);

    // opaque context<V>.
    pos = codec.encodeVarVector(
        buf,
        pos,
        context,
    ) catch unreachable;

    return buf[0..pos];
}

// -- SignWithLabel / VerifyWithLabel (Section 5.1.3) -----------------------

/// SignWithLabel(SignKey, Label, Content)
///
/// Signs the SignContent struct per RFC 9420 Section 5.1.2:
///   struct { opaque label<V>; opaque content<V>; } SignContent;
/// where label = "MLS 1.0 " || Label.
pub fn signWithLabel(
    comptime P: type,
    sk: *const [P.sign_sk_len]u8,
    label: []const u8,
    content: []const u8,
) CryptoError![P.sig_len]u8 {
    assert(label.len > 0 and label.len <= 255);
    assert(label_prefix.len + label.len + content.len + 16 <= 65536);
    var buf: [65536]u8 = undefined;
    defer secureZero(&buf);
    const pos = buildSignContent(&buf, label, content);
    return P.sign(sk, buf[0..pos]);
}

/// VerifyWithLabel(VerifyKey, Label, Content, SignatureValue)
pub fn verifyWithLabel(
    comptime P: type,
    pk: *const [P.sign_pk_len]u8,
    label: []const u8,
    content: []const u8,
    sig: *const [P.sig_len]u8,
) CryptoError!void {
    assert(label.len > 0 and label.len <= 255);
    assert(label_prefix.len + label.len + content.len + 16 <= 65536);
    var buf: [65536]u8 = undefined;
    defer secureZero(&buf);
    const pos = buildSignContent(&buf, label, content);
    return P.verify(pk, buf[0..pos], sig);
}

/// Build the SignContent struct:
///   varint(len("MLS 1.0 " || label)) || "MLS 1.0 " || label
///   || varint(len(content)) || content
fn buildSignContent(
    buf: []u8,
    label: []const u8,
    content: []const u8,
) u32 {
    assert(buf.len >= label_prefix.len + label.len + content.len + 16);
    var pos: u32 = 0;

    // opaque label<V> = "MLS 1.0 " || Label
    const full_label_len: u32 = @intCast(
        label_prefix.len + label.len,
    );
    pos = varint.encode(buf, pos, full_label_len) catch {
        unreachable;
    };
    @memcpy(buf[pos..][0..label_prefix.len], label_prefix);
    pos += @intCast(label_prefix.len);
    @memcpy(buf[pos..][0..label.len], label);
    pos += @intCast(label.len);

    // opaque content<V> = Content
    pos = codec.encodeVarVector(
        buf,
        pos,
        content,
    ) catch unreachable;

    return pos;
}

// -- EncryptWithLabel / DecryptWithLabel (Section 5.1.4) ------------------

const hpke_mod = @import("hpke.zig");

/// EncryptWithLabel(pk, label, context, plaintext)
///
/// HPKE SealBase with info = EncryptContext:
///   struct { opaque label<V>; opaque context<V>; } EncryptContext;
/// where label = "MLS 1.0 " || Label, and aad = "".
///
/// Returns (kem_output, ciphertext, tag).
pub fn encryptWithLabel(
    comptime P: type,
    pk: *const [P.npk]u8,
    label: []const u8,
    context: []const u8,
    plaintext: []const u8,
    eph_seed: *const [P.seed_len]u8,
    ct_out: []u8,
    tag_out: *[P.nt]u8,
) CryptoError![P.npk]u8 {
    assert(ct_out.len == plaintext.len);
    assert(label.len > 0 and label.len <= 255);
    const info = buildEncryptContext(label, context);
    const H = hpke_mod.Hpke(P);
    return H.sealBase(
        pk,
        info.slice(),
        "",
        plaintext,
        eph_seed,
        ct_out,
        tag_out,
    );
}

/// DecryptWithLabel(sk, label, context, kem_output, ciphertext, tag)
///
/// HPKE OpenBase with the same EncryptContext info.
pub fn decryptWithLabel(
    comptime P: type,
    sk: *const [P.nsk]u8,
    pk: *const [P.npk]u8,
    label: []const u8,
    context: []const u8,
    kem_output: *const [P.npk]u8,
    ciphertext: []const u8,
    tag: *const [P.nt]u8,
    pt_out: []u8,
) CryptoError!void {
    assert(pt_out.len == ciphertext.len);
    assert(label.len > 0 and label.len <= 255);
    const info = buildEncryptContext(label, context);
    const H = hpke_mod.Hpke(P);
    return H.openBase(
        kem_output,
        sk,
        pk,
        info.slice(),
        "",
        ciphertext,
        tag,
        pt_out,
    );
}

/// Build the EncryptContext info blob:
///   varint(len("MLS 1.0 " || label)) || "MLS 1.0 " || label
///   || varint(len(context)) || context
///
/// NOTE: This struct is ~65 KB. It is returned by value from
/// buildEncryptContext and relies on compiler RVO to avoid a
/// memcpy. If a future compiler does not perform RVO here,
/// consider passing as an out-pointer parameter.
const EncryptContextBuf = struct {
    buf: [65536 + 128]u8 = undefined,
    len: u32 = 0,

    fn slice(self: *const EncryptContextBuf) []const u8 {
        return self.buf[0..self.len];
    }
};

/// Build the HPKE EncryptContext info blob for
/// /// EncryptWithLabel / DecryptWithLabel.
fn buildEncryptContext(
    label: []const u8,
    context: []const u8,
) EncryptContextBuf {
    assert(label.len > 0 and label.len <= 255);
    var result = EncryptContextBuf{};
    var pos: u32 = 0;

    // opaque label<V> = "MLS 1.0 " || Label.
    const full_label_len: u32 = @intCast(
        label_prefix.len + label.len,
    );
    pos = varint.encode(
        &result.buf,
        pos,
        full_label_len,
    ) catch unreachable;
    @memcpy(
        result.buf[pos..][0..label_prefix.len],
        label_prefix,
    );
    pos += @intCast(label_prefix.len);
    @memcpy(result.buf[pos..][0..label.len], label);
    pos += @intCast(label.len);

    // opaque context<V>.
    pos = codec.encodeVarVector(
        &result.buf,
        pos,
        context,
    ) catch unreachable;

    result.len = pos;
    return result;
}

// -- RefHash (Section 5.2) ------------------------------------------------

/// RefHash(Label, Value) = Hash(RefHashInput)
///
///   struct {
///       opaque label<V>;
///       opaque value<V>;
///   } RefHashInput;
pub fn refHash(
    comptime P: type,
    label: []const u8,
    value: []const u8,
) [P.nh]u8 {
    assert(label.len > 0);
    assert(label.len + value.len + 16 <= 65536);
    // Build RefHashInput into a stack buffer.
    var buf: [65536]u8 = undefined;
    var pos: u32 = 0;

    pos = codec.encodeVarVector(
        &buf,
        pos,
        label,
    ) catch unreachable;
    pos = codec.encodeVarVector(
        &buf,
        pos,
        value,
    ) catch unreachable;

    return P.hash(buf[0..pos]);
}

// -- Secure Zeroing ------------------------------------------------------

/// Zero a byte slice in a way the compiler cannot optimize away.
///
/// Delegates to `std.crypto.secureZero` which uses `[]volatile u8`
/// to prevent dead-store elimination.
pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buf));
}

/// Zero secret data stored behind a const slice. Used in deinit
/// paths where the struct field is `[]const u8` but the struct
/// owns the allocation and must clear it before freeing.
pub fn secureZeroConst(buf: []const u8) void {
    std.crypto.secureZero(u8, @constCast(@volatileCast(buf)));
}

/// Constant-time equality comparison for cryptographic secrets.
///
/// Uses XOR-accumulator pattern (no short-circuit) via
/// std.crypto.timing_safe.eql. Use this instead of std.mem.eql
/// for MACs, tags, hashes, and signatures.
pub fn constantTimeEql(
    comptime N: u32,
    a: *const [N]u8,
    b: *const [N]u8,
) bool {
    return std.crypto.timing_safe.eql([N]u8, a.*, b.*);
}

/// Zero a fixed-size array. Convenience wrapper.
pub fn secureZeroArr(comptime N: usize, ptr: *[N]u8) void {
    secureZero(ptr);
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import("default.zig").DhKemX25519Sha256Aes128GcmEd25519;

test "expandWithLabel produces deterministic output" {
    const secret = [_]u8{0x42} ** Default.nh;
    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;

    expandWithLabel(Default, &secret, "test", "ctx", &out1);
    expandWithLabel(Default, &secret, "test", "ctx", &out2);

    try testing.expectEqualSlices(u8, &out1, &out2);
}

test "expandWithLabel different labels produce different output" {
    const secret = [_]u8{0x42} ** Default.nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    expandWithLabel(Default, &secret, "aaa", "", &out_a);
    expandWithLabel(Default, &secret, "bbb", "", &out_b);

    try testing.expect(
        !std.mem.eql(u8, &out_a, &out_b),
    );
}

test "deriveSecret returns nh bytes" {
    const secret = [_]u8{0x42} ** Default.nh;
    const derived = deriveSecret(Default, &secret, "test");
    try testing.expectEqual(@as(usize, 32), derived.len);

    // Should be non-zero.
    var all_zero = true;
    for (derived) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "signWithLabel and verifyWithLabel round-trip" {
    const seed = [_]u8{0x03} ** 32;
    const kp = try Default.signKeypairFromSeed(&seed);
    const content = "some content to sign";

    const sig = try signWithLabel(
        Default,
        &kp.sk,
        "LeafNode",
        content,
    );
    try verifyWithLabel(
        Default,
        &kp.pk,
        "LeafNode",
        content,
        &sig,
    );
}

test "verifyWithLabel rejects wrong label" {
    const seed = [_]u8{0x04} ** 32;
    const kp = try Default.signKeypairFromSeed(&seed);
    const content = "some content";

    const sig = try signWithLabel(
        Default,
        &kp.sk,
        "CorrectLabel",
        content,
    );
    const result = verifyWithLabel(
        Default,
        &kp.pk,
        "WrongLabel",
        content,
        &sig,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "refHash produces deterministic nh-byte digest" {
    const h1 = refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        "some key package data",
    );
    const h2 = refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        "some key package data",
    );
    try testing.expectEqualSlices(u8, &h1, &h2);

    // Different value produces different hash.
    const h3 = refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        "different data",
    );
    try testing.expect(!std.mem.eql(u8, &h1, &h3));
}

test "encryptWithLabel and decryptWithLabel round-trip" {
    // Generate recipient DH key pair.
    const r_seed = [_]u8{0x50} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0x60} ** 32;

    const plaintext = "UpdatePathNode secret";
    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const kem_output = try encryptWithLabel(
        Default,
        &r_kp.pk,
        "UpdatePathNode",
        "group context bytes",
        plaintext,
        &eph_seed,
        &ct,
        &tag,
    );

    var decrypted: [plaintext.len]u8 = undefined;
    try decryptWithLabel(
        Default,
        &r_kp.sk,
        &r_kp.pk,
        "UpdatePathNode",
        "group context bytes",
        &kem_output,
        &ct,
        &tag,
        &decrypted,
    );
    try testing.expectEqualSlices(
        u8,
        plaintext,
        &decrypted,
    );
}

test "decryptWithLabel rejects wrong label" {
    const r_seed = [_]u8{0x70} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0x80} ** 32;

    const plaintext = "secret";
    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const kem_output = try encryptWithLabel(
        Default,
        &r_kp.pk,
        "CorrectLabel",
        "",
        plaintext,
        &eph_seed,
        &ct,
        &tag,
    );

    // Decrypt with wrong label should fail.
    var out: [plaintext.len]u8 = undefined;
    const result = decryptWithLabel(
        Default,
        &r_kp.sk,
        &r_kp.pk,
        "WrongLabel",
        "",
        &kem_output,
        &ct,
        &tag,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "constantTimeEql returns true for equal inputs" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expect(constantTimeEql(4, &a, &b));
}

test "constantTimeEql returns false for differing inputs" {
    const a = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const b = [_]u8{ 0x01, 0x02, 0x03, 0x05 };
    try std.testing.expect(!constantTimeEql(4, &a, &b));
}
