//! Comptime CryptoProvider interface definition. All cipher suite
//! backends must satisfy this shape via Zig duck-typing.
// CryptoProvider interface for MLS cipher suites.
//
// Per RFC 9420 Section 5.1: each cipher suite specifies a KEM, KDF, AEAD,
// hash, and signature algorithm. This module defines the comptime interface
// that any cipher suite backend must satisfy.
//
// The interface uses Zig's duck-typing: any struct with the required
// constants and functions can serve as a CryptoProvider. The rest of the
// library is generic over this type.

const std = @import("std");
const errors = @import("../common/errors.zig");
const CryptoError = errors.CryptoError;

/// Validate that a type satisfies the CryptoProvider interface at
/// compile time. Call `assertValid(T)` in a comptime block to get
/// clear error messages if a backend is missing required members.
pub fn assertValid(comptime T: type) void {
    // -- Required constants (byte sizes) ----------------------------------
    assertHasConst(T, "nh", u32); // Hash output length.
    assertHasConst(T, "nk", u32); // AEAD key length.
    assertHasConst(T, "nn", u32); // AEAD nonce length.

    // -- Required HPKE algorithm IDs (RFC 9180) ---------------------------
    assertHasConst(T, "kem_id", u16);
    assertHasConst(T, "kdf_id", u16);
    assertHasConst(T, "aead_id", u16);

    // -- Required functions -----------------------------------------------

    // hash(data) -> [nh]u8
    if (!@hasDecl(T, "hash")) {
        @compileError("CryptoProvider missing 'hash'");
    }

    // kdfExtract(salt, ikm) -> [nh]u8
    if (!@hasDecl(T, "kdfExtract")) {
        @compileError("CryptoProvider missing 'kdfExtract'");
    }

    // kdfExpand(prk, info, out) -> void
    if (!@hasDecl(T, "kdfExpand")) {
        @compileError("CryptoProvider missing 'kdfExpand'");
    }

    // aeadSeal(key, nonce, aad, plaintext, out, tag_out) -> void
    if (!@hasDecl(T, "aeadSeal")) {
        @compileError("CryptoProvider missing 'aeadSeal'");
    }

    // aeadOpen(key, nonce, aad, ciphertext, tag, out) -> !void
    if (!@hasDecl(T, "aeadOpen")) {
        @compileError("CryptoProvider missing 'aeadOpen'");
    }

    // signKeypairFromSeed(seed) -> !SignKeyPair
    if (!@hasDecl(T, "signKeypairFromSeed")) {
        @compileError(
            "CryptoProvider missing 'signKeypairFromSeed'",
        );
    }

    // sign(secret_key, msg) -> !Signature
    if (!@hasDecl(T, "sign")) {
        @compileError("CryptoProvider missing 'sign'");
    }

    // verify(public_key, msg, signature) -> !void
    if (!@hasDecl(T, "verify")) {
        @compileError("CryptoProvider missing 'verify'");
    }

    // dhKeypairFromSeed(seed) -> !DhKeyPair
    if (!@hasDecl(T, "dhKeypairFromSeed")) {
        @compileError(
            "CryptoProvider missing 'dhKeypairFromSeed'",
        );
    }

    // dh(secret_key, public_key) -> ![shared_len]u8
    if (!@hasDecl(T, "dh")) {
        @compileError("CryptoProvider missing 'dh'");
    }
}

fn assertHasConst(
    comptime T: type,
    comptime name: []const u8,
    comptime Expected: type,
) void {
    if (!@hasDecl(T, name)) {
        @compileError(
            "CryptoProvider missing constant '" ++ name ++ "'",
        );
    }
    const actual = @TypeOf(@field(T, name));
    if (actual != Expected) {
        @compileError(
            "CryptoProvider constant '" ++ name ++ "' must be " ++ @typeName(Expected),
        );
    }
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

/// A minimal stub that satisfies the interface for compile-time checks.
const StubProvider = struct {
    pub const nh: u32 = 32;
    pub const nk: u32 = 16;
    pub const nn: u32 = 12;
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;

    pub fn hash(data: []const u8) [nh]u8 {
        _ = data;
        return [_]u8{0} ** nh;
    }

    pub fn kdfExtract(
        salt: []const u8,
        ikm: []const u8,
    ) [nh]u8 {
        _ = salt;
        _ = ikm;
        return [_]u8{0} ** nh;
    }

    pub fn kdfExpand(
        prk: *const [nh]u8,
        info: []const u8,
        out: []u8,
    ) void {
        _ = prk;
        _ = info;
        @memset(out, 0);
    }

    pub fn aeadSeal(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[16]u8,
    ) void {
        _ = key;
        _ = nonce;
        _ = aad;
        @memcpy(ciphertext, plaintext);
        @memset(tag, 0);
    }

    pub fn aeadOpen(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [16]u8,
        out: []u8,
    ) CryptoError!void {
        _ = key;
        _ = nonce;
        _ = aad;
        _ = tag;
        @memcpy(out, ciphertext);
    }

    pub fn signKeypairFromSeed(
        seed: *const [32]u8,
    ) CryptoError!struct { sk: [64]u8, pk: [32]u8 } {
        _ = seed;
        return .{
            .sk = [_]u8{0} ** 64,
            .pk = [_]u8{0} ** 32,
        };
    }

    pub fn sign(
        sk: *const [64]u8,
        msg: []const u8,
    ) CryptoError![64]u8 {
        _ = sk;
        _ = msg;
        return [_]u8{0} ** 64;
    }

    pub fn verify(
        pk: *const [32]u8,
        msg: []const u8,
        sig: *const [64]u8,
    ) CryptoError!void {
        _ = pk;
        _ = msg;
        _ = sig;
    }

    pub fn dhKeypairFromSeed(
        seed: *const [32]u8,
    ) CryptoError!struct { sk: [32]u8, pk: [32]u8 } {
        _ = seed;
        return .{
            .sk = [_]u8{0} ** 32,
            .pk = [_]u8{0} ** 32,
        };
    }

    pub fn dh(
        sk: *const [32]u8,
        pk: *const [32]u8,
    ) CryptoError![32]u8 {
        _ = sk;
        _ = pk;
        return [_]u8{0} ** 32;
    }
};

test "StubProvider satisfies CryptoProvider interface" {
    comptime assertValid(StubProvider);
}
