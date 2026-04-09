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
    assertHasConst(T, "nt", u32); // AEAD tag length.
    assertHasConst(T, "npk", u32); // DH public key length.
    assertHasConst(T, "nsk", u32); // DH secret key length.
    assertHasConst(T, "sign_pk_len", u32); // Sig public key len.
    assertHasConst(T, "sign_sk_len", u32); // Sig secret key len.
    assertHasConst(T, "sig_len", u32); // Signature length.

    // -- Required HPKE algorithm IDs (RFC 9180) ---------------------------
    assertHasConst(T, "kem_id", u16);
    assertHasConst(T, "kdf_id", u16);
    assertHasConst(T, "aead_id", u16);

    // -- Required functions (with parameter/return validation) ------------

    // hash(data: []const u8) -> [nh]u8
    assertFnSig(T, "hash", 1, [T.nh]u8);

    // kdfExtract(salt, ikm) -> [nh]u8
    assertFnSig(T, "kdfExtract", 2, [T.nh]u8);

    // kdfExpand(prk, info, out) -> void
    assertFnSig(T, "kdfExpand", 3, void);

    // aeadSeal(key, nonce, aad, pt, ct, tag) -> void
    assertFnSig(T, "aeadSeal", 6, void);

    // aeadOpen(key, nonce, aad, ct, tag, out) -> !void
    assertFnErrSig(T, "aeadOpen", 6, void);

    // signKeypairFromSeed(seed) -> !KeyPair
    assertFnParams(T, "signKeypairFromSeed", 1);

    // sign(sk, msg) -> ![sig_len]u8
    assertFnErrSig(T, "sign", 2, [T.sig_len]u8);

    // verify(pk, msg, sig) -> !void
    assertFnErrSig(T, "verify", 3, void);

    // dhKeypairFromSeed(seed) -> !KeyPair
    assertFnParams(T, "dhKeypairFromSeed", 1);

    // dh(sk, pk) -> ![shared_len]u8
    assertFnParams(T, "dh", 2);
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

/// Assert that `T` has a function `name` with exactly `n_params`
/// parameters and a non-error return type matching `Ret`.
fn assertFnSig(
    comptime T: type,
    comptime name: []const u8,
    comptime n_params: u32,
    comptime Ret: type,
) void {
    assertFnParams(T, name, n_params);
    const info = fnInfo(T, name);
    const ret = info.return_type orelse @compileError(
        "CryptoProvider '" ++ name ++ "' has generic return type",
    );
    if (ret != Ret) {
        @compileError(
            "CryptoProvider '" ++ name ++ "' return type must be " ++ @typeName(Ret) ++
                ", found " ++ @typeName(ret),
        );
    }
}

/// Assert that `T` has a function `name` with exactly `n_params`
/// parameters and an error union return type whose payload is `Ret`.
fn assertFnErrSig(
    comptime T: type,
    comptime name: []const u8,
    comptime n_params: u32,
    comptime Ret: type,
) void {
    assertFnParams(T, name, n_params);
    const info = fnInfo(T, name);
    const ret = info.return_type orelse @compileError(
        "CryptoProvider '" ++ name ++ "' has generic return type",
    );
    const ret_info = @typeInfo(ret);
    if (ret_info != .error_union) {
        @compileError(
            "CryptoProvider '" ++ name ++ "' must return an error union",
        );
    }
    if (ret_info.error_union.payload != Ret) {
        @compileError(
            "CryptoProvider '" ++ name ++ "' error union payload must be " ++ @typeName(Ret),
        );
    }
}

/// Assert that `T` has a function `name` with exactly `n_params`
/// parameters.
fn assertFnParams(
    comptime T: type,
    comptime name: []const u8,
    comptime n_params: u32,
) void {
    if (!@hasDecl(T, name)) {
        @compileError(
            "CryptoProvider missing function '" ++ name ++ "'",
        );
    }
    const info = fnInfo(T, name);
    if (info.params.len != n_params) {
        @compileError(
            "CryptoProvider '" ++ name ++ "' must have " ++
                std.fmt.comptimePrint("{}", .{n_params}) ++
                " parameters",
        );
    }
}

/// Extract the function type info for `T.name`.
fn fnInfo(
    comptime T: type,
    comptime name: []const u8,
) std.builtin.Type.Fn {
    const FnType = @TypeOf(@field(T, name));
    const info = @typeInfo(FnType);
    if (info != .@"fn") {
        @compileError(
            "CryptoProvider '" ++ name ++ "' must be a function",
        );
    }
    return info.@"fn";
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

/// A minimal stub that satisfies the interface for compile-time checks.
const StubProvider = struct {
    pub const nh: u32 = 32;
    pub const nk: u32 = 16;
    pub const nn: u32 = 12;
    pub const nt: u32 = 16;
    pub const npk: u32 = 32;
    pub const nsk: u32 = 32;
    pub const sign_pk_len: u32 = 32;
    pub const sign_sk_len: u32 = 64;
    pub const sig_len: u32 = 64;
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
        tag: *[nt]u8,
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
        tag: *const [nt]u8,
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
    ) CryptoError!struct { sk: [sign_sk_len]u8, pk: [sign_pk_len]u8 } {
        _ = seed;
        return .{
            .sk = [_]u8{0} ** sign_sk_len,
            .pk = [_]u8{0} ** sign_pk_len,
        };
    }

    pub fn sign(
        sk: *const [sign_sk_len]u8,
        msg: []const u8,
    ) CryptoError![sig_len]u8 {
        _ = sk;
        _ = msg;
        return [_]u8{0} ** sig_len;
    }

    pub fn verify(
        pk: *const [sign_pk_len]u8,
        msg: []const u8,
        sig: *const [sig_len]u8,
    ) CryptoError!void {
        _ = pk;
        _ = msg;
        _ = sig;
    }

    pub fn dhKeypairFromSeed(
        seed: *const [32]u8,
    ) CryptoError!struct { sk: [nsk]u8, pk: [npk]u8 } {
        _ = seed;
        return .{
            .sk = [_]u8{0} ** nsk,
            .pk = [_]u8{0} ** npk,
        };
    }

    pub fn dh(
        sk: *const [nsk]u8,
        pk: *const [npk]u8,
    ) CryptoError![npk]u8 {
        _ = sk;
        _ = pk;
        return [_]u8{0} ** npk;
    }
};

test "StubProvider satisfies CryptoProvider interface" {
    comptime assertValid(StubProvider);
}
