//! Cipher suite metadata and dispatch. Maps wire-level CipherSuite
//! enum values to concrete algorithm parameters.
// Cipher suite metadata and dispatch for RFC 9420 Section 5.1.
//
// Maps the wire-level CipherSuite enum (from common/types.zig) to
// concrete algorithm parameters and the CryptoProvider backend type.

const std = @import("std");
const types = @import("../common/types.zig");
const CryptoError = @import("../common/errors.zig").CryptoError;
const Default = @import(
    "default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const ChaCha = @import(
    "chacha20.zig",
).DhKemX25519Sha256ChaCha20Poly1305Ed25519;
const P256 = @import(
    "p256.zig",
).DhKemP256Sha256Aes128GcmP256;
const P256ChaCha = @import(
    "p256_chacha20.zig",
).DhKemP256Sha256ChaCha20Poly1305P256;
const P384 = @import(
    "p384.zig",
).DhKemP384Sha384Aes256GcmP384;

pub const CipherSuite = types.CipherSuite;

/// Algorithm metadata for a cipher suite. All sizes in bytes.
pub const SuiteParams = struct {
    /// Hash output length (Nh).
    nh: u32,
    /// AEAD key length (Nk).
    nk: u32,
    /// AEAD nonce length (Nn).
    nn: u32,
    /// AEAD tag length.
    nt: u32,
    /// DH public key length.
    npk: u32,
    /// DH secret key length.
    nsk: u32,
    /// Signature public key length.
    sign_pk_len: u32,
    /// Signature secret key length.
    sign_sk_len: u32,
    /// Signature output length.
    sig_len: u32,
};

/// Look up algorithm parameters for a given cipher suite.
/// Returns null for unsupported suites.
pub fn params(suite: CipherSuite) ?SuiteParams {
    return switch (suite) {
        // 0x0001: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519 => .{
            .nh = Default.nh,
            .nk = Default.nk,
            .nn = Default.nn,
            .nt = Default.nt,
            .npk = Default.npk,
            .nsk = Default.nsk,
            .sign_pk_len = Default.sign_pk_len,
            .sign_sk_len = Default.sign_sk_len,
            .sig_len = Default.sig_len,
        },
        // 0x0003: MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        // Same key/hash sizes as 0x0001, different AEAD.
        .mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519 => .{
            .nh = ChaCha.nh,
            .nk = ChaCha.nk,
            .nn = ChaCha.nn,
            .nt = ChaCha.nt,
            .npk = ChaCha.npk,
            .nsk = ChaCha.nsk,
            .sign_pk_len = ChaCha.sign_pk_len,
            .sign_sk_len = ChaCha.sign_sk_len,
            .sig_len = ChaCha.sig_len,
        },
        // 0x0002: MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        .mls_128_dhkemp256_aes128gcm_sha256_p256 => .{
            .nh = P256.nh,
            .nk = P256.nk,
            .nn = P256.nn,
            .nt = P256.nt,
            .npk = P256.npk,
            .nsk = P256.nsk,
            .sign_pk_len = P256.sign_pk_len,
            .sign_sk_len = P256.sign_sk_len,
            .sig_len = P256.sig_len,
        },
        // 0x0004: MLS_128_DHKEMP256_CHACHA20POLY1305_SHA256_P256
        .mls_128_dhkemp256_chacha20poly1305_sha256_p256 => .{
            .nh = P256ChaCha.nh,
            .nk = P256ChaCha.nk,
            .nn = P256ChaCha.nn,
            .nt = P256ChaCha.nt,
            .npk = P256ChaCha.npk,
            .nsk = P256ChaCha.nsk,
            .sign_pk_len = P256ChaCha.sign_pk_len,
            .sign_sk_len = P256ChaCha.sign_sk_len,
            .sig_len = P256ChaCha.sig_len,
        },
        // 0x0006: MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        .mls_256_dhkemp384_aes256gcm_sha384_p384 => .{
            .nh = P384.nh,
            .nk = P384.nk,
            .nn = P384.nn,
            .nt = P384.nt,
            .npk = P384.npk,
            .nsk = P384.nsk,
            .sign_pk_len = P384.sign_pk_len,
            .sign_sk_len = P384.sign_sk_len,
            .sig_len = P384.sig_len,
        },
        else => null,
    };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "suite 0x0001 params" {
    const suite = CipherSuite
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519;
    const p = params(suite).?;
    try testing.expectEqual(@as(u32, 32), p.nh);
    try testing.expectEqual(@as(u32, 16), p.nk);
    try testing.expectEqual(@as(u32, 12), p.nn);
    try testing.expectEqual(@as(u32, 16), p.nt);
    try testing.expectEqual(@as(u32, 32), p.npk);
    try testing.expectEqual(@as(u32, 32), p.nsk);
}

test "suite 0x0003 params" {
    const suite = CipherSuite
        .mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519;
    const p = params(suite).?;
    try testing.expectEqual(@as(u32, 32), p.nh);
    try testing.expectEqual(@as(u32, 32), p.nk); // ChaCha20
    try testing.expectEqual(@as(u32, 12), p.nn);
}

test "suite 0x0002 params" {
    const suite = CipherSuite
        .mls_128_dhkemp256_aes128gcm_sha256_p256;
    const p = params(suite).?;
    try testing.expectEqual(@as(u32, 32), p.nh);
    try testing.expectEqual(@as(u32, 16), p.nk);
    try testing.expectEqual(@as(u32, 65), p.npk);
    try testing.expectEqual(@as(u32, 64), p.sig_len);
}

test "suite 0x0004 params" {
    const suite = CipherSuite
        .mls_128_dhkemp256_chacha20poly1305_sha256_p256;
    const p = params(suite).?;
    try testing.expectEqual(@as(u32, 32), p.nh);
    try testing.expectEqual(@as(u32, 32), p.nk); // ChaCha20
    try testing.expectEqual(@as(u32, 65), p.npk);
    try testing.expectEqual(@as(u32, 64), p.sig_len);
}

test "suite 0x0006 params" {
    const suite = CipherSuite
        .mls_256_dhkemp384_aes256gcm_sha384_p384;
    const p = params(suite).?;
    try testing.expectEqual(@as(u32, 48), p.nh);
    try testing.expectEqual(@as(u32, 32), p.nk);
    try testing.expectEqual(@as(u32, 97), p.npk);
    try testing.expectEqual(@as(u32, 48), p.nsk);
    try testing.expectEqual(@as(u32, 96), p.sig_len);
}

test "reserved suite returns null" {
    const p = params(CipherSuite.reserved);
    try testing.expectEqual(@as(?SuiteParams, null), p);
}

test "unknown suite returns null" {
    const p = params(@enumFromInt(0xFFFF));
    try testing.expectEqual(@as(?SuiteParams, null), p);
}
