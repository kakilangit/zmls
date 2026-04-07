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
            .nh = 32, // SHA-256
            .nk = 32, // ChaCha20-Poly1305
            .nn = 12, // ChaCha20-Poly1305
            .nt = 16, // Poly1305
            .npk = 32, // X25519
            .nsk = 32, // X25519
            .sign_pk_len = 32, // Ed25519
            .sign_sk_len = 64, // Ed25519
            .sig_len = 64, // Ed25519
        },
        // 0x0002: MLS_128_DHKEMP256_AES128GCM_SHA256_P256
        .mls_128_dhkemp256_aes128gcm_sha256_p256 => .{
            .nh = 32, // SHA-256
            .nk = 16, // AES-128-GCM
            .nn = 12, // AES-128-GCM
            .nt = 16, // AES-128-GCM
            .npk = 65, // P-256 uncompressed
            .nsk = 32, // P-256 scalar
            .sign_pk_len = 65, // P-256 uncompressed
            .sign_sk_len = 32, // P-256 scalar
            .sig_len = 64, // ECDSA P-256
        },
        // 0x0004: MLS_128_DHKEMP256_CHACHA20POLY1305_SHA256_P256
        .mls_128_dhkemp256_chacha20poly1305_sha256_p256 => .{
            .nh = 32, // SHA-256
            .nk = 32, // ChaCha20-Poly1305
            .nn = 12, // ChaCha20-Poly1305
            .nt = 16, // Poly1305
            .npk = 65, // P-256 uncompressed
            .nsk = 32, // P-256 scalar
            .sign_pk_len = 65, // P-256 uncompressed
            .sign_sk_len = 32, // P-256 scalar
            .sig_len = 64, // ECDSA P-256
        },
        // 0x0006: MLS_256_DHKEMP384_AES256GCM_SHA384_P384
        .mls_256_dhkemp384_aes256gcm_sha384_p384 => .{
            .nh = 48, // SHA-384
            .nk = 32, // AES-256-GCM
            .nn = 12, // AES-256-GCM
            .nt = 16, // AES-256-GCM
            .npk = 97, // P-384 uncompressed
            .nsk = 48, // P-384 scalar
            .sign_pk_len = 97, // P-384 uncompressed
            .sign_sk_len = 48, // P-384 scalar
            .sig_len = 96, // ECDSA P-384
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
