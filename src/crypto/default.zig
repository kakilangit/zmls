//! Default CryptoProvider for MLS cipher suite 0x0001
//! (X25519 + AES-128-GCM + SHA-256 + Ed25519).
// Default CryptoProvider backend for MLS cipher suite 0x0001:
// MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
//
// Hash:      SHA-256         (std.crypto.hash.sha2.Sha256)
// KDF:       HKDF-SHA256     (std.crypto.kdf.hkdf.HkdfSha256)
// AEAD:      AES-128-GCM     (std.crypto.aead.aes_gcm.Aes128Gcm)
// DH/KEM:    X25519          (std.crypto.dh.X25519)
// Signature: Ed25519         (std.crypto.sign.Ed25519)
//
// Per RFC 9420 Section 5.1, Table 2.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const provider = @import("provider.zig");
const primitives = @import("primitives.zig");
const CryptoError = @import("../common/errors.zig").CryptoError;

const Sha256 = crypto.hash.sha2.Sha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;

/// Cipher suite 0x0001 backend.
pub const DhKemX25519Sha256Aes128GcmEd25519 = struct {
    // -- Constants per RFC 9420 Table 2 -----------------------------------

    /// Hash output length (SHA-256 = 32 bytes).
    pub const nh: u32 = Sha256.digest_length;

    /// AEAD key length (AES-128-GCM = 16 bytes).
    pub const nk: u32 = Aes128Gcm.key_length;

    /// AEAD nonce length (AES-128-GCM = 12 bytes).
    pub const nn: u32 = Aes128Gcm.nonce_length;

    /// AEAD authentication tag length (16 bytes).
    pub const nt: u32 = Aes128Gcm.tag_length;

    /// DH public key length (X25519 = 32 bytes).
    pub const npk: u32 = X25519.public_length;

    /// DH secret key length (X25519 = 32 bytes).
    pub const nsk: u32 = X25519.secret_length;

    /// Signature public key length (Ed25519 = 32 bytes).
    pub const sign_pk_len: u32 = Ed25519.PublicKey.encoded_length;

    /// Signature secret key length (Ed25519 = 64 bytes).
    pub const sign_sk_len: u32 = Ed25519.SecretKey.encoded_length;

    /// Signature length (Ed25519 = 64 bytes).
    pub const sig_len: u32 = Ed25519.Signature.encoded_length;

    /// Keypair seed length (Ed25519/X25519 = 32 bytes).
    pub const seed_len: u32 = 32;

    // -- HPKE algorithm IDs per RFC 9180 ---------------------------------

    /// DHKEM(X25519, HKDF-SHA256) = 0x0020.
    pub const kem_id: u16 = 0x0020;
    /// HKDF-SHA256 = 0x0001.
    pub const kdf_id: u16 = 0x0001;
    /// AES-128-GCM = 0x0001.
    pub const aead_id: u16 = 0x0001;

    // -- Hash -------------------------------------------------------------

    pub fn hash(data: []const u8) [nh]u8 {
        var out: [nh]u8 = undefined;
        Sha256.hash(data, &out, .{});
        return out;
    }

    // -- KDF (HKDF-SHA256) ------------------------------------------------

    pub fn kdfExtract(
        salt: []const u8,
        ikm: []const u8,
    ) [nh]u8 {
        return Hkdf.extract(salt, ikm);
    }

    pub fn kdfExpand(
        prk: *const [nh]u8,
        info: []const u8,
        out: []u8,
    ) void {
        assert(out.len > 0 and out.len <= 255 * nh);
        Hkdf.expand(out, info, prk.*);
    }

    // -- AEAD (AES-128-GCM) -----------------------------------------------

    pub fn aeadSeal(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[nt]u8,
    ) void {
        assert(ciphertext.len == plaintext.len);
        Aes128Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            aad,
            nonce.*,
            key.*,
        );
    }

    pub fn aeadOpen(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [nt]u8,
        out: []u8,
    ) CryptoError!void {
        assert(out.len == ciphertext.len);
        Aes128Gcm.decrypt(
            out,
            ciphertext,
            tag.*,
            aad,
            nonce.*,
            key.*,
        ) catch return error.AeadError;
    }

    // -- Signatures (Ed25519) ---------------------------------------------

    pub fn signKeypairFromSeed(
        seed: *const [seed_len]u8,
    ) CryptoError!struct { sk: [sign_sk_len]u8, pk: [sign_pk_len]u8 } {
        const kp = Ed25519.KeyPair.generateDeterministic(
            seed.*,
        ) catch return error.InvalidPrivateKey;
        return .{
            .sk = kp.secret_key.toBytes(),
            .pk = kp.public_key.toBytes(),
        };
    }

    pub fn sign(
        sk: *const [sign_sk_len]u8,
        msg: []const u8,
    ) CryptoError![sig_len]u8 {
        var secret_key = Ed25519.SecretKey.fromBytes(
            sk.*,
        ) catch return error.InvalidPrivateKey;
        defer primitives.secureZero(
            std.mem.asBytes(&secret_key),
        );
        var kp = Ed25519.KeyPair.fromSecretKey(
            secret_key,
        ) catch return error.InvalidPrivateKey;
        defer primitives.secureZero(
            std.mem.asBytes(&kp),
        );
        const sig = kp.sign(msg, null) catch {
            return error.SignatureVerifyFailed;
        };
        return sig.toBytes();
    }

    pub fn verify(
        pk: *const [sign_pk_len]u8,
        msg: []const u8,
        sig: *const [sig_len]u8,
    ) CryptoError!void {
        const public_key = Ed25519.PublicKey.fromBytes(
            pk.*,
        ) catch return error.InvalidPublicKey;
        const signature = Ed25519.Signature.fromBytes(sig.*);
        var verifier = signature.verifier(
            public_key,
        ) catch return error.SignatureVerifyFailed;
        verifier.update(msg);
        verifier.verify() catch {
            return error.SignatureVerifyFailed;
        };
    }

    // -- DH (X25519) ------------------------------------------------------

    /// Known X25519 low-order points (little-endian).
    ///
    /// These produce an all-zero shared secret regardless of the
    /// private key. Rejecting them prevents small-subgroup attacks.
    /// See: https://cr.yp.to/ecdh.html#validate
    const low_order_points = [8][npk]u8{
        // 0 (identity / neutral element)
        .{0} ** npk,
        // 1
        .{ 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        // p - 1 = 2^255 - 20
        .{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        // p = 2^255 - 19 (reduced to 0 mod p)
        .{ 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        // p + 1 (reduced to 1 mod p)
        .{ 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        // Order-8 point: sqrt(-1) in Montgomery form
        .{ 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        // 2p - 1 (reduced to p-1 mod p)
        .{ 0xd9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
        // 2p (reduced to 0 mod p)
        .{ 0xda, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
    };

    /// Validate an X25519 public key, rejecting low-order points.
    ///
    /// Returns error.InvalidPublicKey if the point has small order
    /// (which would produce a predictable all-zero shared secret).
    pub fn validateDhPublicKey(
        pk: *const [npk]u8,
    ) CryptoError!void {
        for (low_order_points) |lop| {
            if (std.mem.eql(u8, pk, &lop)) {
                return error.InvalidPublicKey;
            }
        }
    }

    pub fn dhKeypairFromSeed(
        seed: *const [seed_len]u8,
    ) CryptoError!struct { sk: [nsk]u8, pk: [npk]u8 } {
        const kp = X25519.KeyPair.generateDeterministic(
            seed.*,
        ) catch return error.InvalidPrivateKey;
        return .{
            .sk = kp.secret_key,
            .pk = kp.public_key,
        };
    }

    pub fn dh(
        sk: *const [nsk]u8,
        pk: *const [npk]u8,
    ) CryptoError![X25519.shared_length]u8 {
        try validateDhPublicKey(pk);
        return X25519.scalarmult(
            sk.*,
            pk.*,
        ) catch return error.IdentitySharedSecret;
    }

    // Compile-time validation.
    comptime {
        provider.assertValid(DhKemX25519Sha256Aes128GcmEd25519);
    }
};

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "hash produces 32-byte SHA-256 digest" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const digest = P.hash("hello");
    // Known SHA-256 of "hello".
    const expected = [_]u8{
        0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
        0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
        0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
        0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24,
    };
    try testing.expectEqualSlices(u8, &expected, &digest);
}

test "kdf extract and expand round-trip" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const salt = "salt value";
    const ikm = "input keying material";
    const prk = P.kdfExtract(salt, ikm);
    try testing.expectEqual(@as(usize, 32), prk.len);

    var okm: [42]u8 = undefined;
    P.kdfExpand(&prk, "info", &okm);
    // Just verify it produces non-zero output.
    var all_zero = true;
    for (okm) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "aead seal and open round-trip" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const key = [_]u8{0x42} ** P.nk;
    const nonce = [_]u8{0x24} ** P.nn;
    const aad = "additional data";
    const plaintext = "secret message";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    P.aeadSeal(
        &key,
        &nonce,
        aad,
        plaintext,
        &ciphertext,
        &tag,
    );

    var decrypted: [plaintext.len]u8 = undefined;
    try P.aeadOpen(
        &key,
        &nonce,
        aad,
        &ciphertext,
        &tag,
        &decrypted,
    );
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "aead open rejects tampered ciphertext" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const key = [_]u8{0x42} ** P.nk;
    const nonce = [_]u8{0x24} ** P.nn;
    const plaintext = "secret";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    P.aeadSeal(&key, &nonce, "", plaintext, &ct, &tag);

    // Tamper with ciphertext.
    ct[0] ^= 0xFF;
    var out: [plaintext.len]u8 = undefined;
    const result = P.aeadOpen(
        &key,
        &nonce,
        "",
        &ct,
        &tag,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "ed25519 sign and verify round-trip" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const seed = [_]u8{0x01} ** 32;
    const kp = try P.signKeypairFromSeed(&seed);
    const msg = "message to sign";
    const sig = try P.sign(&kp.sk, msg);
    try P.verify(&kp.pk, msg, &sig);
}

test "ed25519 verify rejects wrong message" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const seed = [_]u8{0x02} ** 32;
    const kp = try P.signKeypairFromSeed(&seed);
    const sig = try P.sign(&kp.sk, "correct message");
    const result = P.verify(&kp.pk, "wrong message", &sig);
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "x25519 dh key exchange" {
    const P = DhKemX25519Sha256Aes128GcmEd25519;
    const seed_a = [_]u8{0x0A} ** 32;
    const seed_b = [_]u8{0x0B} ** 32;

    const kp_a = try P.dhKeypairFromSeed(&seed_a);
    const kp_b = try P.dhKeypairFromSeed(&seed_b);

    // DH(a, B) == DH(b, A).
    const shared_ab = try P.dh(&kp_a.sk, &kp_b.pk);
    const shared_ba = try P.dh(&kp_b.sk, &kp_a.pk);
    try testing.expectEqualSlices(u8, &shared_ab, &shared_ba);
}
