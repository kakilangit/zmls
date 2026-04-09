//! HPKE base-mode single-shot SealBase/OpenBase per RFC 9180,
//! generic over a CryptoProvider backend.
// HPKE base mode for MLS (RFC 9180 + RFC 9420 Section 5).
//
// Implements single-shot SealBase / OpenBase for
// DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM.
//
// Only base mode (mode_base = 0x00) is needed for MLS.
// Generic over a CryptoProvider backend.

const std = @import("std");
const assert = std.debug.assert;
const CryptoError = @import("../common/errors.zig").CryptoError;
const secureZero = @import("primitives.zig").secureZero;

// -- Constants ---------------------------------------------------------------

/// HPKE mode_base per RFC 9180 Table 1.
const mode_base: u8 = 0x00;

/// Build the KEM suite_id: "KEM" || I2OSP(kem_id, 2).
fn kemSuiteId(comptime kem_id: u16) [5]u8 {
    return .{
        'K',                   'E',                     'M',
        @intCast(kem_id >> 8), @intCast(kem_id & 0xFF),
    };
}

/// Build the HPKE suite_id:
///   "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2)
///             || I2OSP(aead_id, 2)
fn hpkeSuiteId(
    comptime kem_id: u16,
    comptime kdf_id: u16,
    comptime aead_id: u16,
) [10]u8 {
    return .{
        'H',                    'P',                      'K',                   'E',
        @intCast(kem_id >> 8),  @intCast(kem_id & 0xFF),  @intCast(kdf_id >> 8), @intCast(kdf_id & 0xFF),
        @intCast(aead_id >> 8), @intCast(aead_id & 0xFF),
    };
}

// -- Generic HPKE over CryptoProvider ----------------------------------------

/// Maximum labeled buffer for HPKE extract/expand.
///
/// The `info` blob in EncryptWithLabel("Welcome", ...) includes
/// the full encrypted_group_info (up to ~66 KB). The labeled
/// IKM/info construction prepends "HPKE-v1" + suite_id + label,
/// so the buffer must accommodate the largest context plus
/// overhead. 68 KB covers the 65536-byte max_gi_buf + tag +
/// HPKE framing.
///
/// NOTE: Each call to hpkeLabeledExtract/hpkeLabeledExpand
/// places this buffer on the stack. Peak transient stack usage
/// during keyScheduleBase is ~68 KB (one buffer per call, not
/// concurrent). To reduce this, kdfExtract/kdfExpand would need
/// incremental update support, requiring changes to all crypto
/// provider backends.
const max_labeled_buf: u32 = 68 * 1024;

/// HPKE base mode bound to a specific CryptoProvider.
///
/// For MLS cipher suite 0x0001 this means:
///   KEM  = DHKEM(X25519, HKDF-SHA256)  kem_id  = 0x0020
///   KDF  = HKDF-SHA256                 kdf_id  = 0x0001
///   AEAD = AES-128-GCM                 aead_id = 0x0001
pub fn Hpke(comptime P: type) type {
    return struct {
        const Self = @This();

        // Algorithm IDs from the CryptoProvider.
        const kem_id: u16 = P.kem_id;
        const kdf_id: u16 = P.kdf_id;
        const aead_id: u16 = P.aead_id;

        /// KEM shared secret length. For DHKEM suites (X25519, P-256,
        /// P-384), Nsecret equals Nh (hash output length). This is a
        /// coincidence of the suites we support — RFC 9180 Table 2
        /// defines them independently. If a future suite has
        /// Nsecret != Nh, this must become a separate provider
        /// constant.
        const n_secret: u32 = P.nh;
        /// Encapsulated key length (Nenc = Npk for DHKEM).
        const n_enc: u32 = P.npk;

        /// KEM keypair: secret key + public key.
        pub const KemKeyPair = struct {
            sk: [P.nsk]u8,
            pk: [P.npk]u8,
        };

        const kem_suite = kemSuiteId(kem_id);
        const hpke_suite = hpkeSuiteId(kem_id, kdf_id, aead_id);

        const hpke_v1 = "HPKE-v1";

        // -- Labeled KDF helpers (KEM context) --

        /// LabeledExtract with KEM suite_id.
        fn kemLabeledExtract(
            salt: []const u8,
            label: []const u8,
            ikm: []const u8,
        ) [P.nh]u8 {
            var buf: [512]u8 = undefined;
            const len = buildLabeledIkm(
                &kem_suite,
                label,
                ikm,
                &buf,
            );
            return P.kdfExtract(salt, buf[0..len]);
        }

        /// LabeledExpand with KEM suite_id.
        fn kemLabeledExpand(
            prk: *const [P.nh]u8,
            label: []const u8,
            info: []const u8,
            out: []u8,
        ) void {
            var buf: [512]u8 = undefined;
            const len = buildLabeledInfo(
                &kem_suite,
                label,
                info,
                @intCast(out.len),
                &buf,
            );
            P.kdfExpand(prk, buf[0..len], out);
        }

        /// LabeledExtract with HPKE suite_id.
        fn hpkeLabeledExtract(
            salt: []const u8,
            label: []const u8,
            ikm: []const u8,
        ) [P.nh]u8 {
            var buf: [max_labeled_buf]u8 = undefined;
            const len = buildLabeledIkm(
                &hpke_suite,
                label,
                ikm,
                &buf,
            );
            return P.kdfExtract(salt, buf[0..len]);
        }

        /// LabeledExpand with HPKE suite_id.
        fn hpkeLabeledExpand(
            prk: *const [P.nh]u8,
            label: []const u8,
            info: []const u8,
            out: []u8,
        ) void {
            var buf: [max_labeled_buf]u8 = undefined;
            const len = buildLabeledInfo(
                &hpke_suite,
                label,
                info,
                @intCast(out.len),
                &buf,
            );
            P.kdfExpand(prk, buf[0..len], out);
        }

        // -- DHKEM Encap / Decap --

        /// DeriveKeyPair(ikm) per RFC 9180 Section 7.1.3.
        ///
        /// Derives a deterministic keypair from input keying
        /// material using the KEM's labeled extract/expand.
        ///
        /// For DHKEM(X25519) (kem_id 0x0020):
        ///   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
        ///   sk = LabeledExpand(dkp_prk, "sk", "", 32)
        ///   return (sk, pk(sk))
        ///
        /// For DHKEM(P-256) (0x0010) / DHKEM(P-384) (0x0011):
        ///   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
        ///   for counter in 0..255:
        ///     candidate = LabeledExpand(dkp_prk, "candidate",
        ///                               I2OSP(counter,1), Nsk)
        ///     candidate[0] &= bitmask
        ///     if candidate < order: return (candidate, pk(candidate))
        pub fn deriveKeyPair(
            ikm: []const u8,
        ) CryptoError!KemKeyPair {
            var dkp_prk = kemLabeledExtract(
                "",
                "dkp_prk",
                ikm,
            );
            defer secureZero(&dkp_prk);

            return deriveKeyPairInner(&dkp_prk);
        }

        /// Inner dispatch: X25519 uses "sk" expand, NIST
        /// curves use candidate rejection loop.
        fn deriveKeyPairInner(
            dkp_prk: *const [P.nh]u8,
        ) CryptoError!KemKeyPair {
            if (kem_id == 0x0020) {
                // DHKEM(X25519): simple expand.
                var sk: [P.nsk]u8 = undefined;
                kemLabeledExpand(
                    dkp_prk,
                    "sk",
                    "",
                    &sk,
                );
                defer secureZero(&sk);
                const seed: *const [P.seed_len]u8 = sk[0..P.seed_len];
                const kp = try P.dhKeypairFromSeed(seed);
                return .{ .sk = kp.sk, .pk = kp.pk };
            } else if (kem_id == 0x0010 or
                kem_id == 0x0011)
            {
                // DHKEM(P-256 / P-384): candidate rejection.
                return deriveNistKeyPair(dkp_prk);
            } else {
                return error.InvalidPrivateKey;
            }
        }

        /// NIST curve DeriveKeyPair with candidate rejection.
        fn deriveNistKeyPair(
            dkp_prk: *const [P.nh]u8,
        ) CryptoError!KemKeyPair {
            const Curve = if (kem_id == 0x0010)
                std.crypto.ecc.P256
            else
                std.crypto.ecc.P384;

            // bitmask: all 0xFF except top byte gets order_mask.
            // For P-256: order ≈ 2^256, mask = 0xFF.
            // For P-384: order ≈ 2^384, mask = 0xFF.
            // RFC 9180 Section 7.1.3: bitmask = 0xFF for both.
            const order_mask: u8 = 0xFF;

            var counter: u16 = 0;
            while (counter < 256) : (counter += 1) {
                const ctr_byte = [1]u8{
                    @intCast(counter),
                };
                var candidate: [P.nsk]u8 = undefined;
                kemLabeledExpand(
                    dkp_prk,
                    "candidate",
                    &ctr_byte,
                    &candidate,
                );
                candidate[0] &= order_mask;

                // Try to use candidate as secret key.
                const bp = Curve.basePoint.mul(
                    candidate,
                    .big,
                ) catch continue;
                const pk = bp.toUncompressedSec1();
                return .{ .sk = candidate, .pk = pk };
            }
            return error.InvalidPrivateKey;
        }

        /// ExtractAndExpand(dh, kem_context) per RFC 9180 Section 4.1.
        fn extractAndExpand(
            dh_bytes: []const u8,
            kem_context: []const u8,
        ) [n_secret]u8 {
            assert(dh_bytes.len == n_secret);
            assert(kem_context.len == n_enc + P.npk);
            var eae_prk = kemLabeledExtract(
                "",
                "eae_prk",
                dh_bytes,
            );
            defer secureZero(&eae_prk);
            var shared_secret: [n_secret]u8 = undefined;
            kemLabeledExpand(
                &eae_prk,
                "shared_secret",
                kem_context,
                &shared_secret,
            );
            return shared_secret;
        }

        /// Encap(pkR) — deterministic variant that takes
        /// an ephemeral seed (for testability).
        ///
        /// WARNING: The `eph_seed` MUST be unique per call.
        /// Reusing the same seed with different recipients
        /// breaks IND-CCA2 security (reveals relationships
        /// between ciphertexts). Only use a fixed seed in
        /// tests; production callers must supply fresh
        /// randomness each time.
        pub fn encapDeterministic(
            pk_r: *const [P.npk]u8,
            eph_seed: *const [P.seed_len]u8,
        ) CryptoError!struct {
            shared_secret: [n_secret]u8,
            enc: [n_enc]u8,
        } {
            var eph = try P.dhKeypairFromSeed(eph_seed);
            defer secureZero(&eph.sk);
            var dh_result = try P.dh(&eph.sk, pk_r);
            defer secureZero(&dh_result);

            // kem_context = enc || pkR.
            var kem_ctx: [n_enc + P.npk]u8 = undefined;
            @memcpy(kem_ctx[0..n_enc], &eph.pk);
            @memcpy(kem_ctx[n_enc..], pk_r);

            const shared = extractAndExpand(
                &dh_result,
                &kem_ctx,
            );
            return .{
                .shared_secret = shared,
                .enc = eph.pk,
            };
        }

        /// Decap(enc, skR) per RFC 9180 Section 4.1.
        pub fn decap(
            enc: *const [n_enc]u8,
            sk_r: *const [P.nsk]u8,
            pk_r: *const [P.npk]u8,
        ) CryptoError![n_secret]u8 {
            // DH(skR, pkE) where pkE = enc.
            var dh_result = try P.dh(sk_r, enc);
            defer secureZero(&dh_result);

            // kem_context = enc || pkR.
            var kem_ctx: [n_enc + P.npk]u8 = undefined;
            @memcpy(kem_ctx[0..n_enc], enc);
            @memcpy(kem_ctx[n_enc..], pk_r);

            return extractAndExpand(&dh_result, &kem_ctx);
        }

        // -- Key Schedule (base mode) --

        /// Key schedule output: AEAD key + base nonce.
        pub const ContextParams = struct {
            key: [P.nk]u8,
            base_nonce: [P.nn]u8,
            exporter_secret: [P.nh]u8,
        };

        /// KeySchedule for base mode.
        /// `info` is application-supplied context.
        fn keyScheduleBase(
            shared_secret: *const [n_secret]u8,
            info: []const u8,
        ) ContextParams {
            assert(info.len <= max_labeled_buf - 64);
            // psk_id_hash = LabeledExtract("", "psk_id_hash", "")
            const psk_id_hash = hpkeLabeledExtract(
                "",
                "psk_id_hash",
                "",
            );
            // info_hash = LabeledExtract("", "info_hash", info)
            const info_hash = hpkeLabeledExtract(
                "",
                "info_hash",
                info,
            );

            // key_schedule_context = mode || psk_id_hash || info_hash
            var ks_ctx: [1 + P.nh + P.nh]u8 = undefined;
            ks_ctx[0] = mode_base;
            @memcpy(ks_ctx[1..][0..P.nh], &psk_id_hash);
            @memcpy(ks_ctx[1 + P.nh ..], &info_hash);

            // secret = LabeledExtract(shared_secret, "secret", "")
            var secret = hpkeLabeledExtract(
                shared_secret,
                "secret",
                "",
            );
            defer secureZero(&secret);

            // Derive key, base_nonce, exporter_secret.
            var key: [P.nk]u8 = undefined;
            hpkeLabeledExpand(
                &secret,
                "key",
                &ks_ctx,
                &key,
            );

            var base_nonce: [P.nn]u8 = undefined;
            hpkeLabeledExpand(
                &secret,
                "base_nonce",
                &ks_ctx,
                &base_nonce,
            );

            var exp_secret: [P.nh]u8 = undefined;
            hpkeLabeledExpand(
                &secret,
                "exp",
                &ks_ctx,
                &exp_secret,
            );

            return .{
                .key = key,
                .base_nonce = base_nonce,
                .exporter_secret = exp_secret,
            };
        }

        // -- Single-shot Seal / Open --

        /// Maximum ciphertext overhead: AEAD tag.
        pub const tag_len: u32 = P.nt;

        /// SealBase(pkR, info, aad, pt) — single-shot encrypt.
        ///
        /// Deterministic variant taking an ephemeral seed.
        /// Returns (enc, ciphertext || tag).
        pub fn sealBase(
            pk_r: *const [P.npk]u8,
            info: []const u8,
            aad: []const u8,
            plaintext: []const u8,
            eph_seed: *const [P.seed_len]u8,
            ct_out: []u8,
            tag_out: *[P.nt]u8,
        ) CryptoError![n_enc]u8 {
            assert(ct_out.len == plaintext.len);
            var encap_result = try encapDeterministic(
                pk_r,
                eph_seed,
            );
            defer secureZero(&encap_result.shared_secret);
            var context = keyScheduleBase(
                &encap_result.shared_secret,
                info,
            );
            defer secureZero(&context.key);
            defer secureZero(&context.base_nonce);
            defer secureZero(&context.exporter_secret);

            // Seal with seq = 0 → nonce = base_nonce.
            P.aeadSeal(
                &context.key,
                &context.base_nonce,
                aad,
                plaintext,
                ct_out,
                tag_out,
            );

            return encap_result.enc;
        }

        /// OpenBase(enc, skR, info, aad, ct, tag) — single-shot decrypt.
        pub fn openBase(
            enc: *const [n_enc]u8,
            sk_r: *const [P.nsk]u8,
            pk_r: *const [P.npk]u8,
            info: []const u8,
            aad: []const u8,
            ciphertext: []const u8,
            tag: *const [P.nt]u8,
            pt_out: []u8,
        ) CryptoError!void {
            assert(pt_out.len == ciphertext.len);
            var shared_secret = try decap(enc, sk_r, pk_r);
            defer secureZero(&shared_secret);
            var context = keyScheduleBase(
                &shared_secret,
                info,
            );
            defer secureZero(&context.key);
            defer secureZero(&context.base_nonce);
            defer secureZero(&context.exporter_secret);

            try P.aeadOpen(
                &context.key,
                &context.base_nonce,
                aad,
                ciphertext,
                tag,
                pt_out,
            );
        }

        // -- Helpers --

        /// Build labeled_ikm = "HPKE-v1" || suite_id || label || ikm.
        fn buildLabeledIkm(
            suite_id: []const u8,
            label: []const u8,
            ikm: []const u8,
            buf: []u8,
        ) u32 {
            assert(buf.len >= hpke_v1.len + suite_id.len + label.len + ikm.len);
            var pos: u32 = 0;
            @memcpy(buf[pos..][0..hpke_v1.len], hpke_v1);
            pos += hpke_v1.len;
            @memcpy(buf[pos..][0..suite_id.len], suite_id);
            pos += @intCast(suite_id.len);
            @memcpy(buf[pos..][0..label.len], label);
            pos += @intCast(label.len);
            @memcpy(buf[pos..][0..ikm.len], ikm);
            pos += @intCast(ikm.len);
            return pos;
        }

        /// Build labeled_info =
        ///   I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info.
        fn buildLabeledInfo(
            suite_id: []const u8,
            label: []const u8,
            info: []const u8,
            length: u16,
            buf: []u8,
        ) u32 {
            assert(buf.len >= 2 + hpke_v1.len + suite_id.len + label.len + info.len);
            assert(length > 0);
            var pos: u32 = 0;
            // I2OSP(L, 2) — big-endian u16.
            buf[pos] = @intCast(length >> 8);
            buf[pos + 1] = @intCast(length & 0xFF);
            pos += 2;
            @memcpy(buf[pos..][0..hpke_v1.len], hpke_v1);
            pos += hpke_v1.len;
            @memcpy(buf[pos..][0..suite_id.len], suite_id);
            pos += @intCast(suite_id.len);
            @memcpy(buf[pos..][0..label.len], label);
            pos += @intCast(label.len);
            @memcpy(buf[pos..][0..info.len], info);
            pos += @intCast(info.len);
            return pos;
        }
    };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const H = Hpke(Default);

test "hpke seal and open round-trip" {
    // Generate recipient key pair.
    const r_seed = [_]u8{0xAA} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);

    // Ephemeral seed for deterministic Encap.
    const eph_seed = [_]u8{0xBB} ** 32;

    const info = "test info";
    const aad = "test aad";
    const plaintext = "hello HPKE";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const enc = try H.sealBase(
        &r_kp.pk,
        info,
        aad,
        plaintext,
        &eph_seed,
        &ct,
        &tag,
    );

    var decrypted: [plaintext.len]u8 = undefined;
    try H.openBase(
        &enc,
        &r_kp.sk,
        &r_kp.pk,
        info,
        aad,
        &ct,
        &tag,
        &decrypted,
    );
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "hpke open rejects tampered ciphertext" {
    const r_seed = [_]u8{0xCC} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0xDD} ** 32;

    const plaintext = "secret";
    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const enc = try H.sealBase(
        &r_kp.pk,
        "",
        "",
        plaintext,
        &eph_seed,
        &ct,
        &tag,
    );

    // Tamper.
    ct[0] ^= 0xFF;

    var out: [plaintext.len]u8 = undefined;
    const result = H.openBase(
        &enc,
        &r_kp.sk,
        &r_kp.pk,
        "",
        "",
        &ct,
        &tag,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "hpke open rejects wrong recipient key" {
    const r_seed = [_]u8{0x11} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0x22} ** 32;

    const plaintext = "payload";
    var ct: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const enc = try H.sealBase(
        &r_kp.pk,
        "info",
        "aad",
        plaintext,
        &eph_seed,
        &ct,
        &tag,
    );

    // Different recipient.
    const wrong_seed = [_]u8{0x33} ** 32;
    const wrong_kp = try Default.dhKeypairFromSeed(&wrong_seed);

    var out: [plaintext.len]u8 = undefined;
    const result = H.openBase(
        &enc,
        &wrong_kp.sk,
        &wrong_kp.pk,
        "info",
        "aad",
        &ct,
        &tag,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "hpke deterministic encap produces same output" {
    const r_seed = [_]u8{0x55} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0x66} ** 32;

    const r1 = try H.encapDeterministic(&r_kp.pk, &eph_seed);
    const r2 = try H.encapDeterministic(&r_kp.pk, &eph_seed);

    try testing.expectEqualSlices(
        u8,
        &r1.shared_secret,
        &r2.shared_secret,
    );
    try testing.expectEqualSlices(u8, &r1.enc, &r2.enc);
}

test "hpke encap/decap shared secret match" {
    const r_seed = [_]u8{0x77} ** 32;
    const r_kp = try Default.dhKeypairFromSeed(&r_seed);
    const eph_seed = [_]u8{0x88} ** 32;

    const encap_result = try H.encapDeterministic(
        &r_kp.pk,
        &eph_seed,
    );
    const decap_secret = try H.decap(
        &encap_result.enc,
        &r_kp.sk,
        &r_kp.pk,
    );

    try testing.expectEqualSlices(
        u8,
        &encap_result.shared_secret,
        &decap_secret,
    );
}
