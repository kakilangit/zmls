const std = @import("std");
const testing = std.testing;

const welcome_mod = @import("welcome.zig");

const GroupSecrets = welcome_mod.GroupSecrets;
const EncryptedGroupSecrets = welcome_mod.EncryptedGroupSecrets;
const Welcome = welcome_mod.Welcome;
const encryptGroupSecrets = welcome_mod.encryptGroupSecrets;
const decryptGroupSecrets = welcome_mod.decryptGroupSecrets;

const psk_mod = @import("../key_schedule/psk.zig");
const PreSharedKeyId = psk_mod.PreSharedKeyId;
const CipherSuite = @import("../common/types.zig").CipherSuite;

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

// -- GroupSecrets codec --------------------------------------------------

test "GroupSecrets encode/decode round-trip, no path, no PSKs" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x42} ** 32;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    var buf: [256]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        &joiner,
        dec_r.value.joiner_secret,
    );
    try testing.expect(dec_r.value.path_secret == null);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.psks.len,
    );
    try testing.expectEqual(end, dec_r.pos);
}

test "GroupSecrets with path_secret round-trip" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x11} ** 32;
    const path = [_]u8{0x22} ** 32;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = &path,
        .psks = &.{},
    };

    var buf: [256]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path_secret != null);
    try testing.expectEqualSlices(
        u8,
        &path,
        dec_r.value.path_secret.?,
    );
}

test "GroupSecrets with PSKs round-trip" {
    const alloc = testing.allocator;

    const joiner = [_]u8{0x33} ** 32;
    const psk_id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-external-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "nonce123",
    };
    const psks = [_]PreSharedKeyId{psk_id};
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &psks,
    };

    var buf: [512]u8 = undefined;
    const end = try gs.encode(&buf, 0);

    var dec_r = try GroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.psks.len,
    );
    try testing.expectEqualSlices(
        u8,
        "my-external-psk",
        dec_r.value.psks[0].external_psk_id,
    );
    try testing.expectEqualSlices(
        u8,
        "nonce123",
        dec_r.value.psks[0].psk_nonce,
    );
}

// -- EncryptedGroupSecrets codec -----------------------------------------

test "EncryptedGroupSecrets encode/decode round-trip" {
    const alloc = testing.allocator;

    const egs = EncryptedGroupSecrets{
        .new_member = "kp-ref-hash-32-bytes!!!!!!!!????",
        .encrypted_group_secrets = .{
            .kem_output = &[_]u8{0xAA} ** 32,
            .ciphertext = &[_]u8{0xBB} ** 64,
        },
    };

    var buf: [512]u8 = undefined;
    const end = try egs.encode(&buf, 0);

    var dec_r = try EncryptedGroupSecrets.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        "kp-ref-hash-32-bytes!!!!!!!!????",
        dec_r.value.new_member,
    );
    try testing.expectEqual(
        @as(usize, 32),
        dec_r.value.encrypted_group_secrets.kem_output.len,
    );
    try testing.expectEqual(end, dec_r.pos);
}

// -- Welcome codec -------------------------------------------------------

test "Welcome encode/decode round-trip" {
    const alloc = testing.allocator;

    const egs = EncryptedGroupSecrets{
        .new_member = "ref1",
        .encrypted_group_secrets = .{
            .kem_output = &[_]u8{0x01} ** 8,
            .ciphertext = &[_]u8{0x02} ** 16,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = &[_]u8{0xFF} ** 48,
    };

    var buf: [512]u8 = undefined;
    const end = try welcome.encode(&buf, 0);

    var dec_r = try Welcome.decode(
        alloc,
        buf[0..end],
        0,
    );
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        CipherSuite.mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        dec_r.value.cipher_suite,
    );
    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.secrets.len,
    );
    try testing.expectEqualSlices(
        u8,
        &[_]u8{0xFF} ** 48,
        dec_r.value.encrypted_group_info,
    );
    try testing.expectEqual(end, dec_r.pos);
}

// -- Encrypt / decrypt ---------------------------------------------------

test "encrypt and decrypt GroupSecrets round-trip" {
    const alloc = testing.allocator;

    // Generate recipient init key pair.
    const init_seed = [_]u8{0xAA} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    // Create GroupSecrets.
    const joiner = [_]u8{0x42} ** Default.nh;
    const path_s = [_]u8{0x77} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = &path_s,
        .psks = &.{},
    };

    const kp_ref = "test-kp-ref-32-bytes!!!!????????";
    const egi = "encrypted-group-info-placeholder";
    const eph_seed = [_]u8{0xBB} ** 32;

    // Encrypt.
    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    // Build a Welcome with this entry.
    // We need to copy the kem_output and ciphertext from the
    // stack-returned egs into heap-allocated slices for the
    // Welcome to be decodable after encode/decode.
    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt.
    var dec_gs = try decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        kp_ref,
        &init_kp.sk,
        &init_kp.pk,
    );
    defer dec_gs.deinit(alloc);

    try testing.expectEqualSlices(
        u8,
        &joiner,
        dec_gs.joiner_secret,
    );
    try testing.expect(dec_gs.path_secret != null);
    try testing.expectEqualSlices(
        u8,
        &path_s,
        dec_gs.path_secret.?,
    );
}

test "decryptGroupSecrets fails with wrong key" {
    const alloc = testing.allocator;

    // Correct recipient.
    const init_seed = [_]u8{0xCC} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    // Wrong recipient.
    const wrong_seed = [_]u8{0xDD} ** 32;
    const wrong_kp = try Default.dhKeypairFromSeed(&wrong_seed);

    const joiner = [_]u8{0x55} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    const kp_ref = "ref-for-wrong-key-test!!!!!!!???";
    const egi = "egi-placeholder";
    const eph_seed = [_]u8{0xEE} ** 32;

    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt with wrong key should fail.
    const result = decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        kp_ref,
        &wrong_kp.sk,
        &wrong_kp.pk,
    );
    try testing.expectError(error.AeadError, result);
}

test "decryptGroupSecrets fails with wrong ref" {
    const alloc = testing.allocator;

    const init_seed = [_]u8{0x11} ** 32;
    const init_kp = try Default.dhKeypairFromSeed(&init_seed);

    const joiner = [_]u8{0x66} ** Default.nh;
    const gs = GroupSecrets{
        .joiner_secret = &joiner,
        .path_secret = null,
        .psks = &.{},
    };

    const kp_ref = "correct-ref-32-bytes!!!!!!!!!???";
    const egi = "egi-data";
    const eph_seed = [_]u8{0x22} ** 32;

    const egs = try encryptGroupSecrets(
        Default,
        &gs,
        kp_ref,
        &init_kp.pk,
        egi,
        &eph_seed,
    );

    const kem_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.kem_output.len);
    defer alloc.free(kem_copy);
    @memcpy(kem_copy, egs.encrypted_group_secrets.kem_output);

    const ct_copy = try alloc.alloc(u8, egs.encrypted_group_secrets.ciphertext.len);
    defer alloc.free(ct_copy);
    @memcpy(ct_copy, egs.encrypted_group_secrets.ciphertext);

    const egs_heap = EncryptedGroupSecrets{
        .new_member = kp_ref,
        .encrypted_group_secrets = .{
            .kem_output = kem_copy,
            .ciphertext = ct_copy,
        },
    };
    const secrets = [_]EncryptedGroupSecrets{egs_heap};

    const welcome = Welcome{
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .secrets = &secrets,
        .encrypted_group_info = egi,
    };

    // Decrypt with wrong ref should fail.
    const result = decryptGroupSecrets(
        Default,
        alloc,
        &welcome,
        "wrong-ref-32-bytes!!!!!!!!!!!???",
        &init_kp.sk,
        &init_kp.pk,
    );
    try testing.expectError(error.KeyPackageNotFound, result);
}
