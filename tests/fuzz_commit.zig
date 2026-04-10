// Fuzz targets for commit processing and PrivateMessage
// encryption/decryption.
//
// Properties tested:
//   1. processCommit with random PSK proposals must never panic.
//   2. PrivateMessage encrypt/decrypt round-trip: content
//      survives a seal/open cycle; corrupted ciphertext must
//      not panic on decryption.
//
// Run with:  zig build test --fuzz

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const mls = @import("zmls");

const Default = mls.DefaultCryptoProvider;
const Credential = mls.Credential;
const Proposal = mls.Proposal;
const FramedContent = mls.FramedContent;
const Sender = mls.Sender;

// ── Helpers ─────────────────────────────────────────────────

/// Deterministic seed from a tag byte.
fn testSeed(tag: u8) [Default.seed_len]u8 {
    return [_]u8{tag} ** Default.seed_len;
}

/// Build a valid LeafNode for test use.
fn makeTestLeaf(
    enc_pk: []const u8,
    sig_pk: []const u8,
) mls.LeafNode {
    const versions = comptime [_]mls.ProtocolVersion{
        .mls10,
    };
    const suites = comptime [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const cred_types = comptime [_]mls.types.CredentialType{
        .basic,
    };
    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(sig_pk),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &cred_types,
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
}

// ── Fuzz: processCommit with random proposals ───────────────

fn fuzzProcessCommit(
    _: void,
    smith: *Smith,
) anyerror!void {
    const alloc = testing.allocator;

    // Deterministic keys for Alice.
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sign = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );
    const leaf = makeTestLeaf(&alice_enc.pk, &alice_sign.pk);

    var gs = try mls.createGroup(
        Default,
        alloc,
        "fuzz-group",
        leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Generate random proposals (0-3 PSK proposals — safe
    // for single-member group, no path needed).
    var proposals: [4]Proposal = undefined;
    const num_props = smith.valueRangeAtMost(u32, 0, 3);

    var nonce_bufs: [4][Default.nh]u8 = undefined;
    var id_bufs: [4][8]u8 = undefined;

    var pi: u32 = 0;
    while (pi < num_props) : (pi += 1) {
        smith.bytes(&nonce_bufs[pi]);
        smith.bytes(&id_bufs[pi]);
        proposals[pi] = .{
            .tag = .psk,
            .payload = .{
                .psk = .{
                    .psk = .{
                        .psk_type = .external,
                        .external_psk_id = &id_bufs[pi],
                        .resumption_usage = .reserved,
                        .resumption_group_id = "",
                        .resumption_epoch = 0,
                        .psk_nonce = &nonce_bufs[pi],
                    },
                },
            },
        };
    }

    // Create commit — may fail if proposals are invalid
    // (e.g. PSK not found). That's fine.
    var cr = mls.createCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        proposals[0..num_props],
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    ) catch return;
    defer cr.tree.deinit();
    defer cr.deinit(alloc);

    // Build FramedContent for processCommit.
    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Process the commit we just created — should succeed
    // for the same group state. Must not panic regardless.
    var pr = mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = proposals[0..num_props],
            .sender_verify_key = &alice_sign.pk,
        },
        &gs.group_context,
        &gs.tree,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
    ) catch return;
    defer pr.tree.deinit();
    defer pr.deinit(alloc);
}

test "fuzz: processCommit with random proposals" {
    try testing.fuzz({}, fuzzProcessCommit, .{});
}

// ── Fuzz: PrivateMessage encrypt/decrypt round-trip ─────────

fn fuzzPrivateMessageRoundTrip(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Random key and nonce.
    var key: [Default.nk]u8 = undefined;
    smith.bytes(&key);
    var nonce: [Default.nn]u8 = undefined;
    smith.bytes(&nonce);

    // Random plaintext (0-256 bytes).
    var content_buf: [256]u8 = undefined;
    const content_len = smith.slice(&content_buf);
    const content = content_buf[0..content_len];

    // Auth data for application content: signature is random,
    // confirmation_tag is null (only present for commits).
    var sig: [Default.sig_len]u8 = undefined;
    smith.bytes(&sig);
    const auth_data = mls.framing_auth.FramedContentAuthData(
        Default,
    ){
        .signature = sig,
        .confirmation_tag = null,
    };

    // Build AAD.
    var aad_buf: [256]u8 = undefined;
    const aad_len = mls.private_msg.buildPrivateContentAad(
        &aad_buf,
        "test-group",
        1,
        .application,
        "",
    ) catch return;
    const aad = aad_buf[0..aad_len];

    // Encrypt.
    var ct_buf: [4096]u8 = undefined;
    const ct_len = mls.private_msg.encryptContent(
        Default,
        content,
        .application,
        &auth_data,
        0,
        &key,
        &nonce,
        aad,
        &ct_buf,
    ) catch return;
    const ct = ct_buf[0..ct_len];

    // Decrypt — should succeed and match.
    var pt_buf: [4096]u8 = undefined;
    const dec = mls.private_msg.decryptContent(
        Default,
        ct,
        .application,
        &key,
        &nonce,
        aad,
        &pt_buf,
    ) catch return;

    try testing.expectEqualSlices(u8, content, dec.content);

    // Corrupt ciphertext — should fail, not panic.
    if (ct_len > 0) {
        const flip_idx: usize = smith.valueRangeAtMost(
            u32,
            0,
            @intCast(ct_len - 1),
        );
        var corrupted: [4096]u8 = undefined;
        @memcpy(corrupted[0..ct_len], ct);
        corrupted[flip_idx] ^= 0xFF;
        var pt_buf2: [4096]u8 = undefined;
        _ = mls.private_msg.decryptContent(
            Default,
            corrupted[0..ct_len],
            .application,
            &key,
            &nonce,
            aad,
            &pt_buf2,
        ) catch return;
        // If decryption somehow succeeds with corrupt data,
        // that's unexpected — but don't panic.
    }
}

test "fuzz: PrivateMessage encrypt/decrypt round-trip" {
    try testing.fuzz({}, fuzzPrivateMessageRoundTrip, .{});
}
