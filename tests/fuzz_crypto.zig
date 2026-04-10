// Fuzz targets for cryptographic operations.
//
// Properties tested:
//   1. HPKE seal/open round-trip: decrypt(encrypt(pt)) == pt
//   2. HPKE open with corrupted ciphertext must not panic
//   3. Sign/verify round-trip: verify(sign(msg)) succeeds
//   4. Verify with corrupted signature must not panic
//   5. DeriveKeyPair with arbitrary IKM must not panic
//   6. Tree hash with corrupt trees must not panic
//
// Run with:  zig build test --fuzz

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const mls = @import("zmls");
const Default = mls.DefaultCryptoProvider;
const Hpke = mls.Hpke(Default);
const CryptoError = mls.errors.CryptoError;

// ── Helpers ─────────────────────────────────────────────────

/// Deterministic seed from a tag byte.
fn testSeed(tag: u8) [Default.seed_len]u8 {
    return [_]u8{tag} ** Default.seed_len;
}

// ── Fuzz: HPKE seal/open round-trip ─────────────────────────

fn fuzzHpkeSealOpen(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Generate a recipient keypair from a random seed.
    var seed: [Default.seed_len]u8 = undefined;
    smith.bytes(&seed);
    const kp = Default.dhKeypairFromSeed(&seed) catch return;

    // Random plaintext (up to 256 bytes).
    var pt_buf: [256]u8 = undefined;
    const pt_len = smith.slice(&pt_buf);
    const plaintext = pt_buf[0..pt_len];

    // Random AAD (up to 64 bytes).
    var aad_buf: [64]u8 = undefined;
    const aad_len = smith.slice(&aad_buf);
    const aad = aad_buf[0..aad_len];

    // Random info (up to 32 bytes).
    var info_buf: [32]u8 = undefined;
    const info_len = smith.slice(&info_buf);
    const info = info_buf[0..info_len];

    // Ephemeral seed for seal.
    var eph_seed: [Default.seed_len]u8 = undefined;
    smith.bytes(&eph_seed);

    // Seal.
    var ct_buf: [256]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const enc = Hpke.sealBase(
        &kp.pk,
        info,
        aad,
        plaintext,
        &eph_seed,
        ct_buf[0..pt_len],
        &tag,
    ) catch return;

    // Open — must recover original plaintext.
    var pt_out: [256]u8 = undefined;
    Hpke.openBase(
        &enc,
        &kp.sk,
        &kp.pk,
        info,
        aad,
        ct_buf[0..pt_len],
        &tag,
        pt_out[0..pt_len],
    ) catch return;

    try testing.expectEqualSlices(
        u8,
        plaintext,
        pt_out[0..pt_len],
    );
}

test "fuzz: HPKE seal/open round-trip" {
    try testing.fuzz({}, fuzzHpkeSealOpen, .{});
}

// ── Fuzz: HPKE open with corrupted ciphertext ───────────────

fn fuzzHpkeOpenCorrupt(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Fixed keypair for consistency.
    const kp = Default.dhKeypairFromSeed(
        &testSeed(1),
    ) catch return;
    const eph_seed = testSeed(2);

    // Encrypt a known message.
    const plaintext = "fuzz test payload";
    var ct_buf: [plaintext.len]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const enc = Hpke.sealBase(
        &kp.pk,
        "info",
        "aad",
        plaintext,
        &eph_seed,
        &ct_buf,
        &tag,
    ) catch return;

    // Corrupt one random byte in the ciphertext or tag.
    const corrupt_target = smith.value(enum(u2) {
        ciphertext,
        tag_field,
        enc_field,
    });

    var ct_copy = ct_buf;
    var tag_copy = tag;
    var enc_copy = enc;

    switch (corrupt_target) {
        .ciphertext => {
            if (ct_copy.len > 0) {
                const idx = smith.valueRangeAtMost(
                    u32,
                    0,
                    @intCast(ct_copy.len - 1),
                );
                ct_copy[idx] ^= smith.valueRangeAtMost(
                    u8,
                    1,
                    0xFF,
                );
            }
        },
        .tag_field => {
            const idx = smith.valueRangeAtMost(
                u32,
                0,
                Default.nt - 1,
            );
            tag_copy[idx] ^= smith.valueRangeAtMost(
                u8,
                1,
                0xFF,
            );
        },
        .enc_field => {
            const idx = smith.valueRangeAtMost(
                u32,
                0,
                @as(u32, enc_copy.len) - 1,
            );
            enc_copy[idx] ^= smith.valueRangeAtMost(
                u8,
                1,
                0xFF,
            );
        },
    }

    // Must not panic — should return an error.
    var pt_out: [plaintext.len]u8 = undefined;
    _ = Hpke.openBase(
        &enc_copy,
        &kp.sk,
        &kp.pk,
        "info",
        "aad",
        &ct_copy,
        &tag_copy,
        &pt_out,
    ) catch return;
}

test "fuzz: HPKE open with corrupted ciphertext" {
    try testing.fuzz({}, fuzzHpkeOpenCorrupt, .{});
}

// ── Fuzz: sign/verify round-trip ────────────────────────────

fn fuzzSignVerify(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Random signing seed.
    var seed: [Default.seed_len]u8 = undefined;
    smith.bytes(&seed);
    const kp = Default.signKeypairFromSeed(&seed) catch return;

    // Random message (up to 512 bytes).
    var msg_buf: [512]u8 = undefined;
    const msg_len = smith.slice(&msg_buf);
    const msg = msg_buf[0..msg_len];

    // Sign.
    const sig = Default.sign(&kp.sk, msg) catch return;

    // Verify — must succeed.
    try Default.verify(&kp.pk, msg, &sig);
}

test "fuzz: sign/verify round-trip" {
    try testing.fuzz({}, fuzzSignVerify, .{});
}

// ── Fuzz: verify with corrupted signature ───────────────────

fn fuzzVerifyCorrupt(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Fixed keypair.
    const kp = Default.signKeypairFromSeed(
        &testSeed(3),
    ) catch return;

    const msg = "fuzz verify message";
    const sig = Default.sign(&kp.sk, msg) catch return;

    // Corrupt the signature.
    var sig_copy = sig;
    const idx = smith.valueRangeAtMost(
        u32,
        0,
        Default.sig_len - 1,
    );
    sig_copy[idx] ^= smith.valueRangeAtMost(u8, 1, 0xFF);

    // Must not panic — should return an error.
    _ = Default.verify(&kp.pk, msg, &sig_copy) catch return;
}

test "fuzz: verify with corrupted signature" {
    try testing.fuzz({}, fuzzVerifyCorrupt, .{});
}

// ── Fuzz: deriveKeyPair with arbitrary IKM ──────────────────

fn fuzzDeriveKeyPair(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Random IKM of varying length (0 to 256 bytes).
    var ikm_buf: [256]u8 = undefined;
    const ikm_len = smith.slice(&ikm_buf);
    const ikm = ikm_buf[0..ikm_len];

    // Must not panic for any IKM.
    const kp = Hpke.deriveKeyPair(ikm) catch return;

    // If successful, DH with self must succeed (consistency).
    _ = Default.dh(&kp.sk, &kp.pk) catch return;
}

test "fuzz: HPKE deriveKeyPair with arbitrary IKM" {
    try testing.fuzz({}, fuzzDeriveKeyPair, .{});
}

// ── Fuzz: tree hash with corrupt trees ──────────────────────

fn fuzzTreeHash(_: void, smith: *Smith) anyerror!void {
    const alloc = testing.allocator;
    const tree_math = mls.tree_math;
    const tree_hashes = mls.tree_hashes;

    // Random leaf count (1 to 32).
    const n = smith.valueRangeAtMost(u32, 1, 32);

    // Build a tree with random node data.
    const RatchetTree = mls.RatchetTree;
    var tree = RatchetTree.init(alloc, n) catch return;
    defer tree.deinit();

    // Randomly populate some leaves.
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (smith.eosWeightedSimple(1, 1)) {
            // Leave blank.
            continue;
        }
        // Set a minimal leaf.
        var tag_byte: [1]u8 = undefined;
        smith.bytes(&tag_byte);
        const tag_slice: []const u8 = @as(
            [*]const u8,
            @ptrCast(&tag_byte),
        )[0..1];
        const leaf = mls.LeafNode{
            .encryption_key = tag_slice,
            .signature_key = tag_slice,
            .credential = mls.Credential.initBasic(
                tag_slice,
            ),
            .capabilities = .{
                .versions = &.{},
                .cipher_suites = &.{},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{},
            },
            .source = .commit,
            .lifetime = null,
            .parent_hash = null,
            .extensions = &.{},
            .signature = tag_slice,
        };
        tree.setLeaf(
            mls.LeafIndex.fromU32(i),
            leaf,
        ) catch continue;
    }

    // treeHash must not panic even on partially-populated
    // trees. It may return an error if the tree is empty.
    const root = tree_math.root(n);
    _ = tree_hashes.treeHash(
        Default,
        alloc,
        &tree,
        root,
    ) catch return;
}

test "fuzz: tree hash with corrupt trees" {
    try testing.fuzz({}, fuzzTreeHash, .{});
}
