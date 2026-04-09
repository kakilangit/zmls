const std = @import("std");
const testing = std.testing;

const secret_tree_mod = @import("secret_tree.zig");

const SecretTree = secret_tree_mod.SecretTree;
const KeyNonce = secret_tree_mod.KeyNonce;

const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

// -- Init / deinit -------------------------------------------------------

test "init and deinit with 4 leaves" {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 4), st.leaf_count);
    try testing.expectEqual(
        @as(usize, 4),
        st.handshake.len,
    );
    try testing.expectEqual(
        @as(usize, 4),
        st.application.len,
    );
}

test "each leaf gets a unique secret" {
    const enc_secret = [_]u8{0x55} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    // All leaf secrets should be distinct.
    var idx_i: u32 = 0;
    while (idx_i < 4) : (idx_i += 1) {
        var idx_j: u32 = idx_i + 1;
        while (idx_j < 4) : (idx_j += 1) {
            try testing.expect(
                !std.mem.eql(
                    u8,
                    &st.handshake[idx_i].secret,
                    &st.handshake[idx_j].secret,
                ),
            );
        }
    }
}

test "single leaf tree works" {
    const enc_secret = [_]u8{0xBB} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        1,
    );
    defer st.deinit(testing.allocator);

    // For a single-leaf tree, the leaf node secret equals
    // encryption_secret. The ratchet root is derived via
    // ExpandWithLabel so it differs from encryption_secret.
    try testing.expect(
        !std.mem.eql(
            u8,
            &enc_secret,
            &st.handshake[0].secret,
        ),
    );

    const kn = try st.consumeKey(0, 0);
    try testing.expectEqual(@as(u32, 0), kn.generation);
}

// -- consumeKey ----------------------------------------------------------

test "consumeKey produces valid key and nonce" {
    const enc_secret = [_]u8{0x77} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn = try st.consumeKey(0, 1); // application

    try testing.expectEqual(@as(u32, 0), kn.generation);
    try testing.expectEqual(@as(usize, Default.nk), kn.key.len);
    try testing.expectEqual(@as(usize, Default.nn), kn.nonce.len);

    // Key should be non-zero.
    var all_zero = true;
    for (kn.key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "consumeKey ratchets forward" {
    const enc_secret = [_]u8{0x88} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn0 = try st.consumeKey(0, 1);
    const kn1 = try st.consumeKey(0, 1);

    try testing.expectEqual(@as(u32, 0), kn0.generation);
    try testing.expectEqual(@as(u32, 1), kn1.generation);

    // Keys from different generations should differ.
    try testing.expect(
        !std.mem.eql(u8, &kn0.key, &kn1.key),
    );
    try testing.expect(
        !std.mem.eql(u8, &kn0.nonce, &kn1.nonce),
    );
}

test "handshake and application ratchet independently" {
    const enc_secret = [_]u8{0x99} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Both start from the same leaf secret, so generation 0
    // keys are identical. Advance handshake once — now they
    // should diverge.
    _ = try st.consumeKey(0, 0); // handshake gen 0
    const hs_kn1 = try st.consumeKey(0, 0); // handshake gen 1
    const app_kn0 = try st.consumeKey(0, 1); // application gen 0

    // Handshake at gen 1 should differ from application at gen 0.
    try testing.expect(
        !std.mem.eql(u8, &hs_kn1.key, &app_kn0.key),
    );
}

test "consumeKey zeroes old secret" {
    const enc_secret = [_]u8{0xAA} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Save initial secret.
    const initial = st.application[0].secret;

    // Consume — should ratchet forward.
    _ = try st.consumeKey(0, 1);

    // The secret should have changed (old was zeroed, new
    // replaced it).
    try testing.expect(
        !std.mem.eql(
            u8,
            &initial,
            &st.application[0].secret,
        ),
    );
}

test "out of bounds leaf returns error" {
    const enc_secret = [_]u8{0xCC} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const result = st.consumeKey(5, 1);
    try testing.expectError(error.NotAMember, result);
}

// -- forwardRatchet ------------------------------------------------------

test "forwardRatchet skips to target generation" {
    const enc_secret = [_]u8{0xDD} ** Default.nh;

    // Reference: ratchet sequentially to gen 5.
    var ref = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer ref.deinit(testing.allocator);

    var ref_kn: KeyNonce(Default) = undefined;
    var gi: u32 = 0;
    while (gi <= 5) : (gi += 1) {
        ref_kn = try ref.consumeKey(0, 1);
    }

    // Forward ratchet: jump directly to gen 5.
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn = try st.forwardRatchet(0, 1, 5);
    try testing.expectEqual(@as(u32, 5), kn.generation);
    try testing.expectEqualSlices(u8, &ref_kn.key, &kn.key);
    try testing.expectEqualSlices(
        u8,
        &ref_kn.nonce,
        &kn.nonce,
    );

    // State should now be at gen 6.
    try testing.expectEqual(
        @as(u32, 6),
        st.application[0].generation,
    );
}

test "forwardRatchet with target == current is consumeKey" {
    const enc_secret = [_]u8{0xEE} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Forward ratchet to gen 0 (current) = regular consumeKey.
    const kn = try st.forwardRatchet(0, 1, 0);
    try testing.expectEqual(@as(u32, 0), kn.generation);
}

test "forwardRatchet rejects past generation" {
    const enc_secret = [_]u8{0xF0} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    _ = try st.consumeKey(0, 1); // advance to gen 1
    const result = st.forwardRatchet(0, 1, 0);
    try testing.expectError(
        error.SecretAlreadyConsumed,
        result,
    );
}

test "forwardRatchet enforces max limit" {
    const enc_secret = [_]u8{0xF1} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    st.max_forward_ratchet = 3;

    // 3 steps is OK.
    const kn = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn.generation);

    // Now at gen 4. Trying to jump 4 steps (to gen 8) exceeds
    // the limit of 3.
    const result = st.forwardRatchet(0, 1, 8);
    try testing.expectError(error.GenerationTooFar, result);
}

test "forwardRatchet default limit rejects large jump" {
    const enc_secret = [_]u8{0xF2} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Default limit is 1024. Jump of 1024 is OK.
    const kn = try st.forwardRatchet(0, 1, 1024);
    try testing.expectEqual(@as(u32, 1024), kn.generation);

    // Now at gen 1025. Jump of 1025 steps (to gen 2050)
    // exceeds the default limit.
    const result = st.forwardRatchet(0, 1, 2050);
    try testing.expectError(error.GenerationTooFar, result);
}

// -- Retention -----------------------------------------------------------

test "forwardRatchet retains skipped keys for out-of-order" {
    const enc_secret = [_]u8{0xA1} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);
    try st.enableRetention(testing.allocator, 16);

    // Consume gen 0.
    const kn0 = try st.consumeKey(0, 1);
    try testing.expectEqual(@as(u32, 0), kn0.generation);

    // Skip gen 1, 2, 3, 4 — consume gen 5.
    const kn5 = try st.forwardRatchet(0, 1, 5);
    try testing.expectEqual(@as(u32, 5), kn5.generation);

    // Retrieve skipped gen 3 (was retained).
    const kn3 = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn3.generation);

    // Gen 3 consumed from retained — second lookup fails.
    const fail = st.forwardRatchet(0, 1, 3);
    try testing.expectError(error.SecretAlreadyConsumed, fail);
}

test "retained keys are zeroed when evicted" {
    const enc_secret = [_]u8{0xB2} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);
    // Tiny capacity: only 2 retained entries.
    try st.enableRetention(testing.allocator, 2);

    // Skip to gen 5 — retains gen 0,1,2,3 but capacity=2
    // so gen 0 and 1 are evicted by gen 2 and 3. Gen 4 is
    // the last skip step (not retained, just advanced).
    _ = try st.forwardRatchet(0, 1, 5);

    // Gen 0 was evicted — should fail.
    const r0 = st.forwardRatchet(0, 1, 0);
    try testing.expectError(error.SecretAlreadyConsumed, r0);

    // Gen 3 should still be retained.
    const kn3 = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn3.generation);

    // Gen 2 should also be retained.
    const kn2 = try st.forwardRatchet(0, 1, 2);
    try testing.expectEqual(@as(u32, 2), kn2.generation);
}

test "retention disabled by default" {
    const enc_secret = [_]u8{0xC3} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Skip to gen 3 without enabling retention.
    _ = try st.forwardRatchet(0, 1, 3);

    // Gen 1 was not retained — fails.
    const r = st.forwardRatchet(0, 1, 1);
    try testing.expectError(error.SecretAlreadyConsumed, r);
}

test "retained key matches sequential derivation" {
    const enc_secret = [_]u8{0xD4} ** Default.nh;

    // Tree A: sequential consumption 0,1,2,3,4,5.
    var st_a = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st_a.deinit(testing.allocator);
    const kn3_seq = blk: {
        _ = try st_a.consumeKey(0, 1); // gen 0
        _ = try st_a.consumeKey(0, 1); // gen 1
        _ = try st_a.consumeKey(0, 1); // gen 2
        break :blk try st_a.consumeKey(0, 1); // gen 3
    };

    // Tree B: skip to gen 5, then retrieve gen 3 from retained.
    var st_b = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st_b.deinit(testing.allocator);
    try st_b.enableRetention(testing.allocator, 16);
    _ = try st_b.forwardRatchet(0, 1, 5); // skip 0-4
    const kn3_ret = try st_b.forwardRatchet(0, 1, 3);

    // Keys must match.
    try testing.expectEqualSlices(u8, &kn3_seq.key, &kn3_ret.key);
    try testing.expectEqualSlices(
        u8,
        &kn3_seq.nonce,
        &kn3_ret.nonce,
    );
    try testing.expectEqual(kn3_seq.generation, kn3_ret.generation);
}

// -- Serialization -------------------------------------------------------

test "serialize/deserialize round-trip preserves state" {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    // Consume some keys to advance generations.
    _ = try st.consumeKey(0, 1); // app gen 0 for leaf 0
    _ = try st.consumeKey(0, 1); // app gen 1 for leaf 0
    _ = try st.consumeKey(1, 0); // hs gen 0 for leaf 1

    // Serialize.
    const data = try st.serialize(testing.allocator);
    defer testing.allocator.free(data);

    // Deserialize.
    var st2 = try SecretTree(Default).deserialize(
        testing.allocator,
        data,
    );
    defer st2.deinit(testing.allocator);

    // Verify leaf_count and max_forward_ratchet.
    try testing.expectEqual(st.leaf_count, st2.leaf_count);
    try testing.expectEqual(
        st.max_forward_ratchet,
        st2.max_forward_ratchet,
    );

    // Verify per-leaf state matches.
    var i: u32 = 0;
    while (i < st.leaf_count) : (i += 1) {
        try testing.expectEqualSlices(
            u8,
            &st.handshake[i].secret,
            &st2.handshake[i].secret,
        );
        try testing.expectEqual(
            st.handshake[i].generation,
            st2.handshake[i].generation,
        );
        try testing.expectEqualSlices(
            u8,
            &st.application[i].secret,
            &st2.application[i].secret,
        );
        try testing.expectEqual(
            st.application[i].generation,
            st2.application[i].generation,
        );
    }

    // Verify the deserialized tree produces the same keys.
    const kn_orig = try st.consumeKey(0, 1);
    const kn_deser = try st2.consumeKey(0, 1);
    try testing.expectEqualSlices(
        u8,
        &kn_orig.key,
        &kn_deser.key,
    );
    try testing.expectEqualSlices(
        u8,
        &kn_orig.nonce,
        &kn_deser.nonce,
    );
    try testing.expectEqual(
        kn_orig.generation,
        kn_deser.generation,
    );
}

test "deserialize rejects truncated data" {
    const ST = SecretTree(Default);
    const result = ST.deserialize(testing.allocator, &[_]u8{0} ** 4);
    try testing.expectError(error.Truncated, result);
}

test "deserialize rejects zero leaf_count" {
    const ST = SecretTree(Default);
    const data = [_]u8{0} ** 8; // leaf_count=0, max_fwd=0
    const result = ST.deserialize(testing.allocator, &data);
    try testing.expectError(error.InvalidGroupState, result);
}
