// Interoperability tests using RFC 9420 official test vectors.
//
// Test vectors sourced from:
//   https://github.com/mlswg/mls-implementations/tree/main/test-vectors
//
// All tests load JSON at runtime via @embedFile + std.json.
// Only cipher suite 1 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
// is tested, matching our default CryptoProvider.

const std = @import("std");
const testing = std.testing;
const zmls = @import("zmls");
const tv = @import("test_vectors");

const P = zmls.DefaultCryptoProvider;
const math = zmls.tree_math;
const NodeIndex = zmls.types.NodeIndex;
const primitives = zmls.crypto_primitives;
const schedule = zmls.key_schedule;
const transcript = zmls.transcript;
const exporter = zmls.exporter;
const codec = zmls.codec;

// Node / credential types for deep-clone helpers.
const Credential = zmls.credential.Credential;
const Certificate = zmls.credential.Certificate;
const Capabilities = zmls.tree_node.Capabilities;
const Extension = zmls.tree_node.Extension;
const ProtocolVersion = zmls.types.ProtocolVersion;
const CipherSuite = zmls.types.CipherSuite;
const ExtensionType = zmls.types.ExtensionType;
const ProposalType = zmls.types.ProposalType;
const CredentialType = zmls.types.CredentialType;

// =====================================================================
// Hex decoder (runtime)
// =====================================================================

/// Decode a hex string into a fixed-size byte array.
/// Returns error on invalid hex or length mismatch.
fn hexDecode(comptime n: u32, hex: []const u8) ![n]u8 {
    if (hex.len != n * 2) return error.InvalidLength;
    var out: [n]u8 = undefined;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const hi = hexVal(hex[i * 2]) orelse
            return error.InvalidHexChar;
        const lo = hexVal(hex[i * 2 + 1]) orelse
            return error.InvalidHexChar;
        out[i] = hi << 4 | lo;
    }
    return out;
}

/// Decode a hex string into an allocator-owned slice.
fn hexDecodeAlloc(
    allocator: std.mem.Allocator,
    hex: []const u8,
) ![]u8 {
    if (hex.len % 2 != 0) return error.InvalidLength;
    const n: u32 = @intCast(hex.len / 2);
    const out = try allocator.alloc(u8, n);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const hi = hexVal(hex[i * 2]) orelse {
            allocator.free(out);
            return error.InvalidHexChar;
        };
        const lo = hexVal(hex[i * 2 + 1]) orelse {
            allocator.free(out);
            return error.InvalidHexChar;
        };
        out[i] = hi << 4 | lo;
    }
    return out;
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// =====================================================================
// 1. Tree Math — loaded from tree-math.json
// =====================================================================

const tree_math_json = tv.tree_math;

const TreeMathEntry = struct {
    n_leaves: u32,
    n_nodes: u32,
    root: u32,
    left: []const ?u32,
    right: []const ?u32,
    parent: []const ?u32,
    sibling: []const ?u32,
};

test "tree math: all entries from JSON" {
    const parsed = try std.json.parseFromSlice(
        []const TreeMathEntry,
        testing.allocator,
        tree_math_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    // Verify we loaded a reasonable number of entries.
    try testing.expect(parsed.value.len >= 10);

    for (parsed.value) |entry| {
        const n = entry.n_leaves;
        const n_nodes = math.nodeWidth(n);
        try testing.expectEqual(entry.n_nodes, n_nodes);

        const r = math.root(n);
        try testing.expectEqual(entry.root, r.toU32());

        // Verify left, right, parent, sibling for every node.
        try testing.expectEqual(
            @as(usize, entry.n_nodes),
            entry.left.len,
        );
        try testing.expectEqual(
            @as(usize, entry.n_nodes),
            entry.right.len,
        );
        try testing.expectEqual(
            @as(usize, entry.n_nodes),
            entry.parent.len,
        );
        try testing.expectEqual(
            @as(usize, entry.n_nodes),
            entry.sibling.len,
        );

        var i: u32 = 0;
        while (i < n_nodes) : (i += 1) {
            const node = NodeIndex.fromU32(i);
            const is_leaf = (i % 2 == 0);

            // left
            if (entry.left[i]) |expected_left| {
                // Non-leaf: left should match.
                try testing.expect(!is_leaf);
                try testing.expectEqual(
                    expected_left,
                    math.left(node).toU32(),
                );
            }

            // right
            if (entry.right[i]) |expected_right| {
                try testing.expect(!is_leaf);
                try testing.expectEqual(
                    expected_right,
                    math.right(node).toU32(),
                );
            }

            // parent (null for root)
            if (entry.parent[i]) |expected_parent| {
                try testing.expectEqual(
                    expected_parent,
                    math.parent(node, n).toU32(),
                );
            }

            // sibling (null for root)
            if (entry.sibling[i]) |expected_sibling| {
                try testing.expectEqual(
                    expected_sibling,
                    math.sibling(node, n).toU32(),
                );
            }
        }
    }
}

// =====================================================================
// 6. Secret Tree — loaded from secret-tree.json
// =====================================================================

const secret_tree_json = tv.secret_tree;

const SecretTreeGeneration = struct {
    generation: u32,
    application_key: []const u8,
    application_nonce: []const u8,
    handshake_key: []const u8,
    handshake_nonce: []const u8,
};

const SecretTreeSenderData = struct {
    sender_data_secret: []const u8,
    ciphertext: []const u8,
    key: []const u8,
    nonce: []const u8,
};

const SecretTreeEntry = struct {
    cipher_suite: u32,
    encryption_secret: []const u8,
    sender_data: SecretTreeSenderData,
    leaves: []const []const SecretTreeGeneration,
};

test "secret tree: sender data key/nonce (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const SecretTreeEntry,
        testing.allocator,
        secret_tree_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    for (parsed.value) |entry| {
        if (entry.cipher_suite != 1) continue;

        const sd = entry.sender_data;
        const sd_secret = try hexDecode(
            P.nh,
            sd.sender_data_secret,
        );
        const ct = try hexDecodeAlloc(
            testing.allocator,
            sd.ciphertext,
        );
        defer testing.allocator.free(ct);
        const expected_key = try hexDecode(P.nk, sd.key);
        const expected_nonce = try hexDecode(P.nn, sd.nonce);

        const kn = zmls.private_msg.deriveSenderDataKeyNonce(
            P,
            &sd_secret,
            ct,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_key,
            &kn.key,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_nonce,
            &kn.nonce,
        );
    }
}

test "secret tree: leaf key/nonce derivation (cipher suite 1)" {
    const SecretTree = zmls.secret_tree.SecretTree(P);

    const parsed = try std.json.parseFromSlice(
        []const SecretTreeEntry,
        testing.allocator,
        secret_tree_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    for (parsed.value) |entry| {
        if (entry.cipher_suite != 1) continue;

        const enc_secret = try hexDecode(
            P.nh,
            entry.encryption_secret,
        );
        const leaf_count: u32 = @intCast(entry.leaves.len);

        for (entry.leaves, 0..) |gens, leaf_i| {
            for (gens) |gen| {
                // Verify handshake key/nonce.
                {
                    var tree = try SecretTree.init(
                        testing.allocator,
                        &enc_secret,
                        leaf_count,
                    );
                    defer tree.deinit(testing.allocator);
                    tree.max_forward_ratchet = 0;

                    const kn = try tree.forwardRatchet(
                        @intCast(leaf_i),
                        0,
                        gen.generation,
                    );

                    const exp_key = try hexDecode(
                        P.nk,
                        gen.handshake_key,
                    );
                    const exp_nonce = try hexDecode(
                        P.nn,
                        gen.handshake_nonce,
                    );
                    try testing.expectEqualSlices(
                        u8,
                        &exp_key,
                        &kn.key,
                    );
                    try testing.expectEqualSlices(
                        u8,
                        &exp_nonce,
                        &kn.nonce,
                    );
                }
                // Verify application key/nonce.
                {
                    var tree = try SecretTree.init(
                        testing.allocator,
                        &enc_secret,
                        leaf_count,
                    );
                    defer tree.deinit(testing.allocator);
                    tree.max_forward_ratchet = 0;

                    const kn = try tree.forwardRatchet(
                        @intCast(leaf_i),
                        1,
                        gen.generation,
                    );

                    const exp_key = try hexDecode(
                        P.nk,
                        gen.application_key,
                    );
                    const exp_nonce = try hexDecode(
                        P.nn,
                        gen.application_nonce,
                    );
                    try testing.expectEqualSlices(
                        u8,
                        &exp_key,
                        &kn.key,
                    );
                    try testing.expectEqualSlices(
                        u8,
                        &exp_nonce,
                        &kn.nonce,
                    );
                }
            }
        }
    }
}

// =====================================================================
// 2. Crypto Basics — loaded from crypto-basics.json
// =====================================================================

const crypto_basics_json = tv.crypto_basics;

const CryptoBasicsEntry = struct {
    cipher_suite: u32,
    ref_hash: struct {
        label: []const u8,
        value: []const u8,
        out: []const u8,
    },
    expand_with_label: struct {
        secret: []const u8,
        label: []const u8,
        context: []const u8,
        length: u32,
        out: []const u8,
    },
    derive_secret: struct {
        secret: []const u8,
        label: []const u8,
        out: []const u8,
    },
    derive_tree_secret: struct {
        secret: []const u8,
        label: []const u8,
        generation: u32,
        length: u32,
        out: []const u8,
    },
    sign_with_label: struct {
        priv: []const u8,
        pub_key: []const u8,
        content: []const u8,
        label: []const u8,
        signature: []const u8,

        // JSON field is "pub" but that's a Zig keyword; use rename.
        pub const jsonParse = @compileError("unused");
        pub const jsonParseFromValue = @compileError("unused");
        pub const jsonStringify = @compileError("unused");
    },
    encrypt_with_label: struct {
        priv: []const u8,
        pub_key: []const u8,
        label: []const u8,
        context: []const u8,
        plaintext: []const u8,
        kem_output: []const u8,
        ciphertext: []const u8,

        pub const jsonParse = @compileError("unused");
        pub const jsonParseFromValue = @compileError("unused");
        pub const jsonStringify = @compileError("unused");
    },
};

// The "pub" field in JSON clashes with Zig keyword. We must parse
// manually using std.json.Value instead of typed parsing.

const CryptoBasicsRaw = struct {
    cipher_suite: u32,
    ref_hash: std.json.Value,
    expand_with_label: std.json.Value,
    derive_secret: std.json.Value,
    derive_tree_secret: std.json.Value,
    sign_with_label: std.json.Value,
    encrypt_with_label: std.json.Value,
};

fn getStr(obj: std.json.Value, key: []const u8) []const u8 {
    return obj.object.get(key).?.string;
}

fn getU32(obj: std.json.Value, key: []const u8) u32 {
    return @intCast(obj.object.get(key).?.integer);
}

test "crypto basics: RefHash (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    // Find cipher suite 1 entry.
    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    // RefHash
    {
        const rh = cs1.ref_hash;
        const label = getStr(rh, "label");
        const value = try hexDecodeAlloc(
            testing.allocator,
            getStr(rh, "value"),
        );
        defer testing.allocator.free(value);
        const expected = try hexDecode(P.nh, getStr(rh, "out"));

        const result = primitives.refHash(
            P,
            label,
            value,
        );
        try testing.expectEqualSlices(u8, &expected, &result);
    }
}

test "crypto basics: ExpandWithLabel (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    {
        const ewl = cs1.expand_with_label;
        const secret = try hexDecode(P.nh, getStr(ewl, "secret"));
        const label = getStr(ewl, "label");
        const context = try hexDecodeAlloc(
            testing.allocator,
            getStr(ewl, "context"),
        );
        defer testing.allocator.free(context);
        const length = getU32(ewl, "length");
        const expected = try hexDecodeAlloc(
            testing.allocator,
            getStr(ewl, "out"),
        );
        defer testing.allocator.free(expected);

        const out = try testing.allocator.alloc(u8, length);
        defer testing.allocator.free(out);

        primitives.expandWithLabel(P, &secret, label, context, out);
        try testing.expectEqualSlices(u8, expected, out);
    }
}

test "crypto basics: DeriveSecret (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    {
        const ds = cs1.derive_secret;
        const secret = try hexDecode(P.nh, getStr(ds, "secret"));
        const label = getStr(ds, "label");
        const expected = try hexDecode(P.nh, getStr(ds, "out"));

        const result = primitives.deriveSecret(P, &secret, label);
        try testing.expectEqualSlices(u8, &expected, &result);
    }
}

test "crypto basics: DeriveTreeSecret (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    {
        const dts = cs1.derive_tree_secret;
        const secret = try hexDecode(P.nh, getStr(dts, "secret"));
        const label = getStr(dts, "label");
        const generation = getU32(dts, "generation");
        const length = getU32(dts, "length");
        const expected = try hexDecodeAlloc(
            testing.allocator,
            getStr(dts, "out"),
        );
        defer testing.allocator.free(expected);

        // Encode generation as 4-byte big-endian context.
        var gen_buf: [4]u8 = undefined;
        _ = codec.encodeUint32(&gen_buf, 0, generation) catch
            unreachable;

        const out = try testing.allocator.alloc(u8, length);
        defer testing.allocator.free(out);

        primitives.expandWithLabel(
            P,
            &secret,
            label,
            &gen_buf,
            out,
        );
        try testing.expectEqualSlices(u8, expected, out);
    }
}

test "crypto basics: SignWithLabel (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    {
        const swl = cs1.sign_with_label;
        const priv_bytes = try hexDecode(32, getStr(swl, "priv"));
        const pub_bytes = try hexDecode(
            P.sign_pk_len,
            getStr(swl, "pub"),
        );
        const content = try hexDecodeAlloc(
            testing.allocator,
            getStr(swl, "content"),
        );
        defer testing.allocator.free(content);
        const label = getStr(swl, "label");
        const expected_sig = try hexDecode(
            P.sig_len,
            getStr(swl, "signature"),
        );

        // Ed25519 secret key = 32-byte seed || 32-byte public key.
        var sk: [P.sign_sk_len]u8 = undefined;
        @memcpy(sk[0..32], &priv_bytes);
        @memcpy(sk[32..64], &pub_bytes);

        // Verify the test vector signature.
        try primitives.verifyWithLabel(
            P,
            &pub_bytes,
            label,
            content,
            &expected_sig,
        );

        // Ed25519 is deterministic — our signature should match.
        const our_sig = try primitives.signWithLabel(
            P,
            &sk,
            label,
            content,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_sig,
            &our_sig,
        );
    }
}

test "crypto basics: EncryptWithLabel (cipher suite 1)" {
    const parsed = try std.json.parseFromSlice(
        []const CryptoBasicsRaw,
        testing.allocator,
        crypto_basics_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?CryptoBasicsRaw = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    {
        const ewl = cs1.encrypt_with_label;
        const priv_bytes = try hexDecode(
            P.nsk,
            getStr(ewl, "priv"),
        );
        const pub_bytes = try hexDecode(
            P.npk,
            getStr(ewl, "pub"),
        );
        const plaintext = try hexDecodeAlloc(
            testing.allocator,
            getStr(ewl, "plaintext"),
        );
        defer testing.allocator.free(plaintext);
        const context = try hexDecodeAlloc(
            testing.allocator,
            getStr(ewl, "context"),
        );
        defer testing.allocator.free(context);
        const label = getStr(ewl, "label");
        const kem_output = try hexDecode(
            P.npk,
            getStr(ewl, "kem_output"),
        );
        const full_ct = try hexDecodeAlloc(
            testing.allocator,
            getStr(ewl, "ciphertext"),
        );
        defer testing.allocator.free(full_ct);

        // ciphertext = ct_bytes || tag (P.nt bytes).
        const ct_len: u32 = @intCast(full_ct.len - P.nt);
        const ct_part = full_ct[0..ct_len];
        var tag: [P.nt]u8 = undefined;
        @memcpy(&tag, full_ct[ct_len..]);

        const pt_out = try testing.allocator.alloc(u8, ct_len);
        defer testing.allocator.free(pt_out);

        try primitives.decryptWithLabel(
            P,
            &priv_bytes,
            &pub_bytes,
            label,
            context,
            &kem_output,
            ct_part,
            &tag,
            pt_out,
        );
        try testing.expectEqualSlices(u8, plaintext, pt_out);
    }
}

// =====================================================================
// 3. Key Schedule — loaded from key-schedule.json
// =====================================================================

const key_schedule_json = tv.key_schedule;

const KeyScheduleExporter = struct {
    label: []const u8,
    context: []const u8,
    length: u32,
    secret: []const u8,
};

const KeyScheduleEpoch = struct {
    group_context: []const u8,
    commit_secret: []const u8,
    psk_secret: []const u8,
    joiner_secret: []const u8,
    welcome_secret: []const u8,
    init_secret: []const u8,
    sender_data_secret: []const u8,
    encryption_secret: []const u8,
    exporter_secret: []const u8,
    external_secret: []const u8,
    confirmation_key: []const u8,
    membership_key: []const u8,
    resumption_psk: []const u8,
    epoch_authenticator: []const u8,
    tree_hash: []const u8,
    confirmed_transcript_hash: []const u8,
    external_pub: []const u8,
    exporter: KeyScheduleExporter,
};

const KeyScheduleEntry = struct {
    cipher_suite: u32,
    group_id: []const u8,
    initial_init_secret: []const u8,
    epochs: []const KeyScheduleEpoch,
};

test "key schedule: cipher suite 1, all epochs" {
    const parsed = try std.json.parseFromSlice(
        []const KeyScheduleEntry,
        testing.allocator,
        key_schedule_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    // Find cipher suite 1.
    var entry: ?KeyScheduleEntry = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;
    try testing.expect(cs1.epochs.len >= 5);

    var current_init = try hexDecode(
        P.nh,
        cs1.initial_init_secret,
    );

    for (cs1.epochs) |epoch| {
        const commit_secret = try hexDecode(
            P.nh,
            epoch.commit_secret,
        );
        const psk_secret = try hexDecode(
            P.nh,
            epoch.psk_secret,
        );
        const gc = try hexDecodeAlloc(
            testing.allocator,
            epoch.group_context,
        );
        defer testing.allocator.free(gc);

        const secrets = schedule.deriveEpochSecrets(
            P,
            &current_init,
            &commit_secret,
            &psk_secret,
            gc,
        );

        // Verify all epoch secrets.
        const expected_joiner = try hexDecode(
            P.nh,
            epoch.joiner_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_joiner,
            &secrets.joiner_secret,
        );

        const expected_welcome = try hexDecode(
            P.nh,
            epoch.welcome_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_welcome,
            &secrets.welcome_secret,
        );

        const expected_sender = try hexDecode(
            P.nh,
            epoch.sender_data_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_sender,
            &secrets.sender_data_secret,
        );

        const expected_enc = try hexDecode(
            P.nh,
            epoch.encryption_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_enc,
            &secrets.encryption_secret,
        );

        const expected_exp = try hexDecode(
            P.nh,
            epoch.exporter_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_exp,
            &secrets.exporter_secret,
        );

        const expected_ext = try hexDecode(
            P.nh,
            epoch.external_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_ext,
            &secrets.external_secret,
        );

        const expected_conf = try hexDecode(
            P.nh,
            epoch.confirmation_key,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_conf,
            &secrets.confirmation_key,
        );

        const expected_memb = try hexDecode(
            P.nh,
            epoch.membership_key,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_memb,
            &secrets.membership_key,
        );

        const expected_resum = try hexDecode(
            P.nh,
            epoch.resumption_psk,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_resum,
            &secrets.resumption_psk,
        );

        const expected_auth = try hexDecode(
            P.nh,
            epoch.epoch_authenticator,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_auth,
            &secrets.epoch_authenticator,
        );

        const expected_init = try hexDecode(
            P.nh,
            epoch.init_secret,
        );
        try testing.expectEqualSlices(
            u8,
            &expected_init,
            &secrets.init_secret,
        );

        // Verify MLS exporter.
        {
            const exp_data = epoch.exporter;
            const exp_secret = try hexDecode(
                P.nh,
                exp_data.secret,
            );
            const exp_context = try hexDecodeAlloc(
                testing.allocator,
                exp_data.context,
            );
            defer testing.allocator.free(exp_context);

            const exp_out = try testing.allocator.alloc(
                u8,
                exp_data.length,
            );
            defer testing.allocator.free(exp_out);

            exporter.mlsExporter(
                P,
                &secrets.exporter_secret,
                exp_data.label,
                exp_context,
                exp_out,
            );
            try testing.expectEqualSlices(
                u8,
                &exp_secret,
                exp_out,
            );
        }

        // Chain to next epoch.
        current_init = secrets.init_secret;
    }
}

// =====================================================================
// 4. Transcript Hashes — loaded from transcript-hashes.json
// =====================================================================

const transcript_hashes_json = tv.transcript_hashes;

const TranscriptHashEntry = struct {
    cipher_suite: u32,
    confirmation_key: []const u8,
    authenticated_content: []const u8,
    interim_transcript_hash_before: []const u8,
    confirmed_transcript_hash_after: []const u8,
    interim_transcript_hash_after: []const u8,
};

test "transcript hashes: cipher suite 1" {
    const parsed = try std.json.parseFromSlice(
        []const TranscriptHashEntry,
        testing.allocator,
        transcript_hashes_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var entry: ?TranscriptHashEntry = null;
    for (parsed.value) |e| {
        if (e.cipher_suite == 1) {
            entry = e;
            break;
        }
    }
    const cs1 = entry orelse return error.NoCipherSuite1;

    const conf_key = try hexDecode(P.nh, cs1.confirmation_key);
    const ac = try hexDecodeAlloc(
        testing.allocator,
        cs1.authenticated_content,
    );
    defer testing.allocator.free(ac);
    const interim_before = try hexDecode(
        P.nh,
        cs1.interim_transcript_hash_before,
    );
    const expected_confirmed = try hexDecode(
        P.nh,
        cs1.confirmed_transcript_hash_after,
    );
    const expected_interim = try hexDecode(
        P.nh,
        cs1.interim_transcript_hash_after,
    );

    // ConfirmedTranscriptHashInput = AuthenticatedContent minus
    // the trailing confirmation_tag (1 byte varint + 32 bytes).
    const confirmed_input = ac[0 .. ac.len - 33];
    const confirmation_tag_raw = ac[ac.len - 32 ..];

    // Step 1: Compute confirmed transcript hash.
    const confirmed_hash = try transcript.updateConfirmedTranscriptHash(
        P,
        &interim_before,
        confirmed_input,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_confirmed,
        &confirmed_hash,
    );

    // Step 2: Verify confirmation tag.
    const computed_tag = zmls.computeConfirmationTag(
        P,
        &conf_key,
        &confirmed_hash,
    );
    try testing.expectEqualSlices(
        u8,
        confirmation_tag_raw,
        &computed_tag,
    );

    // Step 3: Compute interim transcript hash.
    const interim_hash = try transcript.updateInterimTranscriptHash(
        P,
        &confirmed_hash,
        &computed_tag,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_interim,
        &interim_hash,
    );
}

// =====================================================================
// 5. Deserialization (variable-length vectors) — deserialization.json
// =====================================================================

const deserialization_json = tv.deserialization;

const DeserializationEntry = struct {
    vlbytes_header: []const u8,
    length: u32,
};

test "deserialization: varint round-trip from JSON" {
    const parsed = try std.json.parseFromSlice(
        []const DeserializationEntry,
        testing.allocator,
        deserialization_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    try testing.expect(parsed.value.len >= 10);

    const vint = zmls.varint;

    for (parsed.value) |entry| {
        const header_bytes = try hexDecodeAlloc(
            testing.allocator,
            entry.vlbytes_header,
        );
        defer testing.allocator.free(header_bytes);

        // Decode: parse the varint header, verify length matches.
        const decoded = try vint.decode(header_bytes, 0);
        try testing.expectEqual(entry.length, decoded.value);

        // Encode: encode the length, verify output matches header.
        var encode_buf: [4]u8 = undefined;
        const new_pos = try vint.encode(
            &encode_buf,
            0,
            entry.length,
        );
        const encoded_len: u32 = @intCast(header_bytes.len);
        try testing.expectEqual(encoded_len, new_pos);
        try testing.expectEqualSlices(
            u8,
            header_bytes,
            encode_buf[0..new_pos],
        );
    }
}

// =====================================================================
// 7. Message Protection — loaded from message-protection.json
// =====================================================================

const message_protection_json = tv.message_protection;

const MsgProtEntry = struct {
    cipher_suite: u32,
    group_id: []const u8,
    epoch: u64,
    tree_hash: []const u8,
    confirmed_transcript_hash: []const u8,
    signature_priv: []const u8,
    signature_pub: []const u8,
    encryption_secret: []const u8,
    sender_data_secret: []const u8,
    membership_key: []const u8,
    proposal: []const u8,
    proposal_priv: []const u8,
    proposal_pub: []const u8,
    commit: []const u8,
    commit_priv: []const u8,
    commit_pub: []const u8,
    application: []const u8,
    application_priv: []const u8,
};

const MsgProtPublicMsg = zmls.public_msg.PublicMessage(P);
const MsgProtAuthData = zmls.framing_auth.FramedContentAuthData(P);
const MLSMessage = zmls.mls_message.MLSMessage;
const MsgProtSecretTree = zmls.secret_tree.SecretTree(P);
const MsgProtSenderData = zmls.private_msg.SenderData;
const MsgProtPrivateMessage = zmls.private_msg.PrivateMessage;
const MsgProtGC = zmls.GroupContext(P.nh);
const MsgProtFramedContent = zmls.FramedContent;
const MsgProtSender = zmls.Sender;

/// Build serialized GroupContext bytes from test vector fields.
fn buildTestGroupContext(
    alloc: std.mem.Allocator,
    entry: MsgProtEntry,
) ![]u8 {
    const group_id = try hexDecodeAlloc(alloc, entry.group_id);
    defer alloc.free(group_id);
    const tree_hash = try hexDecode(P.nh, entry.tree_hash);
    const cth = try hexDecode(
        P.nh,
        entry.confirmed_transcript_hash,
    );

    const gc = MsgProtGC{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = group_id,
        .epoch = entry.epoch,
        .tree_hash = tree_hash,
        .confirmed_transcript_hash = cth,
        .extensions = &.{},
    };

    var buf: [zmls.group_context.max_gc_encode]u8 = undefined;
    const gc_bytes = gc.serialize(&buf) catch
        return error.InvalidLength;
    const out = try alloc.alloc(u8, gc_bytes.len);
    @memcpy(out, gc_bytes);
    return out;
}

fn findMsgProtCS1(
    entries: []const MsgProtEntry,
) ?MsgProtEntry {
    for (entries) |e| {
        if (e.cipher_suite == 1) return e;
    }
    return null;
}

test "message protection: PublicMessage proposal (CS 1)" {
    const parsed = try std.json.parseFromSlice(
        []const MsgProtEntry,
        testing.allocator,
        message_protection_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const entry = findMsgProtCS1(parsed.value) orelse
        return error.NoCipherSuite1;

    // Decode proposal_pub wire bytes.
    const wire = try hexDecodeAlloc(
        testing.allocator,
        entry.proposal_pub,
    );
    defer testing.allocator.free(wire);

    const mls_result = try MLSMessage.decode(wire, 0);
    try testing.expectEqual(
        zmls.WireFormat.mls_public_message,
        mls_result.value.wire_format,
    );

    const pub_bytes = mls_result.value.body.public_message;
    const pm_result = try MsgProtPublicMsg.decode(
        pub_bytes,
        0,
    );
    const pub_msg = pm_result.value;

    // Build GroupContext.
    const gc_bytes = try buildTestGroupContext(
        testing.allocator,
        entry,
    );
    defer testing.allocator.free(gc_bytes);

    // Verify membership tag.
    const mk = try hexDecode(P.nh, entry.membership_key);
    try zmls.public_msg.verifyMembershipTag(
        P,
        &mk,
        &pub_msg.content,
        &pub_msg.auth,
        &pub_msg.membership_tag.?,
        gc_bytes,
    );

    // Verify signature.
    const sig_pub = try hexDecode(
        P.sign_pk_len,
        entry.signature_pub,
    );
    try zmls.framing_auth.verifyFramedContent(
        P,
        &pub_msg.content,
        .mls_public_message,
        gc_bytes,
        &sig_pub,
        &pub_msg.auth,
    );

    // Verify content matches expected proposal.
    const expected = try hexDecodeAlloc(
        testing.allocator,
        entry.proposal,
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(
        u8,
        expected,
        pub_msg.content.content,
    );
}

test "message protection: PublicMessage commit (CS 1)" {
    const parsed = try std.json.parseFromSlice(
        []const MsgProtEntry,
        testing.allocator,
        message_protection_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const entry = findMsgProtCS1(parsed.value) orelse
        return error.NoCipherSuite1;

    const wire = try hexDecodeAlloc(
        testing.allocator,
        entry.commit_pub,
    );
    defer testing.allocator.free(wire);

    const mls_result = try MLSMessage.decode(wire, 0);
    const pub_bytes = mls_result.value.body.public_message;
    const pm_result = try MsgProtPublicMsg.decode(
        pub_bytes,
        0,
    );
    const pub_msg = pm_result.value;

    const gc_bytes = try buildTestGroupContext(
        testing.allocator,
        entry,
    );
    defer testing.allocator.free(gc_bytes);

    // Verify membership tag.
    const mk = try hexDecode(P.nh, entry.membership_key);
    try zmls.public_msg.verifyMembershipTag(
        P,
        &mk,
        &pub_msg.content,
        &pub_msg.auth,
        &pub_msg.membership_tag.?,
        gc_bytes,
    );

    // Verify signature.
    const sig_pub = try hexDecode(
        P.sign_pk_len,
        entry.signature_pub,
    );
    try zmls.framing_auth.verifyFramedContent(
        P,
        &pub_msg.content,
        .mls_public_message,
        gc_bytes,
        &sig_pub,
        &pub_msg.auth,
    );

    // Verify content matches expected commit.
    const expected = try hexDecodeAlloc(
        testing.allocator,
        entry.commit,
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(
        u8,
        expected,
        pub_msg.content.content,
    );
}

/// Decrypt a PrivateMessage from test vector wire bytes.
/// Returns the decrypted content bytes (caller owns).
fn decryptTestPrivateMsg(
    alloc: std.mem.Allocator,
    wire_hex: []const u8,
    entry: MsgProtEntry,
    gc_bytes: []const u8,
    expected_content_type: zmls.ContentType,
) ![]u8 {
    const wire = try hexDecodeAlloc(alloc, wire_hex);
    defer alloc.free(wire);

    const mls_result = try MLSMessage.decode(wire, 0);
    try testing.expectEqual(
        zmls.WireFormat.mls_private_message,
        mls_result.value.wire_format,
    );
    const priv_msg = mls_result.value.body.private_message;

    // Build SenderDataAAD.
    var sd_aad_buf: [256]u8 = undefined;
    const sd_aad_len = zmls.private_msg.buildSenderDataAad(
        &sd_aad_buf,
        priv_msg.group_id,
        priv_msg.epoch,
        priv_msg.content_type,
    ) catch return error.InvalidLength;
    const sd_aad = sd_aad_buf[0..sd_aad_len];

    // Derive sender data key/nonce and decrypt sender data.
    const sds = try hexDecode(P.nh, entry.sender_data_secret);
    const sd_result = try zmls.private_msg.decryptSenderData(
        P,
        priv_msg.encrypted_sender_data,
        &sds,
        priv_msg.ciphertext,
        sd_aad,
    );

    // Derive content key/nonce from secret tree.
    const enc_secret = try hexDecode(
        P.nh,
        entry.encryption_secret,
    );

    // content_type: 0 = handshake (proposal/commit),
    //               1 = application
    const ct_idx: u8 = if (expected_content_type == .application)
        1
    else
        0;

    var tree = try MsgProtSecretTree.init(
        alloc,
        &enc_secret,
        2, // 2 leaves (sender is leaf 0)
    );
    defer tree.deinit(alloc);
    tree.max_forward_ratchet = 0;

    const kn = try tree.forwardRatchet(
        sd_result.leaf_index,
        ct_idx,
        sd_result.generation,
    );

    // Apply reuse guard.
    var nonce = kn.nonce;
    zmls.private_msg.applyReuseGuard(
        P,
        &nonce,
        &sd_result.reuse_guard,
    );

    // Build PrivateContentAAD.
    var aad_buf: [256]u8 = undefined;
    const aad_len = zmls.private_msg.buildPrivateContentAad(
        &aad_buf,
        priv_msg.group_id,
        priv_msg.epoch,
        priv_msg.content_type,
        priv_msg.authenticated_data,
    ) catch return error.InvalidLength;

    // Decrypt content.
    const ct_len: u32 = @intCast(
        priv_msg.ciphertext.len - P.nt,
    );
    const pt_buf = try alloc.alloc(u8, ct_len);
    errdefer alloc.free(pt_buf);

    const decrypted = zmls.private_msg.decryptContent(
        P,
        priv_msg.ciphertext,
        priv_msg.content_type,
        &kn.key,
        &nonce,
        aad_buf[0..aad_len],
        pt_buf,
    ) catch return error.InvalidLength;

    // Verify signature: reconstruct FramedContent.
    const fc = MsgProtFramedContent{
        .group_id = priv_msg.group_id,
        .epoch = priv_msg.epoch,
        .sender = MsgProtSender.member(
            zmls.types.LeafIndex.fromU32(sd_result.leaf_index),
        ),
        .authenticated_data = priv_msg.authenticated_data,
        .content_type = priv_msg.content_type,
        .content = decrypted.content,
    };

    const sig_pub = try hexDecode(
        P.sign_pk_len,
        entry.signature_pub,
    );
    try zmls.framing_auth.verifyFramedContent(
        P,
        &fc,
        .mls_private_message,
        gc_bytes,
        &sig_pub,
        &decrypted.auth,
    );

    // Copy content to caller-owned buffer.
    const out = try alloc.alloc(u8, decrypted.content.len);
    @memcpy(out, decrypted.content);
    alloc.free(pt_buf);
    return out;
}

test "message protection: PrivateMessage proposal (CS 1)" {
    const parsed = try std.json.parseFromSlice(
        []const MsgProtEntry,
        testing.allocator,
        message_protection_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const entry = findMsgProtCS1(parsed.value) orelse
        return error.NoCipherSuite1;

    const gc_bytes = try buildTestGroupContext(
        testing.allocator,
        entry,
    );
    defer testing.allocator.free(gc_bytes);

    const content = try decryptTestPrivateMsg(
        testing.allocator,
        entry.proposal_priv,
        entry,
        gc_bytes,
        .proposal,
    );
    defer testing.allocator.free(content);

    const expected = try hexDecodeAlloc(
        testing.allocator,
        entry.proposal,
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, content);
}

test "message protection: PrivateMessage commit (CS 1)" {
    const parsed = try std.json.parseFromSlice(
        []const MsgProtEntry,
        testing.allocator,
        message_protection_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const entry = findMsgProtCS1(parsed.value) orelse
        return error.NoCipherSuite1;

    const gc_bytes = try buildTestGroupContext(
        testing.allocator,
        entry,
    );
    defer testing.allocator.free(gc_bytes);

    const content = try decryptTestPrivateMsg(
        testing.allocator,
        entry.commit_priv,
        entry,
        gc_bytes,
        .commit,
    );
    defer testing.allocator.free(content);

    const expected = try hexDecodeAlloc(
        testing.allocator,
        entry.commit,
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, content);
}

test "message protection: PrivateMessage application (CS 1)" {
    const parsed = try std.json.parseFromSlice(
        []const MsgProtEntry,
        testing.allocator,
        message_protection_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();
    const entry = findMsgProtCS1(parsed.value) orelse
        return error.NoCipherSuite1;

    const gc_bytes = try buildTestGroupContext(
        testing.allocator,
        entry,
    );
    defer testing.allocator.free(gc_bytes);

    const content = try decryptTestPrivateMsg(
        testing.allocator,
        entry.application_priv,
        entry,
        gc_bytes,
        .application,
    );
    defer testing.allocator.free(content);

    const expected = try hexDecodeAlloc(
        testing.allocator,
        entry.application,
    );
    defer testing.allocator.free(expected);
    try testing.expectEqualSlices(u8, expected, content);
}

// =====================================================================
// 8. PSK Secret — loaded from psk_secret.json
// =====================================================================

const psk_secret_json = tv.psk_secret;

const PskSecretPskEntry = struct {
    psk_id: []const u8,
    psk: []const u8,
    psk_nonce: []const u8,
};

const PskSecretEntry = struct {
    cipher_suite: u32,
    psks: []const PskSecretPskEntry,
    psk_secret: []const u8,
};

/// Run PSK secret derivation for a given provider and expected
/// hash length. Returns true if the computed value matches.
fn verifyPskSecret(
    comptime Prov: type,
    entry: PskSecretEntry,
) !void {
    const alloc = testing.allocator;
    const PskEntry = zmls.psk.PskEntry;
    const PskId = zmls.psk.PreSharedKeyId;

    const n = entry.psks.len;
    const entries = try alloc.alloc(PskEntry, n);
    defer alloc.free(entries);

    // Allocate decoded buffers for each PSK.
    var decoded_ids = try alloc.alloc([]u8, n);
    defer {
        for (decoded_ids[0..n]) |buf| alloc.free(buf);
        alloc.free(decoded_ids);
    }
    var decoded_secrets = try alloc.alloc([]u8, n);
    defer {
        for (decoded_secrets[0..n]) |buf| alloc.free(buf);
        alloc.free(decoded_secrets);
    }
    var decoded_nonces = try alloc.alloc([]u8, n);
    defer {
        for (decoded_nonces[0..n]) |buf| alloc.free(buf);
        alloc.free(decoded_nonces);
    }

    for (entry.psks, 0..) |psk, i| {
        decoded_ids[i] = try hexDecodeAlloc(alloc, psk.psk_id);
        decoded_secrets[i] = try hexDecodeAlloc(alloc, psk.psk);
        decoded_nonces[i] = try hexDecodeAlloc(
            alloc,
            psk.psk_nonce,
        );
        entries[i] = PskEntry{
            .id = PskId{
                .psk_type = .external,
                .external_psk_id = decoded_ids[i],
                .resumption_usage = .reserved,
                .resumption_group_id = "",
                .resumption_epoch = 0,
                .psk_nonce = decoded_nonces[i],
            },
            .secret = decoded_secrets[i],
        };
    }

    const result = try zmls.psk.derivePskSecret(Prov, entries);
    const expected = try hexDecode(Prov.nh, entry.psk_secret);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "psk secret: cipher suite 1 (all counts)" {
    const parsed = try std.json.parseFromSlice(
        []const PskSecretEntry,
        testing.allocator,
        psk_secret_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyPskSecret(
                zmls.DefaultCryptoProvider,
                entry,
            );
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

test "psk secret: cipher suite 2 (all counts)" {
    const parsed = try std.json.parseFromSlice(
        []const PskSecretEntry,
        testing.allocator,
        psk_secret_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 2) {
            try verifyPskSecret(
                zmls.P256CryptoProvider,
                entry,
            );
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

test "psk secret: cipher suite 3 (all counts)" {
    const parsed = try std.json.parseFromSlice(
        []const PskSecretEntry,
        testing.allocator,
        psk_secret_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 3) {
            try verifyPskSecret(
                zmls.ChaCha20CryptoProvider,
                entry,
            );
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 9. Welcome — loaded from welcome.json
// =====================================================================
//
// Each entry provides: cipher_suite, init_priv, signer_pub,
// key_package (MLSMessage-wrapped), welcome (MLSMessage-wrapped).
//
// Test: decode Welcome, decode KeyPackage, compute kp_ref,
// decrypt GroupSecrets, derive welcome_secret, decrypt GroupInfo,
// verify GroupInfo signature.

const welcome_json = tv.welcome;
const WelcomeMsg = zmls.welcome.Welcome;
const WelcomeGS = zmls.welcome.GroupSecrets;
const KeyPackage = zmls.key_package.KeyPackage;
const GroupInfo = zmls.group_info;

const WelcomeEntry = struct {
    cipher_suite: u32,
    init_priv: []const u8,
    signer_pub: []const u8,
    key_package: []const u8,
    welcome: []const u8,
};

fn verifyWelcome(
    comptime Prov: type,
    entry: WelcomeEntry,
) !void {
    const allocator = testing.allocator;

    // 1. Decode key_package: strip 4-byte MLSMessage header.
    const kp_wire = try hexDecodeAlloc(
        allocator,
        entry.key_package,
    );
    defer allocator.free(kp_wire);

    if (kp_wire.len < 4) return error.Truncated;
    const kp_inner = kp_wire[4..];

    // Decode KeyPackage from inner bytes.
    var kp_r = try KeyPackage.decode(
        allocator,
        kp_inner,
        0,
    );
    defer kp_r.value.deinit(allocator);

    // 2. Compute KeyPackageRef.
    const kp_ref = try kp_r.value.makeRef(Prov);

    // 3. Decode init_priv (secret key).
    const init_sk = try hexDecode(Prov.nsk, entry.init_priv);

    // 4. Extract init_pk from KeyPackage.
    if (kp_r.value.init_key.len != Prov.npk)
        return error.InvalidLength;
    const init_pk: *const [Prov.npk]u8 =
        kp_r.value.init_key[0..Prov.npk];

    // 5. Decode welcome: strip 4-byte MLSMessage header.
    const w_wire = try hexDecodeAlloc(
        allocator,
        entry.welcome,
    );
    defer allocator.free(w_wire);

    if (w_wire.len < 4) return error.Truncated;
    const w_inner = w_wire[4..];

    var w_r = try WelcomeMsg.decode(
        allocator,
        w_inner,
        0,
    );
    defer w_r.value.deinit(allocator);

    // 6. Decrypt GroupSecrets.
    var gs = try zmls.welcome.decryptGroupSecrets(
        Prov,
        allocator,
        &w_r.value,
        &kp_ref,
        &init_sk,
        init_pk,
    );
    defer gs.deinit(allocator);

    // 7. Derive welcome_secret from joiner_secret + zero psk.
    if (gs.joiner_secret.len != Prov.nh)
        return error.InvalidLength;
    const joiner: *const [Prov.nh]u8 =
        gs.joiner_secret[0..Prov.nh];
    const zero_psk = [_]u8{0} ** Prov.nh;

    // welcome_secret = DeriveSecret(
    //     KDF.Extract(joiner_secret, psk_secret), "welcome")
    const member_prk = Prov.kdfExtract(joiner, &zero_psk);
    const welcome_secret = primitives.deriveSecret(
        Prov,
        &member_prk,
        "welcome",
    );

    // 8. Decrypt GroupInfo.
    const egi = w_r.value.encrypted_group_info;
    if (egi.len < Prov.nt) return error.Truncated;
    const gi_pt_len: u32 = @intCast(egi.len - Prov.nt);
    const gi_pt = try allocator.alloc(u8, gi_pt_len);
    defer allocator.free(gi_pt);

    try GroupInfo.decryptGroupInfo(
        Prov,
        &welcome_secret,
        egi,
        gi_pt,
    );

    // 9. Decode GroupInfo.
    var gi_r = try GroupInfo.GroupInfo.decode(
        allocator,
        gi_pt,
        0,
    );
    defer gi_r.value.deinit(allocator);

    // 10. Verify GroupInfo signature.
    const signer_pub = try hexDecode(
        Prov.sign_pk_len,
        entry.signer_pub,
    );
    try GroupInfo.verifyGroupInfo(
        Prov,
        &gi_r.value,
        &signer_pub,
    );
}

test "welcome: cipher suite 1 — decrypt and verify" {
    const parsed = try std.json.parseFromSlice(
        []const WelcomeEntry,
        testing.allocator,
        welcome_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyWelcome(P, entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 10. Tree Operations — loaded from tree-operations.json
// =====================================================================

const tree_ops_json = tv.tree_operations;

const tree_hashes_mod = zmls.tree_hashes;
const tree_path_mod = zmls.tree_path;
const RatchetTree = zmls.RatchetTree;
const Node = zmls.tree_node.Node;
const LeafNode = zmls.LeafNode;
const LeafIndex = zmls.types.LeafIndex;
const Proposal = zmls.Proposal;

const TreeOpsEntry = struct {
    cipher_suite: u16,
    tree_before: []const u8,
    proposal: []const u8,
    proposal_sender: u32,
    tree_hash_before: []const u8,
    tree_hash_after: []const u8,
    tree_after: []const u8,
};

/// Decode a TLS-serialized ratchet tree (varint-prefixed vector
/// of optional<Node>). Returns an allocated RatchetTree.
///
/// Single-pass: decode all nodes into a temporary buffer, then
/// build the tree from the collected entries.
fn decodeRatchetTree(
    allocator: std.mem.Allocator,
    data: []const u8,
) !RatchetTree {
    // Read varint length header.
    const vr = try zmls.varint.decode(data, 0);
    const vec_len = vr.value;
    var pos = vr.pos;
    const end = pos + vec_len;
    if (end > data.len) return error.Truncated;

    // Decode all optional<Node> entries into a list.
    const max_nodes: u32 = 4096;
    var entries: [max_nodes]?Node = undefined;
    var node_count: u32 = 0;

    while (pos < end) {
        if (node_count >= max_nodes) return error.Truncated;
        const presence = try codec.decodeUint8(data, pos);
        pos = presence.pos;
        if (presence.value == 1) {
            const nr = try Node.decode(
                allocator,
                data,
                pos,
            );
            pos = nr.pos;
            entries[node_count] = nr.value;
        } else if (presence.value == 0) {
            entries[node_count] = null;
        } else {
            return error.InvalidEnumValue;
        }
        node_count += 1;
    }

    // leaf_count = (node_count + 1) / 2 for a left-balanced tree.
    const leaf_count: u32 = (node_count + 1) / 2;
    var tree = try RatchetTree.init(allocator, leaf_count);
    errdefer tree.deinit();

    // Copy decoded nodes into the tree.
    var idx: u32 = 0;
    while (idx < node_count) : (idx += 1) {
        tree.nodes[idx] = entries[idx];
    }

    tree.owns_contents = true;
    return tree;
}

/// Encode a RatchetTree to TLS wire format (varint-prefixed
/// vector of optional<Node>).
fn encodeRatchetTree(
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
) ![]u8 {
    // Find the last non-blank node (right-trim trailing blanks).
    const full_width = tree.nodeCount();
    var trim_width: u32 = full_width;
    while (trim_width > 0 and tree.nodes[trim_width - 1] == null) {
        trim_width -= 1;
    }

    // First pass: compute inner payload size.
    var payload_size: u32 = 0;
    var buf_tmp: [65536]u8 = undefined;

    var ni: u32 = 0;
    while (ni < trim_width) : (ni += 1) {
        payload_size += 1; // presence byte
        if (tree.nodes[ni]) |*n| {
            const start: u32 = 0;
            const node_end = try n.encode(&buf_tmp, start);
            payload_size += node_end;
        }
    }

    // Compute varint header size.
    const hdr_size = zmls.varint.encodedLength(payload_size);
    const total = hdr_size + payload_size;
    const out = try allocator.alloc(u8, total);
    errdefer allocator.free(out);

    // Encode varint header.
    var pos = try zmls.varint.encode(out, 0, payload_size);

    // Encode each optional<Node>.
    ni = 0;
    while (ni < trim_width) : (ni += 1) {
        if (tree.nodes[ni]) |*n| {
            pos = try codec.encodeUint8(out, pos, 1);
            pos = try n.encode(out, pos);
        } else {
            pos = try codec.encodeUint8(out, pos, 0);
        }
    }

    std.debug.assert(pos == total);
    return out;
}

/// Apply a proposal to a ratchet tree per the test vector spec.
/// For Add and Update, the leaf node's heap pointers are moved
/// into the tree — the caller must null them out in the proposal
/// to avoid double-free on deinit.
fn applyTreeProposal(
    allocator: std.mem.Allocator,
    tree: *RatchetTree,
    prop: *Proposal,
    sender: u32,
) !void {
    _ = allocator;
    switch (prop.tag) {
        .add => {
            _ = try tree_path_mod.addLeaf(
                tree,
                prop.payload.add.key_package.leaf_node,
            );
        },
        .remove => {
            const li = LeafIndex.fromU32(
                prop.payload.remove.removed,
            );
            // Blank direct-path ancestors.
            var dp_buf: [32]NodeIndex = undefined;
            const dp = math.directPath(
                li.toNodeIndex(),
                tree.leaf_count,
                &dp_buf,
            );
            for (dp) |ancestor| {
                try tree.blankNode(ancestor);
            }
            try tree_path_mod.removeLeaf(tree, li);
        },
        .update => {
            const li = LeafIndex.fromU32(sender);
            try tree.setLeaf(li, prop.payload.update.leaf_node);

            var dp_buf: [32]NodeIndex = undefined;
            const dp = math.directPath(
                li.toNodeIndex(),
                tree.leaf_count,
                &dp_buf,
            );
            for (dp) |ancestor| {
                try tree.blankNode(ancestor);
            }
        },
        else => return error.UnsupportedProposal,
    }
}

fn verifyTreeOps(
    comptime Prov: type,
    entry: TreeOpsEntry,
) !void {
    const allocator = testing.allocator;

    // 1. Decode tree_before.
    const tree_before_bytes = try hexDecodeAlloc(
        allocator,
        entry.tree_before,
    );
    defer allocator.free(tree_before_bytes);

    var tree = try decodeRatchetTree(
        allocator,
        tree_before_bytes,
    );
    defer tree.deinit();
    // 3. Decode the proposal.
    const prop_bytes = try hexDecodeAlloc(
        allocator,
        entry.proposal,
    );
    defer allocator.free(prop_bytes);

    var prop_r = try Proposal.decode(
        allocator,
        prop_bytes,
        0,
    );
    defer prop_r.value.deinit(allocator);

    // 4. Apply proposal to tree.
    try applyTreeProposal(
        allocator,
        &tree,
        &prop_r.value,
        entry.proposal_sender,
    );

    // 5. Verify tree hash after.
    const expected_hash_after = try hexDecode(
        Prov.nh,
        entry.tree_hash_after,
    );
    const root_after = math.root(tree.leaf_count);
    const actual_hash_after = try tree_hashes_mod.treeHash(
        Prov,
        allocator,
        &tree,
        root_after,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_hash_after,
        &actual_hash_after,
    );

    // 6. Verify serialized tree matches tree_after.
    const encoded = try encodeRatchetTree(allocator, &tree);
    defer allocator.free(encoded);

    const expected_after = try hexDecodeAlloc(
        allocator,
        entry.tree_after,
    );
    defer allocator.free(expected_after);

    try testing.expectEqualSlices(
        u8,
        expected_after,
        encoded,
    );
}

test "tree-operations: cipher suite 1 — add, update, remove" {
    const parsed = try std.json.parseFromSlice(
        []const TreeOpsEntry,
        testing.allocator,
        tree_ops_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyTreeOps(P, entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 11. Tree Validation — loaded from tree-validation.json
// =====================================================================

const tree_validation_json = tv.tree_validation;

const TreeValidationEntry = struct {
    cipher_suite: u32,
    tree: []const u8,
    group_id: []const u8,
    resolutions: []const []const u32,
    tree_hashes: []const []const u8,
};

fn verifyTreeValidation(
    comptime Prov: type,
    entry: TreeValidationEntry,
) !void {
    const allocator = testing.allocator;

    // 1. Decode tree.
    const tree_bytes = try hexDecodeAlloc(
        allocator,
        entry.tree,
    );
    defer allocator.free(tree_bytes);

    var tree = try decodeRatchetTree(allocator, tree_bytes);
    defer tree.deinit();

    const width = tree.nodeCount();

    // 2. Verify resolutions.
    try testing.expectEqual(width, @as(u32, @intCast(
        entry.resolutions.len,
    )));

    var res_buf: [RatchetTree.max_resolution_size]NodeIndex =
        undefined;
    var ni: u32 = 0;
    while (ni < width) : (ni += 1) {
        const res = try tree.resolution(
            NodeIndex.fromU32(ni),
            &res_buf,
        );
        const expected = entry.resolutions[ni];
        try testing.expectEqual(
            @as(u32, @intCast(expected.len)),
            @as(u32, @intCast(res.len)),
        );
        for (expected, 0..) |exp_val, j| {
            try testing.expectEqual(
                exp_val,
                res[j].toU32(),
            );
        }
    }

    // 3. Verify tree hashes.
    try testing.expectEqual(width, @as(u32, @intCast(
        entry.tree_hashes.len,
    )));

    const hashes = try tree_hashes_mod.allTreeHashes(
        Prov,
        &tree,
        allocator,
    );
    defer allocator.free(hashes);

    ni = 0;
    while (ni < width) : (ni += 1) {
        const expected_hash = try hexDecode(
            Prov.nh,
            entry.tree_hashes[ni],
        );
        try testing.expectEqualSlices(
            u8,
            &expected_hash,
            &hashes[ni],
        );
    }

    // 4. Verify parent hashes (whole-tree, bottom-up per 7.9.2).
    try tree_hashes_mod.verifyParentHashes(Prov, allocator, &tree);

    // 5. Verify leaf signatures.
    const group_id = try hexDecodeAlloc(
        allocator,
        entry.group_id,
    );
    defer allocator.free(group_id);

    var li: u32 = 0;
    while (li < tree.leaf_count) : (li += 1) {
        const leaf_ni = LeafIndex.fromU32(li).toNodeIndex();
        if (tree.nodes[leaf_ni.toUsize()] == null) continue;
        const leaf = &tree.nodes[leaf_ni.toUsize()].?.payload
            .leaf;
        try leaf.verifyLeafNodeSignature(
            Prov,
            group_id,
            LeafIndex.fromU32(li),
        );
    }
}

test "tree-validation: cipher suite 1 — resolution, hashes, parent hash, signatures" {
    const parsed = try std.json.parseFromSlice(
        []const TreeValidationEntry,
        testing.allocator,
        tree_validation_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyTreeValidation(P, entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 12. TreeKEM — loaded from treekem.json
// =====================================================================

const treekem_json = tv.treekem;
const UpdatePath = zmls.UpdatePath;
const GC = zmls.GroupContext(P.nh);
const gc_mod = zmls.group_context;

const TreeKemLeafPrivate = struct {
    index: u32,
    encryption_priv: []const u8,
    signature_priv: []const u8,
    path_secrets: []const TreeKemPathSecret,
};

const TreeKemPathSecret = struct {
    node: u32,
    path_secret: []const u8,
};

const TreeKemUpdatePath = struct {
    sender: u32,
    update_path: []const u8,
    path_secrets: []const ?[]const u8,
    commit_secret: []const u8,
    tree_hash_after: []const u8,
};

const TreeKemEntry = struct {
    cipher_suite: u32,
    group_id: []const u8,
    epoch: u64,
    confirmed_transcript_hash: []const u8,
    ratchet_tree: []const u8,
    leaves_private: []const TreeKemLeafPrivate,
    update_paths: []const TreeKemUpdatePath,
};

/// Build serialized GroupContext bytes for TreeKEM test.
fn buildTreeKemGC(
    alloc: std.mem.Allocator,
    group_id_hex: []const u8,
    epoch: u64,
    cth_hex: []const u8,
    tree: *const RatchetTree,
) ![]u8 {
    const group_id = try hexDecodeAlloc(alloc, group_id_hex);
    defer alloc.free(group_id);
    const cth = try hexDecode(P.nh, cth_hex);

    // Compute tree hash from current tree.
    const hashes = try tree_hashes_mod.allTreeHashes(
        P,
        tree,
        alloc,
    );
    defer alloc.free(hashes);

    const root_idx = math.root(tree.leaf_count);
    const tree_hash = hashes[root_idx.toU32()];

    const gc = GC{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .group_id = group_id,
        .epoch = epoch,
        .tree_hash = tree_hash,
        .confirmed_transcript_hash = cth,
        .extensions = &.{},
    };

    var buf: [gc_mod.max_gc_encode]u8 = undefined;
    const gc_bytes = gc.serialize(&buf) catch
        return error.InvalidLength;
    const out = try alloc.alloc(u8, gc_bytes.len);
    @memcpy(out, gc_bytes);
    return out;
}

fn cloneBytes(
    alloc: std.mem.Allocator,
    src: []const u8,
) ![]const u8 {
    if (src.len == 0) return &.{};
    const dst = try alloc.alloc(u8, src.len);
    @memcpy(dst, src);
    return dst;
}

fn cloneCredential(
    alloc: std.mem.Allocator,
    c: *const Credential,
) !Credential {
    switch (c.tag) {
        .basic => {
            const id = try cloneBytes(alloc, c.payload.basic);
            return .{
                .tag = .basic,
                .payload = .{ .basic = id },
            };
        },
        .x509 => {
            const src = c.payload.x509;
            if (src.len == 0) return .{
                .tag = .x509,
                .payload = .{ .x509 = &.{} },
            };
            const certs = try alloc.alloc(
                Certificate,
                src.len,
            );
            var i: u32 = 0;
            errdefer {
                var j: u32 = 0;
                while (j < i) : (j += 1) {
                    @constCast(&certs[j]).deinit(alloc);
                }
                alloc.free(certs);
            }
            while (i < src.len) : (i += 1) {
                const d = try cloneBytes(
                    alloc,
                    src[i].data,
                );
                certs[i] = .{ .data = d };
            }
            return .{
                .tag = .x509,
                .payload = .{ .x509 = certs },
            };
        },
        else => return c.*,
    }
}

fn cloneCapabilities(
    alloc: std.mem.Allocator,
    c: *const Capabilities,
) !Capabilities {
    const vers = try cloneSlice(
        ProtocolVersion,
        alloc,
        c.versions,
    );
    errdefer freeSliceIfNonEmpty(
        ProtocolVersion,
        alloc,
        vers,
    );
    const suites = try cloneSlice(
        CipherSuite,
        alloc,
        c.cipher_suites,
    );
    errdefer freeSliceIfNonEmpty(
        CipherSuite,
        alloc,
        suites,
    );
    const exts = try cloneSlice(
        ExtensionType,
        alloc,
        c.extensions,
    );
    errdefer freeSliceIfNonEmpty(
        ExtensionType,
        alloc,
        exts,
    );
    const props = try cloneSlice(
        ProposalType,
        alloc,
        c.proposals,
    );
    errdefer freeSliceIfNonEmpty(
        ProposalType,
        alloc,
        props,
    );
    const creds = try cloneSlice(
        CredentialType,
        alloc,
        c.credentials,
    );
    return .{
        .versions = vers,
        .cipher_suites = suites,
        .extensions = exts,
        .proposals = props,
        .credentials = creds,
    };
}

fn cloneSlice(
    comptime T: type,
    alloc: std.mem.Allocator,
    src: []const T,
) ![]const T {
    if (src.len == 0) return &.{};
    const dst = try alloc.alloc(T, src.len);
    @memcpy(dst, src);
    return dst;
}

fn freeSliceIfNonEmpty(
    comptime T: type,
    alloc: std.mem.Allocator,
    s: []const T,
) void {
    if (s.len > 0) alloc.free(s);
}

fn cloneExtensions(
    alloc: std.mem.Allocator,
    src: []const Extension,
) ![]const Extension {
    if (src.len == 0) return &.{};
    const dst = try alloc.alloc(Extension, src.len);
    var i: u32 = 0;
    errdefer {
        var j: u32 = 0;
        while (j < i) : (j += 1) {
            @constCast(&dst[j]).deinit(alloc);
        }
        alloc.free(dst);
    }
    while (i < src.len) : (i += 1) {
        const d = try cloneBytes(alloc, src[i].data);
        dst[i] = .{
            .extension_type = src[i].extension_type,
            .data = d,
        };
    }
    return dst;
}

fn cloneNode(
    alloc: std.mem.Allocator,
    n: *const Node,
) !Node {
    switch (n.node_type) {
        .leaf => {
            const l = &n.payload.leaf;
            const ek = try cloneBytes(alloc, l.encryption_key);
            errdefer if (ek.len > 0) alloc.free(ek);

            const sk = try cloneBytes(
                alloc,
                l.signature_key,
            );
            errdefer if (sk.len > 0) alloc.free(sk);

            const sig = try cloneBytes(alloc, l.signature);
            errdefer if (sig.len > 0) alloc.free(sig);

            var ph: ?[]const u8 = null;
            if (l.parent_hash) |src_ph| {
                if (src_ph.len > 0) {
                    ph = try cloneBytes(alloc, src_ph);
                }
            }
            errdefer if (ph) |p| {
                if (p.len > 0) alloc.free(p);
            };

            const cred = try cloneCredential(
                alloc,
                &l.credential,
            );
            errdefer {
                var mc = cred;
                mc.deinit(alloc);
            }

            const caps = try cloneCapabilities(
                alloc,
                &l.capabilities,
            );
            errdefer {
                var mc = caps;
                mc.deinit(alloc);
            }

            const exts = try cloneExtensions(
                alloc,
                l.extensions,
            );

            return Node{
                .node_type = .leaf,
                .payload = .{ .leaf = .{
                    .encryption_key = ek,
                    .signature_key = sk,
                    .credential = cred,
                    .capabilities = caps,
                    .source = l.source,
                    .lifetime = l.lifetime,
                    .parent_hash = ph,
                    .extensions = exts,
                    .signature = sig,
                } },
            };
        },
        .parent => {
            const p = &n.payload.parent;
            const ek = try cloneBytes(
                alloc,
                p.encryption_key,
            );
            errdefer if (ek.len > 0) alloc.free(ek);

            const ph = try cloneBytes(
                alloc,
                p.parent_hash,
            );
            errdefer if (ph.len > 0) alloc.free(ph);

            const ul = try cloneSlice(
                LeafIndex,
                alloc,
                p.unmerged_leaves,
            );

            return Node{
                .node_type = .parent,
                .payload = .{ .parent = .{
                    .encryption_key = ek,
                    .parent_hash = ph,
                    .unmerged_leaves = ul,
                } },
            };
        },
    }
}

/// Compute and set parent_hash on parent nodes along the
/// **filtered** direct path after applying an UpdatePath.
/// The leaf's parent_hash is NOT recomputed — it comes from
/// the UpdatePath's leaf_node and is already correct.
///
/// RFC 9420 Section 7.9: parent_hash links consecutive
/// nodes on the filtered direct path. Blank intermediates
/// are skipped. The root's parent_hash is "" (already set).
/// For each pair (child, parent) in the filtered path:
///   child.parent_hash = parentHash(parent, osth)
fn setPathParentHashes(
    comptime Prov: type,
    alloc: std.mem.Allocator,
    tree: *RatchetTree,
    sender: LeafIndex,
) !void {
    // Use the filtered direct path (same as UpdatePath).
    var fp_buf: [32]NodeIndex = undefined;
    var fc_buf: [32]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &fp_buf,
        &fc_buf,
    );
    const n_fp: u32 = @intCast(fdp.path.len);
    if (n_fp < 2) return;

    // Compute sibling tree hashes for the filtered copath.
    var sib_hashes: [32][Prov.nh]u8 = undefined;
    for (0..n_fp) |i| {
        sib_hashes[i] = try tree_hashes_mod.treeHash(
            Prov,
            alloc,
            tree,
            fdp.copath[i],
        );
    }

    // Top-down: fp[n-1] is the topmost filtered node
    // (may be root). Its parent_hash is "" (set by
    // applyTreeKemPath). For i from n-2 down to 0:
    //   fp[i].parent_hash = parentHash(fp[i+1], sib[i+1])
    var i: u32 = n_fp - 2;
    while (true) {
        const parent_idx = fdp.path[i + 1];
        const ph = try tree_hashes_mod.parentHash(
            Prov,
            tree,
            parent_idx,
            &sib_hashes[i + 1],
        );

        const ci = fdp.path[i].toUsize();
        if (tree.nodes[ci]) |*node| {
            var pn = &@constCast(node)
                .payload.parent;
            if (pn.parent_hash.len > 0) {
                alloc.free(pn.parent_hash);
            }
            const new_ph = try alloc.alloc(
                u8,
                Prov.nh,
            );
            @memcpy(new_ph, &ph);
            pn.parent_hash = new_ph;
        }
        if (i == 0) break;
        i -= 1;
    }
}

fn verifyTreeKem(
    comptime Prov: type,
    entry: TreeKemEntry,
) !void {
    const alloc = testing.allocator;

    const tree_bytes = try hexDecodeAlloc(
        alloc,
        entry.ratchet_tree,
    );
    defer alloc.free(tree_bytes);

    // Each update_path is independent — apply to a fresh copy
    // of the original tree.
    for (entry.update_paths) |up_entry| {
        const sender = LeafIndex.fromU32(up_entry.sender);

        // Decode fresh tree for this update_path.
        var tree = try decodeRatchetTree(alloc, tree_bytes);
        defer tree.deinit();

        // Decode UpdatePath.
        const up_bytes = try hexDecodeAlloc(
            alloc,
            up_entry.update_path,
        );
        defer alloc.free(up_bytes);

        var up_result = try UpdatePath.decode(
            alloc,
            up_bytes,
            0,
        );
        defer up_result.value.deinit(alloc);

        // Get filtered direct path from ORIGINAL tree.
        var p_buf: [32]NodeIndex = undefined;
        var c_buf: [32]NodeIndex = undefined;
        const fdp = try tree.filteredDirectPath(
            sender,
            &p_buf,
            &c_buf,
        );
        const n_path: u32 = @intCast(fdp.path.len);

        // Apply UpdatePath to tree.
        try applyTreeKemPath(
            alloc,
            &tree,
            sender,
            &up_result.value,
        );

        // Set parent_hash on non-root parent nodes along
        // the direct path. The leaf's parent_hash is already
        // correct (from UpdatePath's leaf_node).
        try setPathParentHashes(
            Prov,
            alloc,
            &tree,
            sender,
        );

        // Build GroupContext from the UPDATED tree.
        const gc_bytes = try buildTreeKemGC(
            alloc,
            entry.group_id,
            entry.epoch,
            entry.confirmed_transcript_hash,
            &tree,
        );
        defer alloc.free(gc_bytes);

        // Verify tree_hash_after.
        const expected_th = try hexDecode(
            Prov.nh,
            up_entry.tree_hash_after,
        );
        const hashes = try tree_hashes_mod.allTreeHashes(
            Prov,
            &tree,
            alloc,
        );
        defer alloc.free(hashes);

        const root = math.root(tree.leaf_count);
        try testing.expectEqualSlices(
            u8,
            &expected_th,
            &hashes[root.toU32()],
        );

        // For each receiver, decrypt path secret and verify.
        var got_commit_secret = false;
        var commit_secret: [Prov.nh]u8 = undefined;

        for (
            up_entry.path_secrets,
            0..,
        ) |maybe_ps, leaf_u| {
            const leaf_idx: u32 = @intCast(leaf_u);
            if (maybe_ps == null) continue;
            const expected_ps = try hexDecode(
                Prov.nh,
                maybe_ps.?,
            );

            const lp = findLeafPriv(
                entry.leaves_private,
                leaf_idx,
            ) orelse continue;

            const recv_leaf = LeafIndex.fromU32(leaf_idx);
            const recv_ni = recv_leaf.toNodeIndex();

            var found = false;
            var res_buf: [
                RatchetTree.max_resolution_size
            ]NodeIndex = undefined;

            for (0..n_path) |pi_u| {
                const pi: u32 = @intCast(pi_u);
                const cp_node = fdp.copath[pi];
                const res = try tree.resolution(
                    cp_node,
                    &res_buf,
                );

                for (res, 0..) |res_node, ci| {
                    const is_match = if (math.isLeaf(
                        res_node,
                    ))
                        res_node.toU32() == recv_ni.toU32()
                    else
                        math.isInSubtree(
                            res_node,
                            recv_leaf,
                        );

                    if (!is_match) continue;

                    var sk: [Prov.nsk]u8 = undefined;
                    var pk: [Prov.npk]u8 = undefined;

                    if (math.isLeaf(res_node) and
                        res_node.toU32() ==
                            recv_ni.toU32())
                    {
                        sk = try hexDecode(
                            Prov.nsk,
                            lp.encryption_priv,
                        );
                        const ln = tree.nodes[
                            recv_ni.toUsize()
                        ] orelse continue;
                        @memcpy(
                            &pk,
                            ln.payload.leaf
                                .encryption_key[0..Prov.npk],
                        );
                    } else {
                        const nkp = findNodeKeypair(
                            Prov,
                            lp,
                            res_node.toU32(),
                        ) orelse continue;
                        sk = nkp.sk;
                        pk = nkp.pk;
                    }

                    const ct = &up_result.value.nodes[pi]
                        .encrypted_path_secret[ci];

                    const decrypted_ps = try tree_path_mod
                        .decryptPathSecretFrom(
                        Prov,
                        ct,
                        &sk,
                        &pk,
                        gc_bytes,
                    );

                    try testing.expectEqualSlices(
                        u8,
                        &expected_ps,
                        &decrypted_ps,
                    );

                    if (!got_commit_secret) {
                        const remaining = n_path - pi;
                        var secrets: [32][Prov.nh]u8 =
                            undefined;
                        tree_path_mod.derivePathSecrets(
                            Prov,
                            &decrypted_ps,
                            remaining,
                            &secrets,
                        );
                        commit_secret =
                            tree_path_mod.deriveCommitSecret(
                                Prov,
                                &secrets[remaining - 1],
                            );
                        got_commit_secret = true;
                    }

                    found = true;
                    break;
                }
                if (found) break;
            }

            if (!found) return error.ReceiverNotFound;
        }

        // Verify commit_secret.
        if (got_commit_secret) {
            const expected_cs = try hexDecode(
                Prov.nh,
                up_entry.commit_secret,
            );
            try testing.expectEqualSlices(
                u8,
                &expected_cs,
                &commit_secret,
            );
        }
    }
}

fn findLeafPriv(
    leaves: []const TreeKemLeafPrivate,
    leaf_idx: u32,
) ?TreeKemLeafPrivate {
    for (leaves) |lp| {
        if (lp.index == leaf_idx) return lp;
    }
    return null;
}

/// Derive node keypair from a leaf's known path_secrets.
/// Returns null if the leaf has no path_secret for this node.
fn findNodeKeypair(
    comptime Prov: type,
    lp: TreeKemLeafPrivate,
    node_id: u32,
) ?tree_path_mod.NodeKeypair(Prov) {
    for (lp.path_secrets) |ps| {
        if (ps.node == node_id) {
            const secret = hexDecode(
                Prov.nh,
                ps.path_secret,
            ) catch return null;
            return tree_path_mod.deriveNodeKeypair(
                Prov,
                &secret,
            ) catch return null;
        }
    }
    return null;
}

/// Apply an UpdatePath to the tree from the sender side.
/// Sets the new leaf node and parent nodes along the
/// filtered direct path. Deep-frees old node contents.
fn applyTreeKemPath(
    alloc: std.mem.Allocator,
    tree: *RatchetTree,
    sender: LeafIndex,
    update_path: *const UpdatePath,
) !void {
    var p_buf: [32]NodeIndex = undefined;
    var c_buf: [32]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);

    // Set parent nodes.
    var pi: u32 = 0;
    while (pi < n_path) : (pi += 1) {
        const node_idx = fdp.path[pi];
        const upn = &update_path.nodes[pi];

        // Free old node contents if present.
        if (tree.nodes[node_idx.toUsize()]) |*old| {
            @constCast(old).deinit(alloc);
        }

        // Allocate new encryption key.
        const ek = try alloc.alloc(
            u8,
            upn.encryption_key.len,
        );
        @memcpy(ek, upn.encryption_key);

        tree.nodes[node_idx.toUsize()] = Node{
            .node_type = .parent,
            .payload = .{ .parent = .{
                .encryption_key = ek,
                .parent_hash = "",
                .unmerged_leaves = &.{},
            } },
        };
    }

    // Set sender's new leaf. Deep-copy the leaf node from
    // the UpdatePath.
    const sender_ni = sender.toNodeIndex();
    if (tree.nodes[sender_ni.toUsize()]) |*old| {
        @constCast(old).deinit(alloc);
    }

    const new_leaf = try cloneNode(
        alloc,
        &Node{
            .node_type = .leaf,
            .payload = .{ .leaf = update_path.leaf_node },
        },
    );
    tree.nodes[sender_ni.toUsize()] = new_leaf;
}

test "treekem: cipher suite 1 — path decryption, commit secret, tree hash" {
    const parsed = try std.json.parseFromSlice(
        []const TreeKemEntry,
        testing.allocator,
        treekem_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyTreeKem(P, entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 13. Messages — Serialization (messages.json)
// =====================================================================
//
// Each entry contains hex-encoded TLS serializations of all MLS
// message types. The test decodes each field into its Zig struct,
// re-encodes it, and verifies byte-for-byte equality.

const MsgAdd = zmls.proposal.Add;
const MsgUpdate = zmls.proposal.Update;
const MsgRemove = zmls.proposal.Remove;
const MsgPreSharedKey = zmls.proposal.PreSharedKey;
const MsgReInit = zmls.proposal.ReInit;
const MsgExternalInit = zmls.proposal.ExternalInit;
const MsgGCE = zmls.proposal.GroupContextExtensions;
const MsgCommit = zmls.commit.Commit;

const messages_json = tv.messages;

const MessagesEntry = struct {
    mls_welcome: []const u8,
    mls_group_info: []const u8,
    mls_key_package: []const u8,
    ratchet_tree: []const u8,
    group_secrets: []const u8,
    add_proposal: []const u8,
    update_proposal: []const u8,
    remove_proposal: []const u8,
    pre_shared_key_proposal: []const u8,
    re_init_proposal: []const u8,
    external_init_proposal: []const u8,
    group_context_extensions_proposal: []const u8,
    commit: []const u8,
    public_message_application: []const u8,
    public_message_proposal: []const u8,
    public_message_commit: []const u8,
    private_message: []const u8,
};

/// Round-trip for MLSMessage (4-byte header + opaque body).
fn roundTripMLSMessage(
    alloc: std.mem.Allocator,
    hex: []const u8,
) !void {
    const data = try hexDecodeAlloc(alloc, hex);
    defer alloc.free(data);
    const dlen: u32 = @intCast(data.len);

    const result = try MLSMessage.decode(data, 0);
    try testing.expectEqual(dlen, result.pos);

    var buf = try alloc.alloc(u8, data.len + 256);
    defer alloc.free(buf);
    const end = try result.value.encode(buf, 0);

    try testing.expectEqual(dlen, end);
    try testing.expectEqualSlices(u8, data, buf[0..end]);
}

/// Generic round-trip: decode from hex, re-encode, compare.
/// Works for types with `decode(alloc, data, pos)` signature.
fn roundTripAlloc(
    comptime T: type,
    alloc: std.mem.Allocator,
    hex: []const u8,
) !void {
    const data = try hexDecodeAlloc(alloc, hex);
    defer alloc.free(data);
    const dlen: u32 = @intCast(data.len);

    const result = try T.decode(alloc, data, 0);
    var val = result.value;
    defer val.deinit(alloc);

    try testing.expectEqual(dlen, result.pos);

    var buf = try alloc.alloc(u8, data.len + 256);
    defer alloc.free(buf);
    const end = try val.encode(buf, 0);

    try testing.expectEqual(dlen, end);
    try testing.expectEqualSlices(u8, data, buf[0..end]);
}

/// Round-trip for types with `decode(data, pos)` (no allocator).
fn roundTripNoAlloc(
    comptime T: type,
    alloc: std.mem.Allocator,
    hex: []const u8,
) !void {
    const data = try hexDecodeAlloc(alloc, hex);
    defer alloc.free(data);
    const dlen: u32 = @intCast(data.len);

    const result = try T.decode(data, 0);

    try testing.expectEqual(dlen, result.pos);

    var buf = try alloc.alloc(u8, data.len + 256);
    defer alloc.free(buf);
    const end = try result.value.encode(buf, 0);

    try testing.expectEqual(dlen, end);
    try testing.expectEqualSlices(u8, data, buf[0..end]);
}

/// Round-trip for ratchet tree (uses existing helpers).
fn roundTripRatchetTree(
    alloc: std.mem.Allocator,
    hex: []const u8,
) !void {
    const data = try hexDecodeAlloc(alloc, hex);
    defer alloc.free(data);

    var tree = try decodeRatchetTree(alloc, data);
    defer tree.deinit();

    const encoded = try encodeRatchetTree(alloc, &tree);
    defer alloc.free(encoded);

    try testing.expectEqualSlices(u8, data, encoded);
}

fn verifyMessages(entry: MessagesEntry) !void {
    const alloc = testing.allocator;

    // MLSMessage-wrapped types.
    try roundTripMLSMessage(alloc, entry.mls_welcome);
    try roundTripMLSMessage(alloc, entry.mls_group_info);
    try roundTripMLSMessage(alloc, entry.mls_key_package);
    try roundTripMLSMessage(alloc, entry.public_message_application);
    try roundTripMLSMessage(alloc, entry.public_message_proposal);
    try roundTripMLSMessage(alloc, entry.public_message_commit);
    try roundTripMLSMessage(alloc, entry.private_message);

    // Bare types with allocator-based decode.
    try roundTripAlloc(WelcomeGS, alloc, entry.group_secrets);
    try roundTripAlloc(MsgAdd, alloc, entry.add_proposal);
    try roundTripAlloc(MsgUpdate, alloc, entry.update_proposal);
    try roundTripAlloc(MsgReInit, alloc, entry.re_init_proposal);
    try roundTripAlloc(
        MsgExternalInit,
        alloc,
        entry.external_init_proposal,
    );
    try roundTripAlloc(
        MsgGCE,
        alloc,
        entry.group_context_extensions_proposal,
    );
    try roundTripAlloc(MsgCommit, alloc, entry.commit);

    // Bare types without allocator.
    try roundTripNoAlloc(MsgRemove, alloc, entry.remove_proposal);
    try roundTripNoAlloc(
        MsgPreSharedKey,
        alloc,
        entry.pre_shared_key_proposal,
    );

    // Ratchet tree.
    try roundTripRatchetTree(alloc, entry.ratchet_tree);
}

test "messages: serialization round-trip for all MLS types" {
    const parsed = try std.json.parseFromSlice(
        []const MessagesEntry,
        testing.allocator,
        messages_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    for (parsed.value) |entry| {
        try verifyMessages(entry);
    }
    try testing.expect(parsed.value.len > 0);
}

// =====================================================================
// 14. Passive Client — Welcome
//     (`passive-client-welcome.json`)
// =====================================================================
//
// A client joins a group via Welcome. No epochs to process.
// Verifies that processWelcome produces the correct
// initial_epoch_authenticator.
//
// Two sub-cases per entry:
//   (a) ratchet_tree provided in the test vector (out-of-band).
//   (b) ratchet_tree is null — extract from GroupInfo extension.

const passive_welcome_json = tv.passive_client_welcome;
const TreeInput = zmls.group_welcome.TreeInput;

const PassiveExternalPsk = struct {
    psk_id: []const u8,
    psk: []const u8,
};

const PassiveWelcomeEntry = struct {
    cipher_suite: u32,
    external_psks: []const PassiveExternalPsk,
    key_package: []const u8,
    signature_priv: []const u8,
    encryption_priv: []const u8,
    init_priv: []const u8,
    welcome: []const u8,
    ratchet_tree: ?[]const u8,
    initial_epoch_authenticator: []const u8,
    // epochs is always empty for this file; skip it.
};

/// Decrypt Welcome → GroupInfo. Optionally extracts
/// ratchet_tree from GroupInfo extensions if present.
const WelcomeDecryptResult = struct {
    tree: ?RatchetTree,
    signer: u32,
    allocator: std.mem.Allocator,
    gi_gc: []const u8,
    gi_ext: []const Extension,
    gi_ct: []const u8,
    gi_sig: []const u8,

    fn deinit(self: *WelcomeDecryptResult) void {
        if (self.tree) |*t| {
            @constCast(t).deinit();
        }
        self.allocator.free(self.gi_gc);
        for (self.gi_ext) |*ext| {
            @constCast(ext).deinit(self.allocator);
        }
        if (self.gi_ext.len > 0) {
            self.allocator.free(self.gi_ext);
        }
        if (self.gi_ct.len > 0) {
            self.allocator.free(self.gi_ct);
        }
        if (self.gi_sig.len > 0) {
            self.allocator.free(self.gi_sig);
        }
    }
};

/// Decrypt Welcome → GroupSecrets → welcome_secret → GroupInfo,
/// then extract the ratchet_tree from GroupInfo extensions and
/// return tree + signer info.
fn decryptWelcomeForTree(
    allocator: std.mem.Allocator,
    w: *const WelcomeMsg,
    kp_ref: []const u8,
    init_sk: *const [P.nsk]u8,
    init_pk: *const [P.npk]u8,
    ext_psk_store: ?*const zmls.InMemoryPskStore,
) !WelcomeDecryptResult {
    // 1. Decrypt GroupSecrets.
    var gs = try zmls.welcome.decryptGroupSecrets(
        P,
        allocator,
        w,
        kp_ref,
        init_sk,
        init_pk,
    );
    defer gs.deinit(allocator);

    if (gs.joiner_secret.len != P.nh)
        return error.InvalidLength;
    const joiner: *const [P.nh]u8 =
        gs.joiner_secret[0..P.nh];

    // 2. Derive psk_secret from GroupSecrets PSK list.
    var psk_secret: [P.nh]u8 = .{0} ** P.nh;
    if (gs.psks.len > 0) {
        // Build PskEntry array from resolved secrets.
        const max_psks: u32 = 64;
        var psk_entries: [max_psks]zmls.psk.PskEntry = undefined;
        const n_psks: u32 = @intCast(gs.psks.len);
        var pi: u32 = 0;
        while (pi < n_psks) : (pi += 1) {
            const id = &gs.psks[pi];
            const secret: ?[]const u8 = blk: {
                if (id.psk_type == .external) {
                    if (ext_psk_store) |store| {
                        break :blk store.lookup().resolve(id);
                    }
                }
                break :blk null;
            };
            if (secret == null) return error.PskNotFound;
            psk_entries[pi] = .{
                .id = id.*,
                .secret = secret.?,
            };
        }
        psk_secret = try zmls.psk.derivePskSecret(
            P,
            psk_entries[0..n_psks],
        );
    }
    defer primitives.secureZero(&psk_secret);

    // 3. Derive welcome_secret.
    var member_prk = P.kdfExtract(joiner, &psk_secret);
    defer primitives.secureZero(&member_prk);
    var welcome_secret = primitives.deriveSecret(
        P,
        &member_prk,
        "welcome",
    );
    defer primitives.secureZero(&welcome_secret);

    // 4. Decrypt GroupInfo.
    const egi = w.encrypted_group_info;
    if (egi.len < P.nt) return error.Truncated;
    const gi_pt_len: u32 = @intCast(egi.len - P.nt);
    const gi_pt = try allocator.alloc(u8, gi_pt_len);
    defer allocator.free(gi_pt);

    try GroupInfo.decryptGroupInfo(
        P,
        &welcome_secret,
        egi,
        gi_pt,
    );

    // 5. Decode GroupInfo.
    const gi_r = try GroupInfo.GroupInfo.decode(
        allocator,
        gi_pt,
        0,
    );

    // 6. Extract ratchet_tree from extensions (if present).
    var tree: ?RatchetTree = null;
    for (gi_r.value.extensions) |*ext| {
        if (ext.extension_type == .ratchet_tree) {
            tree = try decodeRatchetTree(allocator, ext.data);
            break;
        }
    }

    return .{
        .tree = tree,
        .signer = gi_r.value.signer,
        .allocator = allocator,
        .gi_gc = gi_r.value.group_context,
        .gi_ext = gi_r.value.extensions,
        .gi_ct = gi_r.value.confirmation_tag,
        .gi_sig = gi_r.value.signature,
    };
}

/// Find the joining client's leaf index by matching the
/// KeyPackage's leaf_node signature_key in the tree.
fn findMyLeafIndex(
    tree: *const RatchetTree,
    target_sig_key: []const u8,
) !LeafIndex {
    const lc = tree.leaf_count;
    var li: u32 = 0;
    while (li < lc) : (li += 1) {
        const ni = LeafIndex.fromU32(li).toNodeIndex().toU32();
        if (ni >= tree.nodeCount()) break;
        if (tree.nodes[ni]) |n| {
            if (n.node_type == .leaf) {
                if (std.mem.eql(
                    u8,
                    n.payload.leaf.signature_key,
                    target_sig_key,
                )) return LeafIndex.fromU32(li);
            }
        }
    }
    return error.LeafNotFound;
}

/// Look up a signer's signature public key from a tree.
fn lookupSignerPk(
    tree: *const RatchetTree,
    signer: u32,
) ![P.sign_pk_len]u8 {
    const signer_leaf = LeafIndex.fromU32(signer);
    const signer_node = signer_leaf.toNodeIndex().toU32();
    if (signer_node >= tree.nodeCount())
        return error.IndexOutOfRange;
    const node = tree.nodes[signer_node] orelse
        return error.BlankNode;
    if (node.node_type != .leaf)
        return error.InvalidNodeType;
    const sig_key = node.payload.leaf.signature_key;
    if (sig_key.len != P.sign_pk_len)
        return error.InvalidLength;
    var pk: [P.sign_pk_len]u8 = undefined;
    @memcpy(&pk, sig_key[0..P.sign_pk_len]);
    return pk;
}

fn verifyPassiveWelcome(entry: PassiveWelcomeEntry) !void {
    const allocator = testing.allocator;

    // 1. Decode key_package (MLSMessage-wrapped: 4-byte header).
    const kp_wire = try hexDecodeAlloc(
        allocator,
        entry.key_package,
    );
    defer allocator.free(kp_wire);
    if (kp_wire.len < 4) return error.Truncated;
    const kp_inner = kp_wire[4..];

    var kp_r = try KeyPackage.decode(allocator, kp_inner, 0);
    defer kp_r.value.deinit(allocator);

    // 2. Compute KeyPackageRef.
    const kp_ref = try kp_r.value.makeRef(P);

    // 3. Decode private keys.
    const init_sk = try hexDecode(P.nsk, entry.init_priv);

    if (kp_r.value.init_key.len != P.npk)
        return error.InvalidLength;
    const init_pk: *const [P.npk]u8 =
        kp_r.value.init_key[0..P.npk];

    // 4. Decode Welcome (MLSMessage-wrapped).
    const w_wire = try hexDecodeAlloc(
        allocator,
        entry.welcome,
    );
    defer allocator.free(w_wire);
    if (w_wire.len < 4) return error.Truncated;
    const w_inner = w_wire[4..];

    var w_r = try WelcomeMsg.decode(allocator, w_inner, 0);
    defer w_r.value.deinit(allocator);

    // 5. Set up external PSK store.
    //    Decoded buffers must outlive processWelcome, so track
    //    them for deferred free.
    var psk_store = zmls.InMemoryPskStore.init();
    const max_psks: u32 = 32;
    var psk_bufs: [max_psks * 2][]u8 = undefined;
    var psk_buf_count: u32 = 0;
    defer {
        var di: u32 = 0;
        while (di < psk_buf_count) : (di += 1) {
            allocator.free(psk_bufs[di]);
        }
    }

    for (entry.external_psks) |epsk| {
        const psk_id_bytes = try hexDecodeAlloc(
            allocator,
            epsk.psk_id,
        );
        psk_bufs[psk_buf_count] = psk_id_bytes;
        psk_buf_count += 1;
        const psk_bytes = try hexDecodeAlloc(
            allocator,
            epsk.psk,
        );
        psk_bufs[psk_buf_count] = psk_bytes;
        psk_buf_count += 1;
        _ = psk_store.addPsk(psk_id_bytes, psk_bytes);
    }

    var res_ring = zmls.ResumptionPskRing(P).init(0);
    const resolver: zmls.PskResolver(P) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // 6. Decrypt Welcome to get GroupInfo signer + optional tree.
    var dec = try decryptWelcomeForTree(
        allocator,
        &w_r.value,
        &kp_ref,
        &init_sk,
        init_pk,
        if (entry.external_psks.len > 0) &psk_store else null,
    );
    defer dec.deinit();

    // 7. Determine tree source: test-vector-provided or GroupInfo.
    var tree_owned = false;
    var tree: RatchetTree = undefined;
    if (entry.ratchet_tree) |rt_hex| {
        const rt_bytes = try hexDecodeAlloc(allocator, rt_hex);
        defer allocator.free(rt_bytes);
        tree = try decodeRatchetTree(allocator, rt_bytes);
        tree_owned = true;
    } else {
        // Must come from GroupInfo extension.
        tree = dec.tree orelse return error.MissingRatchetTree;
        // Null it out so dec.deinit() does not free it.
        dec.tree = null;
        tree_owned = true;
    }
    defer if (tree_owned) {
        tree.deinit();
    };

    // 8. Look up signer's signature key from the tree.
    const signer_pk = try lookupSignerPk(&tree, dec.signer);

    // 9. Find my leaf index.
    const my_leaf = try findMyLeafIndex(
        &tree,
        kp_r.value.leaf_node.signature_key,
    );

    // 10. Call processWelcome.
    var gs = try zmls.processWelcome(
        P,
        allocator,
        &w_r.value,
        &kp_ref,
        &init_sk,
        init_pk,
        &signer_pk,
        .{ .prebuilt = tree },
        my_leaf,
        resolver,
    );
    defer gs.deinit();

    // 11. Verify epoch_authenticator.
    const expected_ea = try hexDecode(
        P.nh,
        entry.initial_epoch_authenticator,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_ea,
        &gs.epoch_secrets.epoch_authenticator,
    );
}

test "passive-client-welcome: join via Welcome" {
    const parsed = try std.json.parseFromSlice(
        []const PassiveWelcomeEntry,
        testing.allocator,
        passive_welcome_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyPassiveWelcome(entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 15. Passive Client — Handling Commit
//     (`passive-client-handling-commit.json`)
// =====================================================================
//
// A passive client joins via Welcome, then processes 2 epochs of
// commits (with optional proposals). Each epoch verifies the
// epoch_authenticator matches.

const passive_handling_json = tv.passive_client_handling_commit;

const PassiveEpoch = struct {
    proposals: []const []const u8,
    commit: []const u8,
    epoch_authenticator: []const u8,
};

const PassiveHandlingEntry = struct {
    cipher_suite: u32,
    external_psks: []const PassiveExternalPsk,
    key_package: []const u8,
    signature_priv: []const u8,
    encryption_priv: []const u8,
    init_priv: []const u8,
    welcome: []const u8,
    ratchet_tree: ?[]const u8,
    initial_epoch_authenticator: []const u8,
    epochs: []const PassiveEpoch,
};

// MsgCommit already defined (line 3111). Reuse it.
const MsgProposalOrRef = zmls.commit.ProposalOrRef;

/// Maximum number of parent-node keys tracked across epochs.
const max_path_keys: u32 = 32;

/// Decode an MLSMessage (binary wire bytes) as a PublicMessage,
/// returning the FramedContent and auth data.
fn decodePublicMsg(
    data: []const u8,
) !struct {
    fc: MsgProtFramedContent,
    auth: MsgProtAuthData,
} {
    const mls_r = try MLSMessage.decode(data, 0);
    const pm_bytes = switch (mls_r.value.body) {
        .public_message => |b| b,
        else => return error.UnexpectedWireFormat,
    };
    const pm_r = try MsgProtPublicMsg.decode(pm_bytes, 0);
    return .{
        .fc = pm_r.value.content,
        .auth = pm_r.value.auth,
    };
}

/// Process one epoch: cache proposals, then process the commit.
/// Updates tree, group_context, transcript hashes, init_secret.
/// Also updates path_keys/path_key_count with derived parent keys.
fn processEpoch(
    allocator: std.mem.Allocator,
    epoch: PassiveEpoch,
    tree: *RatchetTree,
    group_context: *MsgProtGC,
    interim_th: *[P.nh]u8,
    init_secret: *[P.nh]u8,
    my_leaf: LeafIndex,
    enc_sk: *const [P.nsk]u8,
    psk_store: *const zmls.InMemoryPskStore,
    res_ring: *zmls.ResumptionPskRing(P),
    path_keys: *[max_path_keys]zmls.PathNodeKey(P),
    path_key_count: *u32,
) !void {
    // 1. Cache proposals.
    //    All decoded p_wire buffers must stay alive until after
    //    processCommit, because Proposal values contain slices
    //    into them (e.g. external_psk_id in PSK proposals).
    //    Decoded proposals with heap allocations (Add, Update,
    //    etc.) are tracked for deferred deinit.
    var cache = zmls.ProposalCache(P).init();
    const max_prop_bufs: u32 = 64;
    var prop_bufs: [max_prop_bufs][]u8 = undefined;
    var prop_buf_count: u32 = 0;
    var decoded_props: [max_prop_bufs]Proposal = undefined;
    var decoded_prop_count: u32 = 0;
    defer {
        var di: u32 = 0;
        while (di < decoded_prop_count) : (di += 1) {
            decoded_props[di].deinit(allocator);
        }
        di = 0;
        while (di < prop_buf_count) : (di += 1) {
            allocator.free(prop_bufs[di]);
        }
    }
    for (epoch.proposals) |p_hex| {
        const p_wire = try hexDecodeAlloc(allocator, p_hex);
        prop_bufs[prop_buf_count] = p_wire;
        prop_buf_count += 1;
        const pm = try decodePublicMsg(p_wire);
        // Decode Proposal from FramedContent.content.
        const prop_r = try Proposal.decode(
            allocator,
            pm.fc.content,
            0,
        );
        decoded_props[decoded_prop_count] = prop_r.value;
        decoded_prop_count += 1;

        // Build AuthenticatedContent bytes:
        //   WireFormat (u16) || FramedContent || AuthData
        // ProposalRef = RefHash of this blob (RFC 9420 12.4).
        var ac_buf: [65536]u8 = undefined;
        var ac_pos: u32 = 0;
        ac_pos = try codec.encodeUint16(
            &ac_buf,
            ac_pos,
            @intFromEnum(zmls.WireFormat.mls_public_message),
        );
        ac_pos = try pm.fc.encode(&ac_buf, ac_pos);
        ac_pos = try pm.auth.encode(
            &ac_buf,
            ac_pos,
            pm.fc.content_type,
        );

        _ = try cache.cacheProposal(
            prop_r.value,
            pm.fc.sender,
            ac_buf[0..ac_pos],
        );
    }

    // 2. Decode commit message.
    const c_wire = try hexDecodeAlloc(allocator, epoch.commit);
    defer allocator.free(c_wire);
    const cm = try decodePublicMsg(c_wire);

    // 3. Decode Commit from FramedContent.content.
    var commit_r = try MsgCommit.decode(
        allocator,
        cm.fc.content,
        0,
    );
    defer commit_r.value.deinit(allocator);

    // 4. Resolve ProposalOrRef list (with per-proposal senders).
    var resolved_buf: [256]Proposal = undefined;
    var senders_buf: [256]zmls.Sender = undefined;
    const commit_sender = cm.fc.sender;
    const n_resolved = try cache.resolveWithSenders(
        commit_r.value.proposals,
        commit_sender,
        &resolved_buf,
        &senders_buf,
    );
    const resolved = resolved_buf[0..n_resolved];
    const resolved_senders = senders_buf[0..n_resolved];

    // 5. Look up sender's signature key.
    const sender_pk = try lookupSignerPk(
        tree,
        cm.fc.sender.leaf_index,
    );

    // 6. Build ReceiverPathParams if path present.
    //    Get receiver's encryption public key from tree.
    const my_node_idx = my_leaf.toNodeIndex().toU32();
    const my_node = tree.nodes[my_node_idx] orelse
        return error.BlankNode;
    if (my_node.node_type != .leaf)
        return error.InvalidNodeType;
    const my_enc_key = my_node.payload.leaf.encryption_key;
    if (my_enc_key.len != P.npk) return error.InvalidLength;
    const enc_pk: *const [P.npk]u8 = my_enc_key[0..P.npk];

    const rp: ?zmls.ReceiverPathParams(P) =
        if (commit_r.value.path != null) .{
            .receiver = my_leaf,
            .receiver_sk = enc_sk,
            .receiver_pk = enc_pk,
            .path_keys = path_keys[0..path_key_count.*],
        } else null;

    // 7. Build PskResolver.
    const resolver: zmls.PskResolver(P) = .{
        .external = psk_store.lookup(),
        .resumption = res_ring,
    };

    // 8. Process commit.
    var result = zmls.processCommit(
        P,
        allocator,
        .{
            .fc = &cm.fc,
            .signature = &cm.auth.signature,
            .confirmation_tag = &(cm.auth.confirmation_tag orelse
                return error.MissingConfirmationTag),
            .proposals = resolved,
            .update_path = if (commit_r.value.path) |*p_val|
                @as(?*const zmls.UpdatePath, p_val)
            else
                null,
            .sender_verify_key = &sender_pk,
            .receiver_params = rp,
            .psk_resolver = resolver,
            .proposal_senders = resolved_senders,
        },
        group_context,
        tree,
        interim_th,
        init_secret,
    ) catch |err| return err;

    // 9. Free old tree, adopt new one.
    tree.deinit();
    tree.* = result.tree;

    // 10. Update state — free old context heap data first.
    group_context.deinit(allocator);
    group_context.* = result.group_context;
    interim_th.* = result.interim_transcript_hash;
    init_secret.* = result.epoch_secrets.init_secret;

    // 10b. Update derived parent-node keys from this epoch's
    //      UpdatePath (if any). Merge: update existing entries
    //      for the same node, append new ones. Keys for nodes
    //      not on this sender's path remain from prior epochs.
    if (result.path_key_count > 0) {
        var ri: u32 = 0;
        while (ri < result.path_key_count) : (ri += 1) {
            const rk = result.path_keys[ri];
            // Check if we already have a key for this node.
            var found = false;
            var ki: u32 = 0;
            while (ki < path_key_count.*) : (ki += 1) {
                if (path_keys[ki].node.toU32() ==
                    rk.node.toU32())
                {
                    path_keys[ki] = rk;
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (path_key_count.* >= max_path_keys) {
                    return error.IndexOutOfRange;
                }
                path_keys[path_key_count.*] = rk;
                path_key_count.* += 1;
            }
        }
    }

    // 11. Store resumption PSK for this epoch.
    res_ring.retain(
        result.group_context.epoch,
        &result.epoch_secrets.resumption_psk,
    );

    // 12. Verify epoch_authenticator.
    const expected_ea = try hexDecode(
        P.nh,
        epoch.epoch_authenticator,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_ea,
        &result.epoch_secrets.epoch_authenticator,
    );
}

fn verifyPassiveHandlingCommit(
    entry: PassiveHandlingEntry,
) !void {
    const allocator = testing.allocator;

    // -- Join via Welcome (same as Phase 20.11) --

    // 1. Decode KeyPackage.
    const kp_wire = try hexDecodeAlloc(
        allocator,
        entry.key_package,
    );
    defer allocator.free(kp_wire);
    if (kp_wire.len < 4) return error.Truncated;
    var kp_r = try KeyPackage.decode(allocator, kp_wire[4..], 0);
    defer kp_r.value.deinit(allocator);
    const kp_ref = try kp_r.value.makeRef(P);

    // 2. Decode private keys.
    const init_sk = try hexDecode(P.nsk, entry.init_priv);
    const enc_sk = try hexDecode(P.nsk, entry.encryption_priv);

    if (kp_r.value.init_key.len != P.npk)
        return error.InvalidLength;
    const init_pk: *const [P.npk]u8 =
        kp_r.value.init_key[0..P.npk];

    // 3. Decode Welcome.
    const w_wire = try hexDecodeAlloc(allocator, entry.welcome);
    defer allocator.free(w_wire);
    if (w_wire.len < 4) return error.Truncated;
    var w_r = try WelcomeMsg.decode(allocator, w_wire[4..], 0);
    defer w_r.value.deinit(allocator);

    // 4. Set up PSK store.
    var psk_store = zmls.InMemoryPskStore.init();
    const max_psks_hc: u32 = 32;
    var psk_bufs: [max_psks_hc * 2][]u8 = undefined;
    var psk_buf_count: u32 = 0;
    defer {
        var di: u32 = 0;
        while (di < psk_buf_count) : (di += 1) {
            allocator.free(psk_bufs[di]);
        }
    }
    for (entry.external_psks) |epsk| {
        const psk_id_bytes = try hexDecodeAlloc(
            allocator,
            epsk.psk_id,
        );
        psk_bufs[psk_buf_count] = psk_id_bytes;
        psk_buf_count += 1;
        const psk_bytes = try hexDecodeAlloc(
            allocator,
            epsk.psk,
        );
        psk_bufs[psk_buf_count] = psk_bytes;
        psk_buf_count += 1;
        _ = psk_store.addPsk(psk_id_bytes, psk_bytes);
    }

    var res_ring = zmls.ResumptionPskRing(P).init(16);
    const resolver: zmls.PskResolver(P) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // 5. Decrypt Welcome to get signer and optional tree.
    var dec = try decryptWelcomeForTree(
        allocator,
        &w_r.value,
        &kp_ref,
        &init_sk,
        init_pk,
        if (entry.external_psks.len > 0) &psk_store else null,
    );
    defer dec.deinit();

    // 6. Determine tree source.
    var tree: RatchetTree = undefined;
    if (entry.ratchet_tree) |rt_hex| {
        const rt_bytes = try hexDecodeAlloc(
            allocator,
            rt_hex,
        );
        defer allocator.free(rt_bytes);
        tree = try decodeRatchetTree(allocator, rt_bytes);
    } else {
        tree = dec.tree orelse return error.MissingRatchetTree;
        dec.tree = null;
    }

    // 7. Look up signer_pk and my leaf.
    const signer_pk = try lookupSignerPk(&tree, dec.signer);
    const my_leaf = try findMyLeafIndex(
        &tree,
        kp_r.value.leaf_node.signature_key,
    );

    // 8. processWelcome.
    var gs = try zmls.processWelcome(
        P,
        allocator,
        &w_r.value,
        &kp_ref,
        &init_sk,
        init_pk,
        &signer_pk,
        .{ .prebuilt = tree },
        my_leaf,
        resolver,
    );
    defer gs.deinit();

    // Free the tree we passed to processWelcome (it was cloned).
    tree.deinit();

    // Set up resumption PSK ring with non-zero capacity and
    // store the initial epoch's resumption PSK.
    gs.resumption_psk_ring = zmls.ResumptionPskRing(P).init(16);
    gs.resumption_psk_ring.retain(
        gs.group_context.epoch,
        &gs.epoch_secrets.resumption_psk,
    );

    // 9. Verify initial_epoch_authenticator.
    const expected_init_ea = try hexDecode(
        P.nh,
        entry.initial_epoch_authenticator,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_init_ea,
        &gs.epoch_secrets.epoch_authenticator,
    );

    // -- Process epochs --

    var pk_buf: [max_path_keys]zmls.PathNodeKey(P) = undefined;
    var pk_count: u32 = 0;

    for (entry.epochs) |epoch| {
        try processEpoch(
            allocator,
            epoch,
            &gs.tree,
            &gs.group_context,
            &gs.interim_transcript_hash,
            &gs.epoch_secrets.init_secret,
            gs.my_leaf_index,
            &enc_sk,
            &psk_store,
            &gs.resumption_psk_ring,
            &pk_buf,
            &pk_count,
        );
    }
}

test "passive-client-handling-commit: process commits" {
    const parsed = try std.json.parseFromSlice(
        []const PassiveHandlingEntry,
        testing.allocator,
        passive_handling_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            verifyPassiveHandlingCommit(entry) catch |err| {
                return err;
            };
            count += 1;
        }
    }
    try testing.expect(count > 0);
}

// =====================================================================
// 20.13: Passive Client — Random
// =====================================================================
//
// Same structure as passive-client-handling-commit but with 200 epochs
// of random group operations (adds, removes, updates, PSKs).

const passive_random_json = tv.passive_client_random;

test "passive-client-random: process 200 random epochs" {
    const parsed = try std.json.parseFromSlice(
        []const PassiveHandlingEntry,
        testing.allocator,
        passive_random_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    var count: u32 = 0;
    for (parsed.value) |entry| {
        if (entry.cipher_suite == 1) {
            try verifyPassiveHandlingCommit(entry);
            count += 1;
        }
    }
    try testing.expect(count > 0);
}
