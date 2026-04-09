//! Path secret derivation and HPKE encryption/decryption for
//! UpdatePath processing per RFC 9420 Section 7.5.

const std = @import("std");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const primitives = @import("../crypto/primitives.zig");
const hpke_mod = @import("../crypto/hpke.zig");
const node_mod = @import("node.zig");
const ratchet_tree_mod = @import("ratchet_tree.zig");
const update_path_mod = @import("update_path.zig");

const NodeIndex = types.NodeIndex;
const TreeError = errors.TreeError;
const CryptoError = errors.CryptoError;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const HPKECiphertext = update_path_mod.HPKECiphertext;
const UpdatePath = update_path_mod.UpdatePath;
const max_path_nodes = update_path_mod.max_path_nodes;

pub const secureZero = primitives.secureZero;

/// Result of generateUpdatePath: the UpdatePath wire struct plus
/// the commit_secret derived from the last path secret.
pub fn GeneratePathResult(comptime P: type) type {
    return struct {
        update_path: UpdatePath,
        commit_secret: [P.nh]u8,
    };
}

/// Derive a chain of path secrets from a leaf secret.
///
/// Per RFC 9420 Section 7.5:
///   path_secret[0] = leaf_secret
///   path_secret[n+1] = DeriveSecret(path_secret[n], "path")
///
/// Returns the number of secrets written (== count).
pub fn derivePathSecrets(
    comptime P: type,
    leaf_secret: *const [P.nh]u8,
    count: u32,
    out: *[max_path_nodes][P.nh]u8,
) void {
    std.debug.assert(count > 0);
    std.debug.assert(count <= max_path_nodes);
    out[0] = leaf_secret.*;
    var i: u32 = 1;
    while (i < count) : (i += 1) {
        out[i] = primitives.deriveSecret(
            P,
            &out[i - 1],
            "path",
        );
    }
}

/// Derive commit_secret from the last path_secret.
///
///   commit_secret = DeriveSecret(path_secret[last], "path")
pub fn deriveCommitSecret(
    comptime P: type,
    last_path_secret: *const [P.nh]u8,
) [P.nh]u8 {
    return primitives.deriveSecret(
        P,
        last_path_secret,
        "path",
    );
}

/// Node keypair result: private and public keys.
pub fn NodeKeypair(comptime P: type) type {
    return struct { sk: [P.nsk]u8, pk: [P.npk]u8 };
}

/// Derive a node keypair from a path secret.
///
/// Per RFC 9420 Section 7.5:
///   node_secret = DeriveSecret(path_secret, "node")
///   (node_priv, node_pub) = KEM.DeriveKeyPair(node_secret)
///
/// KEM.DeriveKeyPair is the HPKE DeriveKeyPair function
/// (RFC 9180 Section 7.1.3), NOT a raw seed derivation.
pub fn deriveNodeKeypair(
    comptime P: type,
    path_secret: *const [P.nh]u8,
) CryptoError!NodeKeypair(P) {
    var node_secret = primitives.deriveSecret(
        P,
        path_secret,
        "node",
    );
    defer secureZero(&node_secret);
    const H = hpke_mod.Hpke(P);
    const raw = try H.deriveKeyPair(&node_secret);
    return .{ .sk = raw.sk, .pk = raw.pk };
}

/// Encrypt a path secret to a single recipient's public key.
///
/// Uses EncryptWithLabel(pk, "UpdatePathNode", group_context,
/// secret). Returns an HPKECiphertext (kem_output || ciphertext
/// || tag).
///
/// The returned slices are heap-allocated; caller must free via
/// deinit.
pub fn encryptPathSecretTo(
    comptime P: type,
    allocator: std.mem.Allocator,
    path_secret: *const [P.nh]u8,
    recipient_pk: *const [P.npk]u8,
    group_context: []const u8,
    eph_seed: *const [P.seed_len]u8,
) (CryptoError || error{OutOfMemory})!HPKECiphertext {
    var ct_buf: [P.nh]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    const kem_output = try primitives.encryptWithLabel(
        P,
        recipient_pk,
        "UpdatePathNode",
        group_context,
        path_secret,
        eph_seed,
        &ct_buf,
        &tag,
    );

    // Heap-allocate kem_output and ciphertext||tag.
    const ko = allocator.alloc(
        u8,
        P.npk,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(ko);
    @memcpy(ko, &kem_output);

    const ct_len = P.nh + P.nt;
    const ct = allocator.alloc(
        u8,
        ct_len,
    ) catch return error.OutOfMemory;
    @memcpy(ct[0..P.nh], &ct_buf);
    @memcpy(ct[P.nh..ct_len], &tag);

    return .{ .kem_output = ko, .ciphertext = ct };
}

/// Decrypt a path secret from an HPKECiphertext.
///
/// Uses DecryptWithLabel(sk, pk, "UpdatePathNode",
/// group_context, ...).
pub fn decryptPathSecretFrom(
    comptime P: type,
    ct: *const HPKECiphertext,
    recipient_sk: *const [P.nsk]u8,
    recipient_pk: *const [P.npk]u8,
    group_context: []const u8,
) CryptoError![P.nh]u8 {
    if (ct.kem_output.len != P.npk)
        return error.HpkeOpenFailed;
    const ct_len = P.nh + P.nt;
    if (ct.ciphertext.len != ct_len)
        return error.HpkeOpenFailed;

    const kem_out: *const [P.npk]u8 =
        ct.kem_output[0..P.npk];
    const ciphertext = ct.ciphertext[0..P.nh];
    const tag: *const [P.nt]u8 =
        ct.ciphertext[P.nh..ct_len];

    var pt_out: [P.nh]u8 = undefined;
    errdefer primitives.secureZero(&pt_out);
    try primitives.decryptWithLabel(
        P,
        recipient_sk,
        recipient_pk,
        "UpdatePathNode",
        group_context,
        kem_out,
        ciphertext,
        tag,
        &pt_out,
    );
    return pt_out;
}

/// Encrypt a path secret to all members in a resolution.
///
/// For each node in the resolution, extracts its public key
/// from the tree and encrypts the path secret to it. Returns
/// allocated slice of HPKECiphertext. eph_seeds[i] provides
/// the deterministic seed for the i-th encryption.
pub fn encryptToResolution(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *const RatchetTree,
    path_secret: *const [P.nh]u8,
    resolution: []const NodeIndex,
    group_context: []const u8,
    eph_seeds: []const [P.seed_len]u8,
) (CryptoError || TreeError || error{
    OutOfMemory,
})![]HPKECiphertext {
    std.debug.assert(resolution.len == eph_seeds.len);

    const cts = allocator.alloc(
        HPKECiphertext,
        resolution.len,
    ) catch return error.OutOfMemory;
    var init_count: u32 = 0;
    errdefer freeCtSlice(allocator, cts, init_count);

    for (resolution, 0..) |node_idx, i| {
        const pk = try nodePublicKey(
            P,
            tree,
            node_idx,
        );
        cts[i] = try encryptPathSecretTo(
            P,
            allocator,
            path_secret,
            &pk,
            group_context,
            &eph_seeds[i],
        );
        init_count += 1;
    }
    return cts;
}

/// Extract the HPKE public key from a tree node.
pub fn nodePublicKey(
    comptime P: type,
    tree: *const RatchetTree,
    index: NodeIndex,
) (TreeError || CryptoError)![P.npk]u8 {
    const node = try tree.getNode(index);
    if (node == null) return error.BlankNode;
    const n = node.?;
    const ek = switch (n.node_type) {
        .leaf => n.payload.leaf.encryption_key,
        .parent => n.payload.parent.encryption_key,
    };
    if (ek.len != P.npk) return error.InvalidPublicKey;
    var pk: [P.npk]u8 = undefined;
    @memcpy(&pk, ek[0..P.npk]);
    return pk;
}

/// Free a partially-initialized slice of HPKECiphertext.
pub fn freeCtSlice(
    allocator: std.mem.Allocator,
    cts: []HPKECiphertext,
    count: u32,
) void {
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        cts[i].deinit(allocator);
    }
    allocator.free(cts);
}
