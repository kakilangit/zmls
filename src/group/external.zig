//! External commit per RFC 9420 Section 12.4.3.2. Allows new
//! members to join a group via GroupInfo + HPKE without a
//! Welcome message.
// External commit per RFC 9420 Section 12.4.3.2.
//
// An external commit allows a new member to join a group
// without a Welcome message. The joiner obtains a GroupInfo
// (which includes the external_pub extension), performs HPKE
// Encap against the external public key, and constructs a
// Commit with an ExternalInit proposal. The resulting HPKE
// shared secret becomes the init_secret for the new epoch.
//
// This module provides:
//   - deriveExternalKeyPair: derive HPKE key pair from
//     external_secret.
//   - extractExternalPub: extract external_pub from extensions.
//   - makeExternalPubExtension: build the extension struct.
//   - createExternalInit: joiner-side HPKE encap + proposal.
//   - processExternalInit: receiver-side HPKE decap to recover
//     the shared secret used as init_secret.
//   - createExternalCommit: full external join flow.
//   - processExternalCommit: existing member accepts an
//     external join.
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const hpke_mod = @import("../crypto/hpke.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_msg = @import("../messages/commit.zig");
const context_mod = @import("context.zig");
const schedule = @import("../key_schedule/schedule.zig");
const transcript = @import("../key_schedule/transcript.zig");
const evolution = @import("evolution.zig");
const path_mod = @import("../tree/path.zig");
const tree_math = @import("../tree/math.zig");
const tree_hashes = @import("../tree/hashes.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import(
    "../framing/framed_content.zig",
);
const auth_mod = @import("../framing/auth.zig");
const codec = @import("../codec/codec.zig");
const primitives = @import("../crypto/primitives.zig");
const secureZero = primitives.secureZero;
const psk_mod = @import("../key_schedule/psk.zig");
const psk_lookup_mod = @import("../key_schedule/psk_lookup.zig");

const Extension = node_mod.Extension;
const ExtensionType = types.ExtensionType;
const ProposalType = types.ProposalType;
const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const LeafNode = node_mod.LeafNode;
const Node = node_mod.Node;
const Epoch = types.Epoch;
const WireFormat = types.WireFormat;
const ExternalInit = proposal_mod.ExternalInit;
const Proposal = proposal_mod.Proposal;
const Commit = commit_msg.Commit;
const ProposalOrRef = commit_msg.ProposalOrRef;
const UpdatePath = path_mod.UpdatePath;
const max_gc_encode = context_mod.max_gc_encode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const FramedContent = framed_content_mod.FramedContent;
const Sender = framing.Sender;
const CommitSender = evolution.CommitSender;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const GroupError = errors.GroupError;
const TreeError = errors.TreeError;

/// Error set for external commit operations.
pub const ExternalCommitError =
    CryptoError || ValidationError || GroupError ||
    TreeError || error{OutOfMemory};

// -- deriveExternalKeyPair --------------------------------------------------

/// Derive the external HPKE key pair from the external_secret.
///
/// Per RFC 9420 Section 8:
///   external_priv, external_pub =
///       KEM.DeriveKeyPair(external_secret)
///
/// This calls dhKeypairFromSeed which maps to
/// DHKEM(X25519).DeriveKeyPair.
/// Key pair result for the external HPKE key derivation.
pub fn ExternalKeyPair(comptime P: type) type {
    return struct {
        sk: [P.nsk]u8,
        pk: [P.npk]u8,
    };
}

pub fn deriveExternalKeyPair(
    comptime P: type,
    external_secret: *const [P.nh]u8,
) CryptoError!ExternalKeyPair(P) {
    // Use the first seed_len bytes of the external_secret
    // as the DH keypair seed. For P-384 (nh=48, seed_len=48)
    // this uses the full secret; for X25519/P-256 (nh=32,
    // seed_len=32) it also uses the full secret.
    const seed: *const [P.seed_len]u8 = external_secret[0..P.seed_len];
    const kp = try P.dhKeypairFromSeed(seed);
    std.debug.assert(kp.pk.len == P.npk);
    return .{ .sk = kp.sk, .pk = kp.pk };
}

// -- extractExternalPub -----------------------------------------------------

/// Extract the external_pub HPKE public key from a list of
/// extensions.
///
/// Per RFC 9420 Section 12.4.3.2, the GroupInfo must contain
/// an external_pub extension (type 0x0004) whose data is the
/// serialized HPKE public key.
///
/// Returns error.MissingExtension if not found.
/// Returns error.InvalidPublicKey if data length is wrong.
pub fn extractExternalPub(
    comptime P: type,
    extensions: []const Extension,
) ExternalCommitError![P.npk]u8 {
    std.debug.assert(P.npk > 0);
    for (extensions) |*ext| {
        if (ext.extension_type == .external_pub) {
            if (ext.data.len != P.npk) {
                return error.InvalidPublicKey;
            }
            var pk: [P.npk]u8 = undefined;
            @memcpy(&pk, ext.data[0..P.npk]);
            return pk;
        }
    }
    return error.MissingExtension;
}

// -- makeExternalPubExtension -----------------------------------------------

/// Create an Extension struct containing the external_pub
/// HPKE public key derived from the external_secret.
///
/// Per RFC 9420 Section 8, the external_pub extension carries
/// the public key so external joiners can perform HPKE Encap.
///
/// The caller provides `out_pk` as owned storage for the
/// public key bytes; the returned Extension's data field
/// points into this buffer.
pub fn makeExternalPubExtension(
    comptime P: type,
    external_secret: *const [P.nh]u8,
    out_pk: *[P.npk]u8,
) CryptoError!Extension {
    const kp = try deriveExternalKeyPair(P, external_secret);
    @memcpy(out_pk, &kp.pk);
    std.debug.assert(out_pk.len == P.npk);
    return Extension{
        .extension_type = .external_pub,
        .data = out_pk,
    };
}

// -- createExternalInit -----------------------------------------------------

/// Result of createExternalInit — the ExternalInit proposal
/// and the HPKE shared secret that becomes init_secret.
pub fn ExternalInitResult(comptime P: type) type {
    return struct {
        /// The ExternalInit proposal to include in the commit.
        proposal: Proposal,
        /// The HPKE shared secret (becomes init_secret for the
        /// external commit's key schedule).
        init_secret: [P.nh]u8,
    };
}

/// Perform joiner-side HPKE Encap against the group's
/// external_pub and produce an ExternalInit proposal.
///
/// Per RFC 9420 Section 12.4.3.2:
///   kem_output, init_secret = Encap(external_pub)
///
/// The kem_output goes into the ExternalInit proposal.
/// The init_secret feeds the key schedule for the new epoch.
///
/// `eph_seed` is used for deterministic Encap (testability).
/// `kem_output_buf` receives the encapsulated key bytes and
/// must outlive the returned proposal.
pub fn createExternalInit(
    comptime P: type,
    external_pub: *const [P.npk]u8,
    eph_seed: *const [P.seed_len]u8,
    kem_output_buf: *[P.npk]u8,
) ExternalCommitError!ExternalInitResult(P) {
    const H = hpke_mod.Hpke(P);
    const encap = try H.encapDeterministic(
        external_pub,
        eph_seed,
    );
    @memcpy(kem_output_buf, &encap.enc);

    std.debug.assert(encap.shared_secret.len == P.nh);
    std.debug.assert(kem_output_buf.len == P.npk);

    return ExternalInitResult(P){
        .proposal = Proposal{
            .tag = .external_init,
            .payload = .{
                .external_init = ExternalInit{
                    .kem_output = kem_output_buf,
                },
            },
        },
        .init_secret = encap.shared_secret,
    };
}

// -- processExternalInit ----------------------------------------------------

/// Recover the HPKE shared secret from an ExternalInit
/// proposal's kem_output (receiver side).
///
/// Per RFC 9420 Section 12.4.3.2:
///   init_secret = Decap(kem_output, external_priv)
///
/// The existing member derives external_priv from their
/// external_secret, then performs HPKE Decap to recover the
/// same shared secret the joiner used as init_secret.
pub fn processExternalInit(
    comptime P: type,
    kem_output: []const u8,
    external_secret: *const [P.nh]u8,
) ExternalCommitError![P.nh]u8 {
    if (kem_output.len != P.npk) {
        return error.InvalidPublicKey;
    }

    var kp = try deriveExternalKeyPair(P, external_secret);
    defer secureZero(&kp.sk);
    const enc: *const [P.npk]u8 = kem_output[0..P.npk];

    const H = hpke_mod.Hpke(P);
    const shared_secret = H.decap(
        enc,
        &kp.sk,
        &kp.pk,
    ) catch return error.HpkeOpenFailed;

    std.debug.assert(shared_secret.len == P.nh);
    return shared_secret;
}

// -- createExternalCommit ---------------------------------------------------

/// Maximum encoded size for FramedContent + auth data.
const max_content_buf: u32 = 65536;

/// Parameters for createExternalCommit.
///
/// The joiner provides their new leaf, signing key, and the
/// group state obtained from GroupInfo.
pub fn ExternalCommitParams(comptime P: type) type {
    return struct {
        /// Allocator for tree and HPKE ciphertexts.
        allocator: std.mem.Allocator,
        /// The joiner's new LeafNode (source = .commit).
        joiner_leaf: LeafNode,
        /// The joiner's signing secret key.
        sign_key: *const [P.sign_sk_len]u8,
        /// Random leaf secret for UpdatePath derivation.
        leaf_secret: *const [P.nh]u8,
        /// Ephemeral seeds for HPKE encryptions along the
        /// UpdatePath. One per resolution member across
        /// all copath nodes.
        eph_seeds: []const [P.seed_len]u8,
        /// Ephemeral seed for ExternalInit HPKE Encap.
        ext_init_seed: *const [P.seed_len]u8,
        /// Additional Remove proposals (optional, for
        /// removing stale members).
        remove_proposals: []const Proposal,
        /// PSK proposals (optional, for external PSKs).
        psk_proposals: []const Proposal = &.{},
        /// External PSK lookup (required if psk_proposals
        /// is non-empty).
        psk_lookup: ?psk_lookup_mod.PskLookup = null,
    };
}

/// Result of createExternalCommit.
pub fn ExternalCommitResult(comptime P: type) type {
    return struct {
        /// Serialized Commit bytes.
        commit_bytes: [max_content_buf]u8,
        commit_len: u32,

        /// Signature over FramedContentTBS.
        signature: [P.sig_len]u8,

        /// Confirmation tag.
        confirmation_tag: [P.nh]u8,

        /// New epoch secrets.
        epoch_secrets: schedule.EpochSecrets(P),

        /// Confirmed transcript hash.
        confirmed_transcript_hash: [P.nh]u8,

        /// Interim transcript hash.
        interim_transcript_hash: [P.nh]u8,

        /// New group context.
        group_context: context_mod.GroupContext(P.nh),

        /// The new tree (with joiner added).
        tree: RatchetTree,

        /// The joiner's leaf index.
        joiner_leaf_index: LeafIndex,

        /// The new epoch number.
        new_epoch: Epoch,

        /// Joiner secret (for Welcome if needed).
        joiner_secret: [P.nh]u8,

        /// Free heap-owned fields (group_context internals).
        pub fn deinit(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) void {
            self.group_context.deinit(allocator);
            // self.* = undefined omitted: tree field is often
            // consumed separately; poisoning would cause
            // use-after-move crashes in callers.
        }
    };
}

/// Steps 1-3: extract external pub, create ExternalInit,
/// clone tree, apply removes, add joiner.
fn ExternalSetupResult(comptime P: type) type {
    return struct {
        new_tree: RatchetTree,
        joiner_leaf: LeafIndex,
        init_secret: [P.nh]u8,
        ext_init_proposal: Proposal,
        kem_output_buf: [P.npk]u8,

        /// Fix kem_output pointer after struct relocation.
        fn fixPointers(self: *@This()) void {
            self.ext_init_proposal.payload
                .external_init.kem_output = &self.kem_output_buf;
        }
    };
}

fn setupExternalTree(
    comptime P: type,
    tree: *const RatchetTree,
    gi_extensions: []const Extension,
    params: *const ExternalCommitParams(P),
) ExternalCommitError!ExternalSetupResult(P) {
    const external_pub = try extractExternalPub(P, gi_extensions);

    var result: ExternalSetupResult(P) = undefined;
    const ext_init = try createExternalInit(
        P,
        &external_pub,
        params.ext_init_seed,
        &result.kem_output_buf,
    );
    result.init_secret = ext_init.init_secret;
    result.ext_init_proposal = ext_init.proposal;

    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    for (params.remove_proposals) |*rm| {
        if (rm.tag != .remove)
            return error.InvalidProposalList;
        try path_mod.removeLeaf(
            &new_tree,
            LeafIndex.fromU32(rm.payload.remove.removed),
        );
    }
    result.joiner_leaf = try path_mod.addLeaf(
        &new_tree,
        params.joiner_leaf,
    );
    result.new_tree = new_tree;
    return result;
}

/// Step 4: generate UpdatePath, apply parent hashes, sign leaf.
/// Caller owns leaf_sig and leaf_ph buffers to avoid dangling.
fn generateExternalPath(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    joiner_leaf: LeafIndex,
    params: *const ExternalCommitParams(P),
    group_context: *const context_mod.GroupContext(P.nh),
    gc_bytes: []const u8,
    leaf_sig: *[P.sig_len]u8,
    leaf_ph: *[P.nh]u8,
) ExternalCommitError!struct {
    commit_secret: [P.nh]u8,
    update_path: UpdatePath,
} {
    const pr = try path_mod.generateUpdatePath(
        P,
        params.allocator,
        new_tree,
        joiner_leaf,
        params.joiner_leaf,
        gc_bytes,
        params.leaf_secret,
        params.eph_seeds,
    );
    var update_path = pr.update_path;
    errdefer {
        const n: u32 = @intCast(update_path.nodes.len);
        path_mod.freeUpnSlice(
            params.allocator,
            @constCast(update_path.nodes),
            n,
        );
    }
    try applyExternalPath(
        P,
        allocator,
        new_tree,
        joiner_leaf,
        &update_path,
        params.sign_key,
        group_context,
        leaf_sig,
        leaf_ph,
    );
    return .{
        .commit_secret = pr.commit_secret,
        .update_path = update_path,
    };
}

/// Steps 4-9: generate path, apply, encode, sign, confirmed hash.
fn buildExternalCommitContent(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    joiner_leaf: LeafIndex,
    ext_init_proposal: Proposal,
    params: *const ExternalCommitParams(P),
    group_context: *const context_mod.GroupContext(P.nh),
    interim_transcript_hash: *const [P.nh]u8,
    wire_format: WireFormat,
) ExternalCommitError!struct {
    commit_secret: [P.nh]u8,
    sign_result: ExternalSignResult(P),
} {
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = group_context.serialize(
        &gc_buf,
    ) catch return error.IndexOutOfRange;
    var leaf_sig: [P.sig_len]u8 = undefined;
    var leaf_ph: [P.nh]u8 = undefined;
    const path_r = try generateExternalPath(
        P,
        allocator,
        new_tree,
        joiner_leaf,
        params,
        group_context,
        gc_bytes,
        &leaf_sig,
        &leaf_ph,
    );
    errdefer {
        const n: u32 = @intCast(path_r.update_path.nodes.len);
        path_mod.freeUpnSlice(
            params.allocator,
            @constCast(path_r.update_path.nodes),
            n,
        );
    }
    const sr = try signExternalCommit(
        P,
        allocator,
        new_tree,
        ext_init_proposal,
        path_r.update_path,
        params,
        group_context,
        gc_bytes,
        interim_transcript_hash,
        wire_format,
    );
    {
        const n: u32 = @intCast(path_r.update_path.nodes.len);
        path_mod.freeUpnSlice(
            params.allocator,
            @constCast(path_r.update_path.nodes),
            n,
        );
    }
    return .{
        .commit_secret = path_r.commit_secret,
        .sign_result = sr,
    };
}

/// Result from signExternalCommit helper.
fn ExternalSignResult(comptime P: type) type {
    return struct {
        commit_buf: [max_content_buf]u8,
        commit_len: u32,
        signature: [P.sig_len]u8,
        confirmed_th: [P.nh]u8,
        new_tree_hash: [P.nh]u8,
    };
}

/// Steps 5-8: compute tree hash, encode commit, build
/// FramedContent, sign, and compute confirmed transcript hash.
fn signExternalCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    ext_init_proposal: Proposal,
    update_path: UpdatePath,
    params: *const ExternalCommitParams(P),
    group_context: *const context_mod.GroupContext(P.nh),
    gc_bytes: []const u8,
    interim_transcript_hash: *const [P.nh]u8,
    wire_format: WireFormat,
) ExternalCommitError!ExternalSignResult(P) {
    // 5. Compute new tree hash.
    const root = tree_math.root(new_tree.leaf_count);
    const new_tree_hash = try tree_hashes.treeHash(
        P,
        allocator,
        new_tree,
        root,
    );

    // 6. Encode the Commit.
    var result: ExternalSignResult(P) = undefined;
    result.new_tree_hash = new_tree_hash;
    result.commit_len = try encodeExternalCommit(
        ext_init_proposal,
        params.remove_proposals,
        params.psk_proposals,
        update_path,
        &result.commit_buf,
    );

    // 7. Build FramedContent with new_member_commit sender.
    const fc = FramedContent{
        .group_id = group_context.group_id,
        .epoch = group_context.epoch,
        .sender = Sender.newMemberCommit(),
        .authenticated_data = "",
        .content_type = .commit,
        .content = result.commit_buf[0..result.commit_len],
    };

    // 8. Sign FramedContent.
    const auth = try auth_mod.signFramedContent(
        P,
        &fc,
        wire_format,
        gc_bytes,
        params.sign_key,
        null,
        null,
    );
    result.signature = auth.signature;

    // 9. Compute confirmed transcript hash.
    result.confirmed_th = try buildConfirmedHash(
        P,
        &fc,
        &auth.signature,
        interim_transcript_hash,
        wire_format,
    );

    return result;
}

/// Steps 10-13: build new GroupContext, derive epoch secrets,
/// compute confirmation tag and interim transcript hash.
fn deriveExternalCreateEpoch(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    new_tree_hash: [P.nh]u8,
    confirmed_th: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
) ExternalCommitError!struct {
    new_gc: context_mod.GroupContext(P.nh),
    epoch_secrets: schedule.EpochSecrets(P),
    confirmation_tag: [P.nh]u8,
    interim_th: [P.nh]u8,
} {
    var new_gc = try group_context.updateForNewEpoch(
        allocator,
        new_tree_hash,
        confirmed_th.*,
        group_context.extensions,
    );
    errdefer new_gc.deinit(allocator);
    var new_gc_buf: [max_gc_encode]u8 = undefined;
    const new_gc_bytes = new_gc.serialize(
        &new_gc_buf,
    ) catch return error.IndexOutOfRange;

    const es = schedule.deriveEpochSecrets(
        P,
        init_secret,
        commit_secret,
        psk_secret,
        new_gc_bytes,
    );
    const confirmation_tag = auth_mod.computeConfirmationTag(
        P,
        &es.confirmation_key,
        confirmed_th,
    );
    const interim_th = transcript.updateInterimTranscriptHash(
        P,
        confirmed_th,
        &confirmation_tag,
    ) catch return error.IndexOutOfRange;

    return .{
        .new_gc = new_gc,
        .epoch_secrets = es,
        .confirmation_tag = confirmation_tag,
        .interim_th = interim_th,
    };
}

/// Create an external commit per RFC 9420 Section 12.4.3.2.
///
/// The joiner:
///   1. Extracts external_pub from GroupInfo extensions.
///   2. Creates an ExternalInit proposal (HPKE Encap).
///   3. Adds themselves to the tree.
///   4. Generates an UpdatePath.
///   5. Signs the commit as new_member_commit.
///   6. Derives epoch secrets using the HPKE init_secret.
///
/// `group_context` is the group's current GroupContext.
/// `tree` is the group's current ratchet tree.
/// `gi_extensions` are the GroupInfo extensions (must include
///   external_pub).
/// `interim_transcript_hash` is the group's current interim
///   transcript hash.
pub fn createExternalCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    gi_extensions: []const Extension,
    interim_transcript_hash: *const [P.nh]u8,
    params: ExternalCommitParams(P),
    wire_format: WireFormat,
) ExternalCommitError!ExternalCommitResult(P) {
    // 1-3. Init secret, clone tree, apply removes, add joiner.
    var setup = try setupExternalTree(
        P,
        tree,
        gi_extensions,
        &params,
    );
    setup.fixPointers();
    errdefer setup.new_tree.deinit();
    defer secureZero(&setup.init_secret);

    // 4-9. Path, encode, sign, confirmed transcript hash.
    var bc = try buildExternalCommitContent(
        P,
        allocator,
        &setup.new_tree,
        setup.joiner_leaf,
        setup.ext_init_proposal,
        &params,
        group_context,
        interim_transcript_hash,
        wire_format,
    );
    defer secureZero(&bc.commit_secret);

    // 10-13. Derive epoch, confirmation, interim hash.
    var psk_secret = try resolveExternalPskSecret(
        P,
        params.psk_proposals,
        params.psk_lookup,
    );
    defer secureZero(&psk_secret);
    const epoch = try deriveExternalCreateEpoch(
        P,
        allocator,
        group_context,
        bc.sign_result.new_tree_hash,
        &bc.sign_result.confirmed_th,
        &setup.init_secret,
        &bc.commit_secret,
        &psk_secret,
    );

    return .{
        .commit_bytes = bc.sign_result.commit_buf,
        .commit_len = bc.sign_result.commit_len,
        .signature = bc.sign_result.signature,
        .confirmation_tag = epoch.confirmation_tag,
        .epoch_secrets = epoch.epoch_secrets,
        .confirmed_transcript_hash = bc.sign_result.confirmed_th,
        .interim_transcript_hash = epoch.interim_th,
        .group_context = epoch.new_gc,
        .tree = setup.new_tree,
        .joiner_leaf_index = setup.joiner_leaf,
        .new_epoch = group_context.epoch + 1,
        .joiner_secret = epoch.epoch_secrets.joiner_secret,
    };
}

/// Encode the Commit struct for an external commit.
///
/// Contains: ExternalInit proposal (+ optional Removes) and
/// an UpdatePath.
fn encodeExternalCommit(
    ext_init_proposal: Proposal,
    remove_proposals: []const Proposal,
    psk_proposals: []const Proposal,
    update_path: UpdatePath,
    buf: *[max_content_buf]u8,
) ExternalCommitError!u32 {
    // Build ProposalOrRef: ExternalInit + Removes + PSKs.
    var por_buf: [257]ProposalOrRef = undefined;
    const total = 1 + remove_proposals.len + psk_proposals.len;
    if (total > 257) return error.InvalidProposalList;

    por_buf[0] = ProposalOrRef.initProposal(ext_init_proposal);
    for (remove_proposals, 0..) |*rm, index| {
        por_buf[1 + index] = ProposalOrRef.initProposal(rm.*);
    }
    const psk_off = 1 + remove_proposals.len;
    for (psk_proposals, 0..) |*p, index| {
        por_buf[psk_off + index] = ProposalOrRef.initProposal(p.*);
    }

    const commit = Commit{
        .proposals = por_buf[0..total],
        .path = update_path,
    };

    const end = commit.encode(buf, 0) catch {
        return error.IndexOutOfRange;
    };
    return end;
}

/// Build confirmed transcript hash (shared with commit.zig).
fn buildConfirmedHash(
    comptime P: type,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    interim_prev: *const [P.nh]u8,
    wire_format: WireFormat,
) ExternalCommitError![P.nh]u8 {
    var input_buf: [max_content_buf]u8 = undefined;
    var pos: u32 = 0;

    // WireFormat (u16).
    pos = codec.encodeUint16(
        &input_buf,
        pos,
        @intFromEnum(wire_format),
    ) catch return error.IndexOutOfRange;

    // FramedContent.
    pos = fc.encode(
        &input_buf,
        pos,
    ) catch return error.IndexOutOfRange;

    // opaque signature<V>.
    pos = codec.encodeVarVector(
        &input_buf,
        pos,
        signature,
    ) catch return error.IndexOutOfRange;

    return transcript.updateConfirmedTranscriptHash(
        P,
        interim_prev,
        input_buf[0..pos],
    ) catch return error.IndexOutOfRange;
}

/// Apply parent keys, compute parent hashes, then set the
/// joiner leaf's parent_hash, source, sign, and install in tree.
fn applyExternalPath(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    joiner_leaf: LeafIndex,
    update_path: *UpdatePath,
    sign_key: *const [P.sign_sk_len]u8,
    group_context: *const context_mod.GroupContext(P.nh),
    leaf_sig: *[P.sig_len]u8,
    ph_buf: *[P.nh]u8,
) ExternalCommitError!void {
    // 1. Apply only parent node keys (not the leaf).
    try applyPathParentNodes(new_tree, joiner_leaf, update_path);
    // 2. Set parent hashes on parent nodes (top-down).
    try path_mod.setPathParentHashes(P, allocator, new_tree, joiner_leaf);
    // 3. Compute leaf parent_hash.
    if (try path_mod.computeLeafParentHash(
        P,
        allocator,
        new_tree,
        joiner_leaf,
    )) |ph| {
        ph_buf.* = ph;
        update_path.leaf_node.parent_hash = ph_buf;
    }
    // 4. Set source and sign.
    update_path.leaf_node.source = .commit;
    update_path.leaf_node.signLeafNode(
        P,
        sign_key,
        leaf_sig,
        group_context.group_id,
        joiner_leaf,
    ) catch return error.InvalidLeafSignature;
    // 5. Install leaf in tree.
    try new_tree.setLeaf(joiner_leaf, update_path.leaf_node);
}

/// Set parent nodes from UpdatePath without touching the leaf.
fn applyPathParentNodes(
    tree: *RatchetTree,
    sender: LeafIndex,
    update_path: *const UpdatePath,
) (TreeError || error{OutOfMemory})!void {
    var p_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    var c_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    const fdp = try tree.filteredDirectPath(
        sender,
        &p_buf,
        &c_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != update_path.nodes.len)
        return error.MalformedUpdatePath;
    for (0..n_path) |pi| {
        const upn = &update_path.nodes[pi];
        try tree.setNode(
            fdp.path[pi],
            Node.initParent(.{
                .encryption_key = upn.encryption_key,
                .parent_hash = "",
                .unmerged_leaves = &.{},
            }),
        );
    }
}

/// Derive new epoch state: tree hash, GroupContext, epoch secrets.
/// Shared by create and process external commit paths.
fn deriveExternalEpochState(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *const RatchetTree,
    group_context: *const context_mod.GroupContext(P.nh),
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    confirmed_th: *const [P.nh]u8,
) ExternalCommitError!struct {
    epoch_secrets: schedule.EpochSecrets(P),
    new_gc: context_mod.GroupContext(P.nh),
    new_tree_hash: [P.nh]u8,
} {
    const root = tree_math.root(new_tree.leaf_count);
    const new_tree_hash = try tree_hashes.treeHash(
        P,
        allocator,
        new_tree,
        root,
    );
    var new_gc = try group_context.updateForNewEpoch(
        allocator,
        new_tree_hash,
        confirmed_th.*,
        group_context.extensions,
    );
    errdefer new_gc.deinit(allocator);
    var new_gc_buf: [max_gc_encode]u8 = undefined;
    const new_gc_bytes = new_gc.serialize(
        &new_gc_buf,
    ) catch return error.IndexOutOfRange;
    const epoch_secrets = schedule.deriveEpochSecrets(
        P,
        init_secret,
        commit_secret,
        psk_secret,
        new_gc_bytes,
    );
    return .{
        .epoch_secrets = epoch_secrets,
        .new_gc = new_gc,
        .new_tree_hash = new_tree_hash,
    };
}

/// Verify preconditions for an external commit: sender type,
/// content type, epoch, and signature.
fn verifyExternalPreconditions(
    comptime P: type,
    fc: *const FramedContent,
    group_context: *const context_mod.GroupContext(P.nh),
    signature: *const [P.sig_len]u8,
    joiner_verify_key: *const [P.sign_pk_len]u8,
    wire_format: WireFormat,
) ExternalCommitError!void {
    if (fc.sender.sender_type != .new_member_commit)
        return error.NotAMember;
    if (fc.content_type != .commit)
        return error.InvalidProposalList;
    if (fc.epoch != group_context.epoch)
        return error.WrongEpoch;
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = group_context.serialize(
        &gc_buf,
    ) catch return error.IndexOutOfRange;
    const auth = auth_mod.FramedContentAuthData(P){
        .signature = signature.*,
        .confirmation_tag = null,
    };
    try auth_mod.verifyFramedContent(
        P,
        fc,
        wire_format,
        gc_bytes,
        joiner_verify_key,
        &auth,
    );
}

/// Find and process the ExternalInit proposal from the list.
fn findAndProcessExternalInit(
    comptime P: type,
    proposals: []const Proposal,
    external_secret: *const [P.nh]u8,
) ExternalCommitError![P.nh]u8 {
    var init_secret: [P.nh]u8 = undefined;
    var found = false;
    for (proposals) |*prop| {
        if (prop.tag == .external_init) {
            if (found) return error.DuplicateProposal;
            init_secret = try processExternalInit(
                P,
                prop.payload.external_init.kem_output,
                external_secret,
            );
            found = true;
        }
    }
    if (!found) return error.InvalidProposalList;
    return init_secret;
}

/// Apply remove proposals and add joiner leaf to the tree.
fn applyExternalTreeChanges(
    new_tree: *RatchetTree,
    proposals: []const Proposal,
    joiner_leaf: LeafNode,
) ExternalCommitError!LeafIndex {
    for (proposals) |*prop| {
        if (prop.tag == .remove) {
            try path_mod.removeLeaf(
                new_tree,
                LeafIndex.fromU32(
                    prop.payload.remove.removed,
                ),
            );
        }
    }
    if (joiner_leaf.source != .commit)
        return error.InvalidLeafNode;
    return try path_mod.addLeaf(new_tree, joiner_leaf);
}

/// Decrypt UpdatePath, apply to tree, set and verify parent hashes.
fn decryptAndVerifyPath(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    joiner_leaf: LeafIndex,
    receiver: LeafIndex,
    update_path: *const path_mod.UpdatePath,
    group_context: *const context_mod.GroupContext(P.nh),
    receiver_sk: *const [P.npk]u8,
    receiver_pk: *const [P.npk]u8,
) ExternalCommitError![P.nh]u8 {
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = group_context.serialize(
        &gc_buf,
    ) catch return error.IndexOutOfRange;
    const path_result = try path_mod.applyUpdatePath(
        P,
        new_tree,
        joiner_leaf,
        receiver,
        update_path,
        gc_bytes,
        receiver_sk,
        receiver_pk,
    );
    try path_mod.setPathParentHashes(
        P,
        allocator,
        new_tree,
        joiner_leaf,
    );
    try tree_hashes.verifyParentHashes(P, allocator, new_tree);
    return path_result.commit_secret;
}

/// Derive epoch secrets, verify confirmation tag, compute
/// interim transcript hash. Returns verified epoch state.
fn verifyExternalEpoch(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *const RatchetTree,
    group_context: *const context_mod.GroupContext(P.nh),
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    confirmed_th: *const [P.nh]u8,
    confirmation_tag: *const [P.nh]u8,
) ExternalCommitError!struct {
    es: schedule.EpochSecrets(P),
    new_gc: context_mod.GroupContext(P.nh),
    interim_th: [P.nh]u8,
} {
    const epoch_state = try deriveExternalEpochState(
        P,
        allocator,
        new_tree,
        group_context,
        init_secret,
        commit_secret,
        psk_secret,
        confirmed_th,
    );
    try auth_mod.verifyConfirmationTag(
        P,
        &epoch_state.epoch_secrets.confirmation_key,
        confirmed_th,
        confirmation_tag,
    );
    const interim_th = transcript.updateInterimTranscriptHash(
        P,
        confirmed_th,
        confirmation_tag,
    ) catch return error.IndexOutOfRange;
    return .{
        .es = epoch_state.epoch_secrets,
        .new_gc = epoch_state.new_gc,
        .interim_th = interim_th,
    };
}

// -- processExternalCommit --------------------------------------------------

/// Process (verify and apply) an external commit per RFC 9420
/// Section 12.4.3.2.
///
/// An existing group member receives an external commit and:
///   1. Verifies the sender is new_member_commit.
///   2. Validates the ExternalInit proposal.
///   3. Recovers init_secret via HPKE Decap.
///   4. Applies proposals (Remove + add joiner via path).
///   5. Decrypts UpdatePath to get commit_secret.
///   6. Derives new epoch secrets.
///   7. Verifies confirmation tag.
///
/// Parameters:
///   - fc: FramedContent with new_member_commit sender.
///   - signature: the signature from auth data.
///   - confirmation_tag: the confirmation tag.
///   - proposals: decoded proposals (ExternalInit + Removes).
///   - update_path: the UpdatePath from the Commit.
///   - group_context: current GroupContext.
///   - tree: current ratchet tree.
///   - joiner_verify_key: joiner's signature public key.
///   - interim_transcript_hash: current interim hash.
///   - external_secret: current epoch's external_secret.
///   - receiver: this member's leaf index.
///   - receiver_sk: this member's HPKE encryption secret key.
///   - receiver_pk: this member's HPKE encryption public key.
fn finalizeAndVerifyExternal(
    comptime P: type,
    allocator: std.mem.Allocator,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    wire_format: WireFormat,
    new_tree: *RatchetTree,
    group_context: *const context_mod.GroupContext(P.nh),
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    proposals: []const Proposal,
    psk_lookup: ?psk_lookup_mod.PskLookup,
    confirmation_tag: *const [P.nh]u8,
    joiner_leaf: LeafIndex,
) ExternalCommitError!ProcessExternalResult(P) {
    const confirmed_th = try buildConfirmedHash(
        P,
        fc,
        signature,
        interim_transcript_hash,
        wire_format,
    );
    var psk_secret = try resolveExternalPskSecret(
        P,
        proposals,
        psk_lookup,
    );
    defer secureZero(&psk_secret);
    const vr = try verifyExternalEpoch(
        P,
        allocator,
        new_tree,
        group_context,
        init_secret,
        commit_secret,
        &psk_secret,
        &confirmed_th,
        confirmation_tag,
    );
    return .{
        .epoch_secrets = vr.es,
        .confirmed_transcript_hash = confirmed_th,
        .interim_transcript_hash = vr.interim_th,
        .group_context = vr.new_gc,
        .tree = new_tree.*,
        .joiner_leaf_index = joiner_leaf,
        .new_epoch = group_context.epoch + 1,
    };
}

pub fn processExternalCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    confirmation_tag: *const [P.nh]u8,
    proposals: []const Proposal,
    update_path: *const UpdatePath,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    joiner_verify_key: *const [P.sign_pk_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    external_secret: *const [P.nh]u8,
    psk_lookup: ?psk_lookup_mod.PskLookup,
    receiver: LeafIndex,
    receiver_sk: *const [P.nsk]u8,
    receiver_pk: *const [P.npk]u8,
    wire_format: WireFormat,
) ExternalCommitError!ProcessExternalResult(P) {
    // 1-3. Verify sender, epoch, signature.
    try verifyExternalPreconditions(
        P,
        fc,
        group_context,
        signature,
        joiner_verify_key,
        wire_format,
    );

    // 4. Validate external commit proposals.
    try validateExternalProposals(proposals);

    // 5. Find ExternalInit and recover init_secret.
    var init_secret = try findAndProcessExternalInit(
        P,
        proposals,
        external_secret,
    );
    defer secureZero(&init_secret);

    // 6. Clone tree, apply removes, add joiner.
    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    const joiner_leaf = try applyExternalTreeChanges(
        &new_tree,
        proposals,
        update_path.leaf_node,
    );

    // 7-8. Decrypt path and verify parent hashes.
    const commit_secret = try decryptAndVerifyPath(
        P,
        allocator,
        &new_tree,
        joiner_leaf,
        receiver,
        update_path,
        group_context,
        receiver_sk,
        receiver_pk,
    );

    // 9-13. Confirmed hash, derive epoch, verify, finalize.
    return finalizeAndVerifyExternal(
        P,
        allocator,
        fc,
        signature,
        interim_transcript_hash,
        wire_format,
        &new_tree,
        group_context,
        &init_secret,
        &commit_secret,
        proposals,
        psk_lookup,
        confirmation_tag,
        joiner_leaf,
    );
}

/// Result of processExternalCommit.
pub fn ProcessExternalResult(comptime P: type) type {
    return struct {
        epoch_secrets: schedule.EpochSecrets(P),
        confirmed_transcript_hash: [P.nh]u8,
        interim_transcript_hash: [P.nh]u8,
        group_context: context_mod.GroupContext(P.nh),
        tree: RatchetTree,
        joiner_leaf_index: LeafIndex,
        new_epoch: Epoch,

        /// Free heap-owned fields (group_context internals).
        pub fn deinit(
            self: *@This(),
            allocator: std.mem.Allocator,
        ) void {
            self.group_context.deinit(allocator);
            // self.* = undefined omitted: tree field is often
            // consumed separately; poisoning would cause
            // use-after-move crashes in callers.
        }
    };
}

// -- External commit proposal validation ------------------------------------

/// Maximum number of proposals in an external commit.
/// ExternalInit(1) + removes + PSKs. Matches max_affected.
const max_ext_proposals: u32 = 256;

/// Resolve ProposalOrRef list into plain Proposals, enforcing
/// that all entries are inline (by-value) per RFC 9420
/// Section 12.4.3.2. External commits must not contain
/// by-reference proposals.
/// Resolve PSK secrets from proposals and derive psk_secret.
/// For external commits, only external PSKs are expected.
fn resolveExternalPskSecret(
    comptime P: type,
    proposals: []const Proposal,
    lookup: ?psk_lookup_mod.PskLookup,
) ExternalCommitError![P.nh]u8 {
    const max_psks: u32 = 64;
    var entries: [max_psks]psk_mod.PskEntry = undefined;
    var count: u32 = 0;

    for (proposals) |*prop| {
        if (prop.tag != .psk) continue;
        if (count >= max_psks) return error.InvalidProposalList;
        const id = &prop.payload.psk.psk;
        const secret: ?[]const u8 = if (lookup) |lk|
            lk.resolve(id)
        else
            null;
        if (secret == null) return error.PskNotFound;
        entries[count] = .{ .id = id.*, .secret = secret.? };
        count += 1;
    }

    if (count == 0) return .{0} ** P.nh;
    return psk_mod.derivePskSecret(P, entries[0..count]) catch
        return error.PskNotFound;
}

pub fn resolveExternalInlineProposals(
    por_list: []const ProposalOrRef,
    out: []Proposal,
) ValidationError![]const Proposal {
    if (por_list.len > out.len)
        return error.InvalidProposalList;
    for (por_list, 0..) |*por, i| {
        if (por.tag != .proposal)
            return error.InvalidProposalList;
        out[i] = por.payload.proposal;
    }
    return out[0..por_list.len];
}

/// Validate that an external commit's proposal list only contains
/// allowed types per RFC 9420 Section 12.4.3.2: exactly one
/// ExternalInit, zero or more Removes and PSKs, nothing else.
fn validateExternalProposals(
    proposals: []const Proposal,
) ValidationError!void {
    var ext_init_count: u32 = 0;
    for (proposals) |*prop| {
        switch (prop.tag) {
            .external_init => ext_init_count += 1,
            .remove, .psk => {},
            .add,
            .update,
            .reinit,
            .group_context_extensions,
            => return error.InvalidProposalList,
            // Unknown/GREASE (includes reserved=0): skip
            // per RFC 9420 S13.
            .reserved, _ => {},
        }
    }
    if (ext_init_count != 1) return error.InvalidProposalList;
}

// -- Tests ------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const Credential = @import(
    "../credential/credential.zig",
).Credential;
const state_mod = @import("state.zig");
const createGroup = state_mod.createGroup;
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;

test "deriveExternalKeyPair is deterministic" {
    const secret = [_]u8{0x42} ** Default.nh;
    const kp1 = try deriveExternalKeyPair(Default, &secret);
    const kp2 = try deriveExternalKeyPair(Default, &secret);

    try testing.expectEqualSlices(u8, &kp1.pk, &kp2.pk);
    try testing.expectEqualSlices(u8, &kp1.sk, &kp2.sk);
}

test "deriveExternalKeyPair produces non-zero output" {
    const secret = [_]u8{0x01} ** Default.nh;
    const kp = try deriveExternalKeyPair(Default, &secret);

    const zero_pk = [_]u8{0} ** Default.npk;
    const zero_sk = [_]u8{0} ** Default.nsk;
    try testing.expect(
        !std.mem.eql(u8, &zero_pk, &kp.pk),
    );
    try testing.expect(
        !std.mem.eql(u8, &zero_sk, &kp.sk),
    );
}

test "deriveExternalKeyPair different secrets give different keys" {
    const secret_a = [_]u8{0xAA} ** Default.nh;
    const secret_b = [_]u8{0xBB} ** Default.nh;
    const kp_a = try deriveExternalKeyPair(Default, &secret_a);
    const kp_b = try deriveExternalKeyPair(Default, &secret_b);

    try testing.expect(
        !std.mem.eql(u8, &kp_a.pk, &kp_b.pk),
    );
}

test "makeExternalPubExtension round-trip with extract" {
    const secret = [_]u8{0x55} ** Default.nh;
    var pk_buf: [Default.npk]u8 = undefined;
    const ext = try makeExternalPubExtension(
        Default,
        &secret,
        &pk_buf,
    );

    // The extension should have external_pub type.
    try testing.expectEqual(
        ExtensionType.external_pub,
        ext.extension_type,
    );
    try testing.expectEqual(
        @as(usize, Default.npk),
        ext.data.len,
    );

    // Extract should recover the same public key.
    const exts = [_]Extension{ext};
    const extracted = try extractExternalPub(Default, &exts);
    try testing.expectEqualSlices(u8, &pk_buf, &extracted);
}

test "extractExternalPub returns MissingExtension when absent" {
    const exts = [_]Extension{};
    const result = extractExternalPub(Default, &exts);
    try testing.expectError(error.MissingExtension, result);
}

test "extractExternalPub returns InvalidPublicKey for wrong size" {
    const bad_ext = Extension{
        .extension_type = .external_pub,
        .data = "too-short",
    };
    const exts = [_]Extension{bad_ext};
    const result = extractExternalPub(Default, &exts);
    try testing.expectError(error.InvalidPublicKey, result);
}

test "createExternalInit and processExternalInit round-trip" {
    // Simulate a group that has derived external_secret.
    const external_secret = [_]u8{0x77} ** Default.nh;

    // Derive the external_pub that would be in GroupInfo.
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    // Joiner performs Encap.
    const eph_seed = [_]u8{0x88} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const joiner_result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    // Existing member performs Decap.
    const recovered = try processExternalInit(
        Default,
        joiner_result.proposal.payload
            .external_init.kem_output,
        &external_secret,
    );

    // Both sides should agree on the init_secret.
    try testing.expectEqualSlices(
        u8,
        &joiner_result.init_secret,
        &recovered,
    );
}

test "createExternalInit shared secret is non-zero" {
    const external_secret = [_]u8{0x33} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const eph_seed = [_]u8{0x44} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &result.init_secret),
    );
}

test "processExternalInit rejects wrong kem_output length" {
    const external_secret = [_]u8{0x11} ** Default.nh;
    const short = [_]u8{ 0x01, 0x02, 0x03 };
    const result = processExternalInit(
        Default,
        &short,
        &external_secret,
    );
    try testing.expectError(error.InvalidPublicKey, result);
}

test "processExternalInit with wrong secret gives different result" {
    // Create an ExternalInit with one external_secret.
    const real_secret = [_]u8{0xAA} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &real_secret,
    );

    const eph_seed = [_]u8{0xBB} ** 32;
    var kem_output_buf: [Default.npk]u8 = undefined;
    const joiner_result = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_output_buf,
    );

    // Try to process with a different external_secret.
    // X25519 Decap does not fail on wrong keys — it produces
    // a different shared secret. So we verify mismatch.
    const wrong_secret = [_]u8{0xCC} ** Default.nh;
    const recovered = try processExternalInit(
        Default,
        &kem_output_buf,
        &wrong_secret,
    );

    // The recovered init_secret should NOT match the joiner's.
    try testing.expect(
        !std.mem.eql(
            u8,
            &joiner_result.init_secret,
            &recovered,
        ),
    );
}

test "createExternalInit is deterministic" {
    const external_secret = [_]u8{0xDD} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const eph_seed = [_]u8{0xEE} ** 32;
    var kem_buf_1: [Default.npk]u8 = undefined;
    var kem_buf_2: [Default.npk]u8 = undefined;

    const r1 = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_buf_1,
    );
    const r2 = try createExternalInit(
        Default,
        &kp.pk,
        &eph_seed,
        &kem_buf_2,
    );

    // Same inputs must produce same outputs.
    try testing.expectEqualSlices(
        u8,
        &r1.init_secret,
        &r2.init_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &kem_buf_1,
        &kem_buf_2,
    );
}

test "external key pair matches HPKE encap/decap directly" {
    // Verify that our derived key pair works with raw HPKE
    // encap/decap, confirming correct key derivation.
    const external_secret = [_]u8{0x99} ** Default.nh;
    const kp = try deriveExternalKeyPair(
        Default,
        &external_secret,
    );

    const H = hpke_mod.Hpke(Default);
    const eph_seed = [_]u8{0xAB} ** 32;

    const encap_result = try H.encapDeterministic(
        &kp.pk,
        &eph_seed,
    );
    const decap_result = try H.decap(
        &encap_result.enc,
        &kp.sk,
        &kp.pk,
    );

    try testing.expectEqualSlices(
        u8,
        &encap_result.shared_secret,
        &decap_result,
    );
}

fn makeTestLeafWithPk(
    id: []const u8,
    enc_pk: []const u8,
    sig_pk: []const u8,
) LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{
        .basic,
    };

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(id),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
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

test "createExternalCommit and processExternalCommit round-trip" {
    const alloc = testing.allocator;

    // -- 1. Generate real crypto keys for Alice (existing
    //       member) and Bob (joiner).

    const alice_enc_seed = [_]u8{0xA1} ** 32;
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &alice_enc_seed,
    );
    const alice_sign_seed = [_]u8{0xA2} ** 32;
    const alice_kp = try Default.signKeypairFromSeed(
        &alice_sign_seed,
    );

    const bob_enc_seed = [_]u8{0xB1} ** 32;
    const bob_enc_kp = try Default.dhKeypairFromSeed(
        &bob_enc_seed,
    );
    const bob_sign_seed = [_]u8{0xB2} ** 32;
    const bob_kp = try Default.signKeypairFromSeed(
        &bob_sign_seed,
    );

    // -- 2. Create a one-member group with Alice at leaf 0.

    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "ext-commit-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // -- 3. Build the external_pub extension from Alice's
    //       epoch secrets.

    var ext_pub_buf: [Default.npk]u8 = undefined;
    const ext_pub_ext = try makeExternalPubExtension(
        Default,
        &gs.epoch_secrets.external_secret,
        &ext_pub_buf,
    );
    const gi_extensions = [_]Extension{ext_pub_ext};

    // -- 4. Bob creates an external commit to join the group.
    //
    // Tree before: [Alice] (1 leaf).
    // Bob will be added as leaf 1 → 2-leaf tree.
    // Bob's direct path = [root].
    // Bob's copath = [leaf 0 = Alice].
    // resolution(Alice) = {Alice} → 1 eph seed.

    const bob_leaf = makeTestLeafWithPk(
        "bob",
        &bob_enc_kp.pk,
        &bob_kp.pk,
    );

    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const ext_init_seed = [_]u8{0xF2} ** 32;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
    };

    var ec_result = try createExternalCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        &gi_extensions,
        &gs.interim_transcript_hash,
        .{
            .allocator = alloc,
            .joiner_leaf = bob_leaf,
            .sign_key = &bob_kp.sk,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
            .ext_init_seed = &ext_init_seed,
            .remove_proposals = &.{},
        },
        .mls_public_message,
    );
    defer ec_result.tree.deinit();
    defer ec_result.deinit(testing.allocator);

    // -- 5. Alice decodes the Commit to extract proposals
    //       and UpdatePath.

    const commit_data =
        ec_result.commit_bytes[0..ec_result.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    // Extract inline proposals from ProposalOrRef list.
    const por_list = dec.value.proposals;
    var prop_buf: [257]Proposal = undefined;
    const proposals = try resolveExternalInlineProposals(
        por_list,
        &prop_buf,
    );

    // -- 6. Alice builds FramedContent and calls
    //       processExternalCommit.

    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.newMemberCommit(),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    var proc_result = try processExternalCommit(
        Default,
        testing.allocator,
        &fc,
        &ec_result.signature,
        &ec_result.confirmation_tag,
        proposals,
        &dec.value.path.?,
        &gs.group_context,
        &gs.tree,
        &bob_kp.pk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.external_secret,
        null,
        gs.my_leaf_index, // Alice = leaf 0
        &alice_enc_kp.sk,
        &alice_enc_kp.pk,
        .mls_public_message,
    );
    defer proc_result.tree.deinit();
    defer proc_result.deinit(testing.allocator);

    // -- 7. Verify both sides agree on the new epoch state.

    // New epoch number.
    try testing.expectEqual(
        ec_result.new_epoch,
        proc_result.new_epoch,
    );
    try testing.expectEqual(@as(u64, 1), ec_result.new_epoch);

    // Epoch secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.epoch_secret,
        &proc_result.epoch_secrets.epoch_secret,
    );

    // Init secret (for next epoch).
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.init_secret,
        &proc_result.epoch_secrets.init_secret,
    );

    // Confirmation key.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.confirmation_key,
        &proc_result.epoch_secrets.confirmation_key,
    );

    // Sender data secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.sender_data_secret,
        &proc_result.epoch_secrets.sender_data_secret,
    );

    // Encryption secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.encryption_secret,
        &proc_result.epoch_secrets.encryption_secret,
    );

    // Exporter secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.exporter_secret,
        &proc_result.epoch_secrets.exporter_secret,
    );

    // External secret.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.external_secret,
        &proc_result.epoch_secrets.external_secret,
    );

    // Membership key.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.membership_key,
        &proc_result.epoch_secrets.membership_key,
    );

    // Resumption PSK.
    try testing.expectEqualSlices(
        u8,
        &ec_result.epoch_secrets.resumption_psk,
        &proc_result.epoch_secrets.resumption_psk,
    );

    // Confirmed transcript hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.confirmed_transcript_hash,
        &proc_result.confirmed_transcript_hash,
    );

    // Interim transcript hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.interim_transcript_hash,
        &proc_result.interim_transcript_hash,
    );

    // Tree hash.
    try testing.expectEqualSlices(
        u8,
        &ec_result.group_context.tree_hash,
        &proc_result.group_context.tree_hash,
    );

    // Joiner leaf index — both should agree Bob is at
    // the same leaf.
    try testing.expectEqual(
        ec_result.joiner_leaf_index,
        proc_result.joiner_leaf_index,
    );

    // Tree leaf count — should be 2 (Alice + Bob).
    try testing.expectEqual(
        @as(u32, 2),
        ec_result.tree.leaf_count,
    );
    try testing.expectEqual(
        @as(u32, 2),
        proc_result.tree.leaf_count,
    );
}
