//! Commit creation and processing per RFC 9420 Section 12.4.
//! Handles UpdatePath generation, proposal application, and
//! new epoch state derivation.
// Commit creation and processing per RFC 9420 Section 12.4.
//
// This module implements:
//   - createCommit: build a Commit message with optional UpdatePath
//     and derive new epoch state.
//   - processCommit: verify and apply a received Commit, including
//     decryption of the UpdatePath if present.
//   - buildWelcome: (in welcome.zig) package the epoch state for
//     new members added by the commit.
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const tree_math = @import("../tree/math.zig");
const tree_hashes = @import("../tree/hashes.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const context_mod = @import("context.zig");
const evolution = @import("evolution.zig");
const schedule = @import("../key_schedule/schedule.zig");
const transcript = @import("../key_schedule/transcript.zig");
const psk_mod = @import("../key_schedule/psk.zig");
const psk_lookup_mod = @import("../key_schedule/psk_lookup.zig");
const framing = @import("../framing/content_type.zig");
const framed_content_mod = @import("../framing/framed_content.zig");
const auth_mod = @import("../framing/auth.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_mod = @import("../messages/commit.zig");
const path_mod = @import("../tree/path.zig");
const primitives = @import("../crypto/primitives.zig");
const secureZero = primitives.secureZero;
const codec = @import("../codec/codec.zig");
const public_msg = @import("../framing/public_msg.zig");

const Epoch = types.Epoch;
const LeafIndex = types.LeafIndex;
const NodeIndex = types.NodeIndex;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const Extension = node_mod.Extension;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const max_gc_encode = context_mod.max_gc_encode;
const Proposal = proposal_mod.Proposal;
const Commit = commit_mod.Commit;
const ProposalOrRef = commit_mod.ProposalOrRef;
const UpdatePath = path_mod.UpdatePath;
const UpdatePathNode = path_mod.UpdatePathNode;
const GeneratePathResult = path_mod.GeneratePathResult;
const FramedContent = framed_content_mod.FramedContent;
const Sender = framing.Sender;
const CommitSender = evolution.CommitSender;
const ValidatedProposals = evolution.ValidatedProposals;
const ProposalApplyResult = evolution.ProposalApplyResult;
const TreeError = errors.TreeError;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const GroupError = errors.GroupError;

/// Determine whether an UpdatePath is required per RFC 9420
/// Section 12.4.
///
/// Path is required when the proposal list:
///   - Is empty (empty commit), or
///   - Contains at least one Update, Remove, or ExternalInit.
///
/// Path is NOT required for Add-only or PSK-only commits.
pub fn isPathRequired(
    validated: *const ValidatedProposals,
) bool {
    assert(validated.updates_len <= validated.updates.len);
    assert(validated.removes_len <= validated.removes.len);
    const total: u32 = validated.updates_len +
        validated.removes_len + validated.adds_len +
        validated.psk_ids_len;

    // Empty commit → path required.
    if (total == 0 and
        validated.gce == null and
        validated.reinit == null and
        validated.external_init == null)
    {
        return true;
    }

    // Update, Remove, ExternalInit, or GCE → path required.
    // RFC 9420 Section 12.2 defines:
    //   pathRequiredTypes = [update, remove, external_init,
    //                        group_context_extensions]
    // All four types plus empty commits require a path.
    if (validated.updates_len > 0) return true;
    if (validated.removes_len > 0) return true;
    if (validated.external_init != null) return true;
    if (validated.gce != null) return true;

    return false;
}

/// Error set for createCommit and processCommit.
pub const CommitError =
    TreeError || CryptoError || ValidationError ||
    GroupError || error{OutOfMemory};

/// Maximum encoded size for FramedContent + auth data.
pub const max_content_buf: u32 = 65536;

// -- CommitResult -----------------------------------------------------------

/// Result of createCommit — everything needed by the caller
/// to send the commit and (optionally) a Welcome to new members.
///
/// GroupContext stores tree_hash and confirmed_transcript_hash
/// as inline [P.nh]u8 arrays. No pointer fixup needed.
///
/// Stack usage: ~130 KiB due to inline `commit_bytes` (64 KiB)
/// and `apply_result` (~50 KiB). Callers should ensure
/// sufficient stack space. Zig uses RVO for the return value,
/// so no copy occurs in practice.
pub fn CommitResult(comptime P: type) type {
    return struct {
        /// The serialized Commit struct (for the content payload).
        commit_bytes: [max_content_buf]u8,
        commit_len: u32,

        /// Signature over FramedContentTBS.
        signature: [P.sig_len]u8,

        /// Confirmation tag.
        confirmation_tag: [P.nh]u8,

        /// New epoch secrets.
        epoch_secrets: schedule.EpochSecrets(P),

        /// New confirmed transcript hash.
        confirmed_transcript_hash: [P.nh]u8,

        /// New interim transcript hash.
        interim_transcript_hash: [P.nh]u8,

        /// New group context.
        group_context: context_mod.GroupContext(P.nh),

        /// The new tree (ownership transferred to caller).
        tree: RatchetTree,

        /// Apply result (added/removed leaves, PSK ids).
        apply_result: ProposalApplyResult,

        /// The new epoch number.
        new_epoch: Epoch,

        /// Joiner secret (needed for Welcome).
        joiner_secret: [P.nh]u8,

        /// Welcome secret (needed for Welcome).
        welcome_secret: [P.nh]u8,

        /// Signed leaf node signature for UpdatePath (commit
        /// source).
        leaf_sig: [P.sig_len]u8,

        /// Path secrets from the committer's filtered direct
        /// path. path_secrets[i] corresponds to fdp_nodes[i].
        /// Only valid for 0..path_secret_count. Needed for
        /// Welcome construction (RFC 9420 §12.4.3.1).
        path_secrets: [path_mod.max_path_nodes][P.nh]u8,
        path_secret_count: u32,
        /// Filtered direct path node indices (parallel to
        /// path_secrets).
        fdp_nodes: [path_mod.max_path_nodes]NodeIndex,

        /// Zero path secrets. Must be called after Welcome
        /// construction is complete.
        pub fn zeroPathSecrets(self: *@This()) void {
            for (0..self.path_secret_count) |i| {
                secureZero(&self.path_secrets[i]);
            }
            self.path_secret_count = 0;
        }

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

// -- Options structs (Phase 33.1) ------------------------------------------

/// Per-call options for `createCommit`. Groups the 5 caller-
/// provided inputs that vary per commit operation.
pub fn CreateCommitOpts(comptime P: type) type {
    return struct {
        /// Proposals to include in the commit.
        proposals: []const Proposal,
        /// Committer's signature private key.
        sign_key: *const [P.sign_sk_len]u8,
        /// Path parameters (required for path commits).
        path_params: ?PathParams(P) = null,
        /// PSK resolver (required when PSK proposals present).
        psk_resolver: ?PskResolver(P) = null,
        /// Wire format for the commit message.
        wire_format: WireFormat = .mls_public_message,
    };
}

/// Per-call options for `processCommit`. Groups the receiver-
/// provided inputs for verifying and applying a commit.
pub fn ProcessCommitOpts(comptime P: type) type {
    return struct {
        /// The FramedContent (content_type = .commit).
        fc: *const FramedContent,
        /// Signature from FramedContentAuthData.
        signature: *const [P.sig_len]u8,
        /// Confirmation tag from FramedContentAuthData.
        confirmation_tag: *const [P.nh]u8,
        /// Decoded proposals from the Commit.
        proposals: []const Proposal,
        /// Decoded UpdatePath (null if no path in Commit).
        update_path: ?*const UpdatePath = null,
        /// Committer's signature verification key.
        sender_verify_key: *const [P.sign_pk_len]u8,
        /// Receiver path parameters (leaf index + keys).
        receiver_params: ?ReceiverPathParams(P) = null,
        /// PSK resolver.
        psk_resolver: ?PskResolver(P) = null,
        /// Original proposal senders (for by-ref proposals).
        proposal_senders: ?[]const Sender = null,
        /// Membership key (for tagged messages).
        membership_key: ?*const [P.nh]u8 = null,
        /// Membership tag (for tagged messages).
        membership_tag: ?*const [P.nh]u8 = null,
        /// Wire format of the commit message.
        wire_format: WireFormat = .mls_public_message,
    };
}

// -- createCommit -----------------------------------------------------------

/// Parameters for UpdatePath generation.
///
/// When the commit requires a path (Update/Remove/ExternalInit
/// proposals or empty commit), the caller must provide these.
pub fn PathParams(comptime P: type) type {
    return struct {
        /// Allocator for HPKE ciphertexts and node arrays.
        allocator: std.mem.Allocator,
        /// The committer's new LeafNode (with source = .commit).
        new_leaf: node_mod.LeafNode,
        /// Random leaf secret (Nh bytes) for path derivation.
        leaf_secret: *const [P.nh]u8,
        /// Ephemeral seeds for HPKE encryptions. One per
        /// resolution member across all copath nodes.
        eph_seeds: []const [P.seed_len]u8,
    };
}

/// Parameters for decrypting an UpdatePath during processCommit.
///
/// When the received Commit contains an UpdatePath, the receiver
/// must provide their leaf index and encryption keys so that the
/// path secrets can be HPKE-decrypted.
pub fn ReceiverPathParams(comptime P: type) type {
    return struct {
        /// The receiver's leaf index in the tree.
        receiver: LeafIndex,
        /// The receiver's HPKE encryption secret key (leaf key).
        receiver_sk: *const [P.nsk]u8,
        /// The receiver's HPKE encryption public key (leaf key).
        receiver_pk: *const [P.npk]u8,
        /// Private keys for parent nodes the receiver holds from
        /// prior epoch path processing. Null means leaf-key only.
        path_keys: ?[]const PathNodeKey(P) = null,

        /// Look up the private key for the given resolution node.
        /// Returns (sk, pk) for the node: leaf key if the node is
        /// the receiver's own leaf, or the matching parent key from
        /// path_keys.
        pub fn keyForNode(
            self: *const @This(),
            node: NodeIndex,
            receiver_leaf: LeafIndex,
        ) ?struct { sk: *const [P.nsk]u8, pk: *const [P.npk]u8 } {
            // If the resolution node is the receiver's own leaf,
            // use the leaf key pair.
            if (node.toU32() ==
                receiver_leaf.toNodeIndex().toU32())
            {
                return .{
                    .sk = self.receiver_sk,
                    .pk = self.receiver_pk,
                };
            }
            // Otherwise search path_keys for a parent node match.
            if (self.path_keys) |keys| {
                for (keys) |*k| {
                    if (k.node.toU32() == node.toU32()) {
                        return .{
                            .sk = &k.sk,
                            .pk = &k.pk,
                        };
                    }
                }
            }
            return null;
        }
    };
}

/// A private key the receiver holds for a parent node on their
/// direct path, derived from a prior epoch's path processing.
pub fn PathNodeKey(comptime P: type) type {
    return struct {
        node: NodeIndex,
        sk: [P.nsk]u8,
        pk: [P.npk]u8,
    };
}

/// Bundles external PSK lookup and resumption PSK sources for
/// PSK secret derivation during commit processing.
///
/// If null is passed where a PskResolver is expected, the commit
/// functions use an all-zero psk_secret (no PSKs).
pub fn PskResolver(comptime P: type) type {
    return struct {
        /// External PSK lookup port (application-provided).
        external: psk_lookup_mod.PskLookup,
        /// Resumption PSK ring (from GroupState).
        resumption: *const psk_lookup_mod.ResumptionPskRing(P),
    };
}

/// Resolve PSK secrets from validated proposals and derive the
/// combined psk_secret.
///
/// For each PSK proposal:
///   - External PSKs are looked up via the PskLookup port.
///   - Resumption PSKs are looked up in the ring buffer.
///
/// If any PSK cannot be resolved, returns GroupError.PskNotFound.
/// If no PSK proposals exist, returns all-zero (default).
fn resolvePskSecret(
    comptime P: type,
    validated: *const ValidatedProposals,
    resolver: ?PskResolver(P),
) (GroupError || ValidationError)![P.nh]u8 {
    const n = validated.psk_ids_len;

    if (n == 0) return .{0} ** P.nh;

    // Collect PskEntry for each PSK proposal.
    const max_psks: u32 = 64;
    var entries: [max_psks]psk_mod.PskEntry = undefined;
    var ei: u32 = 0;

    while (ei < n) : (ei += 1) {
        const id = &validated.psk_ids[ei];
        const secret: ?[]const u8 = blk: {
            if (resolver) |r| {
                switch (id.psk_type) {
                    .external => break :blk r.external.resolve(id),
                    .resumption => {
                        const s = r.resumption.lookupSecret(
                            id.resumption_epoch,
                        );
                        if (s) |ptr| break :blk ptr;
                        break :blk null;
                    },
                    else => break :blk null,
                }
            }
            break :blk null;
        };

        if (secret == null) return error.PskNotFound;

        entries[ei] = .{
            .id = id.*,
            .secret = secret.?,
        };
    }

    return psk_mod.derivePskSecret(P, entries[0..n]);
}

/// Create a Commit message per RFC 9420 Section 12.4.
///
/// Steps:
///   1. Validate proposals.
///   2. Apply to a copy of the tree.
///   3. Generate UpdatePath if needed.
///   4. Compute new tree hash.
///   5. Sign FramedContent.
///   6. Compute confirmed_transcript_hash.
///   7. Build new GroupContext.
///   8. Derive epoch secrets.
///   9. Compute confirmation tag.
///   10. Update interim transcript hash.
///
/// `sign_key` is the committer's signing secret key.
/// `proposals` are the proposals to include inline.
/// `path_params` must be provided when the commit requires an
/// UpdatePath (non-Add-only commits). Pass null for Add-only
/// or PSK-only commits.
///
/// Returns a CommitResult with all new state and output data.
pub fn createCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    my_leaf: LeafIndex,
    proposals: []const Proposal,
    sign_key: *const [P.sign_sk_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    path_params: ?PathParams(P),
    psk_resolver: ?PskResolver(P),
    wire_format: WireFormat,
) CommitError!CommitResult(P) {
    assert(tree.leaf_count > 0);
    assert(my_leaf.toNodeIndex().toUsize() < tree.nodes.len);
    const validated = try validateCommitProposals(
        P,
        allocator,
        proposals,
        my_leaf,
        group_context,
        tree,
    );
    defer validated.destroy(allocator);

    // Apply proposals to a copy of the tree.
    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    const apply_result = try evolution.applyProposals(
        validated,
        &new_tree,
    );
    const new_extensions = resolveExtensions(
        &apply_result,
        group_context,
    );

    // Generate UpdatePath if needed. leaf_sig must outlive
    // new_tree because the tree leaf points into it.
    var leaf_sig: [P.sig_len]u8 = .{0} ** P.sig_len;
    var leaf_ph: [P.nh]u8 = .{0} ** P.nh;
    var path_out = try generateCommitPath(
        P,
        allocator,
        &new_tree,
        my_leaf,
        group_context,
        sign_key,
        path_params,
        isPathRequired(validated),
        new_extensions,
        apply_result.added_leaves[0..apply_result.added_count],
        &leaf_sig,
        &leaf_ph,
    );
    defer secureZero(&path_out.commit_secret);
    errdefer freeCommitPath(P, &path_out);

    // Compute tree hash, encode, sign, derive epoch state.
    var cr = try encodeAndFinalizeCommit(
        P,
        allocator,
        group_context,
        &new_tree,
        my_leaf,
        proposals,
        sign_key,
        interim_transcript_hash,
        init_secret,
        validated,
        psk_resolver,
        new_extensions,
        &path_out,
        apply_result,
        leaf_sig,
        wire_format,
    );

    // Copy path secrets for Welcome (RFC 9420 §12.4.3.1).
    cr.path_secret_count = path_out.path_secret_count;
    for (0..path_out.path_secret_count) |i| {
        cr.path_secrets[i] = path_out.path_secrets[i];
        cr.fdp_nodes[i] = path_out.fdp_nodes[i];
    }
    return cr;
}

// -- ProcessResult ----------------------------------------------------------

/// Result of processCommit — the new group state derived by a
/// receiver who verified and applied the commit.
pub fn ProcessResult(comptime P: type) type {
    return struct {
        /// New epoch secrets.
        epoch_secrets: schedule.EpochSecrets(P),

        /// New confirmed transcript hash.
        confirmed_transcript_hash: [P.nh]u8,

        /// New interim transcript hash.
        interim_transcript_hash: [P.nh]u8,

        /// New group context.
        group_context: context_mod.GroupContext(P.nh),

        /// The new tree (ownership transferred to caller).
        tree: RatchetTree,

        /// Apply result (added/removed leaves, PSK ids).
        apply_result: ProposalApplyResult,

        /// The new epoch number.
        new_epoch: Epoch,

        /// Private keys derived from the UpdatePath for parent
        /// nodes. The receiver stores these for future epochs
        /// so it can decrypt when matched via a parent node.
        path_keys: [path_mod.max_path_nodes]PathNodeKey(P),

        /// Number of valid entries in path_keys.
        path_key_count: u32,

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

// -- processCommit ----------------------------------------------------------

/// Process (verify and apply) a Commit per RFC 9420 Section 12.4.2.
///
/// Steps:
///   1. Verify the epoch matches.
///   2. Verify the sender is a valid member.
///   3. Look up the sender's signature key and verify the
///      signature on the FramedContent.
///   4. Decode and validate the proposals from the Commit.
///   5. Apply proposals to a copy of the tree.
///   6. Check path presence rules.
///   7. If UpdatePath present, decrypt path secrets and apply
///      to the tree.
///   8. Compute new tree hash and build new GroupContext.
///   9. Derive new epoch secrets (using real commit_secret
///      from path or zero if no path).
///   10. Recompute the confirmed transcript hash from the
///       FramedContent + signature.
///   11. Verify the confirmation tag.
///   12. Update interim transcript hash.
///
/// Parameters:
///   - `opts`: message-level parameters (FramedContent,
///     signature, proposals, UpdatePath, etc.).
///   - `group_context`: the receiver's current GroupContext.
///   - `tree`: the receiver's current RatchetTree.
///   - `interim_transcript_hash`: current interim transcript
///     hash.
///   - `init_secret`: current epoch init_secret.
///
/// Returns a ProcessResult with the verified new group state.
pub fn processCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    opts: ProcessCommitOpts(P),
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
) CommitError!ProcessResult(P) {
    assert(opts.fc.content_type == .commit);
    assert(tree.leaf_count > 0);
    // 0-4. Verify membership tag, epoch, sender, content type,
    // signature.
    try verifyCommitPreconditions(
        P,
        opts.fc,
        group_context,
        opts.signature,
        opts.confirmation_tag,
        opts.sender_verify_key,
        opts.membership_key,
        opts.membership_tag,
        opts.wire_format,
    );

    // 5. Validate proposals.
    const sender_leaf = LeafIndex.fromU32(opts.fc.sender.leaf_index);
    const validated = try validateProcessProposals(
        P,
        allocator,
        opts.proposals,
        sender_leaf,
        opts.proposal_senders,
        group_context,
        tree,
    );
    defer validated.destroy(allocator);
    // 6. Apply proposals to a copy of the tree.
    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    const apply_result = try evolution.applyProposals(
        validated,
        &new_tree,
    );
    // 7. Check path presence (single-leaf is vacuously ok).
    if (isPathRequired(validated) and opts.update_path == null and
        new_tree.leaf_count > 1) return error.MissingPath;
    // 8. Process UpdatePath if present.
    const new_ext = resolveExtensions(&apply_result, group_context);
    var path_out = processUpdatePath(
        P,
        allocator,
        opts.update_path,
        opts.receiver_params,
        &new_tree,
        sender_leaf,
        group_context,
        new_ext,
        apply_result.added_leaves[0..apply_result.added_count],
    ) catch |e| return e;
    defer secureZero(&path_out.commit_secret);
    // 10-14. Derive epoch state and verify confirmation.
    return deriveProcessEpochState(
        P,
        allocator,
        opts.fc,
        opts.signature,
        opts.confirmation_tag,
        group_context,
        &new_tree,
        validated,
        new_ext,
        interim_transcript_hash,
        init_secret,
        &path_out.commit_secret,
        opts.psk_resolver,
        apply_result,
        path_out.derived_path_keys,
        path_out.derived_key_count,
        opts.wire_format,
    );
}

// -- processCommit helpers --------------------------------------------------

/// Steps 0-4: Verify membership tag (if present), epoch,
/// sender, content type, signature.
fn verifyCommitPreconditions(
    comptime P: type,
    fc: *const FramedContent,
    group_context: *const context_mod.GroupContext(P.nh),
    signature: *const [P.sig_len]u8,
    confirmation_tag: *const [P.nh]u8,
    sender_verify_key: *const [P.sign_pk_len]u8,
    membership_key: ?*const [P.nh]u8,
    membership_tag: ?*const [P.nh]u8,
    wire_format: WireFormat,
) CommitError!void {
    // Membership key and tag must both be present or both absent.
    assert((membership_key == null) == (membership_tag == null));
    if (fc.epoch != group_context.epoch)
        return error.WrongEpoch;
    if (fc.sender.sender_type != .member)
        return error.NotAMember;
    if (fc.content_type != .commit)
        return error.InvalidProposalList;

    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = group_context.serialize(&gc_buf) catch
        return error.IndexOutOfRange;

    // 0. Verify membership tag (PublicMessage only).
    if (membership_tag) |tag| {
        const mkey = membership_key orelse
            return error.MembershipTagMismatch;
        const auth_m = auth_mod.FramedContentAuthData(P){
            .signature = signature.*,
            .confirmation_tag = confirmation_tag.*,
        };
        public_msg.verifyMembershipTag(
            P,
            mkey,
            fc,
            &auth_m,
            tag,
            gc_bytes,
        ) catch return error.MembershipTagMismatch;
    }

    // 1-4. Verify signature.
    const auth = auth_mod.FramedContentAuthData(P){
        .signature = signature.*,
        .confirmation_tag = null,
    };
    try auth_mod.verifyFramedContent(
        P,
        fc,
        wire_format,
        gc_bytes,
        sender_verify_key,
        &auth,
    );
}

/// Step 5: Validate proposals for a received commit.
fn validateProcessProposals(
    comptime P: type,
    allocator: std.mem.Allocator,
    proposals: []const Proposal,
    sender_leaf: LeafIndex,
    proposal_senders: ?[]const Sender,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
) CommitError!*ValidatedProposals {
    assert(sender_leaf.toNodeIndex().toUsize() < tree.nodes.len);
    if (proposal_senders) |ps| {
        assert(ps.len == proposals.len);
    }
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = sender_leaf,
    };
    const validated = try evolution.validateProposalList(
        allocator,
        proposals,
        sender,
        proposal_senders,
    );
    errdefer validated.destroy(allocator);
    // RFC 9420 S12.2: ExternalInit is only valid in external
    // commits, never in regular member commits.
    if (validated.external_init != null)
        return error.InvalidProposalList;
    try evolution.validateReInitVersion(
        validated,
        group_context.version,
    );
    try evolution.validateAddKeyPackages(
        P,
        validated,
        group_context.cipher_suite,
    );
    try evolution.validateUpdateLeafNodes(
        P,
        validated,
        group_context.group_id,
        group_context.cipher_suite,
    );
    try evolution.validateAddsAgainstTree(
        validated,
        tree,
        group_context.cipher_suite,
    );
    try evolution.validateUpdatesAgainstTree(
        validated,
        tree,
        sender,
    );
    try evolution.validateRemovesAgainstTree(
        validated,
        tree,
    );
    evolution.validateAddsRequiredCapabilities(
        validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    evolution.validateUpdatesRequiredCapabilities(
        validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    try evolution.validatePskProposals(validated, P.nh);
    try evolution.validateGceAgainstTree(validated, tree);
    try evolution.validateNonDefaultProposalCaps(
        proposals,
        tree,
    );
    return validated;
}

/// Output of processUpdatePath.
fn UpdatePathOutput(comptime P: type) type {
    return struct {
        commit_secret: [P.nh]u8,
        derived_path_keys: [path_mod.max_path_nodes]PathNodeKey(P),
        derived_key_count: u32,
    };
}

/// Step 8: Find receiver position (pre-merge), merge UpdatePath
/// into tree, build provisional GC, decrypt and verify path.
fn processUpdatePath(
    comptime P: type,
    allocator: std.mem.Allocator,
    update_path: ?*const UpdatePath,
    receiver_params: ?ReceiverPathParams(P),
    new_tree: *RatchetTree,
    sender_leaf: LeafIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    new_extensions: []const Extension,
    added_leaves: []const LeafIndex,
) CommitError!UpdatePathOutput(P) {
    assert(new_tree.leaf_count > 0);
    assert(sender_leaf.toNodeIndex().toUsize() < new_tree.nodes.len);
    var result: UpdatePathOutput(P) = .{
        .commit_secret = .{0} ** P.nh,
        .derived_path_keys = undefined,
        .derived_key_count = 0,
    };
    const up = update_path orelse return result;
    const rp = receiver_params orelse
        return error.MissingPath;

    // RFC 9420 S12.4.2: leaf_node.source must be commit.
    if (up.leaf_node.source != .commit)
        return error.InvalidLeafNode;

    // RFC 9420 S12.4.2: leaf encryption_key must differ
    // from committer's current key (freshness).
    try validatePathKeyFreshness(
        P,
        up,
        new_tree,
        sender_leaf,
    );

    // Validate path length and find receiver position.
    var fp_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    var fc_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    const fdp = try new_tree.filteredDirectPath(
        sender_leaf,
        &fp_buf,
        &fc_buf,
    );
    const n_path: u32 = @intCast(fdp.path.len);
    if (n_path != up.nodes.len)
        return error.MalformedUpdatePath;
    const pos = try path_mod.findReceiverPos(
        new_tree,
        rp.receiver,
        fdp.copath[0..n_path],
        added_leaves,
    );

    // Merge path, build provisional GC, decrypt, derive.
    try path_mod.applySenderPath(new_tree, sender_leaf, up);
    try path_mod.setPathParentHashes(P, allocator, new_tree, sender_leaf);
    var prov_gc_buf: [max_gc_encode]u8 = undefined;
    const prov_gc_bytes = try buildProvisionalGc(
        P,
        allocator,
        new_tree,
        group_context,
        new_extensions,
        &prov_gc_buf,
    );
    var ps0 = try decryptPathSecret(P, up, rp, pos, prov_gc_bytes);
    defer secureZero(&ps0);

    return deriveAndCollectPathKeys(
        P,
        up,
        &ps0,
        pos.node_idx,
        n_path,
        fdp.path,
        group_context,
        sender_leaf,
        &result,
    );
}

/// RFC 9420 S12.4.2: verify UpdatePath key freshness.
/// Leaf encryption_key must differ from the committer's current
/// key. No UpdatePath key may already appear in the pre-merge
/// tree.
fn validatePathKeyFreshness(
    comptime P: type,
    up: *const UpdatePath,
    tree: *const RatchetTree,
    sender_leaf: LeafIndex,
) CommitError!void {
    _ = P;
    // Check leaf encryption_key against committer's current key.
    const leaf_idx = sender_leaf.toNodeIndex().toUsize();
    if (leaf_idx < tree.nodes.len) {
        if (tree.nodes[leaf_idx]) |node| {
            if (node.node_type == .leaf) {
                const old_ek =
                    node.payload.leaf.encryption_key;
                const new_ek = up.leaf_node.encryption_key;
                if (std.mem.eql(u8, old_ek, new_ek))
                    return error.InvalidLeafNode;
            }
        }
    }
    // Check no path node key already exists in the tree.
    for (up.nodes) |upn| {
        if (keyExistsInTree(tree, upn.encryption_key))
            return error.InvalidLeafNode;
    }
}

/// Return true if `key` matches any non-blank node's
/// encryption_key in the tree.
fn keyExistsInTree(
    tree: *const RatchetTree,
    key: []const u8,
) bool {
    for (tree.nodes) |maybe_node| {
        const node = maybe_node orelse continue;
        const ek = switch (node.node_type) {
            .leaf => node.payload.leaf.encryption_key,
            .parent => node.payload.parent.encryption_key,
        };
        if (std.mem.eql(u8, ek, key)) return true;
    }
    return false;
}

/// Build provisional GroupContext bytes after merging a path.
/// Computes tree hash, creates the provisional GC, serializes.
fn buildProvisionalGc(
    comptime P: type,
    allocator: std.mem.Allocator,
    tree: *RatchetTree,
    gc: *const context_mod.GroupContext(P.nh),
    new_extensions: []const Extension,
    buf: *[max_gc_encode]u8,
) CommitError![]const u8 {
    const root = tree_math.root(tree.leaf_count);
    const th = try tree_hashes.treeHash(P, allocator, tree, root);
    var prov = try gc.updateForNewEpoch(
        allocator,
        th,
        gc.confirmed_transcript_hash,
        new_extensions,
    );
    defer prov.deinit(allocator);
    return prov.serialize(
        buf,
    ) catch return error.IndexOutOfRange;
}

/// Decrypt path_secret[0] from the UpdatePath at the receiver's
/// position using the receiver's HPKE private key.
fn decryptPathSecret(
    comptime P: type,
    up: *const UpdatePath,
    rp: ReceiverPathParams(P),
    pos: path_mod.ReceiverPos,
    prov_gc_bytes: []const u8,
) CommitError![P.nh]u8 {
    const ct = &up.nodes[pos.node_idx]
        .encrypted_path_secret[pos.ct_idx];
    const dec_keys = rp.keyForNode(
        pos.res_node,
        rp.receiver,
    ) orelse return error.MissingDecryptionKey;
    return path_mod.decryptPathSecretFrom(
        P,
        ct,
        dec_keys.sk,
        dec_keys.pk,
        prov_gc_bytes,
    );
}

/// Steps f-h: Derive remaining path secrets, verify public keys,
/// collect derived key pairs, derive commit_secret, verify leaf.
fn deriveAndCollectPathKeys(
    comptime P: type,
    up: *const UpdatePath,
    path_secret_0: *const [P.nh]u8,
    start_idx: u32,
    n_path: u32,
    fdp_path: []const NodeIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    sender_leaf: LeafIndex,
    result: *UpdatePathOutput(P),
) CommitError!UpdatePathOutput(P) {
    assert(start_idx <= n_path);
    assert(n_path <= path_mod.max_path_nodes);
    const remaining = n_path - start_idx;
    var secrets: [path_mod.max_path_nodes][P.nh]u8 = undefined;
    defer for (0..remaining) |si| {
        secureZero(&secrets[si]);
    };
    path_mod.derivePathSecrets(P, path_secret_0, remaining, &secrets);
    try path_mod.verifyPathKeys(
        P,
        up,
        &secrets,
        start_idx,
        remaining,
    );

    // Collect derived key pairs for parent nodes.
    var si: u32 = 0;
    while (si < remaining) : (si += 1) {
        const pi = start_idx + si;
        const kp = try path_mod.deriveNodeKeypair(P, &secrets[si]);
        result.derived_path_keys[result.derived_key_count] = .{
            .node = fdp_path[pi],
            .sk = kp.sk,
            .pk = kp.pk,
        };
        result.derived_key_count += 1;
    }

    // Derive commit_secret from last path secret.
    result.commit_secret = path_mod.deriveCommitSecret(
        P,
        &secrets[remaining - 1],
    );

    // Verify UpdatePath leaf node signature.
    up.leaf_node.verifyLeafNodeSignature(
        P,
        group_context.group_id,
        sender_leaf,
    ) catch return error.InvalidLeafSignature;

    return result.*;
}

/// Steps 10-14: Derive epoch state, verify confirmation.
fn deriveProcessEpochState(
    comptime P: type,
    allocator: std.mem.Allocator,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    confirmation_tag: *const [P.nh]u8,
    group_context: *const context_mod.GroupContext(P.nh),
    new_tree: *RatchetTree,
    validated: *const ValidatedProposals,
    new_extensions: []const Extension,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    psk_resolver: ?PskResolver(P),
    apply_result: ProposalApplyResult,
    derived_path_keys: [path_mod.max_path_nodes]PathNodeKey(P),
    derived_key_count: u32,
    wire_format: WireFormat,
) CommitError!ProcessResult(P) {
    assert(derived_key_count <= path_mod.max_path_nodes);
    assert(fc.content_type == .commit);
    // RFC 9420 S7.9.2: verify parent hash chain before accepting.
    // Returns root tree hash as byproduct (avoids redundant pass).
    const new_tree_hash = try tree_hashes.verifyParentHashes(
        P,
        allocator,
        new_tree,
    );

    const confirmed_th = try buildConfirmedHash(
        P,
        fc,
        signature,
        interim_transcript_hash,
        wire_format,
    );
    var new_gc = try group_context.updateForNewEpoch(
        allocator,
        new_tree_hash,
        confirmed_th,
        new_extensions,
    );
    errdefer new_gc.deinit(allocator);
    var new_gc_buf: [max_gc_encode]u8 = undefined;
    const new_gc_bytes = new_gc.serialize(&new_gc_buf) catch
        return error.IndexOutOfRange;
    const psk_secret = try resolvePskSecret(
        P,
        validated,
        psk_resolver,
    );
    const epoch_secrets = schedule.deriveEpochSecrets(
        P,
        init_secret,
        commit_secret,
        &psk_secret,
        new_gc_bytes,
    );
    try auth_mod.verifyConfirmationTag(
        P,
        &epoch_secrets.confirmation_key,
        &confirmed_th,
        confirmation_tag,
    );
    const interim_th =
        transcript.updateInterimTranscriptHash(
            P,
            &confirmed_th,
            confirmation_tag,
        ) catch return error.IndexOutOfRange;

    return .{
        .epoch_secrets = epoch_secrets,
        .confirmed_transcript_hash = confirmed_th,
        .interim_transcript_hash = interim_th,
        .group_context = new_gc,
        .tree = new_tree.*,
        .apply_result = apply_result,
        .new_epoch = group_context.epoch + 1,
        .path_keys = derived_path_keys,
        .path_key_count = derived_key_count,
    };
}

// -- Helper: encode Commit struct -------------------------------------------

/// Encode the Commit struct (inline proposals + optional path).
fn encodeCommit(
    proposals: []const Proposal,
    update_path: ?UpdatePath,
    buf: *[max_content_buf]u8,
) CommitError!u32 {
    // Build ProposalOrRef array (all inline).
    var por_buf: [256]ProposalOrRef = undefined;
    if (proposals.len > 256) {
        return error.InvalidProposalList;
    }
    for (proposals, 0..) |*p, index| {
        por_buf[index] = ProposalOrRef.initProposal(p.*);
    }

    const commit = Commit{
        .proposals = por_buf[0..proposals.len],
        .path = update_path,
    };

    const end = commit.encode(buf, 0) catch {
        return error.IndexOutOfRange;
    };
    return end;
}

// -- Helper: build confirmed transcript hash --------------------------------

/// Build ConfirmedTranscriptHashInput and compute the hash.
///
/// ConfirmedTranscriptHashInput =
///   WireFormat (u16) || FramedContent || signature<V>
///
/// confirmed_transcript_hash =
///   Hash(interim_transcript_hash || ConfirmedTranscriptHashInput)
///
/// Shared by createCommit and createExternalCommit.
pub fn buildConfirmedHash(
    comptime P: type,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    interim_prev: *const [P.nh]u8,
    wire_format: WireFormat,
) error{IndexOutOfRange}![P.nh]u8 {
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

// -- Helper: resolve extensions after proposals -----------------------------

/// Determine the extensions for the new epoch. If a GCE proposal
/// was applied, use those extensions; otherwise keep the current.
fn resolveExtensions(
    apply_result: *const ProposalApplyResult,
    current_gc: anytype, // GroupContext(nh) — generic hash size
) []const Extension {
    if (apply_result.new_extensions) |exts| {
        return exts;
    }
    return current_gc.extensions;
}

// -- createCommit helpers ---------------------------------------------------

/// Step 1: Validate proposals for a locally-created commit.
fn validateCommitProposals(
    comptime P: type,
    allocator: std.mem.Allocator,
    proposals: []const Proposal,
    my_leaf: LeafIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
) CommitError!*ValidatedProposals {
    assert(tree.leaf_count > 0);
    assert(my_leaf.toNodeIndex().toUsize() < tree.nodes.len);
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = my_leaf,
    };
    const validated = try evolution.validateProposalList(
        allocator,
        proposals,
        sender,
        null,
    );
    errdefer validated.destroy(allocator);
    // RFC 9420 S12.2: ExternalInit is only valid in external
    // commits, never in regular member commits.
    if (validated.external_init != null)
        return error.InvalidProposalList;
    try evolution.validateReInitVersion(
        validated,
        group_context.version,
    );
    try evolution.validateAddKeyPackages(
        P,
        validated,
        group_context.cipher_suite,
    );
    try evolution.validateUpdateLeafNodes(
        P,
        validated,
        group_context.group_id,
        group_context.cipher_suite,
    );
    try evolution.validateAddsAgainstTree(
        validated,
        tree,
        group_context.cipher_suite,
    );
    try evolution.validateUpdatesAgainstTree(
        validated,
        tree,
        sender,
    );
    try evolution.validateRemovesAgainstTree(
        validated,
        tree,
    );
    evolution.validateAddsRequiredCapabilities(
        validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    evolution.validateUpdatesRequiredCapabilities(
        validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    try evolution.validatePskProposals(validated, P.nh);
    try evolution.validateGceAgainstTree(validated, tree);
    try evolution.validateNonDefaultProposalCaps(
        proposals,
        tree,
    );
    return validated;
}

/// Output of generateCommitPath.
fn CommitPathOutput(comptime P: type) type {
    return struct {
        commit_secret: [P.nh]u8,
        update_path: ?UpdatePath,
        path_allocator: ?std.mem.Allocator,
        /// Path secrets from the filtered direct path.
        /// path_secrets[i] corresponds to fdp_nodes[i].
        /// Only valid for indices 0..path_secret_count.
        path_secrets: [path_mod.max_path_nodes][P.nh]u8,
        path_secret_count: u32,
        /// Filtered direct path node indices (parallel to
        /// path_secrets). Needed for Welcome path_secret
        /// computation per RFC 9420 §12.4.3.1.
        fdp_nodes: [path_mod.max_path_nodes]NodeIndex,
    };
}

/// Step 3: Generate UpdatePath if required.
///
/// Derives path secrets, signs the new leaf, merges keys into
/// the tree, sets parent hashes, computes provisional GC, and
/// encrypts path nodes.
///
/// `leaf_sig` must outlive the returned UpdatePath AND the tree,
/// because the tree leaf's signature slice points into it.
fn generateCommitPath(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    my_leaf: LeafIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    sign_key: *const [P.sign_sk_len]u8,
    path_params: ?PathParams(P),
    path_required: bool,
    new_extensions: []const Extension,
    added_leaves: []const LeafIndex,
    leaf_sig: *[P.sig_len]u8,
    leaf_ph: *[P.nh]u8,
) CommitError!CommitPathOutput(P) {
    assert(new_tree.leaf_count > 0);
    assert(my_leaf.toNodeIndex().toUsize() < new_tree.nodes.len);
    var result: CommitPathOutput(P) = .{
        .commit_secret = .{0} ** P.nh,
        .update_path = null,
        .path_allocator = null,
        .path_secrets = undefined,
        .path_secret_count = 0,
        .fdp_nodes = undefined,
    };
    if (!path_required) return result;
    const pp = path_params orelse {
        // Single-leaf trees have an empty filtered direct path
        // (no parent nodes), so path derivation produces zero
        // commit_secret and no UpdatePath. This is equivalent
        // to providing an empty path. RFC §12.2 requires a path
        // for Update/Remove/ExternalInit/GCE, but in a single-
        // member group the path is necessarily empty.
        if (new_tree.leaf_count <= 1) return result;
        return error.MissingPath;
    };

    // Check for an empty filtered direct path. This occurs
    // when only one non-blank leaf remains (e.g. after
    // removing all other members). The path is vacuously
    // satisfied — no parent nodes need updating.
    var fp_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    var fc_buf: [path_mod.max_path_nodes]NodeIndex = undefined;
    const fdp = new_tree.filteredDirectPath(
        my_leaf,
        &fp_buf,
        &fc_buf,
    ) catch return error.MissingPath;
    if (fdp.path.len == 0) return result;

    // a. Derive path secrets and public keys.
    var derived = try path_mod.derivePathKeys(
        P,
        new_tree,
        my_leaf,
        pp.leaf_secret,
    );
    defer for (0..derived.n_path) |i| {
        secureZero(&derived.secrets[i]);
    };
    result.commit_secret = derived.commit_secret;
    result.path_allocator = pp.allocator;

    // Copy path secrets and fdp nodes for Welcome construction
    // (RFC 9420 §12.4.3.1: path_secret per new member).
    result.path_secret_count = derived.n_path;
    for (0..derived.n_path) |i| {
        result.path_secrets[i] = derived.secrets[i];
        result.fdp_nodes[i] = derived.fdp_nodes[i];
    }

    // b. Merge parent keys, compute parent hashes, then
    //    compute leaf parent_hash, sign leaf, set leaf.
    try path_mod.applyParentKeysOnly(
        P.npk,
        new_tree,
        my_leaf,
        derived.public_keys[0..derived.n_path],
    );
    try path_mod.setPathParentHashes(P, allocator, new_tree, my_leaf);

    const skel = try buildSignedLeaf(
        P,
        allocator,
        new_tree,
        my_leaf,
        pp.new_leaf,
        sign_key,
        group_context,
        leaf_sig,
        leaf_ph,
    );

    // d. Encrypt path secrets using provisional GC.
    const nodes = try encryptCommitPathNodes(
        P,
        allocator,
        pp,
        new_tree,
        my_leaf,
        group_context,
        new_extensions,
        &derived,
        added_leaves,
    );

    result.update_path = .{
        .leaf_node = skel.leaf_node,
        .nodes = nodes,
    };
    return result;
}

/// Build a signed commit leaf: set source, compute parent_hash,
/// sign, and install in the tree. Returns UpdatePath skeleton.
fn buildSignedLeaf(
    comptime P: type,
    allocator: std.mem.Allocator,
    new_tree: *RatchetTree,
    my_leaf: LeafIndex,
    new_leaf: node_mod.LeafNode,
    sign_key: *const [P.sign_sk_len]u8,
    group_context: *const context_mod.GroupContext(P.nh),
    leaf_sig: *[P.sig_len]u8,
    leaf_ph: *[P.nh]u8,
) CommitError!UpdatePath {
    var skel = UpdatePath{
        .leaf_node = new_leaf,
        .nodes = &.{},
    };
    skel.leaf_node.source = .commit;
    if (try path_mod.computeLeafParentHash(
        P,
        allocator,
        new_tree,
        my_leaf,
    )) |ph| {
        leaf_ph.* = ph;
        skel.leaf_node.parent_hash = leaf_ph;
    }
    skel.leaf_node.signLeafNode(
        P,
        sign_key,
        leaf_sig,
        group_context.group_id,
        my_leaf,
    ) catch return error.InvalidLeafSignature;
    try new_tree.setLeaf(my_leaf, skel.leaf_node);
    return skel;
}

/// Compute tree hash, build provisional GC, encrypt path nodes.
fn encryptCommitPathNodes(
    comptime P: type,
    allocator: std.mem.Allocator,
    pp: PathParams(P),
    new_tree: *RatchetTree,
    my_leaf: LeafIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    new_extensions: []const Extension,
    derived: *const path_mod.DerivedPathKeys(P),
    added_leaves: []const LeafIndex,
) CommitError![]UpdatePathNode {
    const root = tree_math.root(new_tree.leaf_count);
    const merged_th = try tree_hashes.treeHash(
        P,
        allocator,
        new_tree,
        root,
    );
    var prov_gc = try group_context.updateForNewEpoch(
        allocator,
        merged_th,
        group_context.confirmed_transcript_hash,
        new_extensions,
    );
    defer prov_gc.deinit(allocator);
    var prov_gc_buf: [max_gc_encode]u8 = undefined;
    const prov_gc_bytes = prov_gc.serialize(
        &prov_gc_buf,
    ) catch return error.IndexOutOfRange;

    return path_mod.encryptPathNodes(
        P,
        pp.allocator,
        new_tree,
        my_leaf,
        &derived.secrets,
        &derived.public_keys,
        derived.n_path,
        prov_gc_bytes,
        pp.eph_seeds,
        added_leaves,
    );
}

/// Free HPKE ciphertexts from a CommitPathOutput.
fn freeCommitPath(
    comptime P: type,
    path_out: *CommitPathOutput(P),
) void {
    if (path_out.update_path) |up| {
        if (path_out.path_allocator) |a| {
            const n: u32 = @intCast(up.nodes.len);
            path_mod.freeUpnSlice(
                a,
                @constCast(up.nodes),
                n,
            );
            path_out.update_path = null;
        }
    }
}

/// Steps 4-13: Compute tree hash, encode Commit, free path
/// HPKE ciphertexts, then sign, derive, and finalize.
fn encodeAndFinalizeCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    new_tree: *RatchetTree,
    my_leaf: LeafIndex,
    proposals: []const Proposal,
    sign_key: *const [P.sign_sk_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    validated: *const ValidatedProposals,
    psk_resolver: ?PskResolver(P),
    new_extensions: []const Extension,
    path_out: *CommitPathOutput(P),
    apply_result: ProposalApplyResult,
    leaf_sig: [P.sig_len]u8,
    wire_format: WireFormat,
) CommitError!CommitResult(P) {
    // 4. Compute new tree hash.
    const new_tree_hash = try tree_hashes.treeHash(
        P,
        allocator,
        new_tree,
        tree_math.root(new_tree.leaf_count),
    );

    // 5. Encode Commit and free path HPKE ciphertexts.
    var commit_buf: [max_content_buf]u8 = undefined;
    const commit_len = try encodeCommit(
        proposals,
        path_out.update_path,
        &commit_buf,
    );
    freeCommitPath(P, path_out);

    // 6-13. Sign, derive epoch, compute confirmation.
    return finalizeCommit(
        P,
        allocator,
        group_context,
        my_leaf,
        sign_key,
        interim_transcript_hash,
        init_secret,
        validated,
        psk_resolver,
        new_extensions,
        &path_out.commit_secret,
        new_tree_hash,
        &commit_buf,
        commit_len,
        new_tree.*,
        apply_result,
        leaf_sig,
        wire_format,
    );
}

/// Steps 6-13: Sign FramedContent, derive epoch state, compute
/// confirmation tag, build CommitResult.
fn finalizeCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    my_leaf: LeafIndex,
    sign_key: *const [P.sign_sk_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    validated: *const ValidatedProposals,
    psk_resolver: ?PskResolver(P),
    new_extensions: []const Extension,
    commit_secret: *const [P.nh]u8,
    new_tree_hash: [P.nh]u8,
    commit_buf: *[max_content_buf]u8,
    commit_len: u32,
    new_tree: RatchetTree,
    apply_result: ProposalApplyResult,
    leaf_sig: [P.sig_len]u8,
    wire_format: WireFormat,
) CommitError!CommitResult(P) {
    // 6-9. Sign FramedContent, confirmed transcript hash.
    const fc = FramedContent{
        .group_id = group_context.group_id,
        .epoch = group_context.epoch,
        .sender = Sender.member(my_leaf),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_buf[0..commit_len],
    };
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = group_context.serialize(&gc_buf) catch
        return error.IndexOutOfRange;
    const auth = try auth_mod.signFramedContent(
        P,
        &fc,
        wire_format,
        gc_bytes,
        sign_key,
        null,
        null,
    );
    const confirmed_th = try buildConfirmedHash(
        P,
        &fc,
        &auth.signature,
        interim_transcript_hash,
        wire_format,
    );

    // 10-13. Derive epoch, confirmation, interim.
    return buildCommitResult(
        P,
        allocator,
        group_context,
        validated,
        psk_resolver,
        new_extensions,
        init_secret,
        commit_secret,
        new_tree_hash,
        confirmed_th,
        auth.signature,
        commit_buf,
        commit_len,
        new_tree,
        apply_result,
        leaf_sig,
    );
}

/// Steps 10-13: Build new GC, derive epoch secrets, compute
/// confirmation tag and interim hash, assemble CommitResult.
fn buildCommitResult(
    comptime P: type,
    allocator: std.mem.Allocator,
    group_context: *const context_mod.GroupContext(P.nh),
    validated: *const ValidatedProposals,
    psk_resolver: ?PskResolver(P),
    new_extensions: []const Extension,
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    new_tree_hash: [P.nh]u8,
    confirmed_th: [P.nh]u8,
    signature: [P.sig_len]u8,
    commit_buf: *[max_content_buf]u8,
    commit_len: u32,
    new_tree: RatchetTree,
    apply_result: ProposalApplyResult,
    leaf_sig: [P.sig_len]u8,
) CommitError!CommitResult(P) {
    var new_gc = try group_context.updateForNewEpoch(
        allocator,
        new_tree_hash,
        confirmed_th,
        new_extensions,
    );
    errdefer new_gc.deinit(allocator);
    var new_gc_buf: [max_gc_encode]u8 = undefined;
    const new_gc_bytes = new_gc.serialize(&new_gc_buf) catch
        return error.IndexOutOfRange;
    const psk_secret = try resolvePskSecret(
        P,
        validated,
        psk_resolver,
    );
    const epoch_secrets = schedule.deriveEpochSecrets(
        P,
        init_secret,
        commit_secret,
        &psk_secret,
        new_gc_bytes,
    );
    const confirmation_tag = auth_mod.computeConfirmationTag(
        P,
        &epoch_secrets.confirmation_key,
        &confirmed_th,
    );
    const interim_th =
        transcript.updateInterimTranscriptHash(
            P,
            &confirmed_th,
            &confirmation_tag,
        ) catch return error.IndexOutOfRange;

    return .{
        .commit_bytes = commit_buf.*,
        .commit_len = commit_len,
        .signature = signature,
        .confirmation_tag = confirmation_tag,
        .epoch_secrets = epoch_secrets,
        .confirmed_transcript_hash = confirmed_th,
        .interim_transcript_hash = interim_th,
        .group_context = new_gc,
        .tree = new_tree,
        .apply_result = apply_result,
        .new_epoch = group_context.epoch + 1,
        .joiner_secret = epoch_secrets.joiner_secret,
        .welcome_secret = epoch_secrets.welcome_secret,
        .leaf_sig = leaf_sig,
        // Path secrets populated by createCommit after return.
        .path_secrets = undefined,
        .path_secret_count = 0,
        .fdp_nodes = undefined,
    };
}
