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
    // NOTE: RFC 9420 Section 12.2 only requires a path for
    // Update, Remove, ExternalInit, and empty commits. GCE is
    // not listed. We require a path for GCE as an intentional
    // over-restriction: GCE modifies the group context, and a
    // path ensures the committer proves liveness. This may
    // cause interop failures if a peer sends a GCE-only commit
    // without a path.
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
        eph_seeds: []const [32]u8,
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
        proposals,
        my_leaf,
        group_context,
        tree,
    );

    // Apply proposals to a copy of the tree.
    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    const apply_result = try evolution.applyProposals(
        &validated,
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
        isPathRequired(&validated),
        new_extensions,
        apply_result.added_leaves[0..apply_result.added_count],
        &leaf_sig,
        &leaf_ph,
    );
    defer secureZero(&path_out.commit_secret);
    errdefer freeCommitPath(P, &path_out);

    // Compute tree hash, encode, sign, derive epoch state.
    return encodeAndFinalizeCommit(
        P,
        allocator,
        group_context,
        &new_tree,
        my_leaf,
        proposals,
        sign_key,
        interim_transcript_hash,
        init_secret,
        &validated,
        psk_resolver,
        new_extensions,
        &path_out,
        apply_result,
        leaf_sig,
        wire_format,
    );
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
///   - `fc`: the FramedContent (content_type = .commit).
///   - `signature`: the signature from FramedContentAuthData.
///   - `confirmation_tag`: the confirmation tag from auth data.
///   - `proposals`: the decoded proposals from the Commit body.
///   - `update_path`: the decoded UpdatePath from the Commit
///     (null if the Commit has no path).
///   - `group_context`: the receiver's current GroupContext.
///   - `tree`: the receiver's current RatchetTree.
///   - `sender_verify_key`: the committer's signature pub key.
///   - `interim_transcript_hash`: current interim transcript hash.
///   - `init_secret`: current epoch init_secret.
///   - `receiver_params`: receiver's leaf index + encryption
///     keys for decrypting the UpdatePath. Required when
///     update_path is non-null.
///
/// Returns a ProcessResult with the verified new group state.
pub fn processCommit(
    comptime P: type,
    allocator: std.mem.Allocator,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    confirmation_tag: *const [P.nh]u8,
    proposals: []const Proposal,
    update_path: ?*const UpdatePath,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
    sender_verify_key: *const [P.sign_pk_len]u8,
    interim_transcript_hash: *const [P.nh]u8,
    init_secret: *const [P.nh]u8,
    receiver_params: ?ReceiverPathParams(P),
    psk_resolver: ?PskResolver(P),
    proposal_senders: ?[]const Sender,
    membership_key: ?*const [P.nh]u8,
    membership_tag: ?*const [P.nh]u8,
    wire_format: WireFormat,
) CommitError!ProcessResult(P) {
    assert(fc.content_type == .commit);
    assert(tree.leaf_count > 0);
    // 0-4. Verify membership tag, epoch, sender, content type,
    // signature.
    try verifyCommitPreconditions(
        P,
        fc,
        group_context,
        signature,
        confirmation_tag,
        sender_verify_key,
        membership_key,
        membership_tag,
        wire_format,
    );

    // 5. Validate proposals.
    const sender_leaf = LeafIndex.fromU32(fc.sender.leaf_index);
    const validated = try validateProcessProposals(
        P,
        proposals,
        sender_leaf,
        proposal_senders,
        group_context,
        tree,
    );
    // 6. Apply proposals to a copy of the tree.
    var new_tree = try tree.clone();
    errdefer new_tree.deinit();
    const apply_result = try evolution.applyProposals(
        &validated,
        &new_tree,
    );
    // 7. Check path presence (single-leaf is vacuously ok).
    if (isPathRequired(&validated) and update_path == null and
        new_tree.leaf_count > 1) return error.MissingPath;
    // 8. Process UpdatePath if present.
    const new_ext = resolveExtensions(&apply_result, group_context);
    var path_out = processUpdatePath(
        P,
        allocator,
        update_path,
        receiver_params,
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
        fc,
        signature,
        confirmation_tag,
        group_context,
        &new_tree,
        &validated,
        new_ext,
        interim_transcript_hash,
        init_secret,
        &path_out.commit_secret,
        psk_resolver,
        apply_result,
        path_out.derived_path_keys,
        path_out.derived_key_count,
        wire_format,
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
    proposals: []const Proposal,
    sender_leaf: LeafIndex,
    proposal_senders: ?[]const Sender,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
) CommitError!ValidatedProposals {
    assert(sender_leaf.toNodeIndex().toUsize() < tree.nodes.len);
    if (proposal_senders) |ps| {
        assert(ps.len == proposals.len);
    }
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = sender_leaf,
    };
    const validated = try evolution.validateProposalList(
        proposals,
        sender,
        proposal_senders,
    );
    // RFC 9420 S12.2: ExternalInit is only valid in external
    // commits, never in regular member commits.
    if (validated.external_init != null)
        return error.InvalidProposalList;
    try evolution.validateReInitVersion(
        &validated,
        group_context.version,
    );
    try evolution.validateAddKeyPackages(
        P,
        &validated,
        group_context.cipher_suite,
    );
    try evolution.validateUpdateLeafNodes(
        P,
        &validated,
        group_context.group_id,
        group_context.cipher_suite,
    );
    try evolution.validateAddsAgainstTree(
        &validated,
        tree,
        group_context.cipher_suite,
    );
    try evolution.validateUpdatesAgainstTree(
        &validated,
        tree,
        sender,
    );
    try evolution.validateRemovesAgainstTree(
        &validated,
        tree,
    );
    evolution.validateAddsRequiredCapabilities(
        &validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    evolution.validateUpdatesRequiredCapabilities(
        &validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    try evolution.validatePskProposals(&validated, P.nh);
    try evolution.validateGceAgainstTree(&validated, tree);
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
    try tree_hashes.verifyParentHashes(P, allocator, new_tree);

    const root = tree_math.root(new_tree.leaf_count);
    const new_tree_hash = try tree_hashes.treeHash(
        P,
        allocator,
        new_tree,
        root,
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
fn buildConfirmedHash(
    comptime P: type,
    fc: *const FramedContent,
    signature: *const [P.sig_len]u8,
    interim_prev: *const [P.nh]u8,
    wire_format: WireFormat,
) CommitError![P.nh]u8 {
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
    proposals: []const Proposal,
    my_leaf: LeafIndex,
    group_context: *const context_mod.GroupContext(P.nh),
    tree: *const RatchetTree,
) CommitError!ValidatedProposals {
    assert(tree.leaf_count > 0);
    assert(my_leaf.toNodeIndex().toUsize() < tree.nodes.len);
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = my_leaf,
    };
    const validated = try evolution.validateProposalList(
        proposals,
        sender,
        null,
    );
    // RFC 9420 S12.2: ExternalInit is only valid in external
    // commits, never in regular member commits.
    if (validated.external_init != null)
        return error.InvalidProposalList;
    try evolution.validateReInitVersion(
        &validated,
        group_context.version,
    );
    try evolution.validateAddKeyPackages(
        P,
        &validated,
        group_context.cipher_suite,
    );
    try evolution.validateUpdateLeafNodes(
        P,
        &validated,
        group_context.group_id,
        group_context.cipher_suite,
    );
    try evolution.validateAddsAgainstTree(
        &validated,
        tree,
        group_context.cipher_suite,
    );
    try evolution.validateUpdatesAgainstTree(
        &validated,
        tree,
        sender,
    );
    try evolution.validateRemovesAgainstTree(
        &validated,
        tree,
    );
    evolution.validateAddsRequiredCapabilities(
        &validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    evolution.validateUpdatesRequiredCapabilities(
        &validated,
        group_context.extensions,
    ) catch |e| switch (e) {
        error.InvalidLeafNode => return error.InvalidLeafNode,
        error.UnsupportedCapability,
        => return error.UnsupportedCapability,
        else => return error.InvalidProposalList,
    };
    try evolution.validatePskProposals(&validated, P.nh);
    try evolution.validateGceAgainstTree(&validated, tree);
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
    };
    if (!path_required) return result;
    const pp = path_params orelse {
        // Single-leaf trees have no parent nodes, so path
        // derivation is trivially empty. Allow zero commit_secret.
        if (new_tree.leaf_count <= 1) return result;
        return error.MissingPath;
    };

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
    };
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
const GroupState = state_mod.GroupState;
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;
const KeyPackage = @import(
    "../messages/key_package.zig",
).KeyPackage;

fn makeTestLeaf(
    enc_pk: []const u8,
    sig_pk: []const u8,
) node_mod.LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{.basic};

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(sig_pk),
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

/// Deterministic seed derivation from a u8 tag.
fn testSeed(tag: u8) [32]u8 {
    return [_]u8{tag} ** 32;
}

/// A KeyPackage with valid signature and distinct keys.
const TestKP = struct {
    kp: KeyPackage,
    sig_buf: [Default.sig_len]u8,
    leaf_sig_buf: [Default.sig_len]u8,
    enc_sk: [Default.nsk]u8,
    enc_pk: [Default.npk]u8,
    init_sk: [Default.nsk]u8,
    init_pk: [Default.npk]u8,
    sign_sk: [Default.sign_sk_len]u8,
    sign_pk: [Default.sign_pk_len]u8,

    /// Build a properly signed test KeyPackage in place.
    /// `enc_tag` and `init_tag` must differ so that
    /// init_key != encryption_key (Section 10.1 rule 4).
    /// Caller must declare `var tkp: TestKP = undefined;`
    /// then call `try tkp.init(...)`. No fixup needed.
    fn init(
        self: *TestKP,
        enc_tag: u8,
        init_tag: u8,
        sign_tag: u8,
    ) !void {
        const enc_kp = try Default.dhKeypairFromSeed(
            &testSeed(enc_tag),
        );
        const init_kp = try Default.dhKeypairFromSeed(
            &testSeed(init_tag),
        );
        const sign_kp = try Default.signKeypairFromSeed(
            &testSeed(sign_tag),
        );

        self.enc_sk = enc_kp.sk;
        self.enc_pk = enc_kp.pk;
        self.init_sk = init_kp.sk;
        self.init_pk = init_kp.pk;
        self.sign_sk = sign_kp.sk;
        self.sign_pk = sign_kp.pk;

        self.kp = .{
            .version = .mls10,
            .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            .init_key = &self.init_pk,
            .leaf_node = makeTestLeaf(
                &self.enc_pk,
                &self.sign_pk,
            ),
            .extensions = &.{},
            .signature = &self.sig_buf,
        };
        self.kp.leaf_node.credential =
            Credential.initBasic(&self.sign_pk);
        self.kp.leaf_node.signature = &self.leaf_sig_buf;

        // Sign leaf node first (key_package source: no
        // group context).
        try self.kp.leaf_node.signLeafNode(
            Default,
            &self.sign_sk,
            &self.leaf_sig_buf,
            null,
            null,
        );
        // Then sign the KeyPackage.
        try self.kp.signKeyPackage(
            Default,
            &self.sign_sk,
            &self.sig_buf,
        );
    }
};

const TestGroup = struct {
    gs: GroupState(Default),
    sign_sk: [Default.sign_sk_len]u8,
    sign_pk: [Default.sign_pk_len]u8,
    enc_sk: [Default.nsk]u8,
    enc_pk: [Default.npk]u8,

    fn deinit(self: *TestGroup) void {
        self.gs.deinit();
        self.* = undefined;
    }

    /// Init in-place so leaf node slices point directly at
    /// this struct's owned arrays (no move, no fixup).
    fn init(
        self: *TestGroup,
        allocator: std.mem.Allocator,
    ) !void {
        const alice_sign = try Default.signKeypairFromSeed(
            &testSeed(0x42),
        );
        const alice_enc = try Default.dhKeypairFromSeed(
            &testSeed(0xA0),
        );
        self.sign_sk = alice_sign.sk;
        self.sign_pk = alice_sign.pk;
        self.enc_sk = alice_enc.sk;
        self.enc_pk = alice_enc.pk;
        self.gs = try createGroup(
            Default,
            allocator,
            "test-group",
            makeTestLeaf(&self.enc_pk, &self.sign_pk),
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            &.{},
        );
    }
};

test "createCommit with Add proposal advances epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // New epoch should be 1.
    try testing.expectEqual(@as(u64, 1), result.new_epoch);

    // Tree should now have 2 leaves (alice + bob).
    try testing.expectEqual(
        @as(u32, 2),
        result.tree.leaf_count,
    );

    // One member was added.
    try testing.expectEqual(
        @as(u32, 1),
        result.apply_result.added_count,
    );
}

test "createCommit produces non-zero confirmation tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = carol_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Confirmation tag should be non-zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &result.confirmation_tag),
    );
}

test "createCommit produces non-zero epoch secrets" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Epoch secrets should differ from epoch 0.
    try testing.expect(
        !std.mem.eql(
            u8,
            &tg.gs.epoch_secrets.epoch_secret,
            &result.epoch_secrets.epoch_secret,
        ),
    );
}

test "createCommit is deterministic" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var dave_kp: TestKP = undefined;
    try dave_kp.init(0xD0, 0xD1, 0xD2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = dave_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var r1 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer r1.tree.deinit();
    defer r1.deinit(testing.allocator);

    var r2 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer r2.tree.deinit();
    defer r2.deinit(testing.allocator);

    // Same inputs → same outputs.
    try testing.expectEqualSlices(
        u8,
        &r1.confirmation_tag,
        &r2.confirmation_tag,
    );
    try testing.expectEqualSlices(
        u8,
        &r1.signature,
        &r2.signature,
    );
    try testing.expectEqualSlices(
        u8,
        &r1.confirmed_transcript_hash,
        &r2.confirmed_transcript_hash,
    );
}

test "createCommit with multiple Adds" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    var dave_kp: TestKP = undefined;
    try dave_kp.init(0xD0, 0xD1, 0xD2);

    const proposals = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = bob_kp.kp,
                },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = carol_kp.kp,
                },
            },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = dave_kp.kp,
                },
            },
        },
    };

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Tree should have 4 leaves now.
    try testing.expectEqual(
        @as(u32, 4),
        result.tree.leaf_count,
    );
    try testing.expectEqual(
        @as(u32, 3),
        result.apply_result.added_count,
    );
}

test "createCommit transcript hashes form a chain" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // First commit (epoch 0 → 1).
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const p1 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    }};

    var r1 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &p1,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer r1.tree.deinit();
    defer r1.deinit(testing.allocator);

    // Second commit (epoch 1 → 2) uses r1's outputs.
    // Multi-member group requires a path for the commit.
    const leaf_secret = [_]u8{0xF1} ** Default.nh;
    const eph_seeds = [_][32]u8{[_]u8{0xE1} ** 32};
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0x63),
    );
    const new_leaf = makeTestLeaf(&new_enc.pk, &tg.sign_pk);

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const p2 = [_]Proposal{};

    var r2 = try createCommit(
        Default,
        testing.allocator,
        &r1.group_context,
        &r1.tree,
        tg.gs.my_leaf_index,
        &p2,
        &tg.sign_sk,
        &r1.interim_transcript_hash,
        &r1.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer r2.tree.deinit();
    defer r2.deinit(testing.allocator);

    // Transcript hashes should chain — r2's confirmed hash
    // should differ from r1's.
    try testing.expect(
        !std.mem.eql(
            u8,
            &r1.confirmed_transcript_hash,
            &r2.confirmed_transcript_hash,
        ),
    );
    try testing.expectEqual(@as(u64, 2), r2.new_epoch);
}

test "createCommit rejects invalid proposal list" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Self-remove should be rejected.
    const rm = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 0 } },
    };
    const proposals = [_]Proposal{rm};

    const result = createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "createCommit commit_bytes encode valid Commit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var eve_kp: TestKP = undefined;
    try eve_kp.init(0xE0, 0xE1, 0xE2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = eve_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // The commit_bytes should be decodable as a Commit.
    const data = result.commit_bytes[0..result.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.proposals.len,
    );
    try testing.expect(dec_r.value.path == null);
}

test "processCommit round-trip with createCommit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // Creator creates the commit.
    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Receiver builds the FramedContent that the creator sent.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Receiver processes the commit.
    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null, // no UpdatePath
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null, // no receiver path params
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides should agree on the new epoch.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);

    // Both sides should agree on epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &pr.epoch_secrets.init_secret,
    );

    // Both sides should agree on confirmed transcript hash.
    try testing.expectEqualSlices(
        u8,
        &cr.confirmed_transcript_hash,
        &pr.confirmed_transcript_hash,
    );

    // Both sides should agree on interim transcript hash.
    try testing.expectEqualSlices(
        u8,
        &cr.interim_transcript_hash,
        &pr.interim_transcript_hash,
    );

    // Tree should have 2 leaves on both sides.
    try testing.expectEqual(
        cr.tree.leaf_count,
        pr.tree.leaf_count,
    );
}

test "processCommit rejects wrong epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Build FramedContent with WRONG epoch.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = 999,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.WrongEpoch, result);
}

test "processCommit rejects invalid confirmation tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    // Creator creates the commit.
    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Tamper with the confirmation tag.
    var bad_tag = cr.confirmation_tag;
    bad_tag[0] ^= 0xFF;

    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &bad_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.ConfirmationTagMismatch,
        result,
    );
}

test "processCommit rejects wrong signature key" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Use a different key for verification.
    const wrong_seed = [_]u8{0x99} ** 32;
    const wrong_kp = try Default.signKeypairFromSeed(
        &wrong_seed,
    );

    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &wrong_kp.pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.SignatureVerifyFailed,
        result,
    );
}

test "processCommit rejects non-member sender" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    const proposals = [_]Proposal{};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Build FramedContent with external sender type.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.external(0),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.NotAMember, result);
}

test "processCommit two-epoch chain matches createCommit" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // --- Epoch 0 → 1: Add bob ---
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const p1 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = bob_kp.kp,
            },
        },
    }};

    var cr1 = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &p1,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr1.tree.deinit();
    defer cr1.deinit(testing.allocator);

    const fc1 = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr1.commit_bytes[0..cr1.commit_len],
    };

    var pr1 = try processCommit(
        Default,
        testing.allocator,
        &fc1,
        &cr1.signature,
        &cr1.confirmation_tag,
        &p1,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr1.tree.deinit();
    defer pr1.deinit(testing.allocator);

    // --- Epoch 1 → 2: Add carol (add-only, no path needed) ---
    var carol_kp: TestKP = undefined;
    try carol_kp.init(0xC0, 0xC1, 0xC2);
    const p2 = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = carol_kp.kp,
            },
        },
    }};

    var cr2 = try createCommit(
        Default,
        testing.allocator,
        &cr1.group_context,
        &cr1.tree,
        tg.gs.my_leaf_index,
        &p2,
        &tg.sign_sk,
        &cr1.interim_transcript_hash,
        &cr1.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr2.tree.deinit();
    defer cr2.deinit(testing.allocator);

    const fc2 = FramedContent{
        .group_id = pr1.group_context.group_id,
        .epoch = pr1.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr2.commit_bytes[0..cr2.commit_len],
    };

    var pr2 = try processCommit(
        Default,
        testing.allocator,
        &fc2,
        &cr2.signature,
        &cr2.confirmation_tag,
        &p2,
        null,
        &pr1.group_context,
        &pr1.tree,
        &tg.sign_pk,
        &pr1.interim_transcript_hash,
        &pr1.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr2.tree.deinit();
    defer pr2.deinit(testing.allocator);

    // Both sides should agree at epoch 2.
    try testing.expectEqual(@as(u64, 2), cr2.new_epoch);
    try testing.expectEqual(@as(u64, 2), pr2.new_epoch);

    try testing.expectEqualSlices(
        u8,
        &cr2.epoch_secrets.epoch_secret,
        &pr2.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr2.confirmed_transcript_hash,
        &pr2.confirmed_transcript_hash,
    );
}

fn makeTestLeafWithPk(
    id: []const u8,
    enc_pk: []const u8,
    sig_pk: []const u8,
) node_mod.LeafNode {
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

test "createCommit with path for empty commit" {
    const alloc = testing.allocator;

    // Generate real DH and signing keys.
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );

    // Create group with Alice using real keys.
    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "path-test-group",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob (Add-only commit, no path needed).
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Verify Bob was added.
    try testing.expectEqual(@as(u32, 2), add_cr.tree.leaf_count);

    // Now make sure Bob's leaf has a real encryption key
    // so path can encrypt to it.
    const bob_check = try add_cr.tree.getLeaf(
        LeafIndex.fromU32(1),
    );
    try testing.expect(bob_check != null);

    // Empty commit with path — requires path because empty.
    // 2-leaf tree: leaf 0=alice, leaf 2=bob (node indices).
    // direct path of leaf 0 = [1] (root only).
    // copath of leaf 0 = [2] (bob's leaf node).
    // resolution(2) = {2} (bob is present).
    // So we need 1 eph seed.
    const leaf_secret = [_]u8{0xF0} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE1} ** 32,
    };

    // New alice leaf node for commit source.
    const new_alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty_proposals = [_]Proposal{};

    var path_cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer path_cr.tree.deinit();
    defer path_cr.deinit(testing.allocator);

    // Epoch should advance.
    try testing.expectEqual(@as(u64, 2), path_cr.new_epoch);

    // Commit bytes should decode to a Commit with path.
    const data = path_cr.commit_bytes[0..path_cr.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path != null);
    try testing.expectEqual(
        @as(usize, 0),
        dec_r.value.proposals.len,
    );

    // Confirmation tag should be non-zero.
    const zero = [_]u8{0} ** Default.nh;
    try testing.expect(
        !std.mem.eql(u8, &zero, &path_cr.confirmation_tag),
    );

    // Empty commit without path on multi-member group must fail.
    const no_path_result = createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.MissingPath,
        no_path_result,
    );
}

test "createCommit add-only does not include path" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var zara_kp: TestKP = undefined;
    try zara_kp.init(0x10, 0x11, 0x12);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = zara_kp.kp,
            },
        },
    };
    const proposals = [_]Proposal{add_prop};

    var result = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer result.tree.deinit();
    defer result.deinit(testing.allocator);

    // Decode commit — should have no path.
    const data = result.commit_bytes[0..result.commit_len];
    var dec_r = try Commit.decode(alloc, data, 0);
    defer dec_r.value.deinit(alloc);

    try testing.expect(dec_r.value.path == null);
    try testing.expectEqual(
        @as(usize, 1),
        dec_r.value.proposals.len,
    );
}

test "isPathRequired returns correct values" {
    // Empty commit → path required.
    var v: ValidatedProposals = undefined;
    v.gce = null;
    v.reinit = null;
    v.external_init = null;
    v.updates_len = 0;
    v.removes_len = 0;
    v.adds_len = 0;
    v.psk_ids_len = 0;
    try testing.expect(isPathRequired(&v));

    // Add-only → no path required.
    v.adds_len = 1;
    try testing.expect(!isPathRequired(&v));

    // Update → path required.
    v.adds_len = 0;
    v.updates_len = 1;
    try testing.expect(isPathRequired(&v));

    // Remove → path required.
    v.updates_len = 0;
    v.removes_len = 1;
    try testing.expect(isPathRequired(&v));

    // PSK-only → no path required.
    v.removes_len = 0;
    v.psk_ids_len = 1;
    try testing.expect(!isPathRequired(&v));

    // GCE → path required.
    v.psk_ids_len = 0;
    v.gce = .{ .extensions = &.{} };
    try testing.expect(isPathRequired(&v));
}

test "processCommit with path decryption round-trip" {
    const alloc = testing.allocator;

    // Alice and Bob real keys.
    const alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xC1),
    );
    const alice_kp = try Default.signKeypairFromSeed(
        &testSeed(0xC2),
    );

    // Create group with Alice.
    const alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc_kp.pk,
        &alice_kp.pk,
    );

    var gs = try createGroup(
        Default,
        alloc,
        "process-path-test",
        alice_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob via Add-only commit (no path needed).
    // enc_tag=0xD1, init_tag=0xD3, sign_tag=0xD2
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xD1, 0xD3, 0xD2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_tkp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &add_proposals,
        &alice_kp.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Now Alice creates an empty commit with path.
    // 2-leaf tree: direct path of leaf 0 = [root].
    // copath of leaf 0 = [leaf 2 (bob)].
    // resolution(bob's leaf) = {bob} → need 1 eph seed.
    const leaf_secret = [_]u8{0xF5} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0xE5} ** 32,
    };

    // New leaf must use a FRESH encryption key (RFC S12.4.2).
    const new_alice_enc_kp = try Default.dhKeypairFromSeed(
        &testSeed(0xC3),
    );
    const new_alice_leaf = makeTestLeafWithPk(
        "alice",
        &new_alice_enc_kp.pk,
        &alice_kp.pk,
    );

    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = new_alice_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty_proposals = [_]Proposal{};

    var path_cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &empty_proposals,
        &alice_kp.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer path_cr.tree.deinit();
    defer path_cr.deinit(testing.allocator);

    // Decode the Commit to get the UpdatePath.
    const commit_data = path_cr.commit_bytes[0..path_cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    try testing.expect(dec.value.path != null);

    // Bob builds FramedContent and processes the commit.
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1), // bob
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };

    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &path_cr.signature,
        &path_cr.confirmation_tag,
        &empty_proposals,
        if (dec.value.path) |*p| p else null,
        &add_cr.group_context,
        &add_cr.tree,
        &alice_kp.pk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        rp,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides should agree on the new epoch.
    try testing.expectEqual(path_cr.new_epoch, pr.new_epoch);

    // Both should agree on epoch secrets.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );

    // Both should agree on init_secret.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.init_secret,
        &pr.epoch_secrets.init_secret,
    );

    // Both should agree on confirmation key.
    try testing.expectEqualSlices(
        u8,
        &path_cr.epoch_secrets.confirmation_key,
        &pr.epoch_secrets.confirmation_key,
    );
}

test "processCommit rejects empty commit without path" {
    const alloc = testing.allocator;

    // Multi-member group: empty commit without path must fail.
    // createCommit rejects null path_params for multi-member
    // groups, so we verify that directly.
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Add Bob to make it a 2-member group.
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB1, 0xB3, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    };
    const add_proposals = [_]Proposal{add_prop};

    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &add_proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Empty commit on multi-member group without path must fail.
    const empty_proposals = [_]Proposal{};
    const result = createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        tg.gs.my_leaf_index,
        &empty_proposals,
        &tg.sign_sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.MissingPath, result);
}

// ── KeyPackage validation tests (Section 10.1) ─────────────

test "createCommit rejects Add with mismatched cipher suite" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    // Override cipher suite to a different value.
    bob_kp.kp.cipher_suite =
        .mls_128_dhkemp256_aes128gcm_sha256_p256;
    bob_kp.kp.leaf_node.signature = &bob_kp.sig_buf;

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.CipherSuiteMismatch,
        result,
    );
}

test "createCommit rejects Add with mismatched version" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    // Override version to reserved value.
    bob_kp.kp.version = .reserved;

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.VersionMismatch, result);
}

test "createCommit rejects Add where init_key == enc_key" {
    var tg: TestGroup = undefined;
    try tg.init(testing.allocator);
    defer tg.deinit();

    // Use the same tag for enc and init → same key.
    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB0, 0xB2);

    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const result = createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(
        error.InvalidKeyPackage,
        result,
    );
}

test "createCommit with external PSK produces non-zero psk_secret" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Set up external PSK store with a known secret.
    var psk_store = psk_lookup_mod.InMemoryPskStore.init();
    const psk_secret = [_]u8{0xAA} ** 32;
    _ = psk_store.addPsk("test-psk", &psk_secret);

    var res_ring = psk_lookup_mod.ResumptionPskRing(
        Default,
    ).init(0);
    const resolver: PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // PSK proposal referencing the stored external PSK.
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = .{
            .psk_type = .external,
            .external_psk_id = "test-psk",
            .resumption_usage = .reserved,
            .resumption_group_id = "",
            .resumption_epoch = 0,
            .psk_nonce = &([_]u8{0x01} ** 32),
        } } },
    };
    const proposals = [_]Proposal{psk_prop};

    // Commit with PSK resolver.
    var cr_psk = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null, // PSK-only: no path needed
        resolver,
        .mls_public_message,
    );
    defer cr_psk.tree.deinit();
    defer cr_psk.deinit(testing.allocator);

    // ProcessCommit with same resolver must agree.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr_psk.commit_bytes[0..cr_psk.commit_len],
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr_psk.signature,
        &cr_psk.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        resolver,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqualSlices(
        u8,
        &cr_psk.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "createCommit with resumption PSK from prior epoch" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    // Retain epoch 0 resumption secret in the ring.
    var res_ring = psk_lookup_mod.ResumptionPskRing(
        Default,
    ).init(8);
    res_ring.retain(
        tg.gs.group_context.epoch,
        &tg.gs.epoch_secrets.resumption_psk,
    );

    var psk_store = psk_lookup_mod.InMemoryPskStore.init();
    const resolver: PskResolver(Default) = .{
        .external = psk_store.lookup(),
        .resumption = &res_ring,
    };

    // PSK proposal referencing epoch 0 resumption.
    const psk_prop = Proposal{
        .tag = .psk,
        .payload = .{ .psk = .{ .psk = .{
            .psk_type = .resumption,
            .external_psk_id = "",
            .resumption_usage = .application,
            .resumption_group_id = tg.gs.group_context.group_id,
            .resumption_epoch = 0,
            .psk_nonce = &([_]u8{0x02} ** 32),
        } } },
    };
    const proposals = [_]Proposal{psk_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        resolver,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // ProcessCommit with same resolver must agree.
    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        resolver,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "processCommit accepts valid membership tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_kp.kp } },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Compute a valid membership tag.
    const mkey = &tg.gs.epoch_secrets.membership_key;
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = tg.gs.group_context.serialize(
        &gc_buf,
        // Safe: max_gc_encode is sized for max GroupContext.
    ) catch unreachable;
    const auth = auth_mod.FramedContentAuthData(Default){
        .signature = cr.signature,
        .confirmation_tag = cr.confirmation_tag,
    };
    const mtag = try public_msg.computeMembershipTag(
        Default,
        mkey,
        &fc,
        &auth,
        gc_bytes,
    );

    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        mkey,
        &mtag,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
}

test "processCommit rejects wrong membership tag" {
    const alloc = testing.allocator;
    var tg: TestGroup = undefined;
    try tg.init(alloc);
    defer tg.deinit();

    var bob_kp: TestKP = undefined;
    try bob_kp.init(0xB0, 0xB1, 0xB2);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_kp.kp } },
    };
    const proposals = [_]Proposal{add_prop};

    var cr = try createCommit(
        Default,
        testing.allocator,
        &tg.gs.group_context,
        &tg.gs.tree,
        tg.gs.my_leaf_index,
        &proposals,
        &tg.sign_sk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const fc = FramedContent{
        .group_id = tg.gs.group_context.group_id,
        .epoch = tg.gs.group_context.epoch,
        .sender = Sender.member(tg.gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    // Compute a valid tag then corrupt it.
    const mkey = &tg.gs.epoch_secrets.membership_key;
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = tg.gs.group_context.serialize(
        &gc_buf,
        // Safe: max_gc_encode is sized for max GroupContext.
    ) catch unreachable;
    const auth = auth_mod.FramedContentAuthData(Default){
        .signature = cr.signature,
        .confirmation_tag = cr.confirmation_tag,
    };
    var mtag = try public_msg.computeMembershipTag(
        Default,
        mkey,
        &fc,
        &auth,
        gc_bytes,
    );
    mtag[0] ^= 0xFF;

    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &proposals,
        null,
        &tg.gs.group_context,
        &tg.gs.tree,
        &tg.sign_pk,
        &tg.gs.interim_transcript_hash,
        &tg.gs.epoch_secrets.init_secret,
        null,
        null,
        null,
        mkey,
        &mtag,
        .mls_public_message,
    );
    try testing.expectError(
        error.MembershipTagMismatch,
        result,
    );
}

// ── UpdatePath validation tests (Phase 30.1) ─────────────────

/// Shared setup: Alice+Bob group, Alice creates empty commit
/// with path. Returns state for tampering the decoded path.
const PathTestCtx = struct {
    gs: GroupState(Default),
    add_cr: CommitResult(Default),
    path_cr: CommitResult(Default),
    path_commit: Commit,
    alice_sign: struct {
        sk: [Default.sign_sk_len]u8,
        pk: [Default.sign_pk_len]u8,
    },
    bob_tkp: TestKP,

    fn deinit(self: *PathTestCtx) void {
        self.path_commit.deinit(testing.allocator);
        self.path_cr.tree.deinit();
        self.path_cr.deinit(testing.allocator);
        self.add_cr.tree.deinit();
        self.add_cr.deinit(testing.allocator);
        self.gs.deinit();
        self.* = undefined;
    }

    fn init(self: *PathTestCtx) !void {
        const alloc = testing.allocator;
        const enc = try Default.dhKeypairFromSeed(
            &testSeed(0xC1),
        );
        const sign = try Default.signKeypairFromSeed(
            &testSeed(0xC2),
        );
        self.alice_sign = .{ .sk = sign.sk, .pk = sign.pk };
        self.gs = try createGroup(
            Default,
            alloc,
            "path-val-test",
            makeTestLeafWithPk(
                "alice",
                &enc.pk,
                &self.alice_sign.pk,
            ),
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            &.{},
        );
        try self.bob_tkp.init(0xD1, 0xD3, 0xD2);
        const add = [_]Proposal{.{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = self.bob_tkp.kp,
                },
            },
        }};
        self.add_cr = try createCommit(
            Default,
            testing.allocator,
            &self.gs.group_context,
            &self.gs.tree,
            self.gs.my_leaf_index,
            &add,
            &self.alice_sign.sk,
            &self.gs.interim_transcript_hash,
            &self.gs.epoch_secrets.init_secret,
            null,
            null,
            .mls_public_message,
        );
        try self.initPathCommit(alloc);
    }

    fn initPathCommit(self: *PathTestCtx, alloc: std.mem.Allocator) !void {
        const new_enc = try Default.dhKeypairFromSeed(
            &testSeed(0xC3),
        );
        const ls = [_]u8{0xF5} ** Default.nh;
        const es = [_][32]u8{[_]u8{0xE5} ** 32};
        const pp: PathParams(Default) = .{
            .allocator = alloc,
            .new_leaf = makeTestLeafWithPk(
                "alice",
                &new_enc.pk,
                &self.alice_sign.pk,
            ),
            .leaf_secret = &ls,
            .eph_seeds = &es,
        };
        const empty = [_]Proposal{};
        self.path_cr = try createCommit(
            Default,
            testing.allocator,
            &self.add_cr.group_context,
            &self.add_cr.tree,
            self.gs.my_leaf_index,
            &empty,
            &self.alice_sign.sk,
            &self.add_cr.interim_transcript_hash,
            &self.add_cr.epoch_secrets.init_secret,
            pp,
            null,
            .mls_public_message,
        );
        const data =
            self.path_cr.commit_bytes[0..self.path_cr.commit_len];
        const dec = try Commit.decode(alloc, data, 0);
        self.path_commit = dec.value;
    }

    /// Call processCommit on the path_commit. Caller can
    /// tamper with `self.path_commit.path` before calling.
    fn process(
        self: *PathTestCtx,
    ) CommitError!ProcessResult(Default) {
        const empty = [_]Proposal{};
        const data =
            self.path_cr.commit_bytes[0..self.path_cr.commit_len];
        const fc = FramedContent{
            .group_id = self.add_cr.group_context.group_id,
            .epoch = self.add_cr.group_context.epoch,
            .sender = Sender.member(self.gs.my_leaf_index),
            .authenticated_data = "",
            .content_type = .commit,
            .content = data,
        };
        const rp: ReceiverPathParams(Default) = .{
            .receiver = LeafIndex.fromU32(1),
            .receiver_sk = &self.bob_tkp.enc_sk,
            .receiver_pk = &self.bob_tkp.enc_pk,
        };
        return processCommit(
            Default,
            testing.allocator,
            &fc,
            &self.path_cr.signature,
            &self.path_cr.confirmation_tag,
            &empty,
            if (self.path_commit.path) |*p| p else null,
            &self.add_cr.group_context,
            &self.add_cr.tree,
            &self.alice_sign.pk,
            &self.add_cr.interim_transcript_hash,
            &self.add_cr.epoch_secrets.init_secret,
            rp,
            null,
            null,
            null,
            null,
            .mls_public_message,
        );
    }
};

test "processCommit rejects non-commit leaf source" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    context.path_commit.path.?.leaf_node.source = .key_package;

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "processCommit rejects reused leaf encryption_key" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    // Overwrite path leaf encryption_key bytes with Alice's
    // current key so the freshness check fires.
    const index =
        context.gs.my_leaf_index.toNodeIndex().toUsize();
    const old_ek =
        context.add_cr.tree.nodes[index].?.payload.leaf
            .encryption_key;
    const dst = @constCast(
        context.path_commit.path.?.leaf_node.encryption_key,
    );
    @memcpy(dst, old_ek);

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "processCommit rejects duplicate path node key" {
    var context: PathTestCtx = undefined;
    try context.init();
    defer context.deinit();

    // Overwrite path node key bytes with Bob's leaf key.
    const bob_idx =
        LeafIndex.fromU32(1).toNodeIndex().toUsize();
    const bob_ek =
        context.add_cr.tree.nodes[bob_idx].?.payload.leaf
            .encryption_key;
    if (context.path_commit.path) |*p| {
        if (p.nodes.len > 0) {
            const dst = @constCast(p.nodes)[0]
                .encryption_key;
            @memcpy(@constCast(dst), bob_ek);
        }
    }

    const result = context.process();
    try testing.expectError(error.InvalidLeafNode, result);
}

test "verifyParentHashes rejects tampered parent hash" {
    // Build a 2-leaf tree with a valid commit path, then
    // tamper the leaf's parent_hash. verifyParentHashes must
    // detect the mismatch.
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB2),
    );
    const bob_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB3),
    );
    const bob_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB4),
    );

    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Set two leaves. Alice = commit source with parent_hash.
    var alice_leaf = makeTestLeafWithPk(
        "alice",
        &alice_enc.pk,
        &alice_sig.pk,
    );
    alice_leaf.source = .commit;

    try tree.setLeaf(LeafIndex.fromU32(1), makeTestLeafWithPk(
        "bob",
        &bob_enc.pk,
        &bob_sig.pk,
    ));

    // Set root parent node with a known key.
    const root_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB5),
    );
    try tree.setNode(
        NodeIndex.fromU32(1),
        node_mod.Node.initParent(.{
            .encryption_key = &root_enc.pk,
            .parent_hash = "",
            .unmerged_leaves = &.{},
        }),
    );

    // Compute correct parent_hash for Alice's leaf.
    var ph_buf: [Default.nh]u8 = undefined;
    if (try path_mod.computeLeafParentHash(
        Default,
        testing.allocator,
        &tree,
        LeafIndex.fromU32(0),
    )) |ph| {
        ph_buf = ph;
        alice_leaf.parent_hash = &ph_buf;
    }
    try tree.setLeaf(LeafIndex.fromU32(0), alice_leaf);

    // Valid tree should pass.
    try tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);

    // Tamper the parent_hash on Alice's leaf in the tree.
    const leaf_slot = &tree.nodes[0];
    const leaf_ptr = &leaf_slot.*.?.payload.leaf;
    if (leaf_ptr.parent_hash) |ph| {
        @constCast(ph)[0] ^= 0xFF;
    }

    // Now verification must fail.
    const result = tree_hashes.verifyParentHashes(Default, testing.allocator, &tree);
    try testing.expectError(error.ParentHashMismatch, result);
}

test "processCommit rejects GCE commit without path" {
    // ProcessCommit must reject a commit with a GCE proposal
    // but no UpdatePath, since path is required per RFC 12.4.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xE1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xE2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "gce-no-path",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob so path derivation succeeds.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xE5, 0xE6, 0xE7);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Create a GCE commit with a path (valid for createCommit).
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{ .extensions = &.{} },
        },
    };
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xE8),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xE9} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xEA} ** 32},
    };
    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{gce_prop},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Bob processes — pass null UpdatePath to simulate missing.
    const data = cr.commit_bytes[0..cr.commit_len];
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = data,
    };
    const result = processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &[_]Proposal{gce_prop},
        null,
        &add_cr.group_context,
        &add_cr.tree,
        &alice_sig.pk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        null,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    try testing.expectError(error.MissingPath, result);
}

test "processCommit accepts GCE commit with path" {
    // Companion to the rejection test above: a GCE commit WITH
    // a valid UpdatePath must be accepted by processCommit.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xF2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "gce-path-ok",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob so path derivation works.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xF3, 0xF4, 0xF5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Alice creates GCE commit with path.
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{ .extensions = &.{} },
        },
    };
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xF6),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xF7} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xF8} ** 32},
    };

    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{gce_prop},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Decode commit to get UpdatePath.
    const commit_data = cr.commit_bytes[0..cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);
    try testing.expect(dec.value.path != null);

    // Bob processes commit WITH path — should succeed.
    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };
    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };
    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &[_]Proposal{gce_prop},
        if (dec.value.path) |*p| p else null,
        &add_cr.group_context,
        &add_cr.tree,
        &alice_sig.pk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        rp,
        null,
        null,
        null,
        null,
        .mls_public_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both sides agree on epoch secrets.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "processCommit with mls_private_message wire format" {
    // Verify that a commit created with mls_private_message wire
    // format is correctly processed when the receiver also uses
    // mls_private_message. This exercises the wire_format field
    // in FramedContentTBS (RFC 9420 S6.1).
    const alloc = testing.allocator;

    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xA2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "priv-commit",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    // Add Bob.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xA3, 0xA4, 0xA5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var add_cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer add_cr.tree.deinit();
    defer add_cr.deinit(testing.allocator);

    // Alice creates empty commit with mls_private_message.
    const new_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xA6),
    );
    const pp: PathParams(Default) = .{
        .allocator = alloc,
        .new_leaf = makeTestLeafWithPk(
            "alice",
            &new_enc.pk,
            &alice_sig.pk,
        ),
        .leaf_secret = &([_]u8{0xA7} ** Default.nh),
        .eph_seeds = &[_][32]u8{[_]u8{0xA8} ** 32},
    };

    var cr = try createCommit(
        Default,
        testing.allocator,
        &add_cr.group_context,
        &add_cr.tree,
        gs.my_leaf_index,
        &[_]Proposal{},
        &alice_sig.sk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        pp,
        null,
        .mls_private_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    // Bob processes with mls_private_message wire format.
    const commit_data = cr.commit_bytes[0..cr.commit_len];
    var dec = try Commit.decode(alloc, commit_data, 0);
    defer dec.value.deinit(alloc);

    const fc = FramedContent{
        .group_id = add_cr.group_context.group_id,
        .epoch = add_cr.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    const rp: ReceiverPathParams(Default) = .{
        .receiver = LeafIndex.fromU32(1),
        .receiver_sk = &bob_tkp.enc_sk,
        .receiver_pk = &bob_tkp.enc_pk,
    };

    var pr = try processCommit(
        Default,
        testing.allocator,
        &fc,
        &cr.signature,
        &cr.confirmation_tag,
        &[_]Proposal{},
        if (dec.value.path) |*p| p else null,
        &add_cr.group_context,
        &add_cr.tree,
        &alice_sig.pk,
        &add_cr.interim_transcript_hash,
        &add_cr.epoch_secrets.init_secret,
        rp,
        null,
        null,
        null,
        null,
        .mls_private_message,
    );
    defer pr.tree.deinit();
    defer pr.deinit(testing.allocator);

    // Both agree on epoch secrets.
    try testing.expectEqual(cr.new_epoch, pr.new_epoch);
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &pr.epoch_secrets.epoch_secret,
    );
}

test "epochAuthenticator changes across epochs" {
    // After createCommit advances the epoch, the
    // epoch_authenticator derived in EpochSecrets must differ
    // from the previous epoch.
    const alloc = testing.allocator;
    const alice_enc = try Default.dhKeypairFromSeed(
        &testSeed(0xB1),
    );
    const alice_sig = try Default.signKeypairFromSeed(
        &testSeed(0xB2),
    );
    var gs = try createGroup(
        Default,
        alloc,
        "ea-test",
        makeTestLeafWithPk(
            "alice",
            &alice_enc.pk,
            &alice_sig.pk,
        ),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    defer gs.deinit();

    const ea0 = gs.epoch_secrets.epoch_authenticator;

    // Add Bob and advance epoch.
    var bob_tkp: TestKP = undefined;
    try bob_tkp.init(0xB3, 0xB4, 0xB5);
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob_tkp.kp } },
    };
    var cr = try createCommit(
        Default,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &[_]Proposal{add_prop},
        &alice_sig.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    const ea1 = cr.epoch_secrets.epoch_authenticator;

    // Must differ.
    try testing.expect(!std.mem.eql(u8, &ea0, &ea1));
}
