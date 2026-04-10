//! Proposal processing per RFC 9420 Sections 12.2-12.3. Validates
//! proposal lists and applies Add, Update, Remove, PSK, ReInit,
//! and other proposals to the ratchet tree in the required order.
// Proposal processing per RFC 9420 Section 12.2 – 12.3.
//
// This module implements:
//   - validateProposalList: checks proposal list validity
//     per the rules in Section 12.2.
//   - applyProposals: applies a validated proposal list to a
//     copy of the ratchet tree and returns the result.
//
// Proposals are applied in this order (per Section 12.3):
//   1. GroupContextExtensions (at most one).
//   2. Update proposals (replace sender's leaf).
//   3. Remove proposals (blank leaf + direct path, highest
//      index first).
//   4. Add proposals (insert into leftmost blank or extend).
//   5. Collect PSK IDs for key schedule input.
//
// ExternalInit and ReInit are noted but not directly applied
// to the tree here — they affect the commit flow instead.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const codec = @import("../codec/codec.zig");
const node_mod = @import("../tree/node.zig");
const path_mod = @import("../tree/path.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const proposal_mod = @import("../messages/proposal.zig");
const key_package_mod = @import("../messages/key_package.zig");
const psk_mod = @import("../key_schedule/psk.zig");
const framing = @import("../framing/content_type.zig");

const LeafIndex = types.LeafIndex;
const ProposalType = types.ProposalType;
const SenderType = types.SenderType;
const Sender = framing.Sender;
const CipherSuite = types.CipherSuite;
const ContentType = types.ContentType;
const WireFormat = types.WireFormat;
const WireFormatPolicy = types.WireFormatPolicy;
const ExtensionType = types.ExtensionType;
const CredentialType = types.CredentialType;
const Extension = node_mod.Extension;
const Capabilities = node_mod.Capabilities;
const LeafNode = node_mod.LeafNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const Proposal = proposal_mod.Proposal;
const Add = proposal_mod.Add;
const Update = proposal_mod.Update;
const Remove = proposal_mod.Remove;
const PreSharedKey = proposal_mod.PreSharedKey;
const ReInit = proposal_mod.ReInit;
const ExternalInit = proposal_mod.ExternalInit;
const GroupContextExtensions = proposal_mod.GroupContextExtensions;
const PreSharedKeyId = psk_mod.PreSharedKeyId;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const TreeError = errors.TreeError;

// -- Constants ---------------------------------------------------------------

/// Maximum number of PSK IDs collected from proposals.
const max_psk_ids: u32 = 64;
/// Maximum number of add/remove/update entries tracked.
const max_affected: u32 = 256;

// -- Sender ------------------------------------------------------------------

/// The sender of a commit, needed for validation context.
pub const CommitSender = struct {
    sender_type: SenderType,
    /// Leaf index of the sender (only valid for .member).
    leaf_index: LeafIndex,
};

// -- UpdateEntry -------------------------------------------------------------

/// An Update paired with the leaf it targets.
pub const UpdateEntry = struct {
    leaf_index: LeafIndex,
    leaf_node: LeafNode,
};

// -- ValidatedProposals ------------------------------------------------------

/// Result of validateProposalList — categorized proposals
/// ready for ordered application.
///
/// Heap-allocated (~120 KiB) to avoid stack overflow. Use
/// `create` / `destroy` for lifecycle management.
pub const ValidatedProposals = struct {
    /// GroupContextExtensions proposal (at most one).
    gce: ?GroupContextExtensions,
    /// Update proposals with their target leaf index.
    updates: [max_affected]UpdateEntry,
    updates_len: u32,
    /// Remove proposals (leaf indices to remove).
    removes: [max_affected]u32,
    removes_len: u32,
    /// Add proposals (leaf nodes to add).
    adds: [max_affected]Add,
    adds_len: u32,
    /// PSK IDs collected from PSK proposals.
    psk_ids: [max_psk_ids]PreSharedKeyId,
    psk_ids_len: u32,
    /// ReInit proposal (at most one).
    reinit: ?ReInit,
    /// ExternalInit proposal (at most one).
    external_init: ?ExternalInit,

    /// Heap-allocate a new ValidatedProposals with all
    /// fields zeroed.
    pub fn create(
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!*ValidatedProposals {
        const vp = try allocator.create(ValidatedProposals);
        vp.* = .{
            .gce = null,
            .updates = undefined,
            .updates_len = 0,
            .removes = undefined,
            .removes_len = 0,
            .adds = undefined,
            .adds_len = 0,
            .psk_ids = undefined,
            .psk_ids_len = 0,
            .reinit = null,
            .external_init = null,
        };
        return vp;
    }

    /// Free a heap-allocated ValidatedProposals.
    pub fn destroy(
        self: *ValidatedProposals,
        allocator: std.mem.Allocator,
    ) void {
        allocator.destroy(self);
    }
};

// -- validateProposalList ----------------------------------------------------

/// Validate a list of proposals per RFC 9420 Section 12.2.
///
/// Rules enforced:
///   - At most one GroupContextExtensions proposal.
///   - At most one ReInit proposal; if present, it must be
///     the only proposal.
///   - At most one ExternalInit proposal.
///   - At most one Update per leaf.
///   - At most one Remove per leaf.
///   - A leaf cannot be both Updated and Removed.
///   - The committer cannot remove themselves.
///
/// Returns a heap-allocated ValidatedProposals with
/// categorized proposals ready for applyProposals. The
/// caller must call `destroy` when done.
///
/// `proposal_senders` is optional. When non-null, it provides
/// per-proposal sender information (for by-reference proposals
/// whose sender differs from the commit sender). When null,
/// the commit `sender` is used for all proposals.
pub fn validateProposalList(
    allocator: std.mem.Allocator,
    proposals: []const Proposal,
    sender: CommitSender,
    proposal_senders: ?[]const Sender,
) (ValidationError || error{OutOfMemory})!*ValidatedProposals {
    const result = try ValidatedProposals.create(allocator);
    errdefer result.destroy(allocator);

    for (proposals, 0..) |*prop, pi| {
        // Check sender type is allowed for this proposal type
        // per RFC 9420 Table 4.
        const prop_sender_type = if (proposal_senders) |ps|
            ps[pi].sender_type
        else
            sender.sender_type;
        if (!isSenderAllowedForProposal(
            prop_sender_type,
            prop.tag,
        )) {
            return error.InvalidProposalList;
        }

        try categorizeProposal(
            result,
            prop,
            sender,
            proposal_senders,
            pi,
        );
    }

    try validateReInitExclusivity(result);
    return result;
}

/// Categorize a single proposal into the result struct.
fn categorizeProposal(
    result: *ValidatedProposals,
    prop: *const Proposal,
    sender: CommitSender,
    proposal_senders: ?[]const Sender,
    pi: usize,
) ValidationError!void {
    switch (prop.tag) {
        .group_context_extensions => {
            if (result.gce != null)
                return error.DuplicateProposal;
            result.gce = prop.payload
                .group_context_extensions;
        },
        .reinit => {
            if (result.reinit != null)
                return error.DuplicateProposal;
            result.reinit = prop.payload.reinit;
        },
        .external_init => {
            if (result.external_init != null)
                return error.DuplicateProposal;
            result.external_init = prop.payload
                .external_init;
        },
        .update => try categorizeUpdate(
            result,
            prop,
            sender,
            proposal_senders,
            pi,
        ),
        .remove => try categorizeRemove(
            result,
            prop,
            sender,
        ),
        .add => {
            if (result.adds_len >= max_affected)
                return error.InvalidProposalList;
            result.adds[result.adds_len] = prop.payload.add;
            result.adds_len += 1;
        },
        .psk => {
            if (result.psk_ids_len >= max_psk_ids)
                return error.InvalidProposalList;
            result.psk_ids[result.psk_ids_len] =
                prop.payload.psk.psk;
            result.psk_ids_len += 1;
        },
        else => {
            // Unknown/GREASE: silently skip per Section 13.
        },
    }
}

/// Categorize an Update proposal.
/// Check if an Update already exists for this leaf index.
fn hasUpdateFor(result: *const ValidatedProposals, li: u32) bool {
    for (result.updates[0..result.updates_len]) |entry| {
        if (entry.leaf_index.toU32() == li) return true;
    }
    return false;
}

/// Check if a Remove already exists for this leaf index.
fn hasRemoveFor(result: *const ValidatedProposals, li: u32) bool {
    for (result.removes[0..result.removes_len]) |r| {
        if (r == li) return true;
    }
    return false;
}

fn categorizeUpdate(
    result: *ValidatedProposals,
    prop: *const Proposal,
    sender: CommitSender,
    proposal_senders: ?[]const Sender,
    pi: usize,
) ValidationError!void {
    const update_sender = if (proposal_senders) |ps|
        LeafIndex.fromU32(ps[pi].leaf_index)
    else
        sender.leaf_index;
    const li = update_sender.toU32();
    // Duplicate/conflict detection by scanning existing entries.
    if (hasUpdateFor(result, li))
        return error.DuplicateProposal;
    if (hasRemoveFor(result, li))
        return error.InvalidProposalList;
    if (result.updates_len >= max_affected)
        return error.InvalidProposalList;
    result.updates[result.updates_len] = .{
        .leaf_index = update_sender,
        .leaf_node = prop.payload.update.leaf_node,
    };
    result.updates_len += 1;
}

/// Categorize a Remove proposal.
fn categorizeRemove(
    result: *ValidatedProposals,
    prop: *const Proposal,
    sender: CommitSender,
) ValidationError!void {
    const li = prop.payload.remove.removed;
    // Duplicate/conflict detection by scanning existing entries.
    if (hasRemoveFor(result, li))
        return error.DuplicateProposal;
    if (hasUpdateFor(result, li))
        return error.InvalidProposalList;
    if (sender.sender_type == .member and
        li == sender.leaf_index.toU32())
    {
        return error.InvalidProposalList;
    }
    if (result.removes_len >= max_affected)
        return error.InvalidProposalList;
    result.removes[result.removes_len] = li;
    result.removes_len += 1;
}

/// ReInit must be the only proposal in the list.
fn validateReInitExclusivity(
    result: *const ValidatedProposals,
) ValidationError!void {
    if (result.reinit == null) return;
    const other = result.updates_len +
        result.removes_len + result.adds_len +
        result.psk_ids_len;
    const has_gce: u32 = if (result.gce != null) 1 else 0;
    const has_ei: u32 =
        if (result.external_init != null) 1 else 0;
    if (other + has_gce + has_ei > 0)
        return error.InvalidProposalList;
}

/// RFC 9420 Table 4: allowed (sender_type, proposal_type) pairs.
/// Unknown/GREASE types are allowed from any sender (they are
/// silently skipped during validation per Section 13).
fn isSenderAllowedForProposal(
    st: SenderType,
    pt: ProposalType,
) bool {
    return switch (pt) {
        .add,
        .update,
        .remove,
        .psk,
        .reinit,
        .external_init,
        .group_context_extensions,
        => isKnownSenderAllowed(st, pt),
        // Unknown/GREASE (includes reserved=0): tolerate
        // from any sender.
        .reserved, _ => true,
    };
}

/// Sender-type check for known proposal types only.
fn isKnownSenderAllowed(
    st: SenderType,
    pt: ProposalType,
) bool {
    return switch (st) {
        .member => switch (pt) {
            // ExternalInit is only valid in external commits
            // (new_member_commit sender), per RFC 9420 S12.2.
            .external_init => false,
            else => true,
        },
        .external => switch (pt) {
            .add,
            .remove,
            .psk,
            .reinit,
            .group_context_extensions,
            => true,
            else => false,
        },
        .new_member_proposal => pt == .add,
        .new_member_commit => switch (pt) {
            .external_init, .remove, .psk => true,
            else => false,
        },
        else => false,
    };
}

// -- ProposalApplyResult -----------------------------------------------------

/// Result of applying proposals to a tree.
///
/// Stack usage: ~50 KiB due to inline arrays of up to 256
/// added/removed leaves and 64 PSK IDs.
pub const ProposalApplyResult = struct {
    /// New group extensions (if GCE was applied).
    new_extensions: ?[]const Extension,
    /// Leaf indices of newly added members.
    added_leaves: [max_affected]LeafIndex,
    added_count: u32,
    /// Leaf indices of removed members.
    removed_leaves: [max_affected]u32,
    removed_count: u32,
    /// PSK IDs to inject into the key schedule.
    psk_ids: [max_psk_ids]PreSharedKeyId,
    psk_ids_len: u32,
    /// Whether a ReInit was proposed.
    has_reinit: bool,
    /// Whether an ExternalInit was proposed.
    has_external_init: bool,
};

// -- validateAddKeyPackages --------------------------------------------------

/// Validate each Add proposal's KeyPackage per RFC 9420
/// Section 10.1. Checks version, cipher suite, init_key !=
/// encryption_key, and signature.
///
/// Must be called before applyProposals so that invalid
/// KeyPackages are rejected before modifying the tree.
pub fn validateAddKeyPackages(
    comptime P: type,
    validated: *const ValidatedProposals,
    expected_suite: CipherSuite,
) (ValidationError || CryptoError)!void {
    const n = validated.adds_len;
    for (validated.adds[0..n]) |*add| {
        try add.key_package.validate(P, expected_suite, null);
        // Verify leaf node signature (key_package source:
        // no group_id / leaf_index context per Section 7.2).
        add.key_package.leaf_node.verifyLeafNodeSignature(
            P,
            null,
            null,
        ) catch {
            return error.SignatureVerifyFailed;
        };
    }
}

/// Verify leaf node signatures for Update proposals.
///
/// Update proposals carry leaf nodes with source = update.
/// Per Section 7.2, the TBS for update source includes
/// group_id and leaf_index as context fields.
pub fn validateUpdateLeafNodes(
    comptime P: type,
    validated: *const ValidatedProposals,
    group_id: []const u8,
    expected_suite: CipherSuite,
) (ValidationError || CryptoError)!void {
    const n = validated.updates_len;
    for (validated.updates[0..n]) |*entry| {
        entry.leaf_node.verifyLeafNodeSignature(
            P,
            group_id,
            entry.leaf_index,
        ) catch {
            return error.SignatureVerifyFailed;
        };
        try entry.leaf_node.validate(expected_suite, null);
    }
}

// -- validateAddsAgainstTree -------------------------------------------------

/// Validate Add proposals against the current tree state.
///
/// RFC 9420 Section 12.1 rules:
///   - Encryption key of the added leaf must not duplicate any
///     existing leaf's encryption key.
///   - Signature key of the added leaf must not duplicate any
///     existing leaf's signature key.
///   - Init key of the KeyPackage must not duplicate any other
///     Add proposal's init key in the same commit.
///   - The cipher suite must match (already checked by
///     KeyPackage.validate, but we check again here).
pub fn validateAddsAgainstTree(
    validated: *const ValidatedProposals,
    tree: *const RatchetTree,
    expected_suite: CipherSuite,
) ValidationError!void {
    const n = validated.adds_len;
    const adds = validated.adds[0..n];

    for (adds) |*add| {
        const kp = &add.key_package;

        // Cipher suite check (belt-and-suspenders).
        if (kp.cipher_suite != expected_suite) {
            return error.CipherSuiteMismatch;
        }

        const new_ek = kp.leaf_node.encryption_key;
        const new_sk = kp.leaf_node.signature_key;

        // Check against existing tree leaves (encryption key
        // and signature key must not duplicate).
        try checkKeyUniquenessExceptRemoved(
            tree,
            new_ek,
            new_sk,
            validated,
        );

        // Check encryption_key and signature_key uniqueness
        // among other Add proposals in this commit.
        try checkAddKeyUniqueness(adds, new_ek, new_sk);

        // Check init key uniqueness among other Adds.
        try checkInitKeyUniqueness(adds, kp.init_key);
    }
}

/// Check that encryption_key and signature_key do not duplicate
/// any existing non-blank leaf in the tree, skipping leaves
/// that are being removed in the same commit.
fn checkKeyUniquenessExceptRemoved(
    tree: *const RatchetTree,
    new_ek: []const u8,
    new_sk: []const u8,
    validated: *const ValidatedProposals,
) ValidationError!void {
    var li: u32 = 0;
    while (li < tree.leaf_count) : (li += 1) {
        // Skip leaves being removed.
        if (isBeingRemoved(validated, li)) continue;

        const node_idx = LeafIndex.fromU32(li).toNodeIndex();
        const index = node_idx.toUsize();
        if (index >= tree.nodes.len) continue;
        const node = tree.nodes[index] orelse continue;
        if (node.node_type != .leaf) continue;
        const leaf = &node.payload.leaf;

        if (std.mem.eql(u8, leaf.encryption_key, new_ek)) {
            return error.InvalidKeyPackage;
        }
        if (std.mem.eql(u8, leaf.signature_key, new_sk)) {
            return error.InvalidKeyPackage;
        }
    }
}

/// Check if a leaf index is in the removes list.
fn isBeingRemoved(
    validated: *const ValidatedProposals,
    li: u32,
) bool {
    const n = validated.removes_len;
    for (validated.removes[0..n]) |rm| {
        if (rm == li) return true;
    }
    return false;
}

/// Check that an init key does not appear in more than one Add
/// proposal in the same commit.
fn checkInitKeyUniqueness(
    adds: []const Add,
    init_key: []const u8,
) ValidationError!void {
    var count: u32 = 0;
    for (adds) |*add| {
        if (std.mem.eql(u8, add.key_package.init_key, init_key)) {
            count += 1;
        }
    }
    if (count > 1) return error.InvalidKeyPackage;
}

/// Check that encryption_key and signature_key do not duplicate
/// any other Add proposal in the same commit.
fn checkAddKeyUniqueness(
    adds: []const Add,
    ek: []const u8,
    sk: []const u8,
) ValidationError!void {
    var ek_count: u32 = 0;
    var sk_count: u32 = 0;
    for (adds) |*add| {
        if (std.mem.eql(u8, add.key_package.leaf_node.encryption_key, ek)) {
            ek_count += 1;
        }
        if (std.mem.eql(u8, add.key_package.leaf_node.signature_key, sk)) {
            sk_count += 1;
        }
    }
    if (ek_count > 1) return error.InvalidKeyPackage;
    if (sk_count > 1) return error.InvalidKeyPackage;
}

// -- validateUpdatesAgainstTree ----------------------------------------------

/// Validate Update proposals against the current tree state.
///
/// RFC 9420 Section 12.1:
///   - The committer must not Update via proposal (they update
///     via the commit path instead).
///   - The new encryption key must not duplicate any existing
///     leaf's encryption key.
///   - The new signature key must not duplicate any existing
///     leaf's signature key.
///   - The leaf_node_source must be `update`.
pub fn validateUpdatesAgainstTree(
    validated: *const ValidatedProposals,
    tree: *const RatchetTree,
    sender: CommitSender,
) ValidationError!void {
    const n = validated.updates_len;
    const updates = validated.updates[0..n];
    for (updates) |*entry| {
        // Committer must not use Update proposal.
        if (sender.sender_type == .member and
            entry.leaf_index.toU32() ==
                sender.leaf_index.toU32())
        {
            return error.InvalidProposalList;
        }

        // Source must be `update`.
        if (entry.leaf_node.source != .update) {
            return error.InvalidLeafNode;
        }

        // Encryption/signature key must not duplicate existing
        // leaves (skip self).
        const new_ek = entry.leaf_node.encryption_key;
        const new_sk = entry.leaf_node.signature_key;

        // Freshness: new encryption_key must differ from the
        // sender's current encryption_key (RFC 9420 S7.3).
        const self_idx = entry.leaf_index.toNodeIndex().toUsize();
        if (self_idx < tree.nodes.len) {
            if (tree.nodes[self_idx]) |self_node| {
                if (self_node.node_type == .leaf) {
                    const old_ek = self_node.payload.leaf
                        .encryption_key;
                    if (std.mem.eql(u8, old_ek, new_ek))
                        return error.InvalidLeafNode;
                }
            }
        }

        var li: u32 = 0;
        while (li < tree.leaf_count) : (li += 1) {
            if (li == entry.leaf_index.toU32()) continue;
            const node_idx = LeafIndex.fromU32(li)
                .toNodeIndex();
            const index = node_idx.toUsize();
            if (index >= tree.nodes.len) continue;
            const node = tree.nodes[index] orelse continue;
            if (node.node_type != .leaf) continue;
            const leaf = &node.payload.leaf;
            if (std.mem.eql(u8, leaf.encryption_key, new_ek)) {
                return error.InvalidLeafNode;
            }
            if (std.mem.eql(u8, leaf.signature_key, new_sk)) {
                return error.InvalidLeafNode;
            }
        }

        // Encryption/signature key must not duplicate any
        // other Update in this commit.
        try checkUpdateKeyUniqueness(updates, entry, new_ek, new_sk);
    }
}

/// Check that an Update's encryption_key and signature_key do
/// not duplicate any other Update proposal in the same commit.
fn checkUpdateKeyUniqueness(
    updates: []const UpdateEntry,
    self_entry: *const UpdateEntry,
    ek: []const u8,
    sk: []const u8,
) ValidationError!void {
    for (updates) |*other| {
        if (other == self_entry) continue;
        if (std.mem.eql(
            u8,
            other.leaf_node.encryption_key,
            ek,
        )) {
            return error.InvalidLeafNode;
        }
        if (std.mem.eql(
            u8,
            other.leaf_node.signature_key,
            sk,
        )) {
            return error.InvalidLeafNode;
        }
    }
}

// -- validateRemovesAgainstTree ----------------------------------------------

/// Validate Remove proposals target valid, non-blank leaves.
///
/// RFC 9420 Section 12.1: a Remove must reference an existing
/// (non-blank) leaf within the tree.
pub fn validateRemovesAgainstTree(
    validated: *const ValidatedProposals,
    tree: *const RatchetTree,
) ValidationError!void {
    const n = validated.removes_len;
    for (validated.removes[0..n]) |li| {
        if (li >= tree.leaf_count) {
            return error.UnknownMember;
        }
        const node_idx = LeafIndex.fromU32(li).toNodeIndex();
        const index = node_idx.toUsize();
        if (index >= tree.nodes.len) {
            return error.UnknownMember;
        }
        if (tree.nodes[index] == null) {
            return error.UnknownMember;
        }
    }
}

// -- validateReInitVersion ---------------------------------------------------

/// Validate that a ReInit proposal does not downgrade the
/// protocol version. RFC 9420 Section 12.1.5: "The version
/// field in the ReInit MUST be no less than the version for
/// the current group."
pub fn validateReInitVersion(
    validated: *const ValidatedProposals,
    current_version: types.ProtocolVersion,
) ValidationError!void {
    if (validated.reinit) |ri| {
        if (@intFromEnum(ri.version) <
            @intFromEnum(current_version))
        {
            return error.VersionMismatch;
        }
    }
}

// -- validatePskProposals ----------------------------------------------------

/// Validate PSK proposals per RFC 9420 Section 12.1.
///
/// Rules:
///   - No duplicate PSK IDs within the same commit.
///   - PSK nonce length must equal the cipher suite hash output
///     length (nh).
///   - Resumption PSKs must have usage == application in a
///     normal (non-reinit, non-branch) commit.
pub fn validatePskProposals(
    validated: *const ValidatedProposals,
    nh: u32,
) ValidationError!void {
    const n = validated.psk_ids_len;
    const ids = validated.psk_ids[0..n];

    for (ids, 0..) |*id, i| {
        // Nonce length check.
        if (id.psk_nonce.len != nh) {
            return error.InvalidProposalList;
        }

        // Resumption usage check (normal commit context).
        if (id.psk_type == .resumption and
            id.resumption_usage != .application)
        {
            return error.InvalidProposalList;
        }

        // Duplicate check: compare against all prior IDs.
        for (ids[0..i]) |*prev| {
            if (pskIdsEqual(id, prev)) {
                return error.InvalidProposalList;
            }
        }
    }
}

/// Compare two PreSharedKeyId values for equality.
fn pskIdsEqual(
    a: *const PreSharedKeyId,
    b: *const PreSharedKeyId,
) bool {
    if (a.psk_type != b.psk_type) return false;
    return switch (a.psk_type) {
        .external => std.mem.eql(
            u8,
            a.external_psk_id,
            b.external_psk_id,
        ),
        .resumption => a.resumption_usage ==
            b.resumption_usage and
            a.resumption_epoch == b.resumption_epoch and
            std.mem.eql(
                u8,
                a.resumption_group_id,
                b.resumption_group_id,
            ),
        else => false,
    };
}

// -- validateGceAgainstTree --------------------------------------------------

/// Validate GroupContextExtensions proposal against the tree.
///
/// RFC 9420 Section 12.1:
///   - Every non-blank leaf must support each extension type
///     in the GCE (i.e. the extension type must appear in the
///     leaf's capabilities.extensions list).
pub fn validateGceAgainstTree(
    validated: *const ValidatedProposals,
    tree: *const RatchetTree,
) ValidationError!void {
    const gce = validated.gce orelse return;
    for (gce.extensions) |ext| {
        try checkAllLeavesSupport(tree, ext.extension_type);
    }
}

/// Check that every non-blank leaf in the tree advertises
/// support for the given extension type.
fn checkAllLeavesSupport(
    tree: *const RatchetTree,
    ext_type: ExtensionType,
) ValidationError!void {
    var li: u32 = 0;
    while (li < tree.leaf_count) : (li += 1) {
        const node_idx = LeafIndex.fromU32(li).toNodeIndex();
        const index = node_idx.toUsize();
        if (index >= tree.nodes.len) continue;
        const node = tree.nodes[index] orelse continue;
        if (node.node_type != .leaf) continue;
        const caps = &node.payload.leaf.capabilities;
        if (!capsHasExtension(caps, ext_type)) {
            return error.UnsupportedCapability;
        }
    }
}

/// Check whether a Capabilities struct lists a given extension.
fn capsHasExtension(
    caps: *const node_mod.Capabilities,
    ext_type: ExtensionType,
) bool {
    for (caps.extensions) |e| {
        if (e == ext_type) return true;
    }
    return false;
}

// -- RequiredCapabilities ----------------------------------------------------

/// Parsed RequiredCapabilities extension (type 3).
/// All slices point into the original extension data bytes
/// and are only valid as long as those bytes are alive.
///
/// The encoding is:
///   ExtensionType extension_types<V>;
///   ProposalType  proposal_types<V>;
///   CredentialType credential_types<V>;
///
/// Each sub-vector is a var-length list of u16 values.
pub const RequiredCapabilities = struct {
    extension_types: []const u8,
    proposal_types: []const u8,
    credential_types: []const u8,
};

const DecodeError = errors.DecodeError;

/// Parse RequiredCapabilities from raw extension data.
///
/// Returns a struct with slices pointing into the input data.
pub fn parseRequiredCapabilities(
    data: []const u8,
) DecodeError!RequiredCapabilities {
    var pos: u32 = 0;

    const ext_r = try codec.decodeVarVectorSlice(data, pos);
    pos = ext_r.pos;
    const prop_r = try codec.decodeVarVectorSlice(data, pos);
    pos = prop_r.pos;
    const cred_r = try codec.decodeVarVectorSlice(data, pos);

    return .{
        .extension_types = ext_r.value,
        .proposal_types = prop_r.value,
        .credential_types = cred_r.value,
    };
}

/// Find RequiredCapabilities in a list of extensions.
/// Returns null if no required_capabilities extension is present.
pub fn findRequiredCapabilities(
    extensions: []const Extension,
) DecodeError!?RequiredCapabilities {
    for (extensions) |ext| {
        if (ext.extension_type == .required_capabilities) {
            return try parseRequiredCapabilities(ext.data);
        }
    }
    return null;
}

/// Validate that a leaf's capabilities satisfy the required
/// capabilities. Returns error if any requirement is missing.
pub fn validateLeafMeetsRequired(
    caps: *const Capabilities,
    req: *const RequiredCapabilities,
) ValidationError!void {
    // Check required extension types.
    try checkRequiredU16List(
        req.extension_types,
        caps.extensions,
        ExtensionType,
    );
    // Check required proposal types.
    try checkRequiredU16List(
        req.proposal_types,
        caps.proposals,
        ProposalType,
    );
    // Check required credential types.
    try checkRequiredU16List(
        req.credential_types,
        caps.credentials,
        CredentialType,
    );
}

/// Check that every u16 value in `required_bytes` (a serialized
/// var-vector of u16 values) appears in `supported`.
fn checkRequiredU16List(
    required_bytes: []const u8,
    supported: anytype,
    comptime E: type,
) ValidationError!void {
    if (required_bytes.len % 2 != 0) {
        return error.UnsupportedCapability;
    }
    var i: u32 = 0;
    while (i + 1 < required_bytes.len) : (i += 2) {
        const val = @as(u16, required_bytes[i]) << 8 |
            @as(u16, required_bytes[i + 1]);
        const required: E = @enumFromInt(val);
        var found = false;
        for (supported) |s| {
            if (s == required) {
                found = true;
                break;
            }
        }
        if (!found) return error.UnsupportedCapability;
    }
}

/// Validate Add proposals against RequiredCapabilities.
pub fn validateAddsRequiredCapabilities(
    validated: *const ValidatedProposals,
    group_extensions: []const Extension,
) (ValidationError || DecodeError)!void {
    const req = try findRequiredCapabilities(
        group_extensions,
    ) orelse return;

    const n = validated.adds_len;
    for (validated.adds[0..n]) |*add| {
        try validateLeafMeetsRequired(
            &add.key_package.leaf_node.capabilities,
            &req,
        );
    }
}

/// Validate that Update leaf nodes meet the group's
/// required_capabilities extension (if present).
pub fn validateUpdatesRequiredCapabilities(
    validated: *const ValidatedProposals,
    group_extensions: []const Extension,
) (ValidationError || DecodeError)!void {
    const req = try findRequiredCapabilities(
        group_extensions,
    ) orelse return;

    const n = validated.updates_len;
    for (validated.updates[0..n]) |*entry| {
        try validateLeafMeetsRequired(
            &entry.leaf_node.capabilities,
            &req,
        );
    }
}

// -- validateNonDefaultProposalCaps -------------------------------------------

/// RFC 9420 S12.2: Non-default proposal types (tag > 7) must
/// be listed in every member's capabilities.proposals field.
pub fn validateNonDefaultProposalCaps(
    proposals: []const Proposal,
    tree: *const RatchetTree,
) ValidationError!void {
    for (proposals) |*prop| {
        const v = @intFromEnum(prop.tag);
        if (v <= 7) continue;
        if (!allLeafsSupportProposal(tree, prop.tag))
            return error.UnsupportedCapability;
    }
}

/// Check that every non-blank leaf in the tree lists the
/// given proposal type in its capabilities.
fn allLeafsSupportProposal(
    tree: *const RatchetTree,
    pt: ProposalType,
) bool {
    var i: u32 = 0;
    while (i < tree.nodes.len) : (i += 2) {
        const node = tree.nodes[i] orelse continue;
        if (node.node_type != .leaf) continue;
        const caps = node.payload.leaf.capabilities;
        var found = false;
        for (caps.proposals) |p| {
            if (p == pt) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

// -- validateWireFormat -------------------------------------------------------

/// Validate that the wire format is allowed for the given
/// content type per the wire format policy.
///
/// RFC 9420 Section 6.2: application data MUST be sent as
/// PrivateMessage (never PublicMessage), regardless of policy.
pub fn validateWireFormat(
    wire_format: WireFormat,
    content_type: ContentType,
    policy: WireFormatPolicy,
) ValidationError!void {
    // Application data must always be encrypted.
    if (content_type == .application and
        wire_format == .mls_public_message)
    {
        return error.InvalidProposalList;
    }

    // Under always_encrypt, handshake must also be encrypted.
    if (policy == .always_encrypt and
        wire_format == .mls_public_message)
    {
        return error.InvalidProposalList;
    }
}

// -- applyProposals ----------------------------------------------------------

/// Apply a validated proposal list to the ratchet tree.
///
/// Proposals are applied in this order per Section 12.3:
///   1. GroupContextExtensions
///   2. Update (replace leaf node)
///   3. Remove (blank leaf + direct path, highest first)
///   4. Add (insert into leftmost blank or extend)
///
/// The tree is modified in-place. The caller should pass a
/// copy of the tree if the original must be preserved.
///
/// NOTE: KeyPackage signature/field validation is NOT done
/// here. The caller (createCommit / processCommit) must call
/// KeyPackage.validate() on each Add before invoking this.
pub fn applyProposals(
    validated: *const ValidatedProposals,
    tree: *RatchetTree,
) (TreeError || error{OutOfMemory})!ProposalApplyResult {
    var result: ProposalApplyResult = undefined;
    result.new_extensions = null;
    result.added_count = 0;
    result.removed_count = 0;
    result.psk_ids_len = 0;
    result.has_reinit = validated.reinit != null;
    result.has_external_init = validated.external_init != null;

    // 1. Apply GroupContextExtensions.
    if (validated.gce) |gce| {
        result.new_extensions = gce.extensions;
    }

    // 2. Apply Update proposals.
    //    Per RFC 9420 Section 12.1.2: replace the sender's
    //    LeafNode, then blank intermediate nodes on the path
    //    from the sender's leaf to the root.
    const up_len = validated.updates_len;
    for (validated.updates[0..up_len]) |*entry| {
        try tree.setLeaf(entry.leaf_index, entry.leaf_node);
        try path_mod.blankDirectPath(tree, entry.leaf_index);
    }

    // 3. Apply Remove proposals (highest index first).
    const rm_len = validated.removes_len;
    var rm_idx: u32 = 0;
    while (rm_idx < rm_len) : (rm_idx += 1) {
        result.removed_leaves[rm_idx] =
            validated.removes[rm_idx];
    }
    result.removed_count = rm_len;

    sortDescending(result.removed_leaves[0..rm_len]);

    for (result.removed_leaves[0..rm_len]) |li| {
        try path_mod.removeLeaf(
            tree,
            LeafIndex.fromU32(li),
        );
    }

    // 4. Apply Add proposals.
    const add_len = validated.adds_len;
    for (validated.adds[0..add_len]) |*add| {
        const li = try path_mod.addLeaf(
            tree,
            add.key_package.leaf_node,
        );
        result.added_leaves[result.added_count] = li;
        result.added_count += 1;
    }

    // 5. Copy PSK IDs.
    const psk_len = validated.psk_ids_len;
    var pi: u32 = 0;
    while (pi < psk_len) : (pi += 1) {
        result.psk_ids[pi] = validated.psk_ids[pi];
    }
    result.psk_ids_len = psk_len;

    return result;
}

/// Sort a u32 slice in descending order (insertion sort).
pub fn sortDescending(items: []u32) void {
    if (items.len <= 1) return;
    var index: u32 = 1;
    while (index < items.len) : (index += 1) {
        const key = items[index];
        var j_index: u32 = index;
        while (j_index > 0 and items[j_index - 1] < key) {
            items[j_index] = items[j_index - 1];
            j_index -= 1;
        }
        items[j_index] = key;
    }
}
