//! Commit processing — pure processing of incoming commits
//! from PublicMessage wire bytes per RFC 9420 Section 12.4.2.
//!
//! No I/O, no storage. The caller provides all inputs
//! (group state, wire bytes, receiver keys) and receives
//! the new group state and membership changes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const zmls = @import("zmls");

/// Maximum inline proposals in a single Commit.
const max_inline_proposals: u32 = 256;

pub fn CommitProcess(comptime P: type) type {
    comptime zmls.crypto_provider.assertValid(P);

    const GS = zmls.GroupState(P);
    const PublicMsg = zmls.public_msg.PublicMessage(P);

    return struct {
        pub const ProcessError = error{
            DecodingFailed,
            EpochMismatch,
            NotACommit,
            CommitDecodeFailed,
            SenderLookupFailed,
            CommitProcessingFailed,
            OutOfMemory,
        };

        /// Result of processing a commit. Contains the new
        /// GroupState (ownership transferred to caller) and
        /// membership change counts.
        pub const CommitResult = struct {
            /// New group state for the next epoch.
            group_state: GS,
            /// Epoch number after the commit.
            new_epoch: u64,
            /// Number of members added by this commit.
            added_count: u32,
            /// Leaf indices of members removed by this commit.
            removed_leaves: [max_inline_proposals]u32,
            removed_count: u32,

            pub fn deinit(self: *CommitResult) void {
                self.group_state.deinit();
                self.* = undefined;
            }
        };

        // ── Public API ─────────────────────────────────

        /// Process an incoming commit from a PublicMessage.
        ///
        /// Pure computation. Takes the current GroupState
        /// (read-only), the raw wire bytes, and the
        /// receiver's encryption keys for path decryption.
        ///
        /// Returns a new GroupState and membership changes.
        /// The caller is responsible for persisting the
        /// result and creating a fresh SecretTree.
        pub fn processPublicCommit(
            allocator: Allocator,
            group_state: *const GS,
            wire_bytes: []const u8,
            receiver_encryption_key: *const [P.nsk]u8,
            receiver_public_key: *const [P.npk]u8,
        ) ProcessError!CommitResult {
            // Decode MLSMessage envelope.
            const message = zmls.mls_message.MLSMessage
                .decodeExact(wire_bytes) catch
                return error.DecodingFailed;

            const public_bytes = switch (message.body) {
                .public_message => |b| b,
                else => return error.DecodingFailed,
            };

            // Decode PublicMessage.
            const public_decode = PublicMsg.decode(
                public_bytes,
                0,
            ) catch return error.DecodingFailed;
            const public_message = public_decode.value;

            return processDecodedCommit(
                allocator,
                group_state,
                &public_message,
                receiver_encryption_key,
                receiver_public_key,
            );
        }

        // ── Internal helpers ───────────────────────────

        fn processDecodedCommit(
            allocator: Allocator,
            group_state: *const GS,
            public_message: *const PublicMsg,
            receiver_encryption_key: *const [P.nsk]u8,
            receiver_public_key: *const [P.npk]u8,
        ) ProcessError!CommitResult {
            const framed_content = &public_message.content;

            if (framed_content.epoch !=
                group_state.epoch())
                return error.EpochMismatch;

            if (framed_content.content_type != .commit)
                return error.NotACommit;

            // Decode the Commit struct from content bytes.
            var commit = zmls.Commit.decode(
                allocator,
                framed_content.content,
                0,
            ) catch return error.CommitDecodeFailed;
            defer commit.value.deinit(allocator);

            return applyDecodedCommit(
                allocator,
                group_state,
                framed_content,
                public_message,
                &commit.value,
                receiver_encryption_key,
                receiver_public_key,
            );
        }

        fn applyDecodedCommit(
            allocator: Allocator,
            group_state: *const GS,
            framed_content: *const zmls.FramedContent,
            public_message: *const PublicMsg,
            commit: *const zmls.Commit,
            receiver_encryption_key: *const [P.nsk]u8,
            receiver_public_key: *const [P.npk]u8,
        ) ProcessError!CommitResult {
            // Resolve inline proposals.
            var proposals: [max_inline_proposals]zmls
                .Proposal = undefined;
            const proposal_count = resolveInlineProposals(
                commit,
                &proposals,
            ) catch return error.CommitDecodeFailed;

            // Look up sender's verification key.
            const sender_verify_key = lookupSenderKey(
                group_state,
                framed_content,
            ) catch return error.SenderLookupFailed;

            // Build receiver params for path decryption.
            const confirmation_tag = public_message
                .auth.confirmation_tag orelse
                return error.CommitDecodeFailed;

            var output = group_state.applyCommit(
                allocator,
                .{
                    .fc = framed_content,
                    .signature = &public_message
                        .auth.signature,
                    .confirmation_tag = &confirmation_tag,
                    .proposals = proposals[0..proposal_count],
                    .update_path = if (commit.path) |*p|
                        p
                    else
                        null,
                    .sender_verify_key = &sender_verify_key,
                    .receiver_params = .{
                        .receiver = group_state
                            .my_leaf_index,
                        .receiver_sk = receiver_encryption_key,
                        .receiver_pk = receiver_public_key,
                    },
                    .membership_key = &group_state
                        .epoch_secrets.membership_key,
                    .membership_tag = if (public_message
                        .membership_tag) |*t|
                        t
                    else
                        null,
                    .wire_format = .mls_public_message,
                },
            ) catch return error.CommitProcessingFailed;

            return buildResult(&output, commit);
        }

        fn resolveInlineProposals(
            commit: *const zmls.Commit,
            output: *[max_inline_proposals]zmls.Proposal,
        ) !u32 {
            var count: u32 = 0;
            for (commit.proposals) |*proposal_or_ref| {
                if (count >= max_inline_proposals)
                    return error.TooManyProposals;
                switch (proposal_or_ref.tag) {
                    .proposal => {
                        output[count] =
                            proposal_or_ref.payload.proposal;
                        count += 1;
                    },
                    .reference => {
                        // By-reference proposals require a
                        // proposal cache. Not yet supported.
                        return error.UnsupportedProposalRef;
                    },
                    else => return error.InvalidProposalType,
                }
            }
            return count;
        }

        fn lookupSenderKey(
            group_state: *const GS,
            framed_content: *const zmls.FramedContent,
        ) ![P.sign_pk_len]u8 {
            if (framed_content.sender.sender_type != .member)
                return error.UnsupportedSenderType;

            const leaf = group_state.tree.getLeaf(
                zmls.LeafIndex.fromU32(
                    framed_content.sender.leaf_index,
                ),
            ) catch return error.SenderLookupFailed;
            const leaf_node = leaf orelse
                return error.SenderLookupFailed;

            if (leaf_node.signature_key.len !=
                P.sign_pk_len)
                return error.SenderLookupFailed;

            var key: [P.sign_pk_len]u8 = undefined;
            @memcpy(
                &key,
                leaf_node.signature_key[0..P.sign_pk_len],
            );
            return key;
        }

        fn buildResult(
            output: *GS.ProcessOutput,
            commit: *const zmls.Commit,
        ) CommitResult {
            var removed: [max_inline_proposals]u32 =
                undefined;
            var removed_count: u32 = 0;
            var added_count: u32 = 0;

            for (commit.proposals) |*proposal_or_ref| {
                if (proposal_or_ref.tag != .proposal)
                    continue;
                const proposal =
                    proposal_or_ref.payload.proposal;
                switch (proposal.tag) {
                    .add => added_count += 1,
                    .remove => {
                        if (removed_count <
                            max_inline_proposals)
                        {
                            removed[removed_count] =
                                proposal.payload.remove
                                    .removed;
                            removed_count += 1;
                        }
                    },
                    else => {},
                }
            }

            return .{
                .group_state = output.group_state,
                .new_epoch = output.group_state.epoch(),
                .added_count = added_count,
                .removed_leaves = removed,
                .removed_count = removed_count,
            };
        }
    };
}
