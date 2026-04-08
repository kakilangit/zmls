//! ProposalEncode — Pure computation for encoding
//! standalone proposals as MLSMessage wire bytes.
//!
//! No I/O, no storage. Takes a proposal and group state,
//! returns wire-encoded bytes and AuthenticatedContent
//! bytes for caching.

const std = @import("std");
const Allocator = std.mem.Allocator;
const zmls = @import("zmls");

/// Maximum buffer for encoding wire messages.
const max_wire_encode: u32 = 1 << 17;

pub fn ProposalEncode(comptime P: type) type {
    comptime zmls.crypto_provider.assertValid(P);

    const GS = zmls.GroupState(P);
    const PublicMsg = zmls.public_msg.PublicMessage(P);
    const Auth = zmls.framing_auth.FramedContentAuthData(P);

    return struct {
        pub const EncodeError = error{
            EncodingFailed,
            SigningFailed,
            OutOfMemory,
        };

        /// Result of encoding a proposal. Contains wire
        /// bytes (owned) and the AuthenticatedContent
        /// bytes needed for proposal caching.
        pub const EncodedProposal = struct {
            /// Wire-encoded MLSMessage bytes (caller owns).
            wire_bytes: []u8,
            /// AuthenticatedContent bytes for caching
            /// (WireFormat || FramedContent || Auth).
            /// Caller owns.
            authenticated_content: []u8,

            pub fn deinit(
                self: *EncodedProposal,
                allocator: Allocator,
            ) void {
                allocator.free(self.wire_bytes);
                allocator.free(
                    self.authenticated_content,
                );
                self.* = undefined;
            }
        };

        /// Encode a proposal as an MLSMessage wire message.
        ///
        /// Builds FramedContent with content_type=.proposal,
        /// signs it, wraps in PublicMessage, and encodes to
        /// MLSMessage. Also produces AuthenticatedContent
        /// bytes for proposal caching.
        pub fn encodeProposal(
            allocator: Allocator,
            group_state: *const GS,
            proposal: *const zmls.Proposal,
            sign_key: *const [P.sign_sk_len]u8,
        ) EncodeError!EncodedProposal {
            var proposal_buffer: [max_wire_encode]u8 =
                undefined;
            const proposal_len = encodeProposalContent(
                proposal,
                &proposal_buffer,
            ) catch return error.EncodingFailed;

            const framed_content = buildProposalFramedContent(
                group_state,
                proposal_buffer[0..proposal_len],
            );

            const auth = signProposal(
                group_state,
                &framed_content,
                sign_key,
            ) catch return error.SigningFailed;

            const wire_bytes = encodeProposalWireMessage(
                allocator,
                &framed_content,
                &auth,
                group_state,
            ) catch return error.EncodingFailed;
            errdefer allocator.free(wire_bytes);

            const authenticated_content =
                buildAuthenticatedContent(
                    allocator,
                    &framed_content,
                    &auth,
                ) catch {
                    allocator.free(wire_bytes);
                    return error.EncodingFailed;
                };

            return .{
                .wire_bytes = wire_bytes,
                .authenticated_content = authenticated_content,
            };
        }

        // ── Internal helpers ───────────────────────────

        fn encodeProposalContent(
            proposal: *const zmls.Proposal,
            buffer: *[max_wire_encode]u8,
        ) !u32 {
            return proposal.encode(buffer, 0);
        }

        fn buildProposalFramedContent(
            group_state: *const GS,
            proposal_bytes: []const u8,
        ) zmls.FramedContent {
            return .{
                .group_id = group_state.groupId(),
                .epoch = group_state.epoch(),
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = @intFromEnum(
                        group_state.my_leaf_index,
                    ),
                },
                .authenticated_data = "",
                .content_type = .proposal,
                .content = proposal_bytes,
            };
        }

        fn signProposal(
            group_state: *const GS,
            framed_content: *const zmls.FramedContent,
            sign_key: *const [P.sign_sk_len]u8,
        ) !Auth {
            const max_gc =
                zmls.group_context.max_gc_encode;
            var context_buffer: [max_gc]u8 = undefined;
            const context_bytes =
                try group_state.serializeContext(
                    &context_buffer,
                );

            return zmls.signFramedContent(
                P,
                framed_content,
                .mls_public_message,
                context_bytes,
                sign_key,
                null,
                null,
            );
        }

        fn encodeProposalWireMessage(
            allocator: Allocator,
            framed_content: *const zmls.FramedContent,
            auth: *const Auth,
            group_state: *const GS,
        ) ![]u8 {
            const max_gc =
                zmls.group_context.max_gc_encode;
            var context_buffer: [max_gc]u8 = undefined;
            const context_bytes =
                try group_state.serializeContext(
                    &context_buffer,
                );

            const membership_tag =
                try zmls.public_msg.computeMembershipTag(
                    P,
                    &group_state.epoch_secrets
                        .membership_key,
                    framed_content,
                    auth,
                    context_bytes,
                );

            const public_message = PublicMsg{
                .content = framed_content.*,
                .auth = auth.*,
                .membership_tag = membership_tag,
            };

            var pub_buffer: [max_wire_encode]u8 = undefined;
            const pub_end = try public_message.encode(
                &pub_buffer,
                0,
            );

            const mls_message =
                zmls.mls_message.MLSMessage{
                    .version = .mls10,
                    .wire_format = .mls_public_message,
                    .body = .{
                        .public_message = pub_buffer[0..pub_end],
                    },
                };

            var wire_buffer: [max_wire_encode]u8 = undefined;
            const wire_end = try mls_message.encode(
                &wire_buffer,
                0,
            );

            return allocator.dupe(
                u8,
                wire_buffer[0..wire_end],
            );
        }

        /// Build AuthenticatedContent bytes for proposal
        /// caching: WireFormat(u16) || FramedContent ||
        /// FramedContentAuthData.
        fn buildAuthenticatedContent(
            allocator: Allocator,
            framed_content: *const zmls.FramedContent,
            auth: *const Auth,
        ) ![]u8 {
            var buffer: [max_wire_encode]u8 = undefined;
            var pos: u32 = 0;

            // WireFormat (u16)
            pos = try zmls.codec.encodeUint16(
                &buffer,
                pos,
                @intFromEnum(
                    zmls.types.WireFormat
                        .mls_public_message,
                ),
            );

            // FramedContent
            pos = try framed_content.encode(&buffer, pos);

            // FramedContentAuthData (no confirmation_tag
            // for proposals)
            pos = try auth.encode(
                &buffer,
                pos,
                .proposal,
            );

            return allocator.dupe(u8, buffer[0..pos]);
        }
    };
}
