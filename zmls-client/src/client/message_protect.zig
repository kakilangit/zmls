//! Message protection — pure encrypt/decrypt for application
//! messages as PrivateMessage per RFC 9420 Section 6.3.
//!
//! No I/O, no storage, no global state. The caller provides
//! all inputs (group state, secret tree, keys, randomness)
//! and receives the encrypted/decrypted result. Secret tree
//! state is mutated in place (deterministic key consumption).

const std = @import("std");
const Allocator = std.mem.Allocator;
const zmls = @import("zmls");

/// Maximum wire message buffer size.
pub const wire_buffer_max: u32 = 1 << 17;
/// Maximum GroupContext encode buffer.
const group_context_buffer_max: u32 =
    zmls.group_context.max_gc_encode;
/// Content AAD buffer size.
const content_aad_buffer_max: u32 = 8192;
/// SenderData encoded size (leaf_index + generation + guard).
const sender_data_encoded_size: u32 =
    zmls.private_msg.SenderData.encoded_size;

pub fn MessageProtect(comptime P: type) type {
    comptime zmls.crypto_provider.assertValid(P);

    const GS = zmls.GroupState(P);
    const ST = zmls.SecretTree(P);
    const KN = zmls.secret_tree.KeyNonce(P);
    const Auth = zmls.framing_auth.FramedContentAuthData(P);

    return struct {
        pub const EncryptError = error{
            SigningFailed,
            KeyExhausted,
            EncodingFailed,
        };

        pub const DecryptError = error{
            DecodingFailed,
            EpochMismatch,
            SenderDataDecryptFailed,
            InvalidSender,
            KeyRatchetFailed,
            ContentDecryptFailed,
            SignatureVerifyFailed,
        };

        /// Result of decrypting an application message.
        pub const DecryptedMessage = struct {
            sender_leaf: u32,
            plaintext: []const u8,
        };

        // ── Encryption ─────────────────────────────────

        /// Encrypt an application message as a PrivateMessage.
        ///
        /// Pure computation. Mutates `secret_tree` (consumes
        /// one application key). The `reuse_guard` must be
        /// 4 random bytes provided by the caller.
        ///
        /// Returns MLSMessage wire bytes (caller-owned).
        pub fn encryptApplicationMessage(
            allocator: Allocator,
            group_state: *const GS,
            secret_tree: *ST,
            signing_key: *const [P.sign_sk_len]u8,
            plaintext: []const u8,
            authenticated_data: []const u8,
            reuse_guard: *const [4]u8,
            padding_block: u32,
        ) (EncryptError || Allocator.Error)![]u8 {
            const leaf = @intFromEnum(
                group_state.my_leaf_index,
            );

            // Sign the FramedContent.
            const auth = signContent(
                group_state,
                signing_key,
                plaintext,
                authenticated_data,
            ) catch return error.SigningFailed;

            // Consume encryption key from SecretTree.
            var key_nonce = secret_tree.consumeKey(
                leaf,
                1, // application
            ) catch return error.KeyExhausted;
            defer key_nonce.zeroize();

            zmls.private_msg.applyReuseGuard(
                P,
                &key_nonce.nonce,
                reuse_guard,
            );

            // Encrypt content into stack buffer.
            var ciphertext_buffer: [wire_buffer_max]u8 =
                undefined;
            const ciphertext_length = encryptContent(
                group_state,
                plaintext,
                &auth,
                padding_block,
                &key_nonce,
                authenticated_data,
                &ciphertext_buffer,
            ) catch return error.EncodingFailed;

            return assembleSenderDataAndEncode(
                allocator,
                group_state,
                leaf,
                key_nonce.generation,
                reuse_guard,
                authenticated_data,
                ciphertext_buffer[0..ciphertext_length],
            ) catch return error.EncodingFailed;
        }

        // ── Encryption helpers ─────────────────────────

        fn signContent(
            group_state: *const GS,
            signing_key: *const [P.sign_sk_len]u8,
            plaintext: []const u8,
            authenticated_data: []const u8,
        ) !Auth {
            var context_buffer: [group_context_buffer_max]u8 =
                undefined;
            const context_bytes =
                try group_state.serializeContext(
                    &context_buffer,
                );

            const framed_content = zmls.FramedContent{
                .group_id = group_state.groupId(),
                .epoch = group_state.epoch(),
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = @intFromEnum(
                        group_state.my_leaf_index,
                    ),
                },
                .authenticated_data = authenticated_data,
                .content_type = .application,
                .content = plaintext,
            };

            return zmls.signFramedContent(
                P,
                &framed_content,
                .mls_private_message,
                context_bytes,
                signing_key,
                null,
                null,
            );
        }

        fn encryptContent(
            group_state: *const GS,
            plaintext: []const u8,
            auth: *const Auth,
            padding_block: u32,
            key_nonce: *const KN,
            authenticated_data: []const u8,
            output: *[wire_buffer_max]u8,
        ) !u32 {
            var aad_buffer: [content_aad_buffer_max]u8 =
                undefined;
            const aad_length = try zmls.private_msg
                .buildPrivateContentAad(
                &aad_buffer,
                group_state.groupId(),
                group_state.epoch(),
                .application,
                authenticated_data,
            );

            return zmls.encryptContent(
                P,
                plaintext,
                .application,
                auth,
                padding_block,
                &key_nonce.key,
                &key_nonce.nonce,
                aad_buffer[0..aad_length],
                output,
            );
        }

        fn assembleSenderDataAndEncode(
            allocator: Allocator,
            group_state: *const GS,
            leaf_index: u32,
            generation: u32,
            reuse_guard: *const [4]u8,
            authenticated_data: []const u8,
            ciphertext: []const u8,
        ) ![]u8 {
            const sender_data = zmls.private_msg.SenderData{
                .leaf_index = leaf_index,
                .generation = generation,
                .reuse_guard = reuse_guard.*,
            };

            var sd_aad_buffer: [content_aad_buffer_max]u8 =
                undefined;
            const sd_aad_length = try zmls.private_msg
                .buildSenderDataAad(
                &sd_aad_buffer,
                group_state.groupId(),
                group_state.epoch(),
                .application,
            );

            var encrypted_sd: [sender_data_encoded_size]u8 =
                undefined;
            var sd_tag: [P.nt]u8 = undefined;

            const sample_length = @min(
                P.nh,
                @as(u32, @intCast(ciphertext.len)),
            );
            zmls.private_msg.encryptSenderData(
                P,
                &sender_data,
                &group_state.epoch_secrets
                    .sender_data_secret,
                ciphertext[0..sample_length],
                sd_aad_buffer[0..sd_aad_length],
                &encrypted_sd,
                &sd_tag,
            );

            var full_sd: [sender_data_encoded_size + P.nt]u8 =
                undefined;
            @memcpy(
                full_sd[0..sender_data_encoded_size],
                &encrypted_sd,
            );
            @memcpy(
                full_sd[sender_data_encoded_size..],
                &sd_tag,
            );

            return encodeWireMessage(
                allocator,
                group_state,
                authenticated_data,
                &full_sd,
                ciphertext,
            );
        }

        fn encodeWireMessage(
            allocator: Allocator,
            group_state: *const GS,
            authenticated_data: []const u8,
            encrypted_sender_data: []const u8,
            ciphertext: []const u8,
        ) ![]u8 {
            const private_message =
                zmls.private_msg.PrivateMessage{
                    .group_id = group_state.groupId(),
                    .epoch = group_state.epoch(),
                    .content_type = .application,
                    .authenticated_data = authenticated_data,
                    .encrypted_sender_data = encrypted_sender_data,
                    .ciphertext = ciphertext,
                };

            var wire_buffer: [wire_buffer_max]u8 = undefined;
            const version: u16 = @intFromEnum(
                zmls.ProtocolVersion.mls10,
            );
            const wire_format: u16 = @intFromEnum(
                zmls.types.WireFormat.mls_private_message,
            );
            std.mem.writeInt(
                u16,
                wire_buffer[0..2],
                version,
                .big,
            );
            std.mem.writeInt(
                u16,
                wire_buffer[2..4],
                wire_format,
                .big,
            );
            const end = try private_message.encode(
                &wire_buffer,
                4,
            );

            return allocator.dupe(u8, wire_buffer[0..end]);
        }

        // ── Decryption ─────────────────────────────────

        /// Decrypt a received application PrivateMessage.
        ///
        /// Pure computation. Mutates `secret_tree` (forward
        /// ratchets to the sender's generation). The caller
        /// must persist the updated secret tree afterward.
        ///
        /// Returns the sender leaf index and a plaintext
        /// slice into `plaintext_buffer`.
        pub fn decryptApplicationMessage(
            group_state: *const GS,
            secret_tree: *ST,
            wire_bytes: []const u8,
            plaintext_buffer: *[wire_buffer_max]u8,
        ) DecryptError!DecryptedMessage {
            const message = zmls.mls_message.MLSMessage
                .decodeExact(wire_bytes) catch
                return error.DecodingFailed;

            const private_message = switch (message.body) {
                .private_message => |pm| pm,
                else => return error.DecodingFailed,
            };

            if (private_message.epoch != group_state.epoch())
                return error.EpochMismatch;

            const sender_data = decryptSenderData(
                group_state,
                &private_message,
            ) catch return error.SenderDataDecryptFailed;

            zmls.validateSenderLeafIndex(
                sender_data,
                group_state.leafCount(),
            ) catch return error.InvalidSender;

            const decrypted = forwardRatchetAndDecrypt(
                group_state,
                secret_tree,
                &private_message,
                &sender_data,
                plaintext_buffer,
            ) catch return error.ContentDecryptFailed;

            verifyContentSignature(
                group_state,
                &private_message,
                &sender_data,
                decrypted,
            ) catch return error.SignatureVerifyFailed;

            return .{
                .sender_leaf = sender_data.leaf_index,
                .plaintext = decrypted.content,
            };
        }

        // ── Decryption helpers ─────────────────────────

        const DecryptedContent =
            zmls.private_msg.DecryptedContent(P);

        fn decryptSenderData(
            group_state: *const GS,
            private_message: *const zmls.private_msg
                .PrivateMessage,
        ) !zmls.private_msg.SenderData {
            var aad_buffer: [content_aad_buffer_max]u8 =
                undefined;
            const aad_length = try zmls.private_msg
                .buildSenderDataAad(
                &aad_buffer,
                group_state.groupId(),
                private_message.epoch,
                private_message.content_type,
            );

            const sample_length = @min(
                P.nh,
                @as(u32, @intCast(
                    private_message.ciphertext.len,
                )),
            );

            return zmls.private_msg.decryptSenderData(
                P,
                private_message.encrypted_sender_data,
                &group_state.epoch_secrets
                    .sender_data_secret,
                private_message.ciphertext[0..sample_length],
                aad_buffer[0..aad_length],
            );
        }

        fn forwardRatchetAndDecrypt(
            group_state: *const GS,
            secret_tree: *ST,
            private_message: *const zmls.private_msg
                .PrivateMessage,
            sender_data: *const zmls.private_msg.SenderData,
            plaintext_buffer: *[wire_buffer_max]u8,
        ) !DecryptedContent {
            var key_nonce = try secret_tree.forwardRatchet(
                sender_data.leaf_index,
                1, // application
                sender_data.generation,
            );
            defer key_nonce.zeroize();

            zmls.private_msg.applyReuseGuard(
                P,
                &key_nonce.nonce,
                &sender_data.reuse_guard,
            );

            var aad_buffer: [content_aad_buffer_max]u8 =
                undefined;
            const aad_length = try zmls.private_msg
                .buildPrivateContentAad(
                &aad_buffer,
                group_state.groupId(),
                private_message.epoch,
                private_message.content_type,
                private_message.authenticated_data,
            );

            return zmls.decryptContent(
                P,
                private_message.ciphertext,
                private_message.content_type,
                &key_nonce.key,
                &key_nonce.nonce,
                aad_buffer[0..aad_length],
                plaintext_buffer,
            );
        }

        fn verifyContentSignature(
            group_state: *const GS,
            private_message: *const zmls.private_msg
                .PrivateMessage,
            sender_data: *const zmls.private_msg.SenderData,
            decrypted: DecryptedContent,
        ) !void {
            var context_buffer: [group_context_buffer_max]u8 =
                undefined;
            const context_bytes =
                try group_state.serializeContext(
                    &context_buffer,
                );

            const framed_content = zmls.FramedContent{
                .group_id = group_state.groupId(),
                .epoch = private_message.epoch,
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = sender_data.leaf_index,
                },
                .authenticated_data = private_message
                    .authenticated_data,
                .content_type = private_message.content_type,
                .content = decrypted.content,
            };

            const sender_leaf = group_state.tree.getLeaf(
                zmls.LeafIndex.fromU32(
                    sender_data.leaf_index,
                ),
            ) catch return error.InvalidSender;
            const leaf_node = sender_leaf orelse
                return error.InvalidSender;

            if (leaf_node.signature_key.len !=
                P.sign_pk_len)
                return error.InvalidSender;

            try zmls.verifyFramedContent(
                P,
                &framed_content,
                .mls_private_message,
                context_bytes,
                leaf_node.signature_key[0..P.sign_pk_len],
                &decrypted.auth,
            );
        }
    };
}
