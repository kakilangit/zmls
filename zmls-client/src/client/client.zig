//! Client(P) — High-level MLS client orchestrator.
//!
//! Thin load-compute-persist wrapper around the pure
//! computation modules (`GroupBundle`, `MessageProtect`,
//! `CommitProcess`). Each public method:
//!   1. Loads state from ports
//!   2. Delegates to a pure computation function
//!   3. Persists the result via ports
//!
//! `Io` is NOT stored — passed by value to every method.
//! The `CryptoProvider` parameter `P` flows through from zmls.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const zmls = @import("zmls");

const Credential = zmls.Credential;
const KeyPackage = zmls.KeyPackage;

const GroupStore = @import("../ports/group_store.zig").GroupStore;
const key_store_mod = @import("../ports/key_store.zig");
const transport_mod = @import("../ports/transport.zig");
const Transport = transport_mod.Transport;

const pending_mod = @import("pending.zig");
const client_types = @import("types.zig");
const bundle_mod = @import("group_bundle.zig");
const protect_mod = @import("message_protect.zig");
const commit_mod = @import("commit_process.zig");

pub const WireFormatPolicy = client_types.WireFormatPolicy;
pub const InviteResult = client_types.InviteResult;
pub const JoinGroupResult = client_types.JoinGroupResult;
pub const ReceivedMessage = client_types.ReceivedMessage;
pub const ProcessingResult = client_types.ProcessingResult;

/// Maximum pending KeyPackages a Client can hold.
const max_pending_key_packages: u32 = 64;

fn secureZeroSlice(buffer: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buffer));
}

/// High-level MLS client parameterized over `CryptoProvider`.
pub fn Client(comptime P: type) type {
    comptime zmls.crypto_provider.assertValid(P);

    return struct {
        const Self = @This();
        const GS = zmls.GroupState(P);
        const Ser = zmls.serializer.Serializer(P);
        const KS = key_store_mod.KeyStore(P);
        const ST = zmls.SecretTree(P);
        const Bundle = bundle_mod.GroupBundle(P);
        const Protect = protect_mod.MessageProtect(P);
        const CommitProc = commit_mod.CommitProcess(P);
        const PendingMap = pending_mod.PendingKeyPackageMap(
            P,
            max_pending_key_packages,
        );

        // ── Identity (immutable after init) ────────────
        identity: []const u8,
        cipher_suite: zmls.CipherSuite,
        signing_secret_key: [P.sign_sk_len]u8,
        signing_public_key: [P.sign_pk_len]u8,

        // ── Ports ──────────────────────────────────────
        group_store: GroupStore,
        key_store: KS,
        credential_validator: zmls.credential_validator
            .CredentialValidator,
        transport: ?Transport,

        // ── Configuration ──────────────────────────────
        padding_block: u32,
        wire_format_policy: WireFormatPolicy,

        // ── Pending KeyPackages ────────────────────────
        pending_key_packages: PendingMap,

        // ── Allocator (managed pattern) ────────────────
        allocator: Allocator,

        // ── Lifecycle ──────────────────────────────────
        closed: bool,

        // ────────────────────────────────────────────────
        // Options
        // ────────────────────────────────────────────────

        pub const Options = struct {
            group_store: GroupStore,
            key_store: KS,
            credential_validator: zmls.credential_validator
                .CredentialValidator,
            transport: ?Transport = null,
            padding_block: u32 = 32,
            wire_format_policy: WireFormatPolicy =
                .encrypt_application_only,
        };

        // ────────────────────────────────────────────────
        // Error types (no catch-all)
        // ────────────────────────────────────────────────

        pub const InitError = error{
            KeyGenerationFailed,
            OutOfMemory,
        };

        pub const CreateError = GroupStore.Error ||
            KS.Error || Allocator.Error || error{
            ClientClosed,
            KeyGenerationFailed,
            GroupCreationFailed,
            BundleSerializeFailed,
        };

        pub const KeyPackageError = Allocator.Error ||
            error{
                ClientClosed,
                KeyGenerationFailed,
                SigningFailed,
                EncodingFailed,
                CapacityExhausted,
            };

        pub const InviteError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            KeyPackageDecodeFailed,
            CommitFailed,
            WelcomeBuildFailed,
            EncodingFailed,
            KeyGenerationFailed,
            BundleSerializeFailed,
        };

        pub const JoinError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            WelcomeDecodeFailed,
            NoPendingKeyPackage,
            WelcomeProcessingFailed,
            BundleSerializeFailed,
        };

        pub const MembershipError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            CommitFailed,
            BundleSerializeFailed,
        };

        pub const SendError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            BundleSerializeFailed,
            KeyGenerationFailed,
        } || Protect.EncryptError;

        pub const ReceiveError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            BundleSerializeFailed,
        } || Protect.DecryptError;

        // ────────────────────────────────────────────────
        // Lifecycle
        // ────────────────────────────────────────────────

        /// Initialize a new Client.
        ///
        /// Derives signing keys from `signature_seed`. The
        /// seed is NOT stored — only derived keys are kept.
        pub fn init(
            allocator: Allocator,
            identity: []const u8,
            cipher_suite: zmls.CipherSuite,
            signature_seed: *const [32]u8,
            options: Options,
        ) InitError!Self {
            const key_pair = P.signKeypairFromSeed(
                signature_seed,
            ) catch return error.KeyGenerationFailed;

            const owned_identity = try allocator.dupe(
                u8,
                identity,
            );

            return .{
                .identity = owned_identity,
                .cipher_suite = cipher_suite,
                .signing_secret_key = key_pair.sk,
                .signing_public_key = key_pair.pk,
                .group_store = options.group_store,
                .key_store = options.key_store,
                .credential_validator = options
                    .credential_validator,
                .transport = options.transport,
                .padding_block = options.padding_block,
                .wire_format_policy = options
                    .wire_format_policy,
                .pending_key_packages = PendingMap.init(),
                .allocator = allocator,
                .closed = false,
            };
        }

        pub fn deinit(self: *Self) void {
            secureZeroSlice(&self.signing_secret_key);
            secureZeroSlice(&self.signing_public_key);
            self.pending_key_packages.deinit();
            self.allocator.free(self.identity);
            self.identity = &.{};
            self.closed = true;
        }

        // ────────────────────────────────────────────────
        // Internal: load / persist GroupBundle
        // ────────────────────────────────────────────────

        fn loadBundle(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) (GroupStore.Error || error{
            GroupNotFound,
            BundleDeserializeFailed,
        })!Bundle {
            const blob = (try self.group_store.load(
                self.allocator,
                io,
                group_id,
            )) orelse return error.GroupNotFound;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            return Bundle.deserialize(
                self.allocator,
                blob,
            ) catch return error.BundleDeserializeFailed;
        }

        fn persistBundle(
            self: *Self,
            io: Io,
            group_id: []const u8,
            group_state: *const GS,
            secret_tree: *const ST,
        ) (GroupStore.Error || error{
            BundleSerializeFailed,
        })!void {
            const blob = Bundle.serialize(
                self.allocator,
                group_state,
                secret_tree,
            ) catch return error.BundleSerializeFailed;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            try self.group_store.save(io, group_id, blob);
        }

        // ────────────────────────────────────────────────
        // Group creation
        // ────────────────────────────────────────────────

        /// Create a new 1-member group with a random ID.
        /// Returns the group ID (owned by caller).
        pub fn createGroup(
            self: *Self,
            io: Io,
        ) CreateError![]u8 {
            if (self.closed) return error.ClientClosed;

            var group_id_buffer: [32]u8 = undefined;
            io.randomSecure(&group_id_buffer) catch
                return error.KeyGenerationFailed;

            try self.createGroupWithId(
                io,
                &group_id_buffer,
                &.{},
            );

            return try self.allocator.dupe(
                u8,
                &group_id_buffer,
            );
        }

        /// Create a group with a specific ID and extensions.
        pub fn createGroupWithId(
            self: *Self,
            io: Io,
            group_id: []const u8,
            extensions: []const zmls.Extension,
        ) CreateError!void {
            if (self.closed) return error.ClientClosed;

            const encryption_keypair = generateDhKeypair(
                io,
            ) catch return error.KeyGenerationFailed;

            const leaf = buildLeafNode(
                self,
                &encryption_keypair.pk,
            );

            var group_state = zmls.createGroup(
                P,
                self.allocator,
                group_id,
                leaf,
                self.cipher_suite,
                extensions,
            ) catch return error.GroupCreationFailed;

            var bundle = Bundle.initFromGroupState(
                self.allocator,
                &group_state,
            ) catch |err| {
                group_state.deinit();
                return err;
            };
            defer bundle.deinit(self.allocator);

            try self.persistBundle(
                io,
                group_id,
                &bundle.group_state,
                &bundle.secret_tree,
            );

            try self.key_store.storeEncryptionKey(
                io,
                group_id,
                0,
                &encryption_keypair.sk,
            );
        }

        // ────────────────────────────────────────────────
        // KeyPackage generation
        // ────────────────────────────────────────────────

        /// Maximum encoded KeyPackage size.
        const max_key_package_encode: u32 = 65536;

        /// Result of freshKeyPackage: TLS-encoded bytes
        /// and the reference hash for tracking.
        pub const FreshKeyPackageResult = struct {
            data: []u8,
            ref_hash: [P.nh]u8,
        };

        /// Generate a fresh KeyPackage, store private keys
        /// in the pending map, and return TLS-encoded bytes.
        pub fn freshKeyPackage(
            self: *Self,
            allocator: Allocator,
            io: Io,
        ) KeyPackageError!FreshKeyPackageResult {
            if (self.closed) return error.ClientClosed;

            var context: KeyPackageContext = undefined;
            try self.buildKeyPackage(io, &context);
            defer secureZeroSlice(&context.init_keypair.sk);
            defer secureZeroSlice(
                &context.encryption_keypair.sk,
            );
            defer secureZeroSlice(&context.signature_buffer);
            defer secureZeroSlice(
                &context.leaf_signature_buffer,
            );

            return self.encodeAndStoreKeyPackage(
                allocator,
                &context,
            );
        }

        const DhKeypair = struct {
            sk: [P.nsk]u8,
            pk: [P.npk]u8,
        };

        /// Intermediate state for KeyPackage construction.
        const KeyPackageContext = struct {
            key_package: KeyPackage,
            init_keypair: DhKeypair,
            encryption_keypair: DhKeypair,
            init_public_key: [P.npk]u8,
            encryption_public_key: [P.npk]u8,
            signature_buffer: [P.sig_len]u8,
            leaf_signature_buffer: [P.sig_len]u8,
        };

        fn buildKeyPackage(
            self: *Self,
            io: Io,
            context: *KeyPackageContext,
        ) KeyPackageError!void {
            const init_keypair = generateDhKeypair(
                io,
            ) catch return error.KeyGenerationFailed;
            const encryption_keypair = generateDhKeypair(
                io,
            ) catch return error.KeyGenerationFailed;

            context.init_keypair = init_keypair;
            context.encryption_keypair = encryption_keypair;
            context.init_public_key = init_keypair.pk;
            context.encryption_public_key =
                encryption_keypair.pk;

            context.key_package = .{
                .version = .mls10,
                .cipher_suite = self.cipher_suite,
                .init_key = &context.init_public_key,
                .leaf_node = .{
                    .encryption_key = &context
                        .encryption_public_key,
                    .signature_key = &self
                        .signing_public_key,
                    .credential = Credential.initBasic(
                        self.identity,
                    ),
                    .capabilities = defaultCapabilities(),
                    .source = .key_package,
                    .lifetime = defaultLifetime(),
                    .parent_hash = null,
                    .extensions = &.{},
                    .signature = &.{},
                },
                .extensions = &.{},
                .signature = &.{},
            };

            context.key_package.leaf_node.signLeafNode(
                P,
                &self.signing_secret_key,
                &context.leaf_signature_buffer,
                null,
                null,
            ) catch return error.SigningFailed;

            context.key_package.signKeyPackage(
                P,
                &self.signing_secret_key,
                &context.signature_buffer,
            ) catch return error.SigningFailed;
        }

        fn encodeAndStoreKeyPackage(
            self: *Self,
            allocator: Allocator,
            context: *KeyPackageContext,
        ) KeyPackageError!FreshKeyPackageResult {
            const ref = context.key_package.makeRef(
                P,
            ) catch return error.EncodingFailed;

            var buffer: [max_key_package_encode]u8 =
                undefined;
            const end = context.key_package.encode(
                &buffer,
                0,
            ) catch return error.EncodingFailed;

            const data = try allocator.dupe(
                u8,
                buffer[0..end],
            );
            errdefer allocator.free(data);

            try self.pending_key_packages.insert(
                &ref,
                .{
                    .init_sk = context.init_keypair.sk,
                    .init_pk = context.init_keypair.pk,
                    .enc_sk = context
                        .encryption_keypair.sk,
                    .sign_sk = self.signing_secret_key,
                },
            );

            return .{ .data = data, .ref_hash = ref };
        }

        // ────────────────────────────────────────────────
        // Membership operations
        // ────────────────────────────────────────────────

        /// Maximum Welcome encoding buffer size.
        const max_welcome_buffer: u32 = 1 << 17;
        /// Maximum GroupContext encoding buffer size.
        const max_group_context_buffer: u32 = 8192;

        /// Invite a member by their KeyPackage bytes.
        pub fn inviteMember(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            key_package_bytes: []const u8,
        ) InviteError!InviteResult {
            if (self.closed) return error.ClientClosed;

            const decoded = KeyPackage.decode(
                allocator,
                key_package_bytes,
                0,
            ) catch return error.KeyPackageDecodeFailed;
            var key_package = decoded.value;
            defer key_package.deinit(allocator);

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            var commit_output = bundle.group_state.commit(
                allocator,
                .{
                    .proposals = &.{zmls.Proposal{
                        .tag = .add,
                        .payload = .{ .add = .{
                            .key_package = key_package,
                        } },
                    }},
                    .sign_key = &self.signing_secret_key,
                },
            ) catch return error.CommitFailed;
            defer commit_output.deinit();

            return self.buildInviteResult(
                allocator,
                io,
                group_id,
                &key_package,
                &commit_output,
            );
        }

        fn buildInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            key_package: *const KeyPackage,
            commit_output: *GS.CommitOutput,
        ) InviteError!InviteResult {
            var context_buffer: [max_group_context_buffer]u8 =
                undefined;
            const context_end = commit_output.group_state
                .group_context.encode(
                &context_buffer,
                0,
            ) catch return error.EncodingFailed;

            const key_package_ref = key_package.makeRef(
                P,
            ) catch return error.EncodingFailed;

            var ephemeral_seed: [32]u8 = undefined;
            io.randomSecure(&ephemeral_seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&ephemeral_seed);

            const members = [_]zmls.group_welcome
                .NewMemberEntry{.{
                .kp_ref = &key_package_ref,
                .init_pk = key_package.init_key,
                .eph_seed = &ephemeral_seed,
            }};

            var welcome_result = commit_output.group_state
                .buildWelcome(allocator, .{
                .gc_bytes = context_buffer[0..context_end],
                .confirmation_tag = &commit_output
                    .confirmation_tag,
                .welcome_secret = &commit_output
                    .welcome_secret,
                .joiner_secret = &commit_output
                    .joiner_secret,
                .sign_key = &self.signing_secret_key,
                .signer = @intFromEnum(
                    commit_output.group_state
                        .my_leaf_index,
                ),
                .cipher_suite = self.cipher_suite,
                .new_members = &members,
            }) catch return error.WelcomeBuildFailed;
            defer welcome_result.deinit(allocator);

            return self.encodeInviteResult(
                allocator,
                io,
                group_id,
                commit_output,
                &welcome_result,
            );
        }

        fn encodeInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            commit_output: *GS.CommitOutput,
            welcome_result: *const zmls.group_welcome
                .WelcomeResult,
        ) InviteError!InviteResult {
            const commit_data = try allocator.dupe(
                u8,
                commit_output
                    .commit_bytes[0..commit_output.commit_len],
            );
            errdefer allocator.free(commit_data);

            var welcome_buffer: [max_welcome_buffer]u8 =
                undefined;
            const welcome_end = welcome_result.welcome
                .encode(&welcome_buffer, 0) catch
                return error.EncodingFailed;

            const welcome_data = try allocator.dupe(
                u8,
                welcome_buffer[0..welcome_end],
            );
            errdefer allocator.free(welcome_data);

            var secret_tree = try initSecretTree(
                allocator,
                &commit_output.group_state,
            );
            defer secret_tree.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &commit_output.group_state,
                &secret_tree,
            );

            return .{
                .commit = commit_data,
                .welcome = welcome_data,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Join group via Welcome
        // ────────────────────────────────────────────────

        /// Options for joining a group via Welcome.
        pub const JoinGroupOpts = struct {
            ratchet_tree: zmls.RatchetTree,
            signer_verify_key: *const [P.sign_pk_len]u8,
            my_leaf_index: zmls.LeafIndex,
        };

        /// Join a group via a Welcome message.
        pub fn joinGroup(
            self: *Self,
            allocator: Allocator,
            io: Io,
            welcome_bytes: []const u8,
            opts: JoinGroupOpts,
        ) JoinError!JoinGroupResult {
            if (self.closed) return error.ClientClosed;

            const welcome_decoded = zmls.Welcome.decode(
                allocator,
                welcome_bytes,
                0,
            ) catch return error.WelcomeDecodeFailed;
            var welcome = welcome_decoded.value;
            defer welcome.deinit(allocator);

            const match = self.findPendingMatch(
                &welcome,
            ) orelse return error.NoPendingKeyPackage;

            return self.processAndPersistWelcome(
                allocator,
                io,
                &welcome,
                match,
                opts,
            );
        }

        const PendingMatch = struct {
            ref: [P.nh]u8,
            keys: *const PendingMap.PendingKeys,
        };

        fn findPendingMatch(
            self: *const Self,
            welcome: *const zmls.Welcome,
        ) ?PendingMatch {
            for (welcome.secrets) |secret| {
                if (secret.new_member.len != P.nh)
                    continue;
                const ref: *const [P.nh]u8 =
                    secret.new_member[0..P.nh];
                if (self.pending_key_packages.find(
                    ref,
                )) |keys| {
                    return .{
                        .ref = ref.*,
                        .keys = keys,
                    };
                }
            }
            return null;
        }

        fn processAndPersistWelcome(
            self: *Self,
            allocator: Allocator,
            io: Io,
            welcome: *const zmls.Welcome,
            match: PendingMatch,
            opts: JoinGroupOpts,
        ) JoinError!JoinGroupResult {
            var group_state = GS.joinViaWelcome(
                allocator,
                .{
                    .welcome = welcome,
                    .kp_ref = &match.ref,
                    .init_sk = &match.keys.init_sk,
                    .init_pk = &match.keys.init_pk,
                    .signer_verify_key = opts
                        .signer_verify_key,
                    .tree_data = .{
                        .prebuilt = opts.ratchet_tree,
                    },
                    .my_leaf_index = opts.my_leaf_index,
                },
            ) catch return error.WelcomeProcessingFailed;

            const group_id = group_state.groupId();
            const owned_group_id = try allocator.dupe(
                u8,
                group_id,
            );
            errdefer allocator.free(owned_group_id);

            var bundle = Bundle.initFromGroupState(
                allocator,
                &group_state,
            ) catch |err| {
                group_state.deinit();
                return err;
            };
            defer bundle.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &bundle.group_state,
                &bundle.secret_tree,
            );
            _ = self.pending_key_packages.remove(
                &match.ref,
            );

            return .{
                .group_id = owned_group_id,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Remove / Leave / Self-update
        // ────────────────────────────────────────────────

        /// Remove a member by leaf index.
        pub fn removeMember(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            target_leaf: u32,
        ) MembershipError![]u8 {
            if (self.closed) return error.ClientClosed;
            return self.commitWithProposals(
                allocator,
                io,
                group_id,
                &.{zmls.Proposal{
                    .tag = .remove,
                    .payload = .{ .remove = .{
                        .removed = target_leaf,
                    } },
                }},
            );
        }

        /// Self-update: empty commit with path (key rotation).
        pub fn selfUpdate(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) MembershipError![]u8 {
            if (self.closed) return error.ClientClosed;
            return self.commitWithProposals(
                allocator,
                io,
                group_id,
                &.{},
            );
        }

        /// Leave the group (delete local state).
        pub fn leaveGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) GroupStore.Error!void {
            if (self.closed) return;
            try self.group_store.delete(io, group_id);
        }

        /// Shared commit-and-persist for removeMember and
        /// selfUpdate.
        fn commitWithProposals(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            proposals: []const zmls.Proposal,
        ) MembershipError![]u8 {
            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            var commit_output = bundle.group_state.commit(
                allocator,
                .{
                    .proposals = proposals,
                    .sign_key = &self.signing_secret_key,
                },
            ) catch return error.CommitFailed;
            defer commit_output.deinit();

            const commit_data = try allocator.dupe(
                u8,
                commit_output.commit_bytes[0..commit_output
                    .commit_len],
            );
            errdefer allocator.free(commit_data);

            var secret_tree = try initSecretTree(
                allocator,
                &commit_output.group_state,
            );
            defer secret_tree.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &commit_output.group_state,
                &secret_tree,
            );

            return commit_data;
        }

        // ────────────────────────────────────────────────
        // Messaging
        // ────────────────────────────────────────────────

        /// Encrypt and send an application message.
        pub fn sendMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            plaintext: []const u8,
        ) SendError![]u8 {
            if (self.closed) return error.ClientClosed;

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            var reuse_guard: [4]u8 = undefined;
            io.randomSecure(&reuse_guard) catch
                return error.KeyGenerationFailed;

            const wire = try Protect
                .encryptApplicationMessage(
                allocator,
                &bundle.group_state,
                &bundle.secret_tree,
                &self.signing_secret_key,
                plaintext,
                "",
                &reuse_guard,
                self.padding_block,
            );
            errdefer allocator.free(wire);

            try self.persistBundle(
                io,
                group_id,
                &bundle.group_state,
                &bundle.secret_tree,
            );

            return wire;
        }

        /// Decrypt a received application message.
        pub fn receiveMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            ciphertext: []const u8,
        ) ReceiveError!ReceivedMessage {
            if (self.closed) return error.ClientClosed;

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            var plaintext_buffer: [
                protect_mod
                    .wire_buffer_max
            ]u8 = undefined;
            const decrypted = try Protect
                .decryptApplicationMessage(
                &bundle.group_state,
                &bundle.secret_tree,
                ciphertext,
                &plaintext_buffer,
            );

            const owned_data = try allocator.dupe(
                u8,
                decrypted.plaintext,
            );
            errdefer allocator.free(owned_data);

            try self.persistBundle(
                io,
                group_id,
                &bundle.group_state,
                &bundle.secret_tree,
            );

            return .{
                .sender_leaf = decrypted.sender_leaf,
                .data = owned_data,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────

        fn generateDhKeypair(
            io: Io,
        ) error{KeyGenerationFailed}!DhKeypair {
            var seed: [32]u8 = undefined;
            io.randomSecure(&seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&seed);

            const raw = P.dhKeypairFromSeed(
                &seed,
            ) catch return error.KeyGenerationFailed;
            return .{ .sk = raw.sk, .pk = raw.pk };
        }

        /// Create a fresh SecretTree from a GroupState's
        /// encryption_secret. Used after epoch transitions
        /// where we don't want to transfer ownership.
        fn initSecretTree(
            allocator: Allocator,
            group_state: *const GS,
        ) error{BundleSerializeFailed}!ST {
            return ST.init(
                allocator,
                &group_state.epoch_secrets
                    .encryption_secret,
                group_state.leafCount(),
            ) catch return error.BundleSerializeFailed;
        }

        fn buildLeafNode(
            self: *const Self,
            encryption_public_key: *const [P.npk]u8,
        ) zmls.LeafNode {
            return .{
                .encryption_key = encryption_public_key,
                .signature_key = &self.signing_public_key,
                .credential = Credential.initBasic(
                    self.identity,
                ),
                .capabilities = defaultCapabilities(),
                .source = .key_package,
                .lifetime = defaultLifetime(),
                .parent_hash = null,
                .extensions = &.{},
                .signature = &.{},
            };
        }

        fn defaultCapabilities() zmls.tree_node.Capabilities {
            return .{
                .versions = &default_versions,
                .cipher_suites = &default_suites,
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &default_credential_types,
            };
        }

        const default_versions = [_]zmls.ProtocolVersion{
            .mls10,
        };
        const default_suites = [_]zmls.CipherSuite{
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        };
        const default_credential_types =
            [_]zmls.types.CredentialType{.basic};

        fn defaultLifetime() zmls.tree_node.Lifetime {
            return .{
                .not_before = 0,
                .not_after = 30 * 24 * 60 * 60,
            };
        }
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded =
        Io.Threaded.init_single_threaded;
    return threaded.io();
}

const TestP = zmls.DefaultCryptoProvider;
const MemGS = @import(
    "../adapters/memory_group_store.zig",
).MemoryGroupStore;
const MemKS = @import(
    "../adapters/memory_key_store.zig",
).MemoryKeyStore;

test "Client: init/deinit lifecycle" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    const seed: [32]u8 = .{0x42} ** 32;
    var client = try Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
    defer client.deinit();

    try testing.expect(!client.closed);
    try testing.expectEqualSlices(
        u8,
        "alice",
        client.identity,
    );
}

fn makeTestClient(
    group_store: *MemGS(8),
    key_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x42} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: freshKeyPackage returns decodable bytes" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    try testing.expect(result.data.len > 0);

    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var key_package = decoded.value;
    defer key_package.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u32, @intCast(result.data.len)),
        decoded.pos,
    );

    try testing.expectEqual(
        zmls.ProtocolVersion.mls10,
        key_package.version,
    );
    try testing.expectEqual(
        zmls.CipherSuite
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        key_package.cipher_suite,
    );
    try testing.expectEqual(
        zmls.types.LeafNodeSource.key_package,
        key_package.leaf_node.source,
    );

    try testing.expect(key_package.init_key.len > 0);
    try testing.expect(
        key_package.leaf_node.encryption_key.len > 0,
    );

    try key_package.verifySignature(TestP);
    try key_package.leaf_node.verifyLeafNodeSignature(
        TestP,
        null,
        null,
    );
}

test "Client: freshKeyPackage stores keys in pending map" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    try testing.expectEqual(
        @as(u32, 1),
        client.pending_key_packages.count,
    );

    const found = client.pending_key_packages.find(
        &result.ref_hash,
    );
    try testing.expect(found != null);

    try testing.expectEqualSlices(
        u8,
        &client.signing_secret_key,
        &found.?.sign_sk,
    );
}

test "Client: freshKeyPackage ref_hash matches recomputed" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var key_package = decoded.value;
    defer key_package.deinit(testing.allocator);

    const recomputed = try key_package.makeRef(TestP);
    try testing.expectEqualSlices(
        u8,
        &result.ref_hash,
        &recomputed,
    );
}

test "Client: multiple freshKeyPackages get distinct refs" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result_one = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result_one.data);

    const result_two = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result_two.data);

    try testing.expect(!std.mem.eql(
        u8,
        &result_one.ref_hash,
        &result_two.ref_hash,
    ));

    try testing.expectEqual(
        @as(u32, 2),
        client.pending_key_packages.count,
    );
}

fn makeTestClientBob(
    group_store: *MemGS(8),
    key_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x99} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "bob",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: inviteMember produces valid commit and welcome" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var result = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer result.deinit();

    try testing.expect(result.commit.len > 0);
    try testing.expect(result.welcome.len > 0);

    const welcome_decoded = try zmls.Welcome.decode(
        testing.allocator,
        result.welcome,
        0,
    );
    var welcome = welcome_decoded.value;
    defer welcome.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u32, @intCast(result.welcome.len)),
        welcome_decoded.pos,
    );

    try testing.expectEqual(
        @as(usize, 1),
        welcome.secrets.len,
    );
}

test "Client: inviteMember persists updated group state" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var result = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer result.deinit();

    // Reload Alice's group — epoch should have advanced.
    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u64, 1),
        bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        bundle.group_state.leafCount(),
    );
}

test "Client: joinGroup via Welcome succeeds" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    try testing.expectEqualSlices(
        u8,
        group_id,
        join.group_id,
    );

    try testing.expectEqual(
        @as(u32, 0),
        bob.pending_key_packages.count,
    );
}

test "Client: joinGroup persists group state" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    // Bob can reload the group from his store.
    var bob_bundle = try bob.loadBundle(
        io,
        join.group_id,
    );
    defer bob_bundle.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u64, 1),
        bob_bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        alice_bundle.group_state.epoch(),
        bob_bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        bob_bundle.group_state.leafCount(),
    );
}

test "Client: joinGroup fails without pending KP" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    // Clear Bob's pending map.
    bob.pending_key_packages.deinit();
    bob.pending_key_packages = @TypeOf(
        bob.pending_key_packages,
    ).init();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    const result = bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    try testing.expectError(
        error.NoPendingKeyPackage,
        result,
    );
}

test "Client: removeMember produces commit bytes" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    const commit = try alice.removeMember(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(
        @as(u64, 2),
        bundle.group_state.epoch(),
    );
}

test "Client: selfUpdate advances epoch" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    const commit = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(
        @as(u64, 1),
        bundle.group_state.epoch(),
    );
}

test "Client: leaveGroup deletes state from store" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    try bob.leaveGroup(io, join.group_id);

    const load_result = bob.loadBundle(
        io,
        join.group_id,
    );
    try testing.expectError(
        error.GroupNotFound,
        load_result,
    );
}

fn setupTwoMemberGroup(
    alice_group_store: *MemGS(8),
    alice_key_store: *MemKS(TestP, 8),
    bob_group_store: *MemGS(8),
    bob_key_store: *MemKS(TestP, 8),
    alice: *Client(TestP),
    bob: *Client(TestP),
) ![]u8 {
    const io = testIo();

    alice.* = try makeTestClient(
        alice_group_store,
        alice_key_store,
    );
    bob.* = try makeTestClientBob(
        bob_group_store,
        bob_key_store,
    );

    const group_id = try alice.createGroup(io);
    errdefer testing.allocator.free(group_id);

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    return group_id;
}

test "Client: sendMessage + receiveMessage round-trip" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello bob",
    );
    defer testing.allocator.free(ciphertext);

    try testing.expect(ciphertext.len > 0);

    var received = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext,
    );
    defer received.deinit();

    try testing.expectEqualSlices(
        u8,
        "hello bob",
        received.data,
    );
    try testing.expectEqual(
        @as(u32, 0),
        received.sender_leaf,
    );
}

test "Client: multiple send/receive preserves ordering" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext_one = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "message one",
    );
    defer testing.allocator.free(ciphertext_one);

    const ciphertext_two = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "message two",
    );
    defer testing.allocator.free(ciphertext_two);

    var received_one = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext_one,
    );
    defer received_one.deinit();

    var received_two = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext_two,
    );
    defer received_two.deinit();

    try testing.expectEqualSlices(
        u8,
        "message one",
        received_one.data,
    );
    try testing.expectEqualSlices(
        u8,
        "message two",
        received_two.data,
    );
}

test "Client: Bob sends, Alice receives" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext = try bob.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello alice",
    );
    defer testing.allocator.free(ciphertext);

    var received = try alice.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext,
    );
    defer received.deinit();

    try testing.expectEqualSlices(
        u8,
        "hello alice",
        received.data,
    );
    try testing.expectEqual(
        @as(u32, 1),
        received.sender_leaf,
    );
}
