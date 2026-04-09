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
const proposal_enc = @import("proposal_encode.zig");
const proposal_store_mod = @import("proposal_store.zig");

pub const WireFormatPolicy = client_types.WireFormatPolicy;
pub const InviteResult = client_types.InviteResult;
pub const JoinGroupResult = client_types.JoinGroupResult;
pub const ReceivedMessage = client_types.ReceivedMessage;
pub const ProcessingResult = client_types.ProcessingResult;
pub const ProposalCached = client_types.ProposalCached;

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
        const PropEnc = proposal_enc.ProposalEncode(P);
        const PendingMap = pending_mod.PendingKeyPackageMap(
            P,
            max_pending_key_packages,
        );
        const PropStore =
            proposal_store_mod.PendingProposalStore(P);

        /// In-memory cache of serialized group bundles.
        /// Keyed by group_id. Eliminates GroupStore I/O
        /// for repeated loads of the same group.
        const BlobCache = struct {
            /// Maximum cached entries. Oldest entry is
            /// evicted when capacity is reached.
            const max_entries: u32 = 16;

            map: std.StringArrayHashMapUnmanaged([]u8),
            alloc: Allocator,

            fn init(allocator: Allocator) BlobCache {
                return .{
                    .map = .empty,
                    .alloc = allocator,
                };
            }

            fn deinit(self: *BlobCache) void {
                var it = self.map.iterator();
                while (it.next()) |e| {
                    secureZeroSlice(e.value_ptr.*);
                    self.alloc.free(e.value_ptr.*);
                    self.alloc.free(e.key_ptr.*);
                }
                self.map.deinit(self.alloc);
            }

            /// Look up a cached blob. Returns a borrowed
            /// slice (valid until the next put/evict).
            fn get(self: *BlobCache, gid: []const u8) ?[]const u8 {
                return self.map.get(gid);
            }

            /// Insert or replace a blob for a group.
            /// The cache takes ownership of a copy.
            fn put(
                self: *BlobCache,
                gid: []const u8,
                blob: []const u8,
            ) void {
                // Replace existing entry if present.
                if (self.map.getEntry(gid)) |e| {
                    secureZeroSlice(e.value_ptr.*);
                    self.alloc.free(e.value_ptr.*);
                    const copy = self.alloc.dupe(
                        u8,
                        blob,
                    ) catch return; // best-effort
                    e.value_ptr.* = copy;
                    return;
                }

                // Evict oldest if at capacity.
                if (self.map.count() >= max_entries) {
                    // ArrayHashMap preserves insertion order.
                    // Entry 0 is the oldest.
                    const keys = self.map.keys();
                    const vals = self.map.values();
                    secureZeroSlice(vals[0]);
                    self.alloc.free(vals[0]);
                    self.alloc.free(keys[0]);
                    self.map.swapRemoveAt(0);
                }

                const key = self.alloc.dupe(
                    u8,
                    gid,
                ) catch return;
                const val = self.alloc.dupe(
                    u8,
                    blob,
                ) catch {
                    self.alloc.free(key);
                    return;
                };
                self.map.put(
                    self.alloc,
                    key,
                    val,
                ) catch {
                    self.alloc.free(key);
                    secureZeroSlice(val);
                    self.alloc.free(val);
                };
            }

            /// Remove a cached entry for a group.
            fn evict(self: *BlobCache, gid: []const u8) void {
                if (self.map.fetchSwapRemove(gid)) |e| {
                    secureZeroSlice(e.value);
                    self.alloc.free(e.value);
                    self.alloc.free(e.key);
                }
            }
        };

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

        // ── Pending proposals (survives serialization) ─
        proposal_store: PropStore,

        // ── Bundle cache (in-memory, avoids store I/O) ─
        bundle_cache: BlobCache,

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
            CredentialValidationFailed,
        };

        pub const JoinError = GroupStore.Error ||
            KS.Error || Allocator.Error || error{
            ClientClosed,
            WelcomeDecodeFailed,
            NoPendingKeyPackage,
            WelcomeProcessingFailed,
            BundleSerializeFailed,
            CredentialValidationFailed,
        };

        pub const MembershipError = GroupStore.Error ||
            KS.Error || Allocator.Error || error{
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

        pub const ProcessIncomingError = GroupStore.Error ||
            KS.Error || Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            BundleSerializeFailed,
            WireDecodeFailed,
            UnsupportedWireFormat,
            ReceiverKeyNotFound,
            CredentialValidationFailed,
        } || Protect.DecryptError ||
            CommitProc.ProcessError;

        pub const ProposeError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            BundleSerializeFailed,
            ProposalEncodeFailed,
            ProposalCacheFailed,
        };

        pub const GroupInfoError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            EncodingFailed,
            SigningFailed,
        };

        pub const ExternalJoinError = GroupStore.Error ||
            KS.Error || Allocator.Error || error{
            ClientClosed,
            GroupInfoDecodeFailed,
            TreeDecodeFailed,
            GroupContextDecodeFailed,
            ExternalCommitFailed,
            KeyGenerationFailed,
            BundleSerializeFailed,
            EncodingFailed,
            CredentialValidationFailed,
        };

        pub const StageCommitError = GroupStore.Error ||
            Allocator.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
            CommitFailed,
        };

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
            signature_seed: *const [P.seed_len]u8,
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
                .proposal_store = PropStore.init(),
                .bundle_cache = BlobCache.init(allocator),
                .allocator = allocator,
                .closed = false,
            };
        }

        pub fn deinit(self: *Self) void {
            secureZeroSlice(&self.signing_secret_key);
            secureZeroSlice(&self.signing_public_key);
            self.pending_key_packages.deinit();
            self.bundle_cache.deinit();
            self.allocator.free(self.identity);
            self.identity = &.{};
            self.closed = true;
        }

        // ────────────────────────────────────────────────
        // Internal: load / persist GroupBundle
        // ────────────────────────────────────────────────

        pub fn loadBundle(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) (GroupStore.Error || error{
            GroupNotFound,
            BundleDeserializeFailed,
        })!Bundle {
            // Fast path: use cached serialized blob.
            if (self.bundle_cache.get(group_id)) |cached| {
                return Bundle.deserialize(
                    self.allocator,
                    cached,
                ) catch return error.BundleDeserializeFailed;
            }

            // Slow path: load from store, populate cache.
            const blob = (try self.group_store.load(
                self.allocator,
                io,
                group_id,
            )) orelse return error.GroupNotFound;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            const bundle = Bundle.deserialize(
                self.allocator,
                blob,
            ) catch return error.BundleDeserializeFailed;
            self.bundle_cache.put(group_id, blob);
            return bundle;
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
            // Write-through: update cache with fresh blob.
            self.bundle_cache.put(group_id, blob);
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

            // Validate new member's credential.
            self.credential_validator.validate(
                &key_package.leaf_node.credential,
            ) catch return error.CredentialValidationFailed;

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
                &bundle.group_state,
                &commit_output,
            );
        }

        fn buildInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            key_package: *const KeyPackage,
            pre_commit_state: *const GS,
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

            var ephemeral_seed: [P.seed_len]u8 = undefined;
            io.randomSecure(&ephemeral_seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&ephemeral_seed);

            const members = [_]zmls.group_welcome
                .NewMemberEntry(P){.{
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
                pre_commit_state,
                commit_output,
                &welcome_result,
            );
        }

        fn encodeInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            pre_commit_state: *const GS,
            commit_output: *GS.CommitOutput,
            welcome_result: *const zmls.group_welcome
                .WelcomeResult,
        ) InviteError!InviteResult {
            const commit_data = encodeCommitAsWireMessage(
                allocator,
                pre_commit_state,
                commit_output,
            ) catch return error.EncodingFailed;
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

        /// Search a ratchet tree for a leaf whose signature_key
        /// matches the given public key. Returns the leaf index
        /// or null if no matching leaf is found.
        fn findMyLeaf(
            tree: *const zmls.RatchetTree,
            signing_public_key: *const [P.sign_pk_len]u8,
        ) ?zmls.LeafIndex {
            var i: u32 = 0;
            while (i < tree.leaf_count) : (i += 1) {
                const li = zmls.LeafIndex.fromU32(i);
                const leaf = tree.getLeaf(li) catch continue;
                if (leaf) |ln| {
                    if (ln.signature_key.len ==
                        P.sign_pk_len and
                        std.mem.eql(
                            u8,
                            ln.signature_key,
                            signing_public_key,
                        ))
                    {
                        return li;
                    }
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
            // Derive my_leaf_index by searching the tree for
            // a leaf whose signature_key matches ours. This
            // makes the API foolproof — the caller cannot
            // supply a wrong leaf index.
            const my_leaf_index = findMyLeaf(
                &opts.ratchet_tree,
                &self.signing_public_key,
            ) orelse return error.WelcomeProcessingFailed;

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
                    .my_leaf_index = my_leaf_index,
                },
            ) catch return error.WelcomeProcessingFailed;

            // Validate all leaves' credentials.
            validateTreeCredentials(
                self,
                &group_state.tree,
            ) catch {
                group_state.deinit();
                return error.CredentialValidationFailed;
            };

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

            try self.key_store.storeEncryptionKey(
                io,
                group_id,
                @intFromEnum(my_leaf_index),
                &match.keys.enc_sk,
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

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            const proposals = &.{zmls.Proposal{
                .tag = .remove,
                .payload = .{ .remove = .{
                    .removed = target_leaf,
                } },
            }};

            // Remove in a multi-member group requires an
            // UpdatePath per RFC 9420 Section 12.4.
            // When the tree has <= 2 leaves, removing one
            // leaves a single-leaf tree with no path nodes,
            // so skip path generation.
            if (bundle.group_state.tree.leaf_count <= 2) {
                return self.commitWithProposals(
                    allocator,
                    io,
                    group_id,
                    proposals,
                );
            }

            return self.commitWithPath(
                allocator,
                io,
                group_id,
                proposals,
                &bundle,
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

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            // Single-member tree has no path nodes; the
            // core library handles this with zero commit
            // secret and no UpdatePath.
            if (bundle.group_state.tree.leaf_count <= 1) {
                return self.commitWithProposals(
                    allocator,
                    io,
                    group_id,
                    &.{},
                );
            }

            return self.commitWithPath(
                allocator,
                io,
                group_id,
                &.{},
                &bundle,
            );
        }

        /// Leave the group (delete local state).
        /// Deletes the encryption key (best-effort) and
        /// the group state from the store.
        pub fn leaveGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) GroupStore.Error!void {
            if (self.closed) return;

            // Best-effort: delete our encryption key so
            // secret material is cleaned up promptly.
            if (self.loadBundle(io, group_id)) |bundle| {
                const leaf = @intFromEnum(
                    bundle.group_state.my_leaf_index,
                );
                var b = bundle;
                b.deinit(self.allocator);
                self.key_store.deleteEncryptionKey(
                    io,
                    group_id,
                    leaf,
                ) catch {};
            } else |_| {}

            self.bundle_cache.evict(group_id);
            try self.group_store.delete(io, group_id);
        }

        // ────────────────────────────────────────────────
        // External join
        // ────────────────────────────────────────────────

        /// Join a group via external commit using a signed
        /// GroupInfo message (MLSMessage-wrapped).
        ///
        /// Returns the group_id and commit bytes that
        /// existing members must process.
        pub fn externalJoin(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_info_bytes: []const u8,
        ) ExternalJoinError!client_types.ExternalJoinResult {
            if (self.closed) return error.ClientClosed;

            var parsed = parseGroupInfoMessage(
                allocator,
                group_info_bytes,
            ) catch return error.GroupInfoDecodeFailed;
            defer parsed.deinit(allocator);

            return self.executeExternalJoin(
                allocator,
                io,
                &parsed,
            );
        }

        const ParsedGroupInfo = struct {
            gi: zmls.group_info.GroupInfo,
            gc: zmls.group_context.GroupContext(P.nh),
            tree: zmls.RatchetTree,

            fn deinit(
                self_gi: *@This(),
                alloc: Allocator,
            ) void {
                self_gi.tree.deinit();
                self_gi.gc.deinit(alloc);
                self_gi.gi.deinit(alloc);
            }
        };

        fn parseGroupInfoMessage(
            allocator: Allocator,
            data: []const u8,
        ) error{ParseFailed}!ParsedGroupInfo {
            const wire = zmls.mls_message.MLSMessage
                .decodeExact(data) catch
                return error.ParseFailed;
            if (wire.wire_format != .mls_group_info)
                return error.ParseFailed;
            const gi_bytes = switch (wire.body) {
                .group_info => |b| b,
                else => return error.ParseFailed,
            };

            const gi_dec = zmls.group_info.GroupInfo
                .decode(allocator, gi_bytes, 0) catch
                return error.ParseFailed;
            var gi = gi_dec.value;
            errdefer gi.deinit(allocator);

            const gc_dec = zmls.group_context
                .GroupContext(P.nh).decode(
                allocator,
                gi.group_context,
                0,
            ) catch return error.ParseFailed;
            var gc = gc_dec.value;
            errdefer gc.deinit(allocator);

            const tree = extractRatchetTree(
                allocator,
                gi.extensions,
            ) catch return error.ParseFailed;

            return .{
                .gi = gi,
                .gc = gc,
                .tree = tree,
            };
        }

        fn extractRatchetTree(
            allocator: Allocator,
            extensions: []const zmls.Extension,
        ) error{TreeNotFound}!zmls.RatchetTree {
            for (extensions) |*ext| {
                if (ext.extension_type == .ratchet_tree) {
                    return decodeRatchetTree(
                        allocator,
                        ext.data,
                    ) catch return error.TreeNotFound;
                }
            }
            return error.TreeNotFound;
        }

        fn decodeRatchetTree(
            allocator: Allocator,
            data: []const u8,
        ) !zmls.RatchetTree {
            const vr = try zmls.varint.decode(data, 0);
            const payload_len = vr.value;
            const hdr_end = vr.pos;
            if (hdr_end + payload_len > data.len)
                return error.Truncated;

            // Single-pass decode: collect nodes into a
            // dynamic list, then transfer to RatchetTree.
            var nodes: std.ArrayList(
                ?zmls.tree_node.Node,
            ) = .empty;
            defer nodes.deinit(allocator);
            // On error, free any decoded node contents.
            errdefer for (nodes.items) |*slot| {
                if (slot.*) |*n| {
                    @constCast(n).deinit(allocator);
                }
            };

            var pos: u32 = hdr_end;
            const end: u32 = hdr_end + payload_len;
            while (pos < end) {
                const pres = zmls.codec.decodeUint8(
                    data,
                    pos,
                ) catch return error.Truncated;
                if (pres.value != 0) {
                    const nd = zmls.tree_node.Node.decode(
                        allocator,
                        data,
                        pres.pos,
                    ) catch return error.Truncated;
                    nodes.append(
                        allocator,
                        nd.value,
                    ) catch return error.Truncated;
                    pos = nd.pos;
                } else {
                    nodes.append(
                        allocator,
                        null,
                    ) catch return error.Truncated;
                    pos = pres.pos;
                }
            }

            const node_count = nodes.items.len;
            const leaf_count: u32 = @intCast(
                (node_count + 1) / 2,
            );
            if (leaf_count == 0) return error.Truncated;

            // Transfer ownership: take the list's backing
            // allocation and wrap it in a RatchetTree.
            const owned = nodes.toOwnedSlice(
                allocator,
            ) catch return error.Truncated;
            return .{
                .nodes = owned,
                .leaf_count = leaf_count,
                .allocator = allocator,
                .owns_contents = true,
            };
        }

        fn executeExternalJoin(
            self: *Self,
            allocator: Allocator,
            io: Io,
            parsed: *const ParsedGroupInfo,
        ) ExternalJoinError!client_types.ExternalJoinResult {
            const enc_kp = generateDhKeypair(
                io,
            ) catch return error.KeyGenerationFailed;

            var joiner_leaf = buildLeafNode(
                self,
                &enc_kp.pk,
            );
            joiner_leaf.source = .commit;

            const eph_count = countEphSeeds(
                allocator,
                &parsed.tree,
                parsed.tree.leaf_count,
            ) catch return error.ExternalCommitFailed;

            const eph_seeds = allocator.alloc(
                [32]u8,
                eph_count,
            ) catch return error.OutOfMemory;
            defer allocator.free(eph_seeds);

            for (eph_seeds) |*s| {
                io.randomSecure(s) catch
                    return error.KeyGenerationFailed;
            }

            var leaf_secret: [P.nh]u8 = undefined;
            io.randomSecure(&leaf_secret) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&leaf_secret);

            var ext_init_seed: [P.seed_len]u8 = undefined;
            io.randomSecure(&ext_init_seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&ext_init_seed);

            const interim_th = computeInterimFromGi(
                &parsed.gc.confirmed_transcript_hash,
                parsed.gi.confirmation_tag,
            ) catch return error.ExternalCommitFailed;

            var ec = zmls.createExternalCommit(
                P,
                allocator,
                &parsed.gc,
                &parsed.tree,
                parsed.gi.extensions,
                &interim_th,
                .{
                    .allocator = allocator,
                    .joiner_leaf = joiner_leaf,
                    .sign_key = &self.signing_secret_key,
                    .leaf_secret = &leaf_secret,
                    .eph_seeds = eph_seeds,
                    .ext_init_seed = &ext_init_seed,
                    .remove_proposals = &.{},
                },
                .mls_public_message,
            ) catch return error.ExternalCommitFailed;
            // persistExternalJoinResult moves tree+gc out
            // of ec, replacing ec.tree with a dummy. We
            // must free that dummy when ec goes out of scope.
            defer ec.tree.deinit();

            // Validate existing members' credentials.
            validateTreeCredentials(
                self,
                &parsed.tree,
            ) catch return error.CredentialValidationFailed;

            return self.persistExternalJoinResult(
                allocator,
                io,
                &ec,
                &enc_kp,
            );
        }

        fn computeInterimFromGi(
            confirmed_hash: *const [P.nh]u8,
            confirmation_tag: []const u8,
        ) error{ComputeFailed}![P.nh]u8 {
            return zmls.updateInterimTranscriptHash(
                P,
                confirmed_hash,
                confirmation_tag,
            ) catch return error.ComputeFailed;
        }

        fn countEphSeeds(
            allocator: Allocator,
            tree: *const zmls.RatchetTree,
            leaf_count: u32,
        ) error{CountFailed}!u32 {
            const new_leaf_idx = leaf_count;
            const new_leaf = zmls.LeafIndex.fromU32(
                new_leaf_idx,
            );
            const new_lc = leaf_count + 1;
            const padded_lc = zmls.tree_math.paddedLeafCount(
                new_lc,
            );

            var extended_tree = zmls.RatchetTree.init(
                allocator,
                padded_lc,
            ) catch return error.CountFailed;
            defer extended_tree.deinit();

            const copy_width = @min(
                tree.nodeCount(),
                extended_tree.nodeCount(),
            );
            @memcpy(
                extended_tree.nodes[0..copy_width],
                tree.nodes[0..copy_width],
            );

            var p_buf: [32]zmls.types
                .NodeIndex = undefined;
            var c_buf: [32]zmls.types
                .NodeIndex = undefined;
            const fdp = extended_tree.filteredDirectPath(
                new_leaf,
                &p_buf,
                &c_buf,
            ) catch return error.CountFailed;

            var total: u32 = 0;
            var res_buf: [
                zmls.RatchetTree
                    .max_resolution_size
            ]zmls.types.NodeIndex =
                undefined;
            for (fdp.copath) |cp| {
                const res = extended_tree.resolution(
                    cp,
                    &res_buf,
                ) catch return error.CountFailed;
                total += @intCast(res.len);
            }

            return total;
        }

        /// Count ephemeral seeds needed for an existing
        /// leaf's filtered direct path (for selfUpdate).
        fn countEphSeedsForLeaf(
            tree: *const zmls.RatchetTree,
            leaf_index: zmls.LeafIndex,
        ) error{CountFailed}!u32 {
            var p_buf: [32]zmls.types
                .NodeIndex = undefined;
            var c_buf: [32]zmls.types
                .NodeIndex = undefined;
            const fdp = tree.filteredDirectPath(
                leaf_index,
                &p_buf,
                &c_buf,
            ) catch return error.CountFailed;

            var total: u32 = 0;
            var res_buf: [
                zmls.RatchetTree
                    .max_resolution_size
            ]zmls.types.NodeIndex =
                undefined;
            for (fdp.copath) |cp| {
                const res = tree.resolution(
                    cp,
                    &res_buf,
                ) catch return error.CountFailed;
                total += @intCast(res.len);
            }

            return total;
        }

        fn persistExternalJoinResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            ec: *zmls.ExternalCommitResult(P),
            enc_kp: *const DhKeypair,
        ) ExternalJoinError!client_types.ExternalJoinResult {
            var gs = buildGroupStateFromExternal(
                self.allocator,
                ec,
            ) catch return error.ExternalCommitFailed;
            errdefer gs.deinit();

            const group_id = gs.groupId();
            const owned_gid = allocator.dupe(
                u8,
                group_id,
            ) catch return error.OutOfMemory;
            errdefer allocator.free(owned_gid);

            var bundle = Bundle.initFromGroupState(
                self.allocator,
                &gs,
            ) catch |err| {
                gs.deinit();
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
                @intFromEnum(ec.joiner_leaf_index),
                &enc_kp.sk,
            );

            const commit_data = encodeExternalCommitWire(
                allocator,
                ec,
            ) catch return error.EncodingFailed;
            errdefer allocator.free(commit_data);

            return .{
                .group_id = owned_gid,
                .commit = commit_data,
                .allocator = allocator,
            };
        }

        fn buildGroupStateFromExternal(
            allocator: Allocator,
            ec: *zmls.ExternalCommitResult(P),
        ) !GS {
            // Move ownership of tree and gc from ec.
            const tree = ec.tree;
            ec.tree = zmls.RatchetTree.init(
                allocator,
                1,
            ) catch
                return error.OutOfMemory;

            const gc = ec.group_context;
            ec.group_context = undefined;

            return .{
                .tree = tree,
                .group_context = gc,
                .epoch_secrets = ec.epoch_secrets,
                .interim_transcript_hash = ec
                    .interim_transcript_hash,
                .confirmed_transcript_hash = ec
                    .confirmed_transcript_hash,
                .my_leaf_index = ec.joiner_leaf_index,
                .wire_format_policy = .always_encrypt,
                .pending_proposals = zmls.proposal_cache
                    .ProposalCache(P).init(),
                .epoch_key_ring = zmls.epoch_key_ring
                    .EpochKeyRing(P).init(0),
                .resumption_psk_ring = zmls.psk_lookup
                    .ResumptionPskRing(P).init(0),
                .allocator = allocator,
            };
        }

        fn encodeExternalCommitWire(
            allocator: Allocator,
            ec: *const zmls.ExternalCommitResult(P),
        ) error{
            EncodingFailed,
            OutOfMemory,
        }![]u8 {
            const content = ec.commit_bytes[0..ec.commit_len];
            return allocator.dupe(u8, content);
        }

        // ────────────────────────────────────────────────
        // Standalone proposals
        // ────────────────────────────────────────────────

        /// Propose adding a member (standalone proposal).
        /// Returns wire-encoded proposal bytes.
        pub fn proposeAdd(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            key_package_bytes: []const u8,
        ) ProposeError![]u8 {
            if (self.closed) return error.ClientClosed;

            const decoded = KeyPackage.decode(
                allocator,
                key_package_bytes,
                0,
            ) catch return error.ProposalEncodeFailed;
            var key_package = decoded.value;
            defer key_package.deinit(allocator);

            const proposal = zmls.Proposal{
                .tag = .add,
                .payload = .{ .add = .{
                    .key_package = key_package,
                } },
            };
            return self.encodeAndCacheProposal(
                allocator,
                io,
                group_id,
                &proposal,
            );
        }

        /// Propose removing a member (standalone proposal).
        /// Returns wire-encoded proposal bytes.
        pub fn proposeRemove(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            target_leaf: u32,
        ) ProposeError![]u8 {
            if (self.closed) return error.ClientClosed;

            const proposal = zmls.Proposal{
                .tag = .remove,
                .payload = .{ .remove = .{
                    .removed = target_leaf,
                } },
            };
            return self.encodeAndCacheProposal(
                allocator,
                io,
                group_id,
                &proposal,
            );
        }

        /// Commit all pending (cached) proposals.
        /// Returns wire-encoded commit bytes.
        pub fn commitPending(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) MembershipError![]u8 {
            if (self.closed) return error.ClientClosed;

            // Collect pending proposals for this group.
            var proposal_buf: [256]zmls.Proposal = undefined;
            const proposals = self.proposal_store
                .collectProposals(
                group_id,
                &proposal_buf,
            );

            const wire_bytes = self.commitWithProposals(
                allocator,
                io,
                group_id,
                proposals,
            ) catch |err| return err;

            // Clear proposals only after successful commit.
            self.proposal_store.clearGroup(group_id);

            return wire_bytes;
        }

        /// A staged commit that has not yet been persisted.
        ///
        /// Call `confirm` to persist the new epoch state,
        /// or `discard` to abandon it (original state is
        /// unchanged). The handle owns the commit and
        /// welcome bytes.
        pub const StagedCommitHandle = struct {
            commit_data: []u8,
            welcome_data: ?[]u8,
            staged_group_state: GS,
            staged_secret_tree: ST,
            group_id: []const u8,
            allocator: Allocator,
            confirmed: bool,
            staged_epoch: u64,

            pub fn deinit(
                self_h: *StagedCommitHandle,
            ) void {
                // Always clean up the staged state. Even
                // after confirm (which serializes to store),
                // the in-memory structs still own heap
                // allocations that must be freed.
                self_h.staged_group_state.deinit();
                self_h.staged_secret_tree.deinit(
                    self_h.allocator,
                );
                self_h.allocator.free(
                    self_h.commit_data,
                );
                if (self_h.welcome_data) |w| {
                    self_h.allocator.free(w);
                }
                self_h.allocator.free(
                    self_h.group_id,
                );
                self_h.* = undefined;
            }

            pub const ConfirmError = GroupStore.Error ||
                error{
                    BundleSerializeFailed,
                    BundleDeserializeFailed,
                    GroupNotFound,
                    ConflictingCommit,
                };

            /// Persist the staged state, advancing the
            /// group to the new epoch. Returns
            /// `error.ConflictingCommit` if the group
            /// epoch has changed since staging.
            pub fn confirm(
                self_h: *StagedCommitHandle,
                client: *Self,
                io: Io,
            ) ConfirmError!void {
                const current = try client.loadBundle(
                    io,
                    self_h.group_id,
                );
                var bundle = current;
                defer bundle.deinit(client.allocator);

                if (bundle.group_state.epoch() !=
                    self_h.staged_epoch)
                {
                    return error.ConflictingCommit;
                }

                try client.persistBundle(
                    io,
                    self_h.group_id,
                    &self_h.staged_group_state,
                    &self_h.staged_secret_tree,
                );
                self_h.confirmed = true;
            }

            /// Abandon the staged commit. The original
            /// group state remains unchanged. Must still
            /// call `deinit` afterward to free memory.
            pub fn discard(
                self_h: *StagedCommitHandle,
            ) void {
                // Mark as confirmed so confirm() cannot
                // be called after discard(). Memory is
                // freed in deinit().
                self_h.confirmed = true;
            }
        };

        /// Create a commit without persisting it.
        ///
        /// Returns a `StagedCommitHandle` containing the
        /// commit bytes and the staged group state. Call
        /// `confirm` to persist or `discard` to abandon.
        pub fn stageCommit(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            proposals: []const zmls.Proposal,
        ) StageCommitError!StagedCommitHandle {
            if (self.closed) return error.ClientClosed;

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
            errdefer commit_output.deinit();

            const wire_bytes = encodeCommitAsWireMessage(
                allocator,
                &bundle.group_state,
                &commit_output,
            ) catch return error.CommitFailed;
            errdefer allocator.free(wire_bytes);

            var secret_tree = initSecretTree(
                allocator,
                &commit_output.group_state,
            ) catch return error.CommitFailed;
            errdefer secret_tree.deinit(allocator);

            // Record epoch at staging time for conflict
            // detection in confirm().
            const staged_epoch = bundle.group_state.epoch();

            // Move ownership of staged state to handle.
            const gs = commit_output.group_state;
            commit_output.group_state = undefined;

            const owned_gid = try allocator.dupe(
                u8,
                group_id,
            );

            return .{
                .commit_data = wire_bytes,
                .welcome_data = null,
                .staged_group_state = gs,
                .staged_secret_tree = secret_tree,
                .group_id = owned_gid,
                .allocator = allocator,
                .confirmed = false,
                .staged_epoch = staged_epoch,
            };
        }

        fn encodeAndCacheProposal(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            proposal: *const zmls.Proposal,
        ) ProposeError![]u8 {
            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            const encoded = PropEnc.encodeProposal(
                allocator,
                &bundle.group_state,
                proposal,
                &self.signing_secret_key,
            ) catch return error.ProposalEncodeFailed;
            defer allocator.free(
                encoded.authenticated_content,
            );

            const sender = zmls.Sender{
                .sender_type = .member,
                .leaf_index = @intFromEnum(
                    bundle.group_state.my_leaf_index,
                ),
            };

            // Compute ref hash for later resolution.
            const ref = zmls.crypto_primitives.refHash(
                P,
                "MLS 1.0 Proposal Reference",
                encoded.authenticated_content,
            );

            self.proposal_store.store(
                group_id,
                ref,
                proposal.*,
                sender,
            ) catch return error.ProposalCacheFailed;

            return encoded.wire_bytes;
        }

        /// Shared commit-and-persist for removeMember.
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

            const wire_bytes = encodeCommitAsWireMessage(
                allocator,
                &bundle.group_state,
                &commit_output,
            ) catch return error.CommitFailed;
            errdefer allocator.free(wire_bytes);

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

            return wire_bytes;
        }

        /// Commit with an explicit UpdatePath. Generates
        /// fresh encryption keys, leaf secret, and eph
        /// seeds for the committer's filtered direct path.
        fn commitWithPath(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            proposals: []const zmls.Proposal,
            bundle: *Bundle,
        ) MembershipError![]u8 {
            const enc_kp = generateDhKeypair(
                io,
            ) catch return error.CommitFailed;

            var new_leaf = buildLeafNode(
                self,
                &enc_kp.pk,
            );
            new_leaf.source = .commit;

            const eph_count = countEphSeedsForLeaf(
                &bundle.group_state.tree,
                bundle.group_state.my_leaf_index,
            ) catch return error.CommitFailed;

            const eph_seeds = allocator.alloc(
                [32]u8,
                eph_count,
            ) catch return error.OutOfMemory;
            defer allocator.free(eph_seeds);

            for (eph_seeds) |*s| {
                io.randomSecure(s) catch
                    return error.CommitFailed;
            }

            var leaf_secret: [P.nh]u8 = undefined;
            io.randomSecure(&leaf_secret) catch
                return error.CommitFailed;
            defer secureZeroSlice(&leaf_secret);

            var commit_output = bundle.group_state.commit(
                allocator,
                .{
                    .proposals = proposals,
                    .sign_key = &self.signing_secret_key,
                    .path_params = .{
                        .allocator = allocator,
                        .new_leaf = new_leaf,
                        .leaf_secret = &leaf_secret,
                        .eph_seeds = eph_seeds,
                    },
                },
            ) catch return error.CommitFailed;
            defer commit_output.deinit();

            const wire_bytes = encodeCommitAsWireMessage(
                allocator,
                &bundle.group_state,
                &commit_output,
            ) catch return error.CommitFailed;
            errdefer allocator.free(wire_bytes);

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

            // Store the new leaf encryption key so future
            // processPublicCommit calls can find it.
            const new_leaf_idx = @intFromEnum(
                commit_output.group_state.my_leaf_index,
            );
            try self.key_store.storeEncryptionKey(
                io,
                group_id,
                new_leaf_idx,
                &enc_kp.sk,
            );

            return wire_bytes;
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
        // Incoming message dispatch
        // ────────────────────────────────────────────────

        /// Process an incoming wire message of unknown type.
        ///
        /// Peeks at the wire format to dispatch:
        /// - PrivateMessage → decrypt as application message
        /// - PublicMessage (commit) → process commit, advance
        ///   epoch
        /// - PublicMessage (proposal) → cache for future
        ///   commit resolution
        ///
        /// Returns a discriminated union describing what
        /// happened. The caller does NOT need to know the
        /// wire format in advance.
        pub fn processIncoming(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            wire_bytes: []const u8,
        ) ProcessIncomingError!ProcessingResult {
            if (self.closed) return error.ClientClosed;

            const wire_format = peekWireFormat(
                wire_bytes,
            ) catch return error.WireDecodeFailed;

            return switch (wire_format) {
                .mls_private_message => self.processPrivateMessage(
                    allocator,
                    io,
                    group_id,
                    wire_bytes,
                ),
                .mls_public_message => self.processPublicMessage(
                    allocator,
                    io,
                    group_id,
                    wire_bytes,
                ),
                else => error.UnsupportedWireFormat,
            };
        }

        fn processPrivateMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            wire_bytes: []const u8,
        ) ProcessIncomingError!ProcessingResult {
            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            var plaintext_buffer: [
                protect_mod.wire_buffer_max
            ]u8 = undefined;
            const decrypted = try Protect
                .decryptApplicationMessage(
                &bundle.group_state,
                &bundle.secret_tree,
                wire_bytes,
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

            return .{ .application = .{
                .sender_leaf = decrypted.sender_leaf,
                .data = owned_data,
                .allocator = allocator,
            } };
        }

        fn processPublicMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            wire_bytes: []const u8,
        ) ProcessIncomingError!ProcessingResult {
            // Decode envelope to determine content type.
            const content_type = peekPublicContentType(
                wire_bytes,
            ) catch return error.WireDecodeFailed;

            return switch (content_type) {
                .commit => self.processPublicCommit(
                    allocator,
                    io,
                    group_id,
                    wire_bytes,
                ),
                .proposal => self.processPublicProposal(
                    allocator,
                    group_id,
                    wire_bytes,
                ),
                else => error.UnsupportedWireFormat,
            };
        }

        fn processPublicCommit(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            wire_bytes: []const u8,
        ) ProcessIncomingError!ProcessingResult {
            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            // Inject stored proposals for this group.
            self.proposal_store.injectInto(
                group_id,
                &bundle.group_state.pending_proposals,
            );

            // Load receiver encryption key from store.
            var receiver_secret_key: [P.nsk]u8 = undefined;
            defer secureZeroSlice(&receiver_secret_key);

            const leaf_index = @intFromEnum(
                bundle.group_state.my_leaf_index,
            );
            const found = self.key_store
                .loadEncryptionKey(
                io,
                group_id,
                leaf_index,
                &receiver_secret_key,
            ) catch return error.ReceiverKeyNotFound;
            if (!found) return error.ReceiverKeyNotFound;

            const receiver_public_key = getLeafEncryptionKey(
                &bundle.group_state,
            ) catch return error.ReceiverKeyNotFound;

            var result = try CommitProc
                .processPublicCommit(
                allocator,
                &bundle.group_state,
                wire_bytes,
                &receiver_secret_key,
                &receiver_public_key,
            );

            return self.finalizeCommitResult(
                allocator,
                io,
                group_id,
                &result,
            );
        }

        /// Post-commit finalization: validate credentials, init
        /// secret tree, persist, build result, clear proposals.
        fn finalizeCommitResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            result: *CommitProc.CommitResult,
        ) ProcessIncomingError!ProcessingResult {
            // Validate credentials of all leaves in the
            // resulting tree (catches newly added members).
            validateTreeCredentials(
                self,
                &result.group_state.tree,
            ) catch {
                result.deinit();
                return error.CredentialValidationFailed;
            };

            var secret_tree = initSecretTree(
                allocator,
                &result.group_state,
            ) catch {
                result.deinit();
                return error.BundleSerializeFailed;
            };
            defer secret_tree.deinit(allocator);

            self.persistBundle(
                io,
                group_id,
                &result.group_state,
                &secret_tree,
            ) catch |err| {
                result.deinit();
                return err;
            };

            const commit_applied = buildCommitApplied(
                allocator,
                result,
            ) catch {
                result.deinit();
                return error.OutOfMemory;
            };

            result.deinit();

            // Clear stored proposals — epoch advanced.
            self.proposal_store.clearGroup(group_id);

            return .{ .commit_applied = commit_applied };
        }

        fn processPublicProposal(
            self: *Self,
            allocator: Allocator,
            group_id: []const u8,
            wire_bytes: []const u8,
        ) ProcessIncomingError!ProcessingResult {
            const decoded = decodePublicProposal(
                allocator,
                wire_bytes,
            ) catch return error.WireDecodeFailed;

            // Build AuthenticatedContent for ref hash.
            const auth_content = buildProposalAuthContent(
                &decoded.framed_content,
                &decoded.auth,
            ) catch return error.WireDecodeFailed;

            const ref = zmls.crypto_primitives.refHash(
                P,
                "MLS 1.0 Proposal Reference",
                auth_content.slice(),
            );

            const sender = zmls.Sender{
                .sender_type = decoded.framed_content
                    .sender.sender_type,
                .leaf_index = decoded.framed_content
                    .sender.leaf_index,
            };

            self.proposal_store.store(
                group_id,
                ref,
                decoded.proposal,
                sender,
            ) catch return error.WireDecodeFailed;

            return .{ .proposal_cached = .{
                .proposal_type = @intFromEnum(
                    decoded.proposal.tag,
                ),
                .sender_leaf = decoded.framed_content
                    .sender.leaf_index,
            } };
        }

        // ────────────────────────────────────────────────
        // Group queries (read-only, no persist)
        // ────────────────────────────────────────────────

        const QueryError = GroupStore.Error || error{
            ClientClosed,
            GroupNotFound,
            BundleDeserializeFailed,
        };

        /// Return the current epoch of the group.
        pub fn groupEpoch(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) QueryError!u64 {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            return bundle.group_state.epoch();
        }

        /// Return the cipher suite negotiated for the group.
        pub fn groupCipherSuite(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) QueryError!zmls.types.CipherSuite {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            return bundle.group_state.cipherSuite();
        }

        /// Return this client's leaf index in the group.
        pub fn myLeafIndex(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) QueryError!u32 {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            return bundle.group_state
                .my_leaf_index.toU32();
        }

        /// Return the number of leaf slots in the group's
        /// ratchet tree (includes blank slots from removed
        /// members).
        pub fn groupLeafCount(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) QueryError!u32 {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            return bundle.group_state.leafCount();
        }

        const MembersError = QueryError || error{
            OutOfMemory,
            TreeAccessFailed,
        };

        /// Return information about all occupied leaf slots.
        ///
        /// The returned slice is allocated with `allocator`
        /// and must be freed by the caller. Identity slices
        /// within each `MemberInfo` are copies owned by the
        /// same allocator.
        pub fn groupMembers(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) MembersError![]client_types.MemberInfo {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            return collectMembers(
                allocator,
                &bundle.group_state,
            );
        }

        /// Derive an exported secret from the group's epoch.
        ///
        /// Implements MLS Exporter (RFC 9420 Section 8.5).
        /// `out` determines the export length; it is filled
        /// with the derived keying material.
        pub fn exportSecret(
            self: *Self,
            io: Io,
            group_id: []const u8,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) QueryError!void {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            zmls.mlsExporter(
                P,
                &bundle.group_state
                    .epoch_secrets.exporter_secret,
                label,
                context,
                out,
            );
        }

        /// Return the epoch authenticator for the current
        /// epoch (RFC 9420 Section 8.7).
        ///
        /// Copies the authenticator into `out`. Returns the
        /// number of bytes written (always `P.nh`).
        pub fn epochAuthenticator(
            self: *Self,
            io: Io,
            group_id: []const u8,
            out: *[P.nh]u8,
        ) QueryError!void {
            if (self.closed) return error.ClientClosed;
            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);
            out.* = bundle.group_state
                .epochAuthenticator().*;
        }

        /// Export a signed GroupInfo for external joiners.
        ///
        /// Returns heap-allocated bytes containing the
        /// MLSMessage-wrapped GroupInfo with ratchet_tree
        /// and external_pub extensions.
        pub fn groupInfo(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) GroupInfoError![]u8 {
            if (self.closed) return error.ClientClosed;

            var bundle = try self.loadBundle(
                io,
                group_id,
            );
            defer bundle.deinit(self.allocator);

            return buildSignedGroupInfo(
                allocator,
                &bundle.group_state,
                &self.signing_secret_key,
            );
        }

        /// Clear all pending proposals for a group without
        /// committing them.
        pub fn cancelPendingProposals(
            self: *Self,
            group_id: []const u8,
        ) void {
            self.proposal_store.clearGroup(group_id);
        }

        /// Evict a group's cached bundle blob, forcing the
        /// next loadBundle to read from the GroupStore. Use
        /// this after external store modifications that
        /// bypass the Client API.
        pub fn invalidateGroupCache(
            self: *Self,
            group_id: []const u8,
        ) void {
            self.bundle_cache.evict(group_id);
        }

        /// Encrypt and send an application message with
        /// additional authenticated data.
        pub fn sendMessageWithAad(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            plaintext: []const u8,
            authenticated_data: []const u8,
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
                authenticated_data,
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

        /// Pure extraction of member info from a GroupState.
        fn collectMembers(
            allocator: Allocator,
            gs: *const GS,
        ) (error{ OutOfMemory, TreeAccessFailed })![]client_types.MemberInfo {
            const leaf_count = gs.leafCount();

            // First pass: count occupied leaves.
            var occupied: u32 = 0;
            var i: u32 = 0;
            while (i < leaf_count) : (i += 1) {
                const leaf = gs.tree.getLeaf(
                    zmls.LeafIndex.fromU32(i),
                ) catch return error.TreeAccessFailed;
                if (leaf != null) occupied += 1;
            }

            const members = allocator.alloc(
                client_types.MemberInfo,
                occupied,
            ) catch return error.OutOfMemory;
            errdefer allocator.free(members);

            // Second pass: fill with identity copies.
            var slot: u32 = 0;
            i = 0;
            while (i < leaf_count) : (i += 1) {
                const leaf = gs.tree.getLeaf(
                    zmls.LeafIndex.fromU32(i),
                ) catch return error.TreeAccessFailed;
                if (leaf) |ln| {
                    const identity = allocator.dupe(
                        u8,
                        ln.credential.payload.basic,
                    ) catch {
                        // Free previously copied identities.
                        var j: u32 = 0;
                        while (j < slot) : (j += 1) {
                            allocator.free(
                                members[j].identity,
                            );
                        }
                        return error.OutOfMemory;
                    };
                    members[slot] = .{
                        .leaf_index = i,
                        .identity = identity,
                    };
                    slot += 1;
                }
            }

            return members;
        }

        fn peekWireFormat(
            wire_bytes: []const u8,
        ) error{TooShort}!zmls.types.WireFormat {
            if (wire_bytes.len < 4) return error.TooShort;
            const raw = std.mem.readInt(
                u16,
                wire_bytes[2..4],
                .big,
            );
            return @enumFromInt(raw);
        }

        /// Peek at the content type inside a PublicMessage
        /// within an MLSMessage envelope.
        fn peekPublicContentType(
            wire_bytes: []const u8,
        ) !zmls.types.ContentType {
            const message = zmls.mls_message.MLSMessage
                .decodeExact(wire_bytes) catch
                return error.DecodeFailed;

            const public_bytes = switch (message.body) {
                .public_message => |b| b,
                else => return error.DecodeFailed,
            };

            const PublicMsg2 =
                zmls.public_msg.PublicMessage(P);
            const decoded = PublicMsg2.decode(
                public_bytes,
                0,
            ) catch return error.DecodeFailed;

            return decoded.value.content.content_type;
        }

        /// Decoded proposal from a PublicMessage.
        const DecodedProposal = struct {
            framed_content: zmls.FramedContent,
            auth: Auth,
            proposal: zmls.Proposal,
        };

        /// Decode a proposal from wire bytes.
        fn decodePublicProposal(
            allocator: Allocator,
            wire_bytes: []const u8,
        ) !DecodedProposal {
            const message = zmls.mls_message.MLSMessage
                .decodeExact(wire_bytes) catch
                return error.DecodeFailed;

            const public_bytes = switch (message.body) {
                .public_message => |b| b,
                else => return error.DecodeFailed,
            };

            const PublicMsg2 =
                zmls.public_msg.PublicMessage(P);
            const decoded = PublicMsg2.decode(
                public_bytes,
                0,
            ) catch return error.DecodeFailed;
            const fc = decoded.value.content;

            if (fc.content_type != .proposal)
                return error.NotAProposal;

            // Decode the proposal from the content bytes.
            const prop_decoded = zmls.Proposal.decode(
                allocator,
                fc.content,
                0,
            ) catch return error.DecodeFailed;

            return .{
                .framed_content = fc,
                .auth = decoded.value.auth,
                .proposal = prop_decoded.value,
            };
        }

        /// Maximum buffer for AuthenticatedContent.
        const max_auth_content: u32 = 1 << 17;

        const AuthContentBuffer = struct {
            data: [max_auth_content]u8,
            len: u32,

            fn slice(self: *const AuthContentBuffer) []const u8 {
                return self.data[0..self.len];
            }
        };

        /// Build AuthenticatedContent bytes from a decoded
        /// proposal's FramedContent and auth data.
        /// WireFormat(u16) || FramedContent || AuthData
        fn buildProposalAuthContent(
            framed_content: *const zmls.FramedContent,
            auth: *const Auth,
        ) !AuthContentBuffer {
            var result: AuthContentBuffer = undefined;
            var pos: u32 = 0;

            // WireFormat (u16)
            pos = zmls.codec.encodeUint16(
                &result.data,
                pos,
                @intFromEnum(
                    zmls.types.WireFormat
                        .mls_public_message,
                ),
            ) catch return error.EncodeFailed;

            // FramedContent
            pos = framed_content.encode(
                &result.data,
                pos,
            ) catch return error.EncodeFailed;

            // FramedContentAuthData
            pos = auth.encode(
                &result.data,
                pos,
                .proposal,
            ) catch return error.EncodeFailed;

            result.len = pos;
            return result;
        }

        fn validateTreeCredentials(
            self: *const Self,
            tree: *const zmls.RatchetTree,
        ) error{CredentialValidationFailed}!void {
            var i: u32 = 0;
            while (i < tree.leaf_count) : (i += 1) {
                const li = @as(
                    zmls.LeafIndex,
                    @enumFromInt(i),
                );
                const leaf = tree.getLeaf(
                    li,
                ) catch continue;
                const leaf_node = leaf orelse continue;
                self.credential_validator.validate(
                    &leaf_node.credential,
                ) catch
                    return error.CredentialValidationFailed;
            }
        }

        fn getLeafEncryptionKey(
            group_state: *const GS,
        ) error{LeafNotFound}![P.npk]u8 {
            const leaf_index = group_state.my_leaf_index;
            const leaf = group_state.tree.getLeaf(
                leaf_index,
            ) catch return error.LeafNotFound;
            const leaf_node = leaf orelse
                return error.LeafNotFound;
            if (leaf_node.encryption_key.len != P.npk)
                return error.LeafNotFound;
            var key: [P.npk]u8 = undefined;
            @memcpy(
                &key,
                leaf_node
                    .encryption_key[0..P.npk],
            );
            return key;
        }

        fn buildCommitApplied(
            allocator: Allocator,
            result: *CommitProc.CommitResult,
        ) Allocator.Error!client_types.CommitApplied {
            const removed = try allocator.dupe(
                u32,
                result.removed_leaves[0..result
                    .removed_count],
            );
            errdefer allocator.free(removed);

            // CommitProcess counts adds but doesn't track
            // leaf indices for them (they depend on tree
            // state after apply). Return an empty slice.
            const added = try allocator.alloc(u32, 0);

            return .{
                .new_epoch = result.new_epoch,
                .removed_members = removed,
                .added_members = added,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────

        fn generateDhKeypair(
            io: Io,
        ) error{KeyGenerationFailed}!DhKeypair {
            var seed: [P.seed_len]u8 = undefined;
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

        // ── GroupInfo helpers ─────────────────────────

        const max_gi_encode: u32 = 65536;
        const max_tree_encode: u32 = 1 << 18;

        /// Build a signed GroupInfo wrapped in MLSMessage.
        fn buildSignedGroupInfo(
            allocator: Allocator,
            group_state: *const GS,
            sign_key: *const [P.sign_sk_len]u8,
        ) GroupInfoError![]u8 {
            const tree_bytes = encodeRatchetTree(
                allocator,
                &group_state.tree,
            ) catch return error.EncodingFailed;
            defer allocator.free(tree_bytes);

            var ext_pub_buf: [P.npk]u8 = undefined;
            const ext_pub_ext = zmls
                .makeExternalPubExtension(
                P,
                &group_state.epoch_secrets
                    .external_secret,
                &ext_pub_buf,
            ) catch return error.SigningFailed;

            const gi_exts = [_]zmls.Extension{
                .{
                    .extension_type = .ratchet_tree,
                    .data = tree_bytes,
                },
                ext_pub_ext,
            };

            var gc_buf: [max_group_context_encode]u8 =
                undefined;
            const gc_bytes = group_state.serializeContext(
                &gc_buf,
            ) catch return error.EncodingFailed;

            const conf_tag = zmls.framing_auth
                .computeConfirmationTag(
                P,
                &group_state.epoch_secrets
                    .confirmation_key,
                &group_state.confirmed_transcript_hash,
            );

            return encodeGroupInfoMessage(
                allocator,
                gc_bytes,
                &gi_exts,
                &conf_tag,
                @intFromEnum(group_state.my_leaf_index),
                sign_key,
            );
        }

        /// Encode a signed GroupInfo into an MLSMessage.
        fn encodeGroupInfoMessage(
            allocator: Allocator,
            gc_bytes: []const u8,
            extensions: []const zmls.Extension,
            confirmation_tag: *const [P.nh]u8,
            signer: u32,
            sign_key: *const [P.sign_sk_len]u8,
        ) GroupInfoError![]u8 {
            const sig = zmls.signGroupInfo(
                P,
                gc_bytes,
                extensions,
                confirmation_tag,
                signer,
                sign_key,
            ) catch return error.SigningFailed;

            const gi = zmls.group_info.GroupInfo{
                .group_context = gc_bytes,
                .extensions = extensions,
                .confirmation_tag = confirmation_tag,
                .signer = signer,
                .signature = &sig,
            };

            var gi_buf: [max_gi_encode]u8 = undefined;
            const gi_end = gi.encode(
                &gi_buf,
                0,
            ) catch return error.EncodingFailed;

            const mls_msg = zmls.mls_message.MLSMessage{
                .version = .mls10,
                .wire_format = .mls_group_info,
                .body = .{
                    .group_info = gi_buf[0..gi_end],
                },
            };

            var wire_buf: [max_gi_encode]u8 = undefined;
            const wire_end = mls_msg.encode(
                &wire_buf,
                0,
            ) catch return error.EncodingFailed;

            return allocator.dupe(
                u8,
                wire_buf[0..wire_end],
            );
        }

        /// Encode a ratchet tree as TLS-serialized bytes.
        fn encodeRatchetTree(
            allocator: Allocator,
            tree: *const zmls.RatchetTree,
        ) error{
            EncodingFailed,
            OutOfMemory,
        }![]u8 {
            const full_width = tree.nodeCount();
            var trim_width: u32 = full_width;
            while (trim_width > 0 and
                tree.nodes[trim_width - 1] == null)
            {
                trim_width -= 1;
            }

            // Encode the payload into a large temp buffer.
            var tmp: [max_gi_encode]u8 = undefined;
            var pos: u32 = 0;
            var ni: u32 = 0;
            while (ni < trim_width) : (ni += 1) {
                if (tree.nodes[ni]) |*n| {
                    pos = zmls.codec.encodeUint8(
                        &tmp,
                        pos,
                        1,
                    ) catch return error.EncodingFailed;
                    pos = n.encode(
                        &tmp,
                        pos,
                    ) catch return error.EncodingFailed;
                } else {
                    pos = zmls.codec.encodeUint8(
                        &tmp,
                        pos,
                        0,
                    ) catch return error.EncodingFailed;
                }
            }

            const payload_size: u32 = pos;
            const hdr_size = zmls.varint.encodedLength(
                payload_size,
            );
            const total = hdr_size + payload_size;
            const out = try allocator.alloc(u8, total);
            errdefer allocator.free(out);

            const hdr_end = zmls.varint.encode(
                out,
                0,
                payload_size,
            ) catch return error.EncodingFailed;

            @memcpy(out[hdr_end..total], tmp[0..payload_size]);

            return out;
        }

        // ── Wire encoding ─────────────────────────────

        const PublicMsg =
            zmls.public_msg.PublicMessage(P);
        const Auth =
            zmls.framing_auth.FramedContentAuthData(P);

        /// Maximum buffer for PublicMessage + MLSMessage.
        const max_wire_encode: u32 = 1 << 17;
        const max_group_context_encode: u32 =
            zmls.group_context.max_gc_encode;

        /// Encode a commit output as an MLSMessage wire
        /// message (PublicMessage format). Pure computation.
        ///
        /// Needs the pre-commit group state for the
        /// membership key and group context serialization.
        fn encodeCommitAsWireMessage(
            allocator: Allocator,
            pre_commit_state: *const GS,
            commit_output: *const GS.CommitOutput,
        ) error{
            EncodingFailed,
            OutOfMemory,
        }![]u8 {
            const framed_content = buildCommitFramedContent(
                pre_commit_state,
                commit_output,
            );
            const auth = buildCommitAuth(commit_output);

            const membership_tag = computeCommitMembershipTag(
                pre_commit_state,
                &framed_content,
                &auth,
            ) catch return error.EncodingFailed;

            return encodePublicMlsMessage(
                allocator,
                &framed_content,
                &auth,
                &membership_tag,
            );
        }

        fn buildCommitFramedContent(
            pre_commit_state: *const GS,
            commit_output: *const GS.CommitOutput,
        ) zmls.FramedContent {
            return .{
                .group_id = pre_commit_state.groupId(),
                .epoch = pre_commit_state.epoch(),
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = @intFromEnum(
                        pre_commit_state.my_leaf_index,
                    ),
                },
                .authenticated_data = "",
                .content_type = .commit,
                .content = commit_output
                    .commit_bytes[0..commit_output
                    .commit_len],
            };
        }

        fn buildCommitAuth(
            commit_output: *const GS.CommitOutput,
        ) Auth {
            return .{
                .signature = commit_output.signature,
                .confirmation_tag = commit_output
                    .confirmation_tag,
            };
        }

        fn computeCommitMembershipTag(
            pre_commit_state: *const GS,
            framed_content: *const zmls.FramedContent,
            auth: *const Auth,
        ) ![P.nh]u8 {
            var context_buffer: [
                max_group_context_encode
            ]u8 = undefined;
            const context_bytes =
                try pre_commit_state.serializeContext(
                    &context_buffer,
                );

            return zmls.public_msg.computeMembershipTag(
                P,
                &pre_commit_state.epoch_secrets
                    .membership_key,
                framed_content,
                auth,
                context_bytes,
            );
        }

        fn encodePublicMlsMessage(
            allocator: Allocator,
            framed_content: *const zmls.FramedContent,
            auth: *const Auth,
            membership_tag: *const [P.nh]u8,
        ) error{
            EncodingFailed,
            OutOfMemory,
        }![]u8 {
            const public_message = PublicMsg{
                .content = framed_content.*,
                .auth = auth.*,
                .membership_tag = membership_tag.*,
            };

            var pub_buffer: [max_wire_encode]u8 = undefined;
            const pub_end = public_message.encode(
                &pub_buffer,
                0,
            ) catch return error.EncodingFailed;

            const mls_message =
                zmls.mls_message.MLSMessage{
                    .version = .mls10,
                    .wire_format = .mls_public_message,
                    .body = .{
                        .public_message = pub_buffer[0..pub_end],
                    },
                };

            var wire_buffer: [max_wire_encode]u8 = undefined;
            const wire_end = mls_message.encode(
                &wire_buffer,
                0,
            ) catch return error.EncodingFailed;

            return allocator.dupe(
                u8,
                wire_buffer[0..wire_end],
            );
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
