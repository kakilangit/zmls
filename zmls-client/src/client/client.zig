//! Client(P) — High-level MLS client.
//!
//! Wraps `GroupState(P)` from the zmls protocol core with
//! persistent storage, key management, and transport. The
//! `CryptoProvider` parameter `P` flows through from zmls.
//!
//! `Io` is NOT stored — passed by value to every method.

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

pub const WireFormatPolicy = client_types.WireFormatPolicy;
pub const InviteResult = client_types.InviteResult;
pub const JoinGroupResult = client_types.JoinGroupResult;
pub const ReceivedMessage = client_types.ReceivedMessage;

/// Maximum pending KeyPackages a Client can hold.
const max_pending_kps: u32 = 64;

fn secureZeroSlice(buf: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buf));
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
        const PendingMap = pending_mod.PendingKeyPackageMap(
            P,
            max_pending_kps,
        );

        /// A GroupState paired with its SecretTree.
        const GroupBundle = struct {
            gs: GS,
            st: ST,

            fn deinit(self: *GroupBundle, allocator: Allocator) void {
                self.gs.deinit();
                self.st.deinit(allocator);
                self.* = undefined;
            }
        };

        // ── Identity (immutable after init) ────────────
        identity: []const u8,
        cipher_suite: zmls.CipherSuite,
        sign_sk: [P.sign_sk_len]u8,
        sign_pk: [P.sign_pk_len]u8,

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

        pub const Error = error{
            ClientClosed,
            GroupNotFound,
            SerializationFailed,
            KeyGenerationFailed,
            CapacityExhausted,
            NoPendingKeyPackage,
            WelcomeProcessingFailed,
        } || GroupStore.Error || KS.Error || Allocator.Error;

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
        ) error{ KeyGenerationFailed, OutOfMemory }!Self {
            // Derive signing key pair.
            const kp = P.signKeypairFromSeed(
                signature_seed,
            ) catch return error.KeyGenerationFailed;

            // Clone identity (allocator-owned).
            const owned_id = try allocator.dupe(
                u8,
                identity,
            );

            return .{
                .identity = owned_id,
                .cipher_suite = cipher_suite,
                .sign_sk = kp.sk,
                .sign_pk = kp.pk,
                .group_store = options.group_store,
                .key_store = options.key_store,
                .credential_validator = options.credential_validator,
                .transport = options.transport,
                .padding_block = options.padding_block,
                .wire_format_policy = options.wire_format_policy,
                .pending_key_packages = PendingMap.init(),
                .allocator = allocator,
                .closed = false,
            };
        }

        pub fn deinit(self: *Self) void {
            // secureZero signing keys.
            secureZeroSlice(&self.sign_sk);
            secureZeroSlice(&self.sign_pk);

            // secureZero all pending KP secrets.
            self.pending_key_packages.deinit();

            // Free identity.
            self.allocator.free(self.identity);
            self.identity = &.{};

            self.closed = true;
        }

        // ────────────────────────────────────────────────
        // Internal: load / persist GroupState + SecretTree
        // ────────────────────────────────────────────────

        /// Load and deserialize a GroupBundle (GroupState +
        /// SecretTree) from the store.
        fn loadBundle(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) Error!GroupBundle {
            const blob = (try self.group_store.load(
                self.allocator,
                io,
                group_id,
            )) orelse return error.GroupNotFound;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            return deserializeBundle(
                self.allocator,
                blob,
            ) catch return error.SerializationFailed;
        }

        /// Load only the GroupState (legacy compat, used by
        /// tests and methods that don't need SecretTree).
        fn loadGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) Error!GS {
            var bundle = try self.loadBundle(io, group_id);
            bundle.st.deinit(self.allocator);
            return bundle.gs;
        }

        /// Serialize and persist a GroupBundle.
        fn persistBundle(
            self: *Self,
            io: Io,
            group_id: []const u8,
            gs: *const GS,
            st: *const ST,
        ) Error!void {
            const blob = serializeBundle(
                self.allocator,
                gs,
                st,
            ) catch return error.SerializationFailed;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            try self.group_store.save(io, group_id, blob);
        }

        /// Serialize GroupState + SecretTree into a single
        /// blob.
        ///
        /// Format:
        ///   [4 bytes: GS blob length, big-endian u32]
        ///   [GS blob]
        ///   [SecretTree blob]
        fn serializeBundle(
            allocator: Allocator,
            gs: *const GS,
            st: *const ST,
        ) error{ OutOfMemory, SerializationFailed }![]u8 {
            const gs_data = Ser.serialize(
                allocator,
                gs,
            ) catch return error.SerializationFailed;
            defer {
                secureZeroSlice(gs_data);
                allocator.free(gs_data);
            }

            const st_data = st.serialize(
                allocator,
            ) catch return error.OutOfMemory;
            defer {
                secureZeroSlice(st_data);
                allocator.free(st_data);
            }

            if (gs_data.len > std.math.maxInt(u32))
                return error.SerializationFailed;

            const total = 4 + gs_data.len + st_data.len;
            const buf = allocator.alloc(
                u8,
                total,
            ) catch return error.OutOfMemory;
            errdefer allocator.free(buf);

            std.mem.writeInt(
                u32,
                buf[0..4],
                @intCast(gs_data.len),
                .big,
            );
            @memcpy(buf[4..][0..gs_data.len], gs_data);
            @memcpy(
                buf[4 + gs_data.len ..][0..st_data.len],
                st_data,
            );

            return buf;
        }

        /// Deserialize a GroupBundle from bytes produced by
        /// `serializeBundle`.
        fn deserializeBundle(
            allocator: Allocator,
            data: []const u8,
        ) error{
            OutOfMemory,
            SerializationFailed,
        }!GroupBundle {
            if (data.len < 4)
                return error.SerializationFailed;

            const gs_len = std.mem.readInt(
                u32,
                data[0..4],
                .big,
            );
            if (4 + @as(u64, gs_len) > data.len)
                return error.SerializationFailed;

            var gs = Ser.deserialize(
                allocator,
                data[4..][0..gs_len],
            ) catch return error.SerializationFailed;
            errdefer gs.deinit();

            const st_data = data[4 + gs_len ..];
            var st = ST.deserialize(
                allocator,
                st_data,
            ) catch return error.SerializationFailed;
            errdefer st.deinit(allocator);

            return .{ .gs = gs, .st = st };
        }

        /// Create a fresh SecretTree from a GroupState's
        /// encryption_secret.
        fn initSecretTree(
            allocator: Allocator,
            gs: *const GS,
        ) Error!ST {
            return ST.init(
                allocator,
                &gs.epoch_secrets.encryption_secret,
                gs.leafCount(),
            ) catch return error.SerializationFailed;
        }

        // ────────────────────────────────────────────────
        // Group creation
        // ────────────────────────────────────────────────

        /// Create a new 1-member group with a random group ID.
        /// Returns the group ID (owned by caller).
        pub fn createGroup(
            self: *Self,
            io: Io,
        ) Error![]u8 {
            if (self.closed) return error.ClientClosed;

            // Generate random group_id.
            var gid_buf: [32]u8 = undefined;
            io.randomSecure(&gid_buf) catch
                return error.KeyGenerationFailed;

            try self.createGroupWithId(io, &gid_buf, &.{});

            const result = try self.allocator.dupe(
                u8,
                &gid_buf,
            );
            return result;
        }

        /// Create a group with a specific ID and extensions.
        pub fn createGroupWithId(
            self: *Self,
            io: Io,
            group_id: []const u8,
            extensions: []const zmls.Extension,
        ) Error!void {
            if (self.closed) return error.ClientClosed;

            // Generate encryption keypair for the leaf.
            var enc_seed: [32]u8 = undefined;
            io.randomSecure(&enc_seed) catch
                return error.KeyGenerationFailed;
            const enc_kp = P.dhKeypairFromSeed(
                &enc_seed,
            ) catch return error.KeyGenerationFailed;
            secureZeroSlice(&enc_seed);

            const leaf = zmls.LeafNode{
                .encryption_key = &enc_kp.pk,
                .signature_key = &self.sign_pk,
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

            var gs = zmls.createGroup(
                P,
                self.allocator,
                group_id,
                leaf,
                self.cipher_suite,
                extensions,
            ) catch return error.SerializationFailed;
            defer gs.deinit();

            var st = try initSecretTree(self.allocator, &gs);
            defer st.deinit(self.allocator);

            try self.persistBundle(io, group_id, &gs, &st);

            // Store encryption secret key.
            try self.key_store.storeEncryptionKey(
                io,
                group_id,
                0,
                &enc_kp.sk,
            );
        }

        // ────────────────────────────────────────────────
        // KeyPackage generation
        // ────────────────────────────────────────────────

        /// Maximum encoded KeyPackage size (same as core lib).
        const max_kp_encode: u32 = 65536;

        /// Result of freshKeyPackage: TLS-encoded bytes
        /// and the reference hash for tracking.
        pub const FreshKeyPackageResult = struct {
            /// TLS-encoded KeyPackage bytes (caller-owned).
            data: []u8,
            /// Reference hash for matching against Welcomes.
            ref_hash: [P.nh]u8,
        };

        /// Generate a fresh KeyPackage, store private keys
        /// in the pending map, and return the TLS-encoded
        /// KeyPackage bytes.
        ///
        /// The KeyPackage is ready to be uploaded to a
        /// KeyPackage directory for other clients to fetch.
        pub fn freshKeyPackage(
            self: *Self,
            allocator: Allocator,
            io: Io,
        ) Error!FreshKeyPackageResult {
            if (self.closed) return error.ClientClosed;

            // Caller owns storage; buildKeyPackage writes
            // in-place so slice fields stay valid.
            var ctx: KpContext = undefined;
            try self.buildKeyPackage(io, &ctx);
            defer secureZeroSlice(&ctx.init_kp.sk);
            defer secureZeroSlice(&ctx.enc_kp.sk);
            defer secureZeroSlice(&ctx.sig_buf);
            defer secureZeroSlice(&ctx.leaf_sig_buf);

            return self.encodeAndStore(allocator, &ctx);
        }

        /// Intermediate state for KP construction.
        const KpContext = struct {
            kp: KeyPackage,
            init_kp: DhKeypair,
            enc_kp: DhKeypair,
            init_pk: [P.npk]u8,
            enc_pk: [P.npk]u8,
            sig_buf: [P.sig_len]u8,
            leaf_sig_buf: [P.sig_len]u8,
        };

        const DhKeypair = struct {
            sk: [P.nsk]u8,
            pk: [P.npk]u8,
        };

        /// Build and sign a KeyPackage in-place via
        /// out-pointer. Slice fields in `ctx.kp` point
        /// directly into `ctx`'s backing arrays, so no
        /// fixup is needed after the call.
        fn buildKeyPackage(
            self: *Self,
            io: Io,
            ctx: *KpContext,
        ) Error!void {
            // Generate init + encryption key pairs.
            var init_seed: [32]u8 = undefined;
            var enc_seed: [32]u8 = undefined;
            io.randomSecure(&init_seed) catch
                return error.KeyGenerationFailed;
            io.randomSecure(&enc_seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&init_seed);
            defer secureZeroSlice(&enc_seed);

            const init_kp = toDhKeypair(
                P.dhKeypairFromSeed(&init_seed) catch
                    return error.KeyGenerationFailed,
            );
            const enc_kp = toDhKeypair(
                P.dhKeypairFromSeed(&enc_seed) catch
                    return error.KeyGenerationFailed,
            );

            ctx.init_kp = init_kp;
            ctx.enc_kp = enc_kp;
            ctx.init_pk = init_kp.pk;
            ctx.enc_pk = enc_kp.pk;

            // Slices point into ctx's own backing arrays.
            ctx.kp = .{
                .version = .mls10,
                .cipher_suite = self.cipher_suite,
                .init_key = &ctx.init_pk,
                .leaf_node = .{
                    .encryption_key = &ctx.enc_pk,
                    .signature_key = &self.sign_pk,
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

            // Sign LeafNode (source=key_package: no gid/leaf).
            ctx.kp.leaf_node.signLeafNode(
                P,
                &self.sign_sk,
                &ctx.leaf_sig_buf,
                null,
                null,
            ) catch return error.KeyGenerationFailed;

            // Sign KeyPackage.
            ctx.kp.signKeyPackage(
                P,
                &self.sign_sk,
                &ctx.sig_buf,
            ) catch return error.KeyGenerationFailed;
        }

        fn encodeAndStore(
            self: *Self,
            allocator: Allocator,
            ctx: *KpContext,
        ) Error!FreshKeyPackageResult {
            // Compute reference hash.
            const ref = ctx.kp.makeRef(
                P,
            ) catch return error.KeyGenerationFailed;

            // TLS-encode the KeyPackage.
            var buf: [max_kp_encode]u8 = undefined;
            const end = ctx.kp.encode(
                &buf,
                0,
            ) catch return error.SerializationFailed;

            const data = try allocator.dupe(u8, buf[0..end]);
            errdefer allocator.free(data);

            // Store private keys in pending map.
            try self.pending_key_packages.insert(
                &ref,
                .{
                    .init_sk = ctx.init_kp.sk,
                    .init_pk = ctx.init_kp.pk,
                    .enc_sk = ctx.enc_kp.sk,
                    .sign_sk = self.sign_sk,
                },
            );

            return .{ .data = data, .ref_hash = ref };
        }

        // ────────────────────────────────────────────────
        // Membership operations
        // ────────────────────────────────────────────────

        /// Maximum Welcome encoding buffer size.
        const max_welcome_buf: u32 = 1 << 17;
        /// Maximum GroupContext encoding buffer size.
        const max_gc_buf: u32 = 8192;

        /// Invite a member by their KeyPackage bytes.
        ///
        /// Creates an Add proposal, commits it, and builds
        /// a Welcome for the new member. Returns both the
        /// commit and welcome as TLS-encoded bytes.
        pub fn inviteMember(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            kp_bytes: []const u8,
        ) Error!InviteResult {
            if (self.closed) return error.ClientClosed;

            // Decode the joiner's KeyPackage.
            const kp_dec = KeyPackage.decode(
                allocator,
                kp_bytes,
                0,
            ) catch return error.SerializationFailed;
            var kp = kp_dec.value;
            defer kp.deinit(allocator);

            // Load current group state.
            var gs = try self.loadGroup(io, group_id);
            defer gs.deinit();

            // Build Add proposal and commit.
            const add_prop = zmls.Proposal{
                .tag = .add,
                .payload = .{ .add = .{
                    .key_package = kp,
                } },
            };
            const props = [_]zmls.Proposal{add_prop};

            var co = gs.commit(
                allocator,
                .{
                    .proposals = &props,
                    .sign_key = &self.sign_sk,
                },
            ) catch return error.SerializationFailed;
            defer co.deinit();

            return self.buildInviteResult(
                allocator,
                io,
                group_id,
                &kp,
                &co,
            );
        }

        /// Build the InviteResult from a CommitOutput.
        fn buildInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            kp: *const KeyPackage,
            co: *GS.CommitOutput,
        ) Error!InviteResult {
            // Serialize GroupContext for buildWelcome.
            var gc_buf: [max_gc_buf]u8 = undefined;
            const gc_end = co.group_state.group_context
                .encode(&gc_buf, 0) catch
                return error.SerializationFailed;

            // Compute KP ref and generate ephemeral seed.
            const kp_ref = kp.makeRef(
                P,
            ) catch return error.KeyGenerationFailed;
            var eph_seed: [32]u8 = undefined;
            io.randomSecure(&eph_seed) catch
                return error.KeyGenerationFailed;
            defer secureZeroSlice(&eph_seed);

            const members = [_]zmls.group_welcome
                .NewMemberEntry{.{
                .kp_ref = &kp_ref,
                .init_pk = kp.init_key,
                .eph_seed = &eph_seed,
            }};

            var wr = co.group_state.buildWelcome(
                allocator,
                .{
                    .gc_bytes = gc_buf[0..gc_end],
                    .confirmation_tag = &co.confirmation_tag,
                    .welcome_secret = &co.welcome_secret,
                    .joiner_secret = &co.joiner_secret,
                    .sign_key = &self.sign_sk,
                    .signer = @intFromEnum(
                        co.group_state.my_leaf_index,
                    ),
                    .cipher_suite = self.cipher_suite,
                    .new_members = &members,
                },
            ) catch return error.SerializationFailed;
            defer wr.deinit(allocator);

            return self.encodeInviteResult(
                allocator,
                io,
                group_id,
                co,
                &wr,
            );
        }

        /// Encode commit + welcome to bytes, persist state.
        fn encodeInviteResult(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            co: *GS.CommitOutput,
            wr: *const zmls.group_welcome.WelcomeResult,
        ) Error!InviteResult {
            const commit_data = try allocator.dupe(
                u8,
                co.commit_bytes[0..co.commit_len],
            );
            errdefer allocator.free(commit_data);

            // Encode Welcome to TLS bytes.
            var w_buf: [max_welcome_buf]u8 = undefined;
            const w_end = wr.welcome.encode(
                &w_buf,
                0,
            ) catch return error.SerializationFailed;

            const welcome_data = try allocator.dupe(
                u8,
                w_buf[0..w_end],
            );
            errdefer allocator.free(welcome_data);

            // Persist the new group state with fresh SecretTree.
            var st = try initSecretTree(
                allocator,
                &co.group_state,
            );
            defer st.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &co.group_state,
                &st,
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
            /// Ratchet tree from the inviter (out-of-band).
            ratchet_tree: zmls.RatchetTree,
            /// Inviter's signature verification key.
            signer_verify_key: *const [P.sign_pk_len]u8,
            /// This joiner's leaf index in the new tree.
            my_leaf_index: zmls.LeafIndex,
        };

        /// Join a group via a Welcome message.
        ///
        /// Decodes the Welcome, matches against pending
        /// KeyPackages, calls processWelcome, persists
        /// the resulting GroupState, and consumes the
        /// pending KP entry. Returns the group ID.
        pub fn joinGroup(
            self: *Self,
            allocator: Allocator,
            io: Io,
            welcome_bytes: []const u8,
            opts: JoinGroupOpts,
        ) Error!JoinGroupResult {
            if (self.closed) return error.ClientClosed;

            // Decode the Welcome.
            const w_dec = zmls.Welcome.decode(
                allocator,
                welcome_bytes,
                0,
            ) catch return error.SerializationFailed;
            var welcome = w_dec.value;
            defer welcome.deinit(allocator);

            // Match against pending KPs.
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

        /// Find a pending KP that matches a Welcome secret.
        fn findPendingMatch(
            self: *const Self,
            welcome: *const zmls.Welcome,
        ) ?PendingMatch {
            for (welcome.secrets) |s| {
                if (s.new_member.len != P.nh) continue;
                const ref: *const [P.nh]u8 =
                    s.new_member[0..P.nh];
                const keys = self.pending_key_packages
                    .find(ref);
                if (keys != null) {
                    return .{
                        .ref = ref.*,
                        .keys = keys.?,
                    };
                }
            }
            return null;
        }

        /// Process Welcome and persist the new GroupState.
        fn processAndPersistWelcome(
            self: *Self,
            allocator: Allocator,
            io: Io,
            welcome: *const zmls.Welcome,
            match: PendingMatch,
            opts: JoinGroupOpts,
        ) Error!JoinGroupResult {
            var gs = GS.joinViaWelcome(
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
            defer gs.deinit();

            const gid = gs.groupId();
            const owned_gid = try allocator.dupe(
                u8,
                gid,
            );
            errdefer allocator.free(owned_gid);

            var st = try initSecretTree(allocator, &gs);
            defer st.deinit(allocator);

            try self.persistBundle(io, gid, &gs, &st);
            _ = self.pending_key_packages.remove(
                &match.ref,
            );

            return .{
                .group_id = owned_gid,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Remove / Leave / Self-update
        // ────────────────────────────────────────────────

        /// Remove a member by leaf index.
        ///
        /// Creates a Remove proposal, commits, persists the
        /// new state, and returns the commit bytes.
        pub fn removeMember(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            target_leaf: u32,
        ) Error![]u8 {
            if (self.closed) return error.ClientClosed;

            var gs = try self.loadGroup(io, group_id);
            defer gs.deinit();

            const remove_prop = zmls.Proposal{
                .tag = .remove,
                .payload = .{ .remove = .{
                    .removed = target_leaf,
                } },
            };
            const props = [_]zmls.Proposal{remove_prop};

            var co = gs.commit(
                allocator,
                .{
                    .proposals = &props,
                    .sign_key = &self.sign_sk,
                },
            ) catch return error.SerializationFailed;
            defer co.deinit();

            const commit_data = try allocator.dupe(
                u8,
                co.commit_bytes[0..co.commit_len],
            );
            errdefer allocator.free(commit_data);

            var st = try initSecretTree(
                allocator,
                &co.group_state,
            );
            defer st.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &co.group_state,
                &st,
            );

            return commit_data;
        }

        /// Leave the group (delete local state).
        ///
        /// Deletes the group state from the store. The actual
        /// protocol-level removal (Remove proposal + commit)
        /// is another member's responsibility.
        pub fn leaveGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) Error!void {
            if (self.closed) return error.ClientClosed;
            try self.group_store.delete(io, group_id);
        }

        /// Self-update: empty commit with path (key rotation).
        ///
        /// Commits with no proposals (empty commit), which
        /// updates the committer's key material. Persists the
        /// new state and returns the commit bytes.
        pub fn selfUpdate(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) Error![]u8 {
            if (self.closed) return error.ClientClosed;

            var gs = try self.loadGroup(io, group_id);
            defer gs.deinit();

            var co = gs.commit(
                allocator,
                .{
                    .proposals = &.{},
                    .sign_key = &self.sign_sk,
                },
            ) catch return error.SerializationFailed;
            defer co.deinit();

            const commit_data = try allocator.dupe(
                u8,
                co.commit_bytes[0..co.commit_len],
            );
            errdefer allocator.free(commit_data);

            var st = try initSecretTree(
                allocator,
                &co.group_state,
            );
            defer st.deinit(allocator);

            try self.persistBundle(
                io,
                group_id,
                &co.group_state,
                &st,
            );

            return commit_data;
        }

        // ────────────────────────────────────────────────
        // Messaging
        // ────────────────────────────────────────────────

        /// Maximum wire message buffer size.
        const max_wire_buf: u32 = 1 << 17;
        /// Maximum GroupContext encode buffer.
        const max_gc_enc: u32 = zmls.group_context.max_gc_encode;
        /// Private content AAD buffer size.
        const max_aad_buf: u32 = 8192;
        /// SenderData encoded size (leaf_index + gen + guard).
        const sd_enc_size: u32 = zmls.private_msg
            .SenderData.encoded_size;
        /// FramedContentAuthData type alias.
        const Auth = zmls.framing_auth.FramedContentAuthData(P);

        /// Encrypt and send an application message.
        ///
        /// Loads the group bundle, consumes a key from the
        /// SecretTree, encrypts content as a PrivateMessage,
        /// persists the updated SecretTree, and returns the
        /// MLSMessage wire bytes.
        pub fn sendMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            plaintext: []const u8,
        ) Error![]u8 {
            if (self.closed) return error.ClientClosed;

            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);

            const wire = try self.encryptAppMessage(
                allocator,
                io,
                &bundle,
                plaintext,
                "",
            );
            errdefer allocator.free(wire);

            // Persist updated SecretTree (key consumed).
            try self.persistBundle(
                io,
                group_id,
                &bundle.gs,
                &bundle.st,
            );

            return wire;
        }

        /// Decrypt a received application message.
        ///
        /// Loads the group bundle, decrypts the PrivateMessage,
        /// verifies the signature, persists the updated
        /// SecretTree, and returns the plaintext.
        pub fn receiveMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            ciphertext: []const u8,
        ) Error!ReceivedMessage {
            if (self.closed) return error.ClientClosed;

            var bundle = try self.loadBundle(io, group_id);
            defer bundle.deinit(self.allocator);

            const result = try self.decryptAppMessage(
                allocator,
                &bundle,
                ciphertext,
            );
            errdefer {
                var rm = result;
                rm.deinit();
            }

            // Persist updated SecretTree (key consumed).
            try self.persistBundle(
                io,
                group_id,
                &bundle.gs,
                &bundle.st,
            );

            return result;
        }

        /// Build a PrivateMessage from plaintext. Mutates
        /// `bundle.st` (consumes a key). Returns MLSMessage
        /// wire bytes (caller-owned).
        fn encryptAppMessage(
            self: *Self,
            allocator: Allocator,
            io: Io,
            bundle: *GroupBundle,
            plaintext: []const u8,
            aad_data: []const u8,
        ) Error![]u8 {
            const gs = &bundle.gs;
            const gid = gs.groupId();

            // 1. Sign FramedContent.
            var gc_buf: [max_gc_enc]u8 = undefined;
            const gc_bytes = gs.serializeContext(
                &gc_buf,
            ) catch return error.SerializationFailed;

            const fc = zmls.FramedContent{
                .group_id = gid,
                .epoch = gs.epoch(),
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = @intFromEnum(
                        gs.my_leaf_index,
                    ),
                },
                .authenticated_data = aad_data,
                .content_type = .application,
                .content = plaintext,
            };

            const auth = zmls.signFramedContent(
                P,
                &fc,
                .mls_private_message,
                gc_bytes,
                &self.sign_sk,
                null,
                null,
            ) catch return error.SerializationFailed;

            // 2. Consume encryption key from SecretTree.
            const leaf_u32 = @intFromEnum(gs.my_leaf_index);
            var kn = bundle.st.consumeKey(
                leaf_u32,
                1, // application
            ) catch return error.SerializationFailed;
            defer kn.zeroize();

            // 3. Generate reuse guard.
            var reuse_guard: [4]u8 = undefined;
            io.randomSecure(&reuse_guard) catch
                return error.KeyGenerationFailed;
            zmls.private_msg.applyReuseGuard(
                P,
                &kn.nonce,
                &reuse_guard,
            );

            // 4. Build content AAD.
            var c_aad_buf: [max_aad_buf]u8 = undefined;
            const c_aad_len = zmls.private_msg
                .buildPrivateContentAad(
                &c_aad_buf,
                gid,
                gs.epoch(),
                .application,
                aad_data,
            ) catch return error.SerializationFailed;

            // 5. Encrypt content.
            var ct_buf: [max_wire_buf]u8 = undefined;
            const ct_len = zmls.encryptContent(
                P,
                plaintext,
                .application,
                &auth,
                self.padding_block,
                &kn.key,
                &kn.nonce,
                c_aad_buf[0..c_aad_len],
                &ct_buf,
            ) catch return error.SerializationFailed;

            // 6. Build and encrypt SenderData.
            const sd = zmls.private_msg.SenderData{
                .leaf_index = leaf_u32,
                .generation = kn.generation,
                .reuse_guard = reuse_guard,
            };

            var sd_aad_buf: [max_aad_buf]u8 = undefined;
            const sd_aad_len = zmls.private_msg
                .buildSenderDataAad(
                &sd_aad_buf,
                gid,
                gs.epoch(),
                .application,
            ) catch return error.SerializationFailed;

            var enc_sd: [sd_enc_size]u8 = undefined;
            var sd_tag: [P.nt]u8 = undefined;

            // Ciphertext sample = first min(nh, ct_len) bytes.
            const sample_len = @min(P.nh, ct_len);
            zmls.private_msg.encryptSenderData(
                P,
                &sd,
                &gs.epoch_secrets.sender_data_secret,
                ct_buf[0..sample_len],
                sd_aad_buf[0..sd_aad_len],
                &enc_sd,
                &sd_tag,
            );

            // 7. Combine encrypted_sender_data = ct + tag.
            var full_enc_sd: [sd_enc_size + P.nt]u8 = undefined;
            @memcpy(
                full_enc_sd[0..sd_enc_size],
                &enc_sd,
            );
            @memcpy(
                full_enc_sd[sd_enc_size..],
                &sd_tag,
            );

            // 8. Assemble PrivateMessage and encode.
            const pm = zmls.private_msg.PrivateMessage{
                .group_id = gid,
                .epoch = gs.epoch(),
                .content_type = .application,
                .authenticated_data = aad_data,
                .encrypted_sender_data = &full_enc_sd,
                .ciphertext = ct_buf[0..ct_len],
            };

            var wire_buf: [max_wire_buf]u8 = undefined;
            // MLSMessage header: version(u16) + wire_format(u16)
            const ver: u16 = @intFromEnum(
                zmls.ProtocolVersion.mls10,
            );
            const wf: u16 = @intFromEnum(
                zmls.types.WireFormat.mls_private_message,
            );
            std.mem.writeInt(u16, wire_buf[0..2], ver, .big);
            std.mem.writeInt(u16, wire_buf[2..4], wf, .big);
            const pm_end = pm.encode(
                &wire_buf,
                4,
            ) catch return error.SerializationFailed;

            return allocator.dupe(u8, wire_buf[0..pm_end]);
        }

        /// Decrypt a PrivateMessage. Mutates `bundle.st`
        /// (consumes/forward-ratchets a key). Returns
        /// `ReceivedMessage` with plaintext.
        fn decryptAppMessage(
            _: *Self,
            allocator: Allocator,
            bundle: *GroupBundle,
            wire_bytes: []const u8,
        ) Error!ReceivedMessage {
            const gs = &bundle.gs;
            const gid = gs.groupId();

            // 1. Decode MLSMessage header.
            const msg = zmls.mls_message.MLSMessage.decodeExact(
                wire_bytes,
            ) catch return error.SerializationFailed;

            const pm = switch (msg.body) {
                .private_message => |p| p,
                else => return error.SerializationFailed,
            };

            // 2. Verify epoch matches.
            if (pm.epoch != gs.epoch())
                return error.SerializationFailed;

            // 3. Decrypt SenderData.
            var sd_aad_buf: [max_aad_buf]u8 = undefined;
            const sd_aad_len = zmls.private_msg
                .buildSenderDataAad(
                &sd_aad_buf,
                gid,
                pm.epoch,
                pm.content_type,
            ) catch return error.SerializationFailed;

            const sample_len = @min(
                P.nh,
                @as(u32, @intCast(pm.ciphertext.len)),
            );
            const sd = zmls.private_msg.decryptSenderData(
                P,
                pm.encrypted_sender_data,
                &gs.epoch_secrets.sender_data_secret,
                pm.ciphertext[0..sample_len],
                sd_aad_buf[0..sd_aad_len],
            ) catch return error.SerializationFailed;

            // 4. Validate sender leaf index.
            zmls.validateSenderLeafIndex(
                sd,
                gs.leafCount(),
            ) catch return error.SerializationFailed;

            // 5. Get key from SecretTree (forward ratchet).
            var kn = bundle.st.forwardRatchet(
                sd.leaf_index,
                1, // application
                sd.generation,
            ) catch return error.SerializationFailed;
            defer kn.zeroize();

            // 6. Apply reuse guard.
            zmls.private_msg.applyReuseGuard(
                P,
                &kn.nonce,
                &sd.reuse_guard,
            );

            // 7. Decrypt content.
            var c_aad_buf: [max_aad_buf]u8 = undefined;
            const c_aad_len = zmls.private_msg
                .buildPrivateContentAad(
                &c_aad_buf,
                gid,
                pm.epoch,
                pm.content_type,
                pm.authenticated_data,
            ) catch return error.SerializationFailed;

            var pt_buf: [max_wire_buf]u8 = undefined;
            const decrypted = zmls.decryptContent(
                P,
                pm.ciphertext,
                pm.content_type,
                &kn.key,
                &kn.nonce,
                c_aad_buf[0..c_aad_len],
                &pt_buf,
            ) catch return error.SerializationFailed;

            // 8. Verify signature.
            var gc_buf: [max_gc_enc]u8 = undefined;
            const gc_bytes = gs.serializeContext(
                &gc_buf,
            ) catch return error.SerializationFailed;

            // Reconstruct FramedContent for verification.
            const fc = zmls.FramedContent{
                .group_id = gid,
                .epoch = pm.epoch,
                .sender = .{
                    .sender_type = .member,
                    .leaf_index = sd.leaf_index,
                },
                .authenticated_data = pm.authenticated_data,
                .content_type = pm.content_type,
                .content = decrypted.content,
            };

            // Get sender's verification key from the tree.
            const sender_leaf = gs.tree.getLeaf(
                zmls.LeafIndex.fromU32(sd.leaf_index),
            ) catch return error.SerializationFailed;
            const leaf_node = sender_leaf orelse
                return error.SerializationFailed;
            if (leaf_node.signature_key.len !=
                P.sign_pk_len)
                return error.SerializationFailed;

            zmls.verifyFramedContent(
                P,
                &fc,
                .mls_private_message,
                gc_bytes,
                leaf_node.signature_key[0..P.sign_pk_len],
                &decrypted.auth,
            ) catch return error.SerializationFailed;

            // 9. Return plaintext.
            const owned = try allocator.dupe(
                u8,
                decrypted.content,
            );
            return .{
                .sender_leaf = sd.leaf_index,
                .data = owned,
                .allocator = allocator,
            };
        }

        // ────────────────────────────────────────────────
        // Helpers
        // ────────────────────────────────────────────────

        fn toDhKeypair(raw: anytype) DhKeypair {
            return .{ .sk = raw.sk, .pk = raw.pk };
        }

        /// Default capabilities for KeyPackages. Lists only
        /// the mandatory/default values per RFC 9420 Section
        /// 7.2 — no non-default extensions or proposal types.
        fn defaultCapabilities() zmls.tree_node.Capabilities {
            return .{
                .versions = &default_versions,
                .cipher_suites = &default_suites,
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &default_cred_types,
            };
        }

        const default_versions = [_]zmls.ProtocolVersion{
            .mls10,
        };
        const default_suites = [_]zmls.CipherSuite{
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        };
        const default_cred_types = [_]zmls.types.CredentialType{
            .basic,
        };

        /// Default lifetime: 30 days from a fixed reference.
        /// Real applications should use actual timestamps.
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
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

// Use the real DefaultCryptoProvider for Client tests.
const TestP = zmls.DefaultCryptoProvider;
const MemGS = @import(
    "../adapters/memory_group_store.zig",
).MemoryGroupStore;
const MemKS = @import(
    "../adapters/memory_key_store.zig",
).MemoryKeyStore;

test "Client: init/deinit lifecycle" {
    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();

    const seed: [32]u8 = .{0x42} ** 32;
    var client = try Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = gs_store.groupStore(),
            .key_store = ks_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
    defer client.deinit();

    try testing.expect(!client.closed);
    try testing.expectEqualSlices(u8, "alice", client.identity);
}

fn makeTestClient(
    gs_store: *MemGS(8),
    ks_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x42} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = gs_store.groupStore(),
            .key_store = ks_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: freshKeyPackage returns decodable bytes" {
    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();

    var client = try makeTestClient(&gs_store, &ks_store);
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    // Must produce non-empty bytes.
    try testing.expect(result.data.len > 0);

    // Must be decodable as a KeyPackage.
    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var kp = decoded.value;
    defer kp.deinit(testing.allocator);

    // Verify it consumed all bytes.
    try testing.expectEqual(
        @as(u32, @intCast(result.data.len)),
        decoded.pos,
    );

    // Verify basic fields.
    try testing.expectEqual(
        zmls.ProtocolVersion.mls10,
        kp.version,
    );
    try testing.expectEqual(
        zmls.CipherSuite
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        kp.cipher_suite,
    );
    try testing.expectEqual(
        zmls.types.LeafNodeSource.key_package,
        kp.leaf_node.source,
    );

    // init_key and encryption_key must be present.
    try testing.expect(kp.init_key.len > 0);
    try testing.expect(kp.leaf_node.encryption_key.len > 0);

    // Signature must verify.
    try kp.verifySignature(TestP);

    // LeafNode signature must verify (key_package source).
    try kp.leaf_node.verifyLeafNodeSignature(
        TestP,
        null,
        null,
    );
}

test "Client: freshKeyPackage stores keys in pending map" {
    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();

    var client = try makeTestClient(&gs_store, &ks_store);
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    // Pending map should have exactly one entry.
    try testing.expectEqual(
        @as(u32, 1),
        client.pending_key_packages.count,
    );

    // Lookup by ref_hash should succeed.
    const found = client.pending_key_packages.find(
        &result.ref_hash,
    );
    try testing.expect(found != null);

    // The signing key should match the client's key.
    try testing.expectEqualSlices(
        u8,
        &client.sign_sk,
        &found.?.sign_sk,
    );
}

test "Client: freshKeyPackage ref_hash matches recomputed" {
    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();

    var client = try makeTestClient(&gs_store, &ks_store);
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    // Decode the KP and recompute the ref hash.
    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var kp = decoded.value;
    defer kp.deinit(testing.allocator);

    const recomputed = try kp.makeRef(TestP);
    try testing.expectEqualSlices(
        u8,
        &result.ref_hash,
        &recomputed,
    );
}

test "Client: multiple freshKeyPackages get distinct refs" {
    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();

    var client = try makeTestClient(&gs_store, &ks_store);
    defer client.deinit();

    const io = testIo();
    const r1 = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(r1.data);

    const r2 = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(r2.data);

    // Two KPs must have different ref hashes (different keys).
    try testing.expect(!std.mem.eql(
        u8,
        &r1.ref_hash,
        &r2.ref_hash,
    ));

    // Pending map should have two entries.
    try testing.expectEqual(
        @as(u32, 2),
        client.pending_key_packages.count,
    );
}

fn makeTestClientBob(
    gs_store: *MemGS(8),
    ks_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x99} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "bob",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = gs_store.groupStore(),
            .key_store = ks_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: inviteMember produces valid commit and welcome" {
    const io = testIo();

    // Alice: create a group.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Bob: generate a KeyPackage.
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    // Alice invites Bob.
    var result = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer result.deinit();

    // Commit and Welcome must be non-empty.
    try testing.expect(result.commit.len > 0);
    try testing.expect(result.welcome.len > 0);

    // Welcome bytes must be decodable.
    const w_dec = try zmls.Welcome.decode(
        testing.allocator,
        result.welcome,
        0,
    );
    var w = w_dec.value;
    defer w.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u32, @intCast(result.welcome.len)),
        w_dec.pos,
    );

    // Welcome should target exactly one recipient.
    try testing.expectEqual(
        @as(usize, 1),
        w.secrets.len,
    );
}

test "Client: inviteMember persists updated group state" {
    const io = testIo();

    // Alice: create a group.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Bob: generate a KeyPackage.
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    // Alice invites Bob.
    var result = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer result.deinit();

    // Reload Alice's group — epoch should have advanced.
    var gs = try alice.loadGroup(io, gid);
    defer gs.deinit();

    try testing.expectEqual(@as(u64, 1), gs.epoch());

    // Tree should now have 2 leaf slots (Alice + Bob).
    try testing.expectEqual(@as(u32, 2), gs.leafCount());
}

test "Client: joinGroup via Welcome succeeds" {
    const io = testIo();

    // Alice: create group.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Bob: generate a KeyPackage.
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    // Alice invites Bob.
    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    // Get Alice's tree for Bob (out-of-band).
    var a_state = try alice.loadGroup(io, gid);
    defer a_state.deinit();
    var tree_copy = try a_state.tree.clone();
    defer tree_copy.deinit();

    // Bob joins via Welcome.
    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice.sign_pk,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    // Group ID should match Alice's group.
    try testing.expectEqualSlices(u8, gid, join.group_id);

    // Bob's pending KP should be consumed.
    try testing.expectEqual(
        @as(u32, 0),
        bob.pending_key_packages.count,
    );
}

test "Client: joinGroup persists group state" {
    const io = testIo();

    // Alice: create group.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Bob: generate a KeyPackage.
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    // Alice invites Bob.
    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    // Get Alice's tree for Bob.
    var a_state = try alice.loadGroup(io, gid);
    defer a_state.deinit();
    var tree_copy = try a_state.tree.clone();
    defer tree_copy.deinit();

    // Bob joins.
    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice.sign_pk,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    // Bob can reload the group from his store.
    var b_state = try bob.loadGroup(io, join.group_id);
    defer b_state.deinit();

    // Both should be at epoch 1.
    try testing.expectEqual(@as(u64, 1), b_state.epoch());
    try testing.expectEqual(a_state.epoch(), b_state.epoch());

    // Both should see 2 members.
    try testing.expectEqual(@as(u32, 2), b_state.leafCount());
}

test "Client: joinGroup fails without pending KP" {
    const io = testIo();

    // Alice: create group and invite Bob.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Bob generates a KP (for Alice to use).
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    // Clear Bob's pending map to simulate lost state.
    bob.pending_key_packages.deinit();
    bob.pending_key_packages = @TypeOf(
        bob.pending_key_packages,
    ).init();

    var a_state = try alice.loadGroup(io, gid);
    defer a_state.deinit();
    var tree_copy = try a_state.tree.clone();
    defer tree_copy.deinit();

    // joinGroup should fail: no matching pending KP.
    const result = bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice.sign_pk,
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

    // Alice creates group, invites Bob.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    // Alice removes Bob (leaf index 1).
    const commit = try alice.removeMember(
        testing.allocator,
        io,
        gid,
        1,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    // Alice's state should advance to epoch 2.
    var gs = try alice.loadGroup(io, gid);
    defer gs.deinit();
    try testing.expectEqual(@as(u64, 2), gs.epoch());
}

test "Client: selfUpdate advances epoch" {
    const io = testIo();

    var gs_store = MemGS(8).init();
    defer gs_store.deinit();
    var ks_store = MemKS(TestP, 8).init();
    defer ks_store.deinit();
    var alice = try makeTestClient(&gs_store, &ks_store);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    // Self-update (empty commit with path).
    const commit = try alice.selfUpdate(
        testing.allocator,
        io,
        gid,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    // Epoch should advance from 0 to 1.
    var gs = try alice.loadGroup(io, gid);
    defer gs.deinit();
    try testing.expectEqual(@as(u64, 1), gs.epoch());
}

test "Client: leaveGroup deletes state from store" {
    const io = testIo();

    // Alice creates group, invites Bob, Bob joins.
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var alice = try makeTestClient(&a_gs, &a_ks);
    defer alice.deinit();

    const gid = try alice.createGroup(io);
    defer testing.allocator.free(gid);

    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var bob = try makeTestClientBob(&b_gs, &b_ks);
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    var a_state = try alice.loadGroup(io, gid);
    defer a_state.deinit();
    var tree_copy = try a_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice.sign_pk,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    // Bob leaves (deletes local state).
    try bob.leaveGroup(io, join.group_id);

    // Bob's group state should be gone from the store.
    const load_result = bob.loadGroup(io, join.group_id);
    try testing.expectError(error.GroupNotFound, load_result);
}

/// Helper: set up a two-member group (Alice + Bob) where
/// both have joined. Returns group_id, and callers must
/// defer-free it.
///
/// IMPORTANT: Stores are passed by pointer to avoid
/// interior-pointer invalidation on struct move (RULES.md
/// Section 0).
fn setupTwoMemberGroup(
    a_gs: *MemGS(8),
    a_ks: *MemKS(TestP, 8),
    b_gs: *MemGS(8),
    b_ks: *MemKS(TestP, 8),
    alice: *Client(TestP),
    bob: *Client(TestP),
) ![]u8 {
    const io = testIo();

    alice.* = try makeTestClient(a_gs, a_ks);
    bob.* = try makeTestClientBob(b_gs, b_ks);

    const gid = try alice.createGroup(io);
    errdefer testing.allocator.free(gid);

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        gid,
        bob_kp.data,
    );
    defer invite.deinit();

    var a_state = try alice.loadGroup(io, gid);
    defer a_state.deinit();
    var tree_copy = try a_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice.sign_pk,
            .my_leaf_index = zmls.LeafIndex.fromU32(1),
        },
    );
    defer join.deinit();

    return gid;
}

test "Client: sendMessage + receiveMessage round-trip" {
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const gid = try setupTwoMemberGroup(
        &a_gs,
        &a_ks,
        &b_gs,
        &b_ks,
        &alice,
        &bob,
    );
    defer testing.allocator.free(gid);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    // Alice sends a message.
    const ct = try alice.sendMessage(
        testing.allocator,
        io,
        gid,
        "hello bob",
    );
    defer testing.allocator.free(ct);

    try testing.expect(ct.len > 0);

    // Bob receives the message.
    var rm = try bob.receiveMessage(
        testing.allocator,
        io,
        gid,
        ct,
    );
    defer rm.deinit();

    try testing.expectEqualSlices(u8, "hello bob", rm.data);
    try testing.expectEqual(@as(u32, 0), rm.sender_leaf);
}

test "Client: multiple send/receive preserves ordering" {
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const gid = try setupTwoMemberGroup(
        &a_gs,
        &a_ks,
        &b_gs,
        &b_ks,
        &alice,
        &bob,
    );
    defer testing.allocator.free(gid);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    // Alice sends two messages.
    const ct1 = try alice.sendMessage(
        testing.allocator,
        io,
        gid,
        "message one",
    );
    defer testing.allocator.free(ct1);

    const ct2 = try alice.sendMessage(
        testing.allocator,
        io,
        gid,
        "message two",
    );
    defer testing.allocator.free(ct2);

    // Bob receives both in order.
    var rm1 = try bob.receiveMessage(
        testing.allocator,
        io,
        gid,
        ct1,
    );
    defer rm1.deinit();

    var rm2 = try bob.receiveMessage(
        testing.allocator,
        io,
        gid,
        ct2,
    );
    defer rm2.deinit();

    try testing.expectEqualSlices(
        u8,
        "message one",
        rm1.data,
    );
    try testing.expectEqualSlices(
        u8,
        "message two",
        rm2.data,
    );
}

test "Client: Bob sends, Alice receives" {
    var a_gs = MemGS(8).init();
    defer a_gs.deinit();
    var a_ks = MemKS(TestP, 8).init();
    defer a_ks.deinit();
    var b_gs = MemGS(8).init();
    defer b_gs.deinit();
    var b_ks = MemKS(TestP, 8).init();
    defer b_ks.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const gid = try setupTwoMemberGroup(
        &a_gs,
        &a_ks,
        &b_gs,
        &b_ks,
        &alice,
        &bob,
    );
    defer testing.allocator.free(gid);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    // Bob sends a message to Alice.
    const ct = try bob.sendMessage(
        testing.allocator,
        io,
        gid,
        "hello alice",
    );
    defer testing.allocator.free(ct);

    // Alice receives.
    var rm = try alice.receiveMessage(
        testing.allocator,
        io,
        gid,
        ct,
    );
    defer rm.deinit();

    try testing.expectEqualSlices(u8, "hello alice", rm.data);
    try testing.expectEqual(@as(u32, 1), rm.sender_leaf);
}
