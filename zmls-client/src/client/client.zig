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
        const PendingMap = pending_mod.PendingKeyPackageMap(
            P,
            max_pending_kps,
        );

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
        // Internal: load / persist GroupState
        // ────────────────────────────────────────────────

        /// Load and deserialize a GroupState from the store.
        fn loadGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
        ) Error!GS {
            const blob = (try self.group_store.load(
                self.allocator,
                io,
                group_id,
            )) orelse return error.GroupNotFound;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            return Ser.deserialize(
                self.allocator,
                blob,
            ) catch return error.SerializationFailed;
        }

        /// Serialize and persist a GroupState to the store.
        fn persistGroup(
            self: *Self,
            io: Io,
            group_id: []const u8,
            gs: *const GS,
        ) Error!void {
            const blob = Ser.serialize(
                self.allocator,
                gs,
            ) catch return error.SerializationFailed;
            defer {
                secureZeroSlice(blob);
                self.allocator.free(blob);
            }
            try self.group_store.save(io, group_id, blob);
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

            try self.persistGroup(io, group_id, &gs);

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

            // Persist the new group state.
            try self.persistGroup(
                io,
                group_id,
                &co.group_state,
            );

            return .{
                .commit = commit_data,
                .welcome = welcome_data,
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
