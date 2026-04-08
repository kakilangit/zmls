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

            // Build creator LeafNode.
            // Generate encryption keypair for the leaf.
            var enc_seed: [32]u8 = undefined;
            io.randomSecure(&enc_seed) catch
                return error.KeyGenerationFailed;
            const enc_kp = P.dhKeypairFromSeed(
                &enc_seed,
            ) catch return error.KeyGenerationFailed;
            secureZeroSlice(&enc_seed);

            const cred = zmls.Credential{
                .credential_type = .basic,
                .data = self.identity,
            };

            const leaf = zmls.LeafNode{
                .encryption_key = &enc_kp.pk,
                .signature_key = &self.sign_pk,
                .credential = cred,
                .capabilities = .{},
                .source = .key_package,
                .lifetime = null,
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
            self.key_store.storeEncryptionKey(
                io,
                group_id,
                0,
                &enc_kp.sk,
            ) catch {};
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
