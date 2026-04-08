//! GroupBundle — GroupState + SecretTree paired for persistence.
//!
//! Pure serialization and deserialization. No I/O, no storage
//! access. The caller is responsible for loading and saving
//! the raw bytes via the GroupStore port.
//!
//! Wire format:
//!   [4 bytes: group_state length, big-endian u32]
//!   [group_state blob]
//!   [secret_tree blob]

const std = @import("std");
const Allocator = std.mem.Allocator;
const zmls = @import("zmls");

fn secureZeroSlice(buffer: []u8) void {
    std.crypto.secureZero(
        u8,
        @volatileCast(buffer),
    );
}

/// A GroupState paired with its SecretTree for a single epoch.
/// Both must advance together on every commit.
pub fn GroupBundle(comptime P: type) type {
    const GS = zmls.GroupState(P);
    const ST = zmls.SecretTree(P);
    const Ser = zmls.serializer.Serializer(P);

    return struct {
        group_state: GS,
        secret_tree: ST,

        const Self = @This();

        pub fn deinit(
            self: *Self,
            allocator: Allocator,
        ) void {
            self.group_state.deinit();
            self.secret_tree.deinit(allocator);
            self.* = undefined;
        }

        /// Create a fresh SecretTree from a GroupState's
        /// encryption_secret. Used after every epoch
        /// transition (create, join, commit).
        ///
        /// Takes ownership of `group_state`. On success the
        /// caller must not deinit the original GroupState --
        /// the bundle owns it. On failure the GroupState is
        /// NOT consumed; the caller retains ownership.
        pub fn initFromGroupState(
            allocator: Allocator,
            group_state: *GS,
        ) error{OutOfMemory}!Self {
            const secret_tree = ST.init(
                allocator,
                &group_state.epoch_secrets
                    .encryption_secret,
                group_state.leafCount(),
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };
            // Transfer ownership: move the value out and
            // poison the source so accidental deinit is
            // caught immediately.
            const owned = group_state.*;
            group_state.* = undefined;
            return .{
                .group_state = owned,
                .secret_tree = secret_tree,
            };
        }

        // ── Pure serialization ─────────────────────────

        pub const SerializeError = error{
            OutOfMemory,
            GroupStateTooLarge,
        };

        /// Serialize to a single blob. Pure computation.
        pub fn serialize(
            allocator: Allocator,
            group_state: *const GS,
            secret_tree: *const ST,
        ) SerializeError![]u8 {
            const gs_data = Ser.serialize(
                allocator,
                group_state,
            ) catch return error.OutOfMemory;
            defer {
                secureZeroSlice(gs_data);
                allocator.free(gs_data);
            }

            const st_data = secret_tree.serialize(
                allocator,
            ) catch return error.OutOfMemory;
            defer {
                secureZeroSlice(st_data);
                allocator.free(st_data);
            }

            if (gs_data.len > std.math.maxInt(u32))
                return error.GroupStateTooLarge;

            const total = 4 + gs_data.len + st_data.len;
            const buffer = allocator.alloc(
                u8,
                total,
            ) catch return error.OutOfMemory;
            errdefer allocator.free(buffer);

            std.mem.writeInt(
                u32,
                buffer[0..4],
                @intCast(gs_data.len),
                .big,
            );
            @memcpy(
                buffer[4..][0..gs_data.len],
                gs_data,
            );
            @memcpy(
                buffer[4 + gs_data.len ..][0..st_data.len],
                st_data,
            );

            return buffer;
        }

        pub const DeserializeError = error{
            OutOfMemory,
            InvalidBundleFormat,
        };

        /// Deserialize from bytes produced by `serialize`.
        /// Pure computation.
        pub fn deserialize(
            allocator: Allocator,
            data: []const u8,
        ) DeserializeError!Self {
            if (data.len < 4)
                return error.InvalidBundleFormat;

            const gs_length = std.mem.readInt(
                u32,
                data[0..4],
                .big,
            );

            if (4 + @as(u64, gs_length) > data.len)
                return error.InvalidBundleFormat;

            var group_state = Ser.deserialize(
                allocator,
                data[4..][0..gs_length],
            ) catch return error.InvalidBundleFormat;
            errdefer group_state.deinit();

            const st_data = data[4 + gs_length ..];
            var secret_tree = ST.deserialize(
                allocator,
                st_data,
            ) catch return error.InvalidBundleFormat;
            errdefer secret_tree.deinit(allocator);

            return .{
                .group_state = group_state,
                .secret_tree = secret_tree,
            };
        }
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;
const TestP = zmls.DefaultCryptoProvider;
const TestBundle = GroupBundle(TestP);

test "GroupBundle: serialize then deserialize round-trip" {
    const allocator = testing.allocator;

    const leaf = zmls.LeafNode{
        .encryption_key = &(.{0xaa} ** TestP.npk),
        .signature_key = &(.{0xbb} ** TestP.sign_pk_len),
        .credential = zmls.Credential.initBasic("test"),
        .capabilities = .{
            .versions = &.{.mls10},
            .cipher_suites = &.{
                .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            },
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 86400,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &.{},
    };

    var group_state = try zmls.createGroup(
        TestP,
        allocator,
        "test-group",
        leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    );
    errdefer group_state.deinit();

    // initFromGroupState takes ownership. On success the
    // source is poisoned — no manual cleanup needed.
    var bundle = try TestBundle.initFromGroupState(
        allocator,
        &group_state,
    );
    defer bundle.deinit(allocator);

    const blob = try TestBundle.serialize(
        allocator,
        &bundle.group_state,
        &bundle.secret_tree,
    );
    defer {
        secureZeroSlice(blob);
        allocator.free(blob);
    }

    var restored = try TestBundle.deserialize(
        allocator,
        blob,
    );
    defer restored.deinit(allocator);

    try testing.expectEqual(
        bundle.group_state.epoch(),
        restored.group_state.epoch(),
    );
    try testing.expectEqualSlices(
        u8,
        bundle.group_state.groupId(),
        restored.group_state.groupId(),
    );
}

test "GroupBundle: deserialize rejects truncated data" {
    const allocator = testing.allocator;

    const short: []const u8 = &.{ 0, 0 };
    const result = TestBundle.deserialize(allocator, short);
    try testing.expectError(
        error.InvalidBundleFormat,
        result,
    );
}

test "GroupBundle: deserialize rejects invalid length" {
    const allocator = testing.allocator;

    // Length field claims 999 bytes but only 4 bytes total.
    var bad: [4]u8 = undefined;
    std.mem.writeInt(u32, &bad, 999, .big);
    const result = TestBundle.deserialize(allocator, &bad);
    try testing.expectError(
        error.InvalidBundleFormat,
        result,
    );
}
