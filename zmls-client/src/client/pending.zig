//! PendingKeyPackageMap — Tracks un-consumed KeyPackages.
//!
//! When a Client generates a fresh KeyPackage, the private keys
//! (init secret key and encryption secret key) are stored here
//! keyed by the KeyPackage's reference hash. When the Client
//! joins a group via Welcome, the matching entry is consumed.
//! All secrets are `secureZero`d on removal and in `deinit`.

const std = @import("std");
const zmls = @import("zmls");

fn secureZeroSlice(buf: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buf));
}

/// Bounded map from KeyPackage ref hash to private keys.
///
/// `P` is the CryptoProvider. `capacity` is the maximum number
/// of pending KeyPackages (controls how many un-consumed KPs a
/// Client can have outstanding).
pub fn PendingKeyPackageMap(comptime P: type, comptime capacity: u32) type {
    return struct {
        const Self = @This();

        /// Private keys associated with a pending KeyPackage.
        pub const PendingKeys = struct {
            /// HPKE init secret key for Welcome decryption.
            init_sk: [P.nsk]u8,
            /// HPKE init public key for Welcome decryption.
            init_pk: [P.npk]u8,
            /// Encryption secret key for the leaf.
            enc_sk: [P.nsk]u8,
            /// Signature secret key snapshot (needed to verify
            /// the Welcome was meant for this identity).
            sign_sk: [P.sign_sk_len]u8,
        };

        const Entry = struct {
            occupied: bool = false,
            /// SHA-256 hash of the ref hash for lookup.
            ref_hash: [P.nh]u8 = .{0} ** P.nh,
            keys: PendingKeys = std.mem.zeroes(PendingKeys),
        };

        entries: [capacity]Entry =
            [_]Entry{.{}} ** capacity,
        count: u32 = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self) void {
            for (&self.entries) |*e| {
                if (e.occupied) {
                    secureZeroSlice(&e.keys.init_sk);
                    secureZeroSlice(&e.keys.enc_sk);
                    secureZeroSlice(&e.keys.sign_sk);
                }
                e.* = .{};
            }
            self.count = 0;
        }

        /// Store private keys for a pending KeyPackage.
        /// `ref_hash` is the KeyPackage reference hash.
        pub fn insert(
            self: *Self,
            ref_hash: *const [P.nh]u8,
            keys: PendingKeys,
        ) error{CapacityExhausted}!void {
            for (&self.entries) |*e| {
                if (!e.occupied) {
                    e.occupied = true;
                    e.ref_hash = ref_hash.*;
                    e.keys = keys;
                    self.count += 1;
                    return;
                }
            }
            return error.CapacityExhausted;
        }

        /// Look up private keys by ref hash.
        /// Returns null if not found.
        pub fn find(
            self: *const Self,
            ref_hash: *const [P.nh]u8,
        ) ?*const PendingKeys {
            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.ref_hash, ref_hash))
                    return &e.keys;
            }
            return null;
        }

        /// Remove and secureZero a pending KeyPackage entry.
        /// Returns true if found and removed, false if not found.
        pub fn remove(
            self: *Self,
            ref_hash: *const [P.nh]u8,
        ) bool {
            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.ref_hash, ref_hash))
                {
                    secureZeroSlice(&e.keys.init_sk);
                    secureZeroSlice(&e.keys.enc_sk);
                    secureZeroSlice(&e.keys.sign_sk);
                    e.* = .{};
                    self.count -= 1;
                    return true;
                }
            }
            return false;
        }
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

/// Minimal stub CryptoProvider for tests.
const StubP = struct {
    pub const nh: u32 = 32;
    pub const nk: u32 = 16;
    pub const nn: u32 = 12;
    pub const nsk: u32 = 32;
    pub const npk: u32 = 32;
    pub const sign_sk_len: u32 = 64;
};

test "PendingKeyPackageMap: insert/find/remove" {
    var map = PendingKeyPackageMap(StubP, 8).init();
    defer map.deinit();

    const ref: [StubP.nh]u8 = .{0xAA} ** StubP.nh;
    const keys = PendingKeyPackageMap(StubP, 8).PendingKeys{
        .init_sk = .{0x11} ** StubP.nsk,
        .init_pk = .{0x44} ** StubP.npk,
        .enc_sk = .{0x22} ** StubP.nsk,
        .sign_sk = .{0x33} ** StubP.sign_sk_len,
    };

    try map.insert(&ref, keys);
    try testing.expectEqual(@as(u32, 1), map.count);

    const found = map.find(&ref);
    try testing.expect(found != null);
    try testing.expectEqualSlices(
        u8,
        &keys.init_sk,
        &found.?.init_sk,
    );

    const removed = map.remove(&ref);
    try testing.expect(removed);
    try testing.expectEqual(@as(u32, 0), map.count);

    const gone = map.find(&ref);
    try testing.expectEqual(null, gone);
}

test "PendingKeyPackageMap: remove returns false for unknown" {
    var map = PendingKeyPackageMap(StubP, 4).init();
    defer map.deinit();

    const ref: [StubP.nh]u8 = .{0xFF} ** StubP.nh;
    try testing.expect(!map.remove(&ref));
}

test "PendingKeyPackageMap: capacity exhausted" {
    var map = PendingKeyPackageMap(StubP, 2).init();
    defer map.deinit();

    const r1: [StubP.nh]u8 = .{1} ** StubP.nh;
    const r2: [StubP.nh]u8 = .{2} ** StubP.nh;
    const r3: [StubP.nh]u8 = .{3} ** StubP.nh;

    const keys = std.mem.zeroes(
        PendingKeyPackageMap(StubP, 2).PendingKeys,
    );
    try map.insert(&r1, keys);
    try map.insert(&r2, keys);
    try testing.expectError(
        error.CapacityExhausted,
        map.insert(&r3, keys),
    );
}

test "PendingKeyPackageMap: deinit zeros secrets" {
    var map = PendingKeyPackageMap(StubP, 4).init();

    const ref: [StubP.nh]u8 = .{0xBB} ** StubP.nh;
    const keys = PendingKeyPackageMap(StubP, 4).PendingKeys{
        .init_sk = .{0x11} ** StubP.nsk,
        .init_pk = .{0x44} ** StubP.npk,
        .enc_sk = .{0x22} ** StubP.nsk,
        .sign_sk = .{0x33} ** StubP.sign_sk_len,
    };
    try map.insert(&ref, keys);

    map.deinit();

    // After deinit, all entries should be cleared.
    try testing.expectEqual(@as(u32, 0), map.count);
    for (map.entries) |e| {
        try testing.expect(!e.occupied);
    }
}
