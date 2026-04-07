//! Bounded ring buffer for retaining past-epoch decryption secrets.
//! Enables out-of-order message decryption with secure zeroing
//! on eviction.
// Past-epoch key retention for out-of-order message decryption.
//
// When a group advances epoch, the outgoing epoch's secrets
// needed for message decryption (sender_data_secret) are stored
// in a bounded ring buffer. Messages arriving from a recent
// past epoch can still be decrypted.
//
// Design: a fixed-capacity ring buffer indexed by epoch modulo
// capacity. When a slot is evicted, its secrets are zeroed via
// secureZero. Default retention count is 0 (current epoch only).

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const primitives = @import("../crypto/primitives.zig");
const errors = @import("../common/errors.zig");
const secureZero = primitives.secureZero;

const Epoch = types.Epoch;
const GroupError = errors.GroupError;

/// Maximum supported retention window.
const max_retention: u32 = 64;

/// A retained epoch's secrets needed for message decryption.
fn RetainedEpoch(comptime nh: u32) type {
    return struct {
        epoch: Epoch,
        sender_data_secret: [nh]u8,
        valid: bool,
    };
}

/// Ring buffer of past-epoch secrets for out-of-order
/// message decryption.
///
/// Generic over the CryptoProvider (for hash output size).
pub fn EpochKeyRing(comptime P: type) type {
    const nh = P.nh;

    return struct {
        slots: [max_retention]RetainedEpoch(nh),
        capacity: u32,

        const Self = @This();

        /// Create a ring with the given retention capacity.
        ///
        /// `retention` is the number of past epochs to keep.
        /// 0 means no past-epoch retention (default behavior).
        /// Clamped to max_retention.
        pub fn init(retention: u32) Self {
            const cap = @min(retention, max_retention);
            var ring: Self = .{
                .slots = undefined,
                .capacity = cap,
            };
            var i: u32 = 0;
            while (i < max_retention) : (i += 1) {
                ring.slots[i] = .{
                    .epoch = 0,
                    .sender_data_secret = .{0} ** nh,
                    .valid = false,
                };
            }
            return ring;
        }

        /// Retain the secrets for an epoch that is being replaced.
        ///
        /// If the ring is at capacity, the oldest slot is evicted
        /// and its secrets zeroed.
        pub fn retain(
            self: *Self,
            epoch: Epoch,
            sender_data_secret: *const [nh]u8,
        ) void {
            if (self.capacity == 0) return;

            const slot_idx: u32 = @intCast(
                epoch % @as(u64, self.capacity),
            );
            // Zero the slot being evicted.
            if (self.slots[slot_idx].valid) {
                secureZero(
                    &self.slots[slot_idx].sender_data_secret,
                );
            }
            self.slots[slot_idx] = .{
                .epoch = epoch,
                .sender_data_secret = sender_data_secret.*,
                .valid = true,
            };
        }

        /// Look up retained secrets for a past epoch.
        ///
        /// Returns the sender_data_secret if the epoch is
        /// retained, or null if not found or evicted.
        pub fn lookup(
            self: *const Self,
            epoch: Epoch,
        ) ?*const [nh]u8 {
            if (self.capacity == 0) return null;

            const slot_idx: u32 = @intCast(
                epoch % @as(u64, self.capacity),
            );
            const slot = &self.slots[slot_idx];
            if (slot.valid and slot.epoch == epoch) {
                return &slot.sender_data_secret;
            }
            return null;
        }

        /// Zero all retained secrets.
        pub fn zeroAll(self: *Self) void {
            var i: u32 = 0;
            while (i < max_retention) : (i += 1) {
                if (self.slots[i].valid) {
                    secureZero(
                        &self.slots[i].sender_data_secret,
                    );
                    self.slots[i].valid = false;
                }
            }
        }
    };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "EpochKeyRing: zero retention returns null" {
    const ring = EpochKeyRing(Default).init(0);
    try testing.expect(ring.lookup(0) == null);
    try testing.expect(ring.lookup(1) == null);
}

test "EpochKeyRing: retain and lookup" {
    var ring = EpochKeyRing(Default).init(3);

    const secret0: [Default.nh]u8 = .{0x01} ** Default.nh;
    const secret1: [Default.nh]u8 = .{0x02} ** Default.nh;
    const secret2: [Default.nh]u8 = .{0x03} ** Default.nh;

    ring.retain(0, &secret0);
    ring.retain(1, &secret1);
    ring.retain(2, &secret2);

    // All three should be retrievable.
    try testing.expectEqualSlices(
        u8,
        &secret0,
        ring.lookup(0).?,
    );
    try testing.expectEqualSlices(
        u8,
        &secret1,
        ring.lookup(1).?,
    );
    try testing.expectEqualSlices(
        u8,
        &secret2,
        ring.lookup(2).?,
    );

    // Unknown epoch returns null.
    try testing.expect(ring.lookup(3) == null);
}

test "EpochKeyRing: eviction on overflow" {
    var ring = EpochKeyRing(Default).init(2);

    const s0: [Default.nh]u8 = .{0x10} ** Default.nh;
    const s1: [Default.nh]u8 = .{0x20} ** Default.nh;
    const s2: [Default.nh]u8 = .{0x30} ** Default.nh;

    ring.retain(0, &s0);
    ring.retain(1, &s1);

    // Both present.
    try testing.expect(ring.lookup(0) != null);
    try testing.expect(ring.lookup(1) != null);

    // Retaining epoch 2 evicts epoch 0 (slot 0 % 2 = 0).
    ring.retain(2, &s2);

    // Epoch 0 is gone, epoch 1 and 2 are present.
    try testing.expect(ring.lookup(0) == null);
    try testing.expect(ring.lookup(1) != null);
    try testing.expect(ring.lookup(2) != null);
}

test "EpochKeyRing: zeroAll clears everything" {
    var ring = EpochKeyRing(Default).init(3);

    const s0: [Default.nh]u8 = .{0xAA} ** Default.nh;
    ring.retain(0, &s0);

    try testing.expect(ring.lookup(0) != null);

    ring.zeroAll();

    try testing.expect(ring.lookup(0) == null);
}

test "EpochKeyRing: large epoch values" {
    var ring = EpochKeyRing(Default).init(4);

    const s: [Default.nh]u8 = .{0xFF} ** Default.nh;
    const epoch: u64 = 1_000_000;
    ring.retain(epoch, &s);

    try testing.expectEqualSlices(
        u8,
        &s,
        ring.lookup(epoch).?,
    );
    try testing.expect(ring.lookup(epoch - 1) == null);
}
