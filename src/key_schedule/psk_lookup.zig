//! Runtime PSK lookup interface for application-provided external
//! pre-shared keys per RFC 9420 Section 8.4.
// PSK lookup port for MLS external pre-shared keys.
//
// Per RFC 9420 Section 8.4, external PSKs are application-provided
// secrets. The application decides how to store and retrieve them
// (database, HSM, etc.). This module defines the runtime port
// interface.
//
// Resumption PSKs are derived internally from EpochSecrets and
// stored in GroupState — they do not use this port.

const std = @import("std");
const assert = std.debug.assert;
const psk = @import("psk.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const primitives = @import("../crypto/primitives.zig");

const PreSharedKeyId = psk.PreSharedKeyId;
const GroupError = errors.GroupError;

/// Runtime port for resolving external PSK secrets.
///
/// The application implements this interface to provide external
/// PSK secret material. The `resolve` method looks up a PSK by
/// its identifier and returns the raw secret bytes, or null if
/// the PSK is not found.
///
/// This is a runtime interface (function pointer) because PSK
/// storage depends on external application state.
pub const PskLookup = struct {
    /// Opaque pointer to application-specific context.
    context: *const anyopaque,

    /// Resolve an external PSK by its PreSharedKeyId.
    ///
    /// Returns the raw PSK secret bytes, or null if the PSK is
    /// unknown. The returned slice must remain valid for the
    /// duration of the commit operation.
    resolve_fn: *const fn (
        context: *const anyopaque,
        psk_id: *const PreSharedKeyId,
    ) ?[]const u8,

    /// Look up a PSK by its identifier.
    pub fn resolve(
        self: *const PskLookup,
        psk_id: *const PreSharedKeyId,
    ) ?[]const u8 {
        return self.resolve_fn(self.context, psk_id);
    }
};

/// A PskLookup adapter that always returns null (no PSKs).
/// Suitable for groups that never use external PSKs.
pub const NoPskLookup = struct {
    const instance: NoPskLookup = .{};

    fn resolveNone(
        _: *const anyopaque,
        _: *const PreSharedKeyId,
    ) ?[]const u8 {
        return null;
    }

    pub fn lookup() PskLookup {
        return .{
            .context = @ptrCast(&instance),
            .resolve_fn = &resolveNone,
        };
    }
};

/// In-memory PSK store for testing.
///
/// Stores up to `max_entries` PSK (id, secret) pairs. PSK IDs
/// are matched by external_psk_id bytes. Not suitable for
/// production (no secure deletion, no persistence).
pub const InMemoryPskStore = struct {
    const max_entries: u32 = 32;

    const Entry = struct {
        psk_id: []const u8,
        secret: []const u8,
    };

    entries: [max_entries]Entry,
    len: u32,

    pub fn init() InMemoryPskStore {
        var store: InMemoryPskStore = .{
            .entries = undefined,
            .len = 0,
        };
        var i: u32 = 0;
        while (i < max_entries) : (i += 1) {
            store.entries[i] = .{ .psk_id = "", .secret = "" };
        }
        return store;
    }

    /// Clear all entries, zeroing stored secret slice metadata.
    /// Does NOT zero caller-owned secret buffers — callers must
    /// zero those independently.
    pub fn deinit(self: *InMemoryPskStore) void {
        var i: u32 = 0;
        while (i < self.len) : (i += 1) {
            self.entries[i] = .{ .psk_id = "", .secret = "" };
        }
        self.len = 0;
        self.* = undefined;
    }

    /// Add an external PSK. Returns false if the store is full.
    pub fn addPsk(
        self: *InMemoryPskStore,
        psk_id: []const u8,
        secret: []const u8,
    ) bool {
        if (self.len >= max_entries) return false;
        self.entries[self.len] = .{
            .psk_id = psk_id,
            .secret = secret,
        };
        self.len += 1;
        return true;
    }

    fn resolveImpl(
        ctx: *const anyopaque,
        psk_id: *const PreSharedKeyId,
    ) ?[]const u8 {
        const self: *const InMemoryPskStore = @ptrCast(
            @alignCast(ctx),
        );
        if (psk_id.psk_type != .external) return null;
        const target = psk_id.external_psk_id;
        var i: u32 = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].psk_id, target)) {
                return self.entries[i].secret;
            }
        }
        return null;
    }

    pub fn lookup(self: *const InMemoryPskStore) PskLookup {
        return .{
            .context = @ptrCast(self),
            .resolve_fn = &resolveImpl,
        };
    }
};

/// Bounded ring buffer for resumption PSK retention.
///
/// Stores `(epoch, resumption_secret)` pairs from past epochs.
/// Used internally by GroupState — not a port.
pub fn ResumptionPskRing(comptime P: type) type {
    const nh = P.nh;
    const max_capacity: u32 = 64;

    return struct {
        const Entry = struct {
            epoch: types.Epoch,
            secret: [nh]u8,
            valid: bool,
        };

        slots: [max_capacity]Entry,
        capacity: u32,

        const Self = @This();

        /// Create a ring with the given retention capacity.
        /// 0 means no resumption PSK retention.
        pub fn init(retention: u32) Self {
            const cap = @min(retention, max_capacity);
            var ring: Self = .{
                .slots = undefined,
                .capacity = cap,
            };
            var i: u32 = 0;
            while (i < max_capacity) : (i += 1) {
                ring.slots[i] = .{
                    .epoch = 0,
                    .secret = .{0} ** nh,
                    .valid = false,
                };
            }
            return ring;
        }

        /// Retain a resumption secret for an epoch.
        pub fn retain(
            self: *Self,
            epoch: types.Epoch,
            secret: *const [nh]u8,
        ) void {
            if (self.capacity == 0) return;
            const slot: u32 = @intCast(
                epoch % @as(u64, self.capacity),
            );
            if (self.slots[slot].valid) {
                primitives.secureZero(&self.slots[slot].secret);
            }
            self.slots[slot] = .{
                .epoch = epoch,
                .secret = secret.*,
                .valid = true,
            };
        }

        /// Look up a resumption secret by epoch.
        pub fn lookupSecret(
            self: *const Self,
            epoch: types.Epoch,
        ) ?*const [nh]u8 {
            if (self.capacity == 0) return null;
            const slot: u32 = @intCast(
                epoch % @as(u64, self.capacity),
            );
            const entry = &self.slots[slot];
            if (entry.valid and entry.epoch == epoch) {
                return &entry.secret;
            }
            return null;
        }

        /// Zero all retained secrets.
        pub fn zeroAll(self: *Self) void {
            var i: u32 = 0;
            while (i < max_capacity) : (i += 1) {
                if (self.slots[i].valid) {
                    primitives.secureZero(&self.slots[i].secret);
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

test "NoPskLookup always returns null" {
    const lk = NoPskLookup.lookup();
    const id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "some-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "",
    };
    try testing.expect(lk.resolve(&id) == null);
}

test "InMemoryPskStore: add and resolve external PSK" {
    var store = InMemoryPskStore.init();
    const secret = [_]u8{0xAA} ** 32;
    try testing.expect(store.addPsk("my-psk", &secret));

    const lk = store.lookup();
    const id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "",
    };
    const result = lk.resolve(&id);
    try testing.expect(result != null);
    try testing.expectEqualSlices(u8, &secret, result.?);
}

test "InMemoryPskStore: unknown PSK returns null" {
    var store = InMemoryPskStore.init();
    const secret = [_]u8{0xBB} ** 32;
    try testing.expect(store.addPsk("known", &secret));

    const lk = store.lookup();
    const id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "unknown",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "",
    };
    try testing.expect(lk.resolve(&id) == null);
}

test "InMemoryPskStore: resumption type returns null" {
    var store = InMemoryPskStore.init();
    const secret = [_]u8{0xCC} ** 32;
    try testing.expect(store.addPsk("ext-psk", &secret));

    const lk = store.lookup();
    const id = PreSharedKeyId{
        .psk_type = .resumption,
        .external_psk_id = "",
        .resumption_usage = .application,
        .resumption_group_id = "group",
        .resumption_epoch = 1,
        .psk_nonce = "",
    };
    try testing.expect(lk.resolve(&id) == null);
}

test "ResumptionPskRing: zero capacity returns null" {
    const ring = ResumptionPskRing(Default).init(0);
    try testing.expect(ring.lookupSecret(0) == null);
}

test "ResumptionPskRing: retain and lookup" {
    var ring = ResumptionPskRing(Default).init(3);
    const s0: [Default.nh]u8 = .{0x01} ** Default.nh;
    const s1: [Default.nh]u8 = .{0x02} ** Default.nh;

    ring.retain(0, &s0);
    ring.retain(1, &s1);

    try testing.expectEqualSlices(
        u8,
        &s0,
        ring.lookupSecret(0).?,
    );
    try testing.expectEqualSlices(
        u8,
        &s1,
        ring.lookupSecret(1).?,
    );
    try testing.expect(ring.lookupSecret(2) == null);
}

test "ResumptionPskRing: eviction and zeroAll" {
    var ring = ResumptionPskRing(Default).init(2);
    const s0: [Default.nh]u8 = .{0x10} ** Default.nh;
    const s1: [Default.nh]u8 = .{0x20} ** Default.nh;
    const s2: [Default.nh]u8 = .{0x30} ** Default.nh;

    ring.retain(0, &s0);
    ring.retain(1, &s1);
    ring.retain(2, &s2); // evicts epoch 0

    try testing.expect(ring.lookupSecret(0) == null);
    try testing.expect(ring.lookupSecret(1) != null);
    try testing.expect(ring.lookupSecret(2) != null);

    ring.zeroAll();
    try testing.expect(ring.lookupSecret(1) == null);
    try testing.expect(ring.lookupSecret(2) == null);
}
