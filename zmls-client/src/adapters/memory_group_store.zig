//! In-memory bounded group state store.
//!
//! Fixed-capacity adapter for `GroupStore`. All state blobs
//! are `secureZero`d on removal and in `deinit`. Uses a
//! fixed array — no heap allocation for the index structure.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const GroupStore = @import("../ports/group_store.zig").GroupStore;

/// Hash a group_id to a fixed-size key for comparison.
const KeyHash = [32]u8;

fn hashGroupId(group_id: []const u8) KeyHash {
    var out: KeyHash = undefined;
    std.crypto.hash.sha2.Sha256.hash(group_id, &out, .{});
    return out;
}

fn secureZeroSlice(buf: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buf));
}

/// Bounded in-memory group state store.
///
/// `capacity` is the maximum number of groups stored
/// concurrently. Entries are matched by SHA-256 hash of
/// the group_id. State blobs are heap-allocated via the
/// allocator passed to `save`; the adapter stores only the
/// allocator-owned copy.
pub fn MemoryGroupStore(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            occupied: bool = false,
            key: KeyHash = .{0} ** 32,
            state: ?[]u8 = null,
            allocator: ?Allocator = null,
        };

        entries: [capacity]Entry = [_]Entry{.{}} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self) void {
            for (&self.entries) |*e| {
                if (e.state) |s| {
                    secureZeroSlice(s);
                    e.allocator.?.free(s);
                }
                e.* = .{};
            }
        }

        pub fn groupStore(self: *Self) GroupStore {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        fn findSlot(
            self: *Self,
            key: KeyHash,
        ) ?*Entry {
            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.key, &key))
                    return e;
            }
            return null;
        }

        fn findFree(self: *Self) ?*Entry {
            for (&self.entries) |*e| {
                if (!e.occupied) return e;
            }
            return null;
        }

        fn saveFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            state: []const u8,
        ) GroupStore.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const key = hashGroupId(group_id);
            const slot = self.findSlot(key) orelse
                self.findFree() orelse
                return error.StorageFault;

            // Free old state if overwriting.
            if (slot.state) |old| {
                secureZeroSlice(old);
                slot.allocator.?.free(old);
            }

            // Copy state into a new allocation.
            const alloc = std.heap.page_allocator;
            const copy = alloc.alloc(u8, state.len) catch
                return error.StorageFault;
            @memcpy(copy, state);

            slot.occupied = true;
            slot.key = key;
            slot.state = copy;
            slot.allocator = alloc;
        }

        fn loadFn(
            ctx: *anyopaque,
            allocator: Allocator,
            _: Io,
            group_id: []const u8,
        ) GroupStore.Error!?[]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const key = hashGroupId(group_id);
            const slot = self.findSlot(key) orelse
                return null;
            const src = slot.state orelse return null;
            const copy = allocator.alloc(u8, src.len) catch
                return error.StorageFault;
            @memcpy(copy, src);
            return copy;
        }

        fn deleteFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
        ) GroupStore.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const key = hashGroupId(group_id);
            const slot = self.findSlot(key) orelse return;
            if (slot.state) |s| {
                secureZeroSlice(s);
                slot.allocator.?.free(s);
            }
            slot.* = .{};
        }

        const vtable: GroupStore.VTable = .{
            .save = &saveFn,
            .load = &loadFn,
            .delete = &deleteFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "MemoryGroupStore: save/load round-trip" {
    var store = MemoryGroupStore(8).init();
    defer store.deinit();
    const gs = store.groupStore();
    const io = testIo();

    try gs.save(io, "group-1", "state-data-123");

    const loaded = try gs.load(
        testing.allocator,
        io,
        "group-1",
    );
    defer if (loaded) |l| testing.allocator.free(l);

    try testing.expect(loaded != null);
    try testing.expectEqualSlices(u8, "state-data-123", loaded.?);
}

test "MemoryGroupStore: load returns null for unknown" {
    var store = MemoryGroupStore(4).init();
    defer store.deinit();
    const gs = store.groupStore();
    const io = testIo();

    const loaded = try gs.load(
        testing.allocator,
        io,
        "nonexistent",
    );
    try testing.expectEqual(null, loaded);
}

test "MemoryGroupStore: delete is idempotent" {
    var store = MemoryGroupStore(4).init();
    defer store.deinit();
    const gs = store.groupStore();
    const io = testIo();

    try gs.save(io, "group-1", "state");
    try gs.delete(io, "group-1");
    try gs.delete(io, "group-1"); // second delete: no error

    const loaded = try gs.load(
        testing.allocator,
        io,
        "group-1",
    );
    try testing.expectEqual(null, loaded);
}

test "MemoryGroupStore: save overwrites existing" {
    var store = MemoryGroupStore(4).init();
    defer store.deinit();
    const gs = store.groupStore();
    const io = testIo();

    try gs.save(io, "group-1", "v1");
    try gs.save(io, "group-1", "v2-updated");

    const loaded = try gs.load(
        testing.allocator,
        io,
        "group-1",
    );
    defer if (loaded) |l| testing.allocator.free(l);

    try testing.expectEqualSlices(u8, "v2-updated", loaded.?);
}
