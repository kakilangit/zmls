//! In-memory bounded GroupInfo directory.
//!
//! Fixed-capacity adapter for `GroupInfoDirectory`. Stores
//! signed GroupInfo blobs keyed by group_id hash.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const GroupInfoDirectory =
    @import("../ports/gi_directory.zig").GroupInfoDirectory;

const KeyHash = [32]u8;

fn hashBytes(data: []const u8) KeyHash {
    var out: KeyHash = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

/// Bounded in-memory GroupInfo directory.
pub fn MemoryGroupInfoDirectory(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            occupied: bool = false,
            group_hash: KeyHash = .{0} ** 32,
            data: ?[]u8 = null,
            alloc: ?Allocator = null,
        };

        entries: [capacity]Entry =
            [_]Entry{.{}} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self) void {
            for (&self.entries) |*e| {
                if (e.data) |d| {
                    if (e.alloc) |a| a.free(d);
                }
                e.* = .{};
            }
        }

        pub fn groupInfoDirectory(
            self: *Self,
        ) GroupInfoDirectory {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        fn setFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            data: []const u8,
        ) GroupInfoDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashBytes(group_id);

            // Find existing or free slot.
            var slot: ?*Entry = null;
            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.group_hash, &kh))
                {
                    slot = e;
                    break;
                }
            }
            if (slot == null) {
                for (&self.entries) |*e| {
                    if (!e.occupied) {
                        slot = e;
                        break;
                    }
                }
            }
            const s = slot orelse return error.StorageFault;

            // Free old data if overwriting.
            if (s.data) |d| if (s.alloc) |a| a.free(d);

            const alloc = std.heap.page_allocator;
            const copy = alloc.alloc(u8, data.len) catch
                return error.StorageFault;
            @memcpy(copy, data);

            s.occupied = true;
            s.group_hash = kh;
            s.data = copy;
            s.alloc = alloc;
        }

        fn getFn(
            ctx: *anyopaque,
            allocator: Allocator,
            _: Io,
            group_id: []const u8,
        ) GroupInfoDirectory.Error!?[]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashBytes(group_id);

            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.group_hash, &kh))
                {
                    const src = e.data orelse return null;
                    const copy = allocator.alloc(
                        u8,
                        src.len,
                    ) catch return error.StorageFault;
                    @memcpy(copy, src);
                    return copy;
                }
            }
            return null;
        }

        const vtable: GroupInfoDirectory.VTable = .{
            .set = &setFn,
            .get = &getFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "MemoryGroupInfoDirectory: set/get round-trip" {
    var dir = MemoryGroupInfoDirectory(4).init();
    defer dir.deinit();
    const gid = dir.groupInfoDirectory();
    const io = testIo();

    try gid.set(io, "group-1", "group-info-blob");

    const got = try gid.get(
        testing.allocator,
        io,
        "group-1",
    );
    defer if (got) |g| testing.allocator.free(g);

    try testing.expect(got != null);
    try testing.expectEqualSlices(
        u8,
        "group-info-blob",
        got.?,
    );
}

test "MemoryGroupInfoDirectory: get unknown returns null" {
    var dir = MemoryGroupInfoDirectory(4).init();
    defer dir.deinit();
    const gid = dir.groupInfoDirectory();
    const io = testIo();

    const r = try gid.get(
        testing.allocator,
        io,
        "nonexistent",
    );
    try testing.expectEqual(null, r);
}

test "MemoryGroupInfoDirectory: set overwrites" {
    var dir = MemoryGroupInfoDirectory(4).init();
    defer dir.deinit();
    const gid = dir.groupInfoDirectory();
    const io = testIo();

    try gid.set(io, "g", "v1");
    try gid.set(io, "g", "v2-updated");

    const got = try gid.get(testing.allocator, io, "g");
    defer if (got) |g| testing.allocator.free(g);

    try testing.expectEqualSlices(u8, "v2-updated", got.?);
}
