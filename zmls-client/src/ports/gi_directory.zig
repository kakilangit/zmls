//! GroupInfoDirectory — Server-side GroupInfo registry.
//!
//! Stores signed GroupInfo blobs published by group members
//! so that external joiners can retrieve them.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const GroupInfoDirectory = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        set: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            data: []const u8,
        ) Error!void,
        get: *const fn (
            context: *anyopaque,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) Error!?[]u8,
    };

    pub const Error = Io.Cancelable || error{
        StorageFault,
    };

    pub fn set(
        self: GroupInfoDirectory,
        io: Io,
        group_id: []const u8,
        data: []const u8,
    ) Error!void {
        return self.vtable.set(
            self.context,
            io,
            group_id,
            data,
        );
    }

    /// Returns a copy of the GroupInfo blob for `group_id`,
    /// or `null` if none is stored. Caller owns the slice.
    pub fn get(
        self: GroupInfoDirectory,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
    ) Error!?[]u8 {
        return self.vtable.get(
            self.context,
            allocator,
            io,
            group_id,
        );
    }
};

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

const NoOpGIDir = struct {
    fn setFn(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupInfoDirectory.Error!void {}

    fn getFn(
        _: *anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
    ) GroupInfoDirectory.Error!?[]u8 {
        return null;
    }

    const vtable: GroupInfoDirectory.VTable = .{
        .set = &setFn,
        .get = &getFn,
    };
};

test "GroupInfoDirectory: no-op stub is callable" {
    var dummy: u8 = 0;
    const gid = GroupInfoDirectory{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpGIDir.vtable,
    };
    const io = testIo();

    try gid.set(io, "group-1", "group-info-data");
    const fetched = try gid.get(
        testing.allocator,
        io,
        "group-1",
    );
    try testing.expectEqual(null, fetched);
}
