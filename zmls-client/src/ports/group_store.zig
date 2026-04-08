//! GroupStore — Group state persistence port.
//!
//! Adapters implement this interface to provide durable
//! storage for serialized `GroupState` blobs.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const GroupStore = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        save: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            state: []const u8,
        ) Error!void,
        load: *const fn (
            context: *anyopaque,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) Error!?[]u8,
        delete: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
        ) Error!void,
    };

    pub const Error = Io.Cancelable || error{
        StorageFault,
    };

    pub fn save(
        self: GroupStore,
        io: Io,
        group_id: []const u8,
        state: []const u8,
    ) Error!void {
        return self.vtable.save(
            self.context,
            io,
            group_id,
            state,
        );
    }

    pub fn load(
        self: GroupStore,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
    ) Error!?[]u8 {
        return self.vtable.load(
            self.context,
            allocator,
            io,
            group_id,
        );
    }

    pub fn delete(
        self: GroupStore,
        io: Io,
        group_id: []const u8,
    ) Error!void {
        return self.vtable.delete(
            self.context,
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

const NoOpGroupStore = struct {
    fn save(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupStore.Error!void {}

    fn load(
        _: *anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
    ) GroupStore.Error!?[]u8 {
        return null;
    }

    fn delete(
        _: *anyopaque,
        _: Io,
        _: []const u8,
    ) GroupStore.Error!void {}

    const vtable: GroupStore.VTable = .{
        .save = &save,
        .load = &load,
        .delete = &delete,
    };
};

test "GroupStore: no-op stub is callable" {
    var dummy: u8 = 0;
    const store = GroupStore{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpGroupStore.vtable,
    };
    const io = testIo();

    try store.save(io, "group-1", "state-blob");
    const loaded = try store.load(
        testing.allocator,
        io,
        "group-1",
    );
    try testing.expectEqual(null, loaded);
    try store.delete(io, "group-1");
}
