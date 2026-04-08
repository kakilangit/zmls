//! GroupDirectory — Server-side group membership and message queue.
//!
//! Tracks which members belong to which groups and maintains
//! per-member message queues for the delivery service.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const MessageType = @import("transport.zig").MessageType;
const ReceivedEnvelope = @import("transport.zig").ReceivedEnvelope;

pub const GroupDirectory = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        create_group: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            creator_id: []const u8,
        ) Error!void,
        add_member: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) Error!void,
        remove_member: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) Error!void,
        enqueue: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            sender_id: []const u8,
            message_type: MessageType,
            data: []const u8,
        ) Error!void,
        dequeue: *const fn (
            context: *anyopaque,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) Error!?ReceivedEnvelope,
    };

    pub const Error = Io.Cancelable || error{
        StorageFault,
        GroupNotFound,
        MemberNotFound,
        QueueFull,
    };

    pub fn createGroup(
        self: GroupDirectory,
        io: Io,
        group_id: []const u8,
        creator_id: []const u8,
    ) Error!void {
        return self.vtable.create_group(
            self.context,
            io,
            group_id,
            creator_id,
        );
    }

    pub fn addMember(
        self: GroupDirectory,
        io: Io,
        group_id: []const u8,
        member_id: []const u8,
    ) Error!void {
        return self.vtable.add_member(
            self.context,
            io,
            group_id,
            member_id,
        );
    }

    pub fn removeMember(
        self: GroupDirectory,
        io: Io,
        group_id: []const u8,
        member_id: []const u8,
    ) Error!void {
        return self.vtable.remove_member(
            self.context,
            io,
            group_id,
            member_id,
        );
    }

    pub fn enqueue(
        self: GroupDirectory,
        io: Io,
        group_id: []const u8,
        sender_id: []const u8,
        message_type: MessageType,
        data: []const u8,
    ) Error!void {
        return self.vtable.enqueue(
            self.context,
            io,
            group_id,
            sender_id,
            message_type,
            data,
        );
    }

    pub fn dequeue(
        self: GroupDirectory,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
        member_id: []const u8,
    ) Error!?ReceivedEnvelope {
        return self.vtable.dequeue(
            self.context,
            allocator,
            io,
            group_id,
            member_id,
        );
    }
};

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

const NoOpGroupDir = struct {
    fn createGroup(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupDirectory.Error!void {}

    fn addMember(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupDirectory.Error!void {}

    fn removeMember(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupDirectory.Error!void {}

    fn enqueueMsg(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
        _: MessageType,
        _: []const u8,
    ) GroupDirectory.Error!void {}

    fn dequeueMsg(
        _: *anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) GroupDirectory.Error!?ReceivedEnvelope {
        return null;
    }

    const vtable: GroupDirectory.VTable = .{
        .create_group = &createGroup,
        .add_member = &addMember,
        .remove_member = &removeMember,
        .enqueue = &enqueueMsg,
        .dequeue = &dequeueMsg,
    };
};

test "GroupDirectory: no-op stub is callable" {
    var dummy: u8 = 0;
    const gd = GroupDirectory{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpGroupDir.vtable,
    };
    const io = testIo();

    try gd.createGroup(io, "group-1", "alice");
    try gd.addMember(io, "group-1", "bob");
    try gd.removeMember(io, "group-1", "bob");
    try gd.enqueue(io, "group-1", "alice", .commit, "data");
    const msg = try gd.dequeue(
        testing.allocator,
        io,
        "group-1",
        "bob",
    );
    try testing.expectEqual(null, msg);
}
