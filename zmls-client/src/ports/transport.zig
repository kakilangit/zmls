//! Transport — Message delivery port.
//!
//! Adapters implement this to send and receive MLS messages.
//! The Client never opens a socket directly.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const MessageType = enum(u8) {
    commit = 1,
    welcome = 2,
    proposal = 3,
    application = 4,
    group_info = 5,
};

pub const ReceivedEnvelope = struct {
    message_type: MessageType,
    data: []u8,
    sender_id: []u8,

    pub fn deinit(self: *ReceivedEnvelope, allocator: Allocator) void {
        allocator.free(self.data);
        allocator.free(self.sender_id);
        self.* = undefined;
    }
};

pub const Transport = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (
            context: *anyopaque,
            io: Io,
            group_id: []const u8,
            message_type: MessageType,
            data: []const u8,
        ) Error!void,
        receive: *const fn (
            context: *anyopaque,
            allocator: Allocator,
            io: Io,
            group_id: []const u8,
        ) Error!?ReceivedEnvelope,
    };

    pub const Error = Io.Cancelable || error{
        TransportFault,
        ConnectionClosed,
    };

    pub fn send(
        self: Transport,
        io: Io,
        group_id: []const u8,
        message_type: MessageType,
        data: []const u8,
    ) Error!void {
        return self.vtable.send(
            self.context,
            io,
            group_id,
            message_type,
            data,
        );
    }

    pub fn receive(
        self: Transport,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
    ) Error!?ReceivedEnvelope {
        return self.vtable.receive(
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

const NoOpTransport = struct {
    fn send(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: MessageType,
        _: []const u8,
    ) Transport.Error!void {}

    fn receive(
        _: *anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
    ) Transport.Error!?ReceivedEnvelope {
        return null;
    }

    const vtable: Transport.VTable = .{
        .send = &send,
        .receive = &receive,
    };
};

test "Transport: no-op stub is callable" {
    var dummy: u8 = 0;
    const t = Transport{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpTransport.vtable,
    };
    const io = testIo();

    try t.send(io, "group-1", .commit, "payload");
    const received = try t.receive(
        testing.allocator,
        io,
        "group-1",
    );
    try testing.expectEqual(null, received);
}
