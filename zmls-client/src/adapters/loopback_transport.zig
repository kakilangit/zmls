//! In-process loopback message transport.
//!
//! Fixed-capacity FIFO queue for testing. Messages sent via
//! `send` are immediately available via `receive`. Messages
//! are stored as heap-allocated copies.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const transport_mod = @import("../ports/transport.zig");
const Transport = transport_mod.Transport;
const MessageType = transport_mod.MessageType;
const ReceivedEnvelope = transport_mod.ReceivedEnvelope;

/// Loopback transport for in-process testing.
///
/// All groups share a single FIFO queue of `capacity` entries.
/// `send` copies the payload; `receive` returns ownership to
/// the caller.
pub fn LoopbackTransport(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        const QueueEntry = struct {
            occupied: bool = false,
            message_type: MessageType = .commit,
            group_id_hash: [32]u8 = .{0} ** 32,
            data: ?[]u8 = null,
            sender_id: ?[]u8 = null,
            alloc: ?Allocator = null,
        };

        queue: [capacity]QueueEntry =
            [_]QueueEntry{.{}} ** capacity,
        head: u32 = 0,
        tail: u32 = 0,
        count: u32 = 0,
        sender_name: []const u8 = "unknown",

        pub fn init() Self {
            return .{};
        }

        /// Set the sender name used for all subsequent sends.
        pub fn setSender(self: *Self, name: []const u8) void {
            self.sender_name = name;
        }

        pub fn deinit(self: *Self) void {
            for (&self.queue) |*e| {
                if (e.data) |d| {
                    if (e.alloc) |a| a.free(d);
                }
                if (e.sender_id) |s| {
                    if (e.alloc) |a| a.free(s);
                }
                e.* = .{};
            }
        }

        pub fn transport(self: *Self) Transport {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        fn hashGid(group_id: []const u8) [32]u8 {
            var out: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(
                group_id,
                &out,
                .{},
            );
            return out;
        }

        fn sendFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            message_type: MessageType,
            data: []const u8,
        ) Transport.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (self.count >= capacity)
                return error.TransportFault;

            const alloc = std.heap.page_allocator;
            const data_copy = alloc.alloc(u8, data.len) catch
                return error.TransportFault;
            @memcpy(data_copy, data);

            const sid_copy = alloc.alloc(
                u8,
                self.sender_name.len,
            ) catch {
                alloc.free(data_copy);
                return error.TransportFault;
            };
            @memcpy(sid_copy, self.sender_name);

            self.queue[self.tail] = .{
                .occupied = true,
                .message_type = message_type,
                .group_id_hash = hashGid(group_id),
                .data = data_copy,
                .sender_id = sid_copy,
                .alloc = alloc,
            };
            self.tail = (self.tail + 1) % capacity;
            self.count += 1;
        }

        fn receiveFn(
            ctx: *anyopaque,
            allocator: Allocator,
            _: Io,
            group_id: []const u8,
        ) Transport.Error!?ReceivedEnvelope {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const gid_hash = hashGid(group_id);

            // Scan for first matching entry (not strictly
            // FIFO per-group, but sufficient for testing).
            var i: u32 = 0;
            var idx = self.head;
            while (i < self.count) : (i += 1) {
                const e = &self.queue[idx];
                if (e.occupied and
                    std.mem.eql(u8, &e.group_id_hash, &gid_hash))
                {
                    // Copy to caller-owned allocation.
                    const src_data = e.data orelse
                        return error.TransportFault;
                    const src_sid = e.sender_id orelse
                        return error.TransportFault;

                    const d = allocator.alloc(
                        u8,
                        src_data.len,
                    ) catch return error.TransportFault;
                    errdefer allocator.free(d);
                    @memcpy(d, src_data);

                    const s = allocator.alloc(
                        u8,
                        src_sid.len,
                    ) catch return error.TransportFault;
                    @memcpy(s, src_sid);

                    const mt = e.message_type;

                    // Free internal copy and clear slot.
                    if (e.alloc) |a| {
                        a.free(src_data);
                        a.free(src_sid);
                    }
                    e.* = .{};

                    // Advance head if this was the head.
                    if (idx == self.head) {
                        self.head = (self.head + 1) % capacity;
                    }
                    self.count -= 1;

                    return .{
                        .message_type = mt,
                        .data = d,
                        .sender_id = s,
                    };
                }
                idx = (idx + 1) % capacity;
            }
            return null;
        }

        const vtable: Transport.VTable = .{
            .send = &sendFn,
            .receive = &receiveFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "LoopbackTransport: send/receive round-trip" {
    var lt = LoopbackTransport(8).init();
    defer lt.deinit();
    lt.setSender("alice");
    const t = lt.transport();
    const io = testIo();

    try t.send(io, "group-1", .application, "hello");

    var env = (try t.receive(
        testing.allocator,
        io,
        "group-1",
    )) orelse return error.TestUnexpectedResult;
    defer env.deinit(testing.allocator);

    try testing.expectEqual(MessageType.application, env.message_type);
    try testing.expectEqualSlices(u8, "hello", env.data);
    try testing.expectEqualSlices(u8, "alice", env.sender_id);
}

test "LoopbackTransport: receive returns null when empty" {
    var lt = LoopbackTransport(4).init();
    defer lt.deinit();
    const t = lt.transport();
    const io = testIo();

    const env = try t.receive(
        testing.allocator,
        io,
        "group-1",
    );
    try testing.expectEqual(null, env);
}

test "LoopbackTransport: FIFO ordering" {
    var lt = LoopbackTransport(8).init();
    defer lt.deinit();
    lt.setSender("bob");
    const t = lt.transport();
    const io = testIo();

    try t.send(io, "g", .commit, "first");
    try t.send(io, "g", .proposal, "second");

    var e1 = (try t.receive(
        testing.allocator,
        io,
        "g",
    )) orelse return error.TestUnexpectedResult;
    defer e1.deinit(testing.allocator);

    var e2 = (try t.receive(
        testing.allocator,
        io,
        "g",
    )) orelse return error.TestUnexpectedResult;
    defer e2.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, "first", e1.data);
    try testing.expectEqual(MessageType.commit, e1.message_type);
    try testing.expectEqualSlices(u8, "second", e2.data);
    try testing.expectEqual(MessageType.proposal, e2.message_type);
}
