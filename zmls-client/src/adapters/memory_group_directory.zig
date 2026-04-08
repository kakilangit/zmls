//! In-memory bounded group directory.
//!
//! Fixed-capacity adapter for `GroupDirectory`. Tracks groups,
//! members, and per-member message queues for the delivery
//! service.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const transport_mod = @import("../ports/transport.zig");
const MessageType = transport_mod.MessageType;
const ReceivedEnvelope = transport_mod.ReceivedEnvelope;
const GroupDirectory =
    @import("../ports/group_directory.zig").GroupDirectory;

const KeyHash = [32]u8;

fn hashBytes(data: []const u8) KeyHash {
    var out: KeyHash = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

/// Bounded in-memory group directory.
///
/// - `group_cap`: max groups.
/// - `member_cap`: max members per group.
/// - `queue_cap`: max queued messages per member.
pub fn MemoryGroupDirectory(
    comptime group_cap: u32,
    comptime member_cap: u32,
    comptime queue_cap: u32,
) type {
    return struct {
        const Self = @This();

        const QueueMsg = struct {
            occupied: bool = false,
            message_type: MessageType = .commit,
            data: ?[]u8 = null,
            sender_id: ?[]u8 = null,
            alloc: ?Allocator = null,
        };

        const Member = struct {
            occupied: bool = false,
            id_hash: KeyHash = .{0} ** 32,
            queue: [queue_cap]QueueMsg =
                [_]QueueMsg{.{}} ** queue_cap,
            q_head: u32 = 0,
            q_tail: u32 = 0,
            q_count: u32 = 0,
        };

        const Group = struct {
            occupied: bool = false,
            id_hash: KeyHash = .{0} ** 32,
            members: [member_cap]Member =
                [_]Member{.{}} ** member_cap,
        };

        groups: [group_cap]Group =
            [_]Group{.{}} ** group_cap,

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self) void {
            for (&self.groups) |*g| {
                Self.freeGroup(g);
            }
        }

        fn freeGroup(g: *Group) void {
            for (&g.members) |*m| Self.freeMember(m);
            g.* = .{};
        }

        fn freeMember(m: *Member) void {
            for (&m.queue) |*q| {
                if (q.data) |d| if (q.alloc) |a| a.free(d);
                if (q.sender_id) |s| {
                    if (q.alloc) |a| a.free(s);
                }
                q.* = .{};
            }
            m.* = .{};
        }

        pub fn groupDirectory(self: *Self) GroupDirectory {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        fn findGroup(self: *Self, kh: KeyHash) ?*Group {
            for (&self.groups) |*g| {
                if (g.occupied and
                    std.mem.eql(u8, &g.id_hash, &kh))
                    return g;
            }
            return null;
        }

        fn findMember(
            g: *Group,
            kh: KeyHash,
        ) ?*Member {
            for (&g.members) |*m| {
                if (m.occupied and
                    std.mem.eql(u8, &m.id_hash, &kh))
                    return m;
            }
            return null;
        }

        fn createGroupFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            creator_id: []const u8,
        ) GroupDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const gkh = hashBytes(group_id);

            // Find free group slot.
            var slot: ?*Group = null;
            for (&self.groups) |*g| {
                if (!g.occupied) {
                    slot = g;
                    break;
                }
            }
            const g = slot orelse return error.StorageFault;

            g.occupied = true;
            g.id_hash = gkh;
            g.members = [_]Member{.{}} ** member_cap;

            // Add creator as first member.
            g.members[0] = .{
                .occupied = true,
                .id_hash = hashBytes(creator_id),
            };
        }

        fn addMemberFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) GroupDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const g = self.findGroup(hashBytes(group_id)) orelse
                return error.GroupNotFound;
            const mkh = hashBytes(member_id);

            // Check if already a member.
            if (findMember(g, mkh) != null) return;

            // Find free member slot.
            for (&g.members) |*m| {
                if (!m.occupied) {
                    m.occupied = true;
                    m.id_hash = mkh;
                    return;
                }
            }
            return error.StorageFault; // member_cap reached
        }

        fn removeMemberFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) GroupDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const g = self.findGroup(hashBytes(group_id)) orelse
                return error.GroupNotFound;
            const m = findMember(g, hashBytes(member_id)) orelse
                return;
            Self.freeMember(m);
        }

        fn enqueueFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            sender_id: []const u8,
            message_type: MessageType,
            data: []const u8,
        ) GroupDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const g = self.findGroup(hashBytes(group_id)) orelse
                return error.GroupNotFound;
            const sid_hash = hashBytes(sender_id);
            const alloc = std.heap.page_allocator;

            // Enqueue for every member except the sender.
            for (&g.members) |*m| {
                if (!m.occupied) continue;
                if (std.mem.eql(u8, &m.id_hash, &sid_hash))
                    continue;
                if (m.q_count >= queue_cap)
                    return error.QueueFull;

                const d = alloc.alloc(u8, data.len) catch
                    return error.StorageFault;
                @memcpy(d, data);
                const s = alloc.alloc(
                    u8,
                    sender_id.len,
                ) catch {
                    alloc.free(d);
                    return error.StorageFault;
                };
                @memcpy(s, sender_id);

                m.queue[m.q_tail] = .{
                    .occupied = true,
                    .message_type = message_type,
                    .data = d,
                    .sender_id = s,
                    .alloc = alloc,
                };
                m.q_tail = (m.q_tail + 1) % queue_cap;
                m.q_count += 1;
            }
        }

        fn dequeueFn(
            ctx: *anyopaque,
            allocator: Allocator,
            _: Io,
            group_id: []const u8,
            member_id: []const u8,
        ) GroupDirectory.Error!?ReceivedEnvelope {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const g = self.findGroup(hashBytes(group_id)) orelse
                return error.GroupNotFound;
            const m = findMember(g, hashBytes(member_id)) orelse
                return error.MemberNotFound;
            if (m.q_count == 0) return null;

            const e = &m.queue[m.q_head];
            const src_d = e.data orelse return null;
            const src_s = e.sender_id orelse return null;

            const d = allocator.alloc(u8, src_d.len) catch
                return error.StorageFault;
            errdefer allocator.free(d);
            @memcpy(d, src_d);

            const s = allocator.alloc(u8, src_s.len) catch
                return error.StorageFault;
            @memcpy(s, src_s);

            const mt = e.message_type;

            // Free internal copy.
            if (e.alloc) |a| {
                a.free(src_d);
                a.free(src_s);
            }
            e.* = .{};
            m.q_head = (m.q_head + 1) % queue_cap;
            m.q_count -= 1;

            return .{
                .message_type = mt,
                .data = d,
                .sender_id = s,
            };
        }

        const vtable: GroupDirectory.VTable = .{
            .create_group = &createGroupFn,
            .add_member = &addMemberFn,
            .remove_member = &removeMemberFn,
            .enqueue = &enqueueFn,
            .dequeue = &dequeueFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "MemoryGroupDirectory: create/enqueue/dequeue" {
    var dir = MemoryGroupDirectory(4, 8, 16).init();
    defer dir.deinit();
    const gd = dir.groupDirectory();
    const io = testIo();

    try gd.createGroup(io, "group-1", "alice");
    try gd.addMember(io, "group-1", "bob");
    try gd.enqueue(io, "group-1", "alice", .commit, "msg1");

    // Alice sent, so Bob should receive.
    var env = (try gd.dequeue(
        testing.allocator,
        io,
        "group-1",
        "bob",
    )) orelse return error.TestUnexpectedResult;
    defer env.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, "msg1", env.data);
    try testing.expectEqualSlices(u8, "alice", env.sender_id);
    try testing.expectEqual(MessageType.commit, env.message_type);

    // Alice should NOT receive her own message.
    const self_msg = try gd.dequeue(
        testing.allocator,
        io,
        "group-1",
        "alice",
    );
    try testing.expectEqual(null, self_msg);
}

test "MemoryGroupDirectory: dequeue returns null when empty" {
    var dir = MemoryGroupDirectory(4, 4, 4).init();
    defer dir.deinit();
    const gd = dir.groupDirectory();
    const io = testIo();

    try gd.createGroup(io, "g", "alice");
    const env = try gd.dequeue(
        testing.allocator,
        io,
        "g",
        "alice",
    );
    try testing.expectEqual(null, env);
}

test "MemoryGroupDirectory: remove member" {
    var dir = MemoryGroupDirectory(4, 4, 4).init();
    defer dir.deinit();
    const gd = dir.groupDirectory();
    const io = testIo();

    try gd.createGroup(io, "g", "alice");
    try gd.addMember(io, "g", "bob");
    try gd.removeMember(io, "g", "bob");

    // Enqueue after removal should not fail (bob is gone).
    try gd.enqueue(io, "g", "alice", .application, "data");
}
