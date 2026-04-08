//! DeliveryService — Dumb relay for MLS messages.
//!
//! Routes opaque MLS messages between clients. Does NOT
//! depend on the zmls protocol core — it handles raw bytes
//! only. Not parameterized by CryptoProvider.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const GroupDirectory =
    @import("../ports/group_directory.zig").GroupDirectory;
const KeyPackageDirectory =
    @import("../ports/kp_directory.zig").KeyPackageDirectory;
const GroupInfoDirectory =
    @import("../ports/gi_directory.zig").GroupInfoDirectory;
const transport_mod = @import("../ports/transport.zig");
const MessageType = transport_mod.MessageType;
const ReceivedEnvelope = transport_mod.ReceivedEnvelope;
const ds_types = @import("types.zig");
const DeliveryServiceOptions = ds_types.DeliveryServiceOptions;

/// Delivery service (dumb relay).
///
/// Routes messages between group members, manages the
/// KeyPackage and GroupInfo directories. All message payloads
/// are opaque byte slices — the relay never interprets MLS
/// content.
pub const DeliveryService = struct {
    group_directory: GroupDirectory,
    kp_directory: KeyPackageDirectory,
    gi_directory: GroupInfoDirectory,
    options: DeliveryServiceOptions,
    allocator: Allocator,

    pub const Error = GroupDirectory.Error ||
        KeyPackageDirectory.Error ||
        GroupInfoDirectory.Error ||
        ds_types.DeliveryServiceError ||
        Allocator.Error;

    pub fn init(
        allocator: Allocator,
        group_directory: GroupDirectory,
        kp_directory: KeyPackageDirectory,
        gi_directory: GroupInfoDirectory,
        options: DeliveryServiceOptions,
    ) DeliveryService {
        return .{
            .group_directory = group_directory,
            .kp_directory = kp_directory,
            .gi_directory = gi_directory,
            .options = options,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *DeliveryService) void {
        self.* = undefined;
    }

    /// Route a message to all group members except sender.
    pub fn processMessage(
        self: *DeliveryService,
        io: Io,
        sender_id: []const u8,
        group_id: []const u8,
        message_type: MessageType,
        data: []const u8,
    ) Error!void {
        if (data.len > self.options.max_message_size)
            return error.MessageTooLarge;
        try self.group_directory.enqueue(
            io,
            group_id,
            sender_id,
            message_type,
            data,
        );
    }

    /// Fetch the next queued message for a member.
    pub fn fetchMessage(
        self: *DeliveryService,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
        member_id: []const u8,
    ) Error!?ReceivedEnvelope {
        return self.group_directory.dequeue(
            allocator,
            io,
            group_id,
            member_id,
        );
    }

    /// Upload a KeyPackage for later retrieval.
    pub fn uploadKeyPackage(
        self: *DeliveryService,
        io: Io,
        owner_id: []const u8,
        kp_bytes: []const u8,
    ) Error!void {
        if (kp_bytes.len > self.options.max_key_package_size)
            return error.KeyPackageTooLarge;
        try self.kp_directory.store(io, owner_id, kp_bytes);
    }

    /// Download (and consume) a KeyPackage.
    pub fn downloadKeyPackage(
        self: *DeliveryService,
        allocator: Allocator,
        io: Io,
        target_id: []const u8,
    ) Error!?[]u8 {
        return self.kp_directory.fetch(
            allocator,
            io,
            target_id,
        );
    }

    /// Publish GroupInfo for external joiners.
    pub fn publishGroupInfo(
        self: *DeliveryService,
        io: Io,
        group_id: []const u8,
        data: []const u8,
    ) Error!void {
        if (data.len > self.options.max_group_info_size)
            return error.GroupInfoTooLarge;
        try self.gi_directory.set(io, group_id, data);
    }

    /// Get published GroupInfo for a group.
    pub fn getGroupInfo(
        self: *DeliveryService,
        allocator: Allocator,
        io: Io,
        group_id: []const u8,
    ) Error!?[]u8 {
        return self.gi_directory.get(
            allocator,
            io,
            group_id,
        );
    }
};

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;
const MemGD = @import(
    "../adapters/memory_group_directory.zig",
).MemoryGroupDirectory;
const MemKPD = @import(
    "../adapters/memory_kp_directory.zig",
).MemoryKeyPackageDirectory;
const MemGID = @import(
    "../adapters/memory_gi_directory.zig",
).MemoryGroupInfoDirectory;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "DeliveryService: message routing" {
    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();
    const io = testIo();

    var ds = DeliveryService.init(
        testing.allocator,
        gd.groupDirectory(),
        kpd.keyPackageDirectory(),
        gid.groupInfoDirectory(),
        .{},
    );
    defer ds.deinit();

    // Set up a group.
    try ds.group_directory.createGroup(
        io,
        "g1",
        "alice",
    );
    try ds.group_directory.addMember(io, "g1", "bob");

    // Alice sends a message.
    try ds.processMessage(
        io,
        "alice",
        "g1",
        .application,
        "hello bob",
    );

    // Bob receives it.
    var env = (try ds.fetchMessage(
        testing.allocator,
        io,
        "g1",
        "bob",
    )) orelse return error.TestUnexpectedResult;
    defer env.deinit(testing.allocator);

    try testing.expectEqualSlices(u8, "hello bob", env.data);
    try testing.expectEqual(
        MessageType.application,
        env.message_type,
    );
}

test "DeliveryService: KP upload/download/consume" {
    var gd = MemGD(4, 4, 4).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();
    const io = testIo();

    var ds = DeliveryService.init(
        testing.allocator,
        gd.groupDirectory(),
        kpd.keyPackageDirectory(),
        gid.groupInfoDirectory(),
        .{},
    );
    defer ds.deinit();

    try ds.uploadKeyPackage(io, "bob", "bob-kp-data");

    const fetched = try ds.downloadKeyPackage(
        testing.allocator,
        io,
        "bob",
    );
    defer if (fetched) |f| testing.allocator.free(f);
    try testing.expectEqualSlices(
        u8,
        "bob-kp-data",
        fetched.?,
    );

    // Second fetch returns null (consumed).
    const again = try ds.downloadKeyPackage(
        testing.allocator,
        io,
        "bob",
    );
    try testing.expectEqual(null, again);
}

test "DeliveryService: GroupInfo publish/fetch" {
    var gd = MemGD(4, 4, 4).init();
    defer gd.deinit();
    var kpd = MemKPD(4).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();
    const io = testIo();

    var ds = DeliveryService.init(
        testing.allocator,
        gd.groupDirectory(),
        kpd.keyPackageDirectory(),
        gid.groupInfoDirectory(),
        .{},
    );
    defer ds.deinit();

    try ds.publishGroupInfo(io, "g1", "gi-blob");

    const got = try ds.getGroupInfo(
        testing.allocator,
        io,
        "g1",
    );
    defer if (got) |g| testing.allocator.free(g);
    try testing.expectEqualSlices(u8, "gi-blob", got.?);
}

test "DeliveryService: oversized message rejected" {
    var gd = MemGD(4, 4, 4).init();
    defer gd.deinit();
    var kpd = MemKPD(4).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();
    const io = testIo();

    var ds = DeliveryService.init(
        testing.allocator,
        gd.groupDirectory(),
        kpd.keyPackageDirectory(),
        gid.groupInfoDirectory(),
        .{ .max_message_size = 10 },
    );
    defer ds.deinit();

    try ds.group_directory.createGroup(
        io,
        "g1",
        "alice",
    );

    const result = ds.processMessage(
        io,
        "alice",
        "g1",
        .application,
        "this is way too long for 10 bytes",
    );
    try testing.expectError(error.MessageTooLarge, result);
}
