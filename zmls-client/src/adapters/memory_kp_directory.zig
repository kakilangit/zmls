//! In-memory bounded KeyPackage directory.
//!
//! Fixed-capacity adapter for `KeyPackageDirectory`. `fetch`
//! consumes the entry (single-use KeyPackage semantics per
//! RFC 9420).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const KeyPackageDirectory =
    @import("../ports/kp_directory.zig").KeyPackageDirectory;

const KeyHash = [32]u8;

fn hashBytes(data: []const u8) KeyHash {
    var out: KeyHash = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &out, .{});
    return out;
}

/// Bounded in-memory KeyPackage directory.
pub fn MemoryKeyPackageDirectory(comptime capacity: u32) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            occupied: bool = false,
            owner_hash: KeyHash = .{0} ** 32,
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

        pub fn keyPackageDirectory(
            self: *Self,
        ) KeyPackageDirectory {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        fn storeFn(
            ctx: *anyopaque,
            _: Io,
            owner_id: []const u8,
            key_package_bytes: []const u8,
        ) KeyPackageDirectory.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashBytes(owner_id);

            // Find existing or free slot.
            var slot: ?*Entry = null;
            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.owner_hash, &kh))
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
            const copy = alloc.alloc(
                u8,
                key_package_bytes.len,
            ) catch return error.StorageFault;
            @memcpy(copy, key_package_bytes);

            s.occupied = true;
            s.owner_hash = kh;
            s.data = copy;
            s.alloc = alloc;
        }

        /// Fetch and consume: returns ownership to caller,
        /// removes from directory (single-use semantics).
        fn fetchFn(
            ctx: *anyopaque,
            allocator: Allocator,
            _: Io,
            owner_id: []const u8,
        ) KeyPackageDirectory.Error!?[]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashBytes(owner_id);

            for (&self.entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.owner_hash, &kh))
                {
                    const src = e.data orelse return null;
                    const copy = allocator.alloc(
                        u8,
                        src.len,
                    ) catch return error.StorageFault;
                    @memcpy(copy, src);

                    // Consume: free internal and clear slot.
                    if (e.alloc) |a| a.free(src);
                    e.* = .{};

                    return copy;
                }
            }
            return null;
        }

        const vtable: KeyPackageDirectory.VTable = .{
            .store = &storeFn,
            .fetch = &fetchFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

test "MemoryKeyPackageDirectory: store/fetch/consume" {
    var dir = MemoryKeyPackageDirectory(8).init();
    defer dir.deinit();
    const kpd = dir.keyPackageDirectory();
    const io = testIo();

    try kpd.store(io, "bob", "bob-key-package");

    // First fetch succeeds.
    const fetched = try kpd.fetch(
        testing.allocator,
        io,
        "bob",
    );
    defer if (fetched) |f| testing.allocator.free(f);
    try testing.expect(fetched != null);
    try testing.expectEqualSlices(
        u8,
        "bob-key-package",
        fetched.?,
    );

    // Second fetch returns null (consumed).
    const again = try kpd.fetch(
        testing.allocator,
        io,
        "bob",
    );
    try testing.expectEqual(null, again);
}

test "MemoryKeyPackageDirectory: fetch unknown returns null" {
    var dir = MemoryKeyPackageDirectory(4).init();
    defer dir.deinit();
    const kpd = dir.keyPackageDirectory();
    const io = testIo();

    const r = try kpd.fetch(
        testing.allocator,
        io,
        "unknown",
    );
    try testing.expectEqual(null, r);
}
