//! KeyPackageDirectory — Server-side KeyPackage registry.
//!
//! Stores KeyPackages uploaded by clients. `fetch` is
//! single-use: it consumes the KeyPackage on retrieval.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const KeyPackageDirectory = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        store: *const fn (
            context: *anyopaque,
            io: Io,
            owner_id: []const u8,
            key_package_bytes: []const u8,
        ) Error!void,
        fetch: *const fn (
            context: *anyopaque,
            allocator: Allocator,
            io: Io,
            owner_id: []const u8,
        ) Error!?[]u8,
    };

    pub const Error = Io.Cancelable || error{
        StorageFault,
    };

    pub fn store(
        self: KeyPackageDirectory,
        io: Io,
        owner_id: []const u8,
        key_package_bytes: []const u8,
    ) Error!void {
        return self.vtable.store(
            self.context,
            io,
            owner_id,
            key_package_bytes,
        );
    }

    /// Fetch and consume a KeyPackage for `owner_id`.
    /// Returns `null` if no KeyPackage is available.
    /// The caller owns the returned slice.
    pub fn fetch(
        self: KeyPackageDirectory,
        allocator: Allocator,
        io: Io,
        owner_id: []const u8,
    ) Error!?[]u8 {
        return self.vtable.fetch(
            self.context,
            allocator,
            io,
            owner_id,
        );
    }
};

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

const NoOpKPDir = struct {
    fn storeFn(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: []const u8,
    ) KeyPackageDirectory.Error!void {}

    fn fetchFn(
        _: *anyopaque,
        _: Allocator,
        _: Io,
        _: []const u8,
    ) KeyPackageDirectory.Error!?[]u8 {
        return null;
    }

    const vtable: KeyPackageDirectory.VTable = .{
        .store = &storeFn,
        .fetch = &fetchFn,
    };
};

test "KeyPackageDirectory: no-op stub is callable" {
    var dummy: u8 = 0;
    const kpd = KeyPackageDirectory{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpKPDir.vtable,
    };
    const io = testIo();

    try kpd.store(io, "bob", "kp-bytes");
    const fetched = try kpd.fetch(
        testing.allocator,
        io,
        "bob",
    );
    try testing.expectEqual(null, fetched);
}
