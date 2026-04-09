//! In-memory bounded private key store.
//!
//! Fixed-capacity adapter for `KeyStore(P)`. All keys are
//! `secureZero`d on removal and in `deinit`. Keys are stored
//! in fixed-size arrays — no heap allocation for key material.

const std = @import("std");
const Io = std.Io;
const key_store_mod = @import("../ports/key_store.zig");

fn secureZeroSlice(buf: []u8) void {
    std.crypto.secureZero(u8, @volatileCast(buf));
}

/// Hash an identity or composite key to a fixed-size lookup key.
const KeyHash = [32]u8;

fn hashId(id: []const u8) KeyHash {
    var out: KeyHash = undefined;
    std.crypto.hash.sha2.Sha256.hash(id, &out, .{});
    return out;
}

/// Hash a (group_id, leaf_index) pair for encryption key lookup.
fn hashGroupLeaf(group_id: []const u8, leaf: u32) KeyHash {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(group_id);
    const leaf_bytes = std.mem.asBytes(&leaf);
    h.update(leaf_bytes);
    var out: KeyHash = undefined;
    h.final(&out);
    return out;
}

/// Bounded in-memory private key store.
pub fn MemoryKeyStore(comptime P: type, comptime capacity: u32) type {
    const KS = key_store_mod.KeyStore(P);

    return struct {
        const Self = @This();

        const SigEntry = struct {
            occupied: bool = false,
            key_hash: KeyHash = .{0} ** 32,
            secret: [P.sign_sk_len]u8 = .{0} ** P.sign_sk_len,
        };

        const EncEntry = struct {
            occupied: bool = false,
            key_hash: KeyHash = .{0} ** 32,
            secret: [P.nsk]u8 = .{0} ** P.nsk,
        };

        sig_entries: [capacity]SigEntry =
            [_]SigEntry{.{}} ** capacity,
        enc_entries: [capacity]EncEntry =
            [_]EncEntry{.{}} ** capacity,

        pub fn init() Self {
            return .{};
        }

        pub fn deinit(self: *Self) void {
            for (&self.sig_entries) |*e| {
                secureZeroSlice(&e.secret);
                e.* = .{};
            }
            for (&self.enc_entries) |*e| {
                secureZeroSlice(&e.secret);
                e.* = .{};
            }
        }

        pub fn keyStore(self: *Self) KS {
            return .{
                .context = @ptrCast(self),
                .vtable = &vtable,
            };
        }

        // ── Signature key operations ───────────────────

        fn findSig(
            self: *Self,
            kh: KeyHash,
        ) ?*SigEntry {
            for (&self.sig_entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.key_hash, &kh))
                    return e;
            }
            return null;
        }

        fn findFreeSig(self: *Self) ?*SigEntry {
            for (&self.sig_entries) |*e| {
                if (!e.occupied) return e;
            }
            return null;
        }

        fn storeSigFn(
            ctx: *anyopaque,
            _: Io,
            identity: []const u8,
            key: *const [P.sign_sk_len]u8,
        ) KS.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashId(identity);
            const slot = self.findSig(kh) orelse
                self.findFreeSig() orelse
                return error.StorageFault;

            // secureZero old if overwriting.
            if (slot.occupied) secureZeroSlice(&slot.secret);

            slot.occupied = true;
            slot.key_hash = kh;
            slot.secret = key.*;
        }

        fn loadSigFn(
            ctx: *anyopaque,
            _: Io,
            identity: []const u8,
            out: *[P.sign_sk_len]u8,
        ) KS.Error!bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashId(identity);
            const slot = self.findSig(kh) orelse return false;
            out.* = slot.secret;
            return true;
        }

        // ── Encryption key operations ──────────────────

        fn findEnc(
            self: *Self,
            kh: KeyHash,
        ) ?*EncEntry {
            for (&self.enc_entries) |*e| {
                if (e.occupied and
                    std.mem.eql(u8, &e.key_hash, &kh))
                    return e;
            }
            return null;
        }

        fn findFreeEnc(self: *Self) ?*EncEntry {
            for (&self.enc_entries) |*e| {
                if (!e.occupied) return e;
            }
            return null;
        }

        fn storeEncFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            leaf_index: u32,
            key: *const [P.nsk]u8,
        ) KS.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashGroupLeaf(group_id, leaf_index);
            const slot = self.findEnc(kh) orelse
                self.findFreeEnc() orelse
                return error.StorageFault;

            if (slot.occupied) secureZeroSlice(&slot.secret);

            slot.occupied = true;
            slot.key_hash = kh;
            slot.secret = key.*;
        }

        fn loadEncFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            leaf_index: u32,
            out: *[P.nsk]u8,
        ) KS.Error!bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashGroupLeaf(group_id, leaf_index);
            const slot = self.findEnc(kh) orelse return false;
            out.* = slot.secret;
            return true;
        }

        fn deleteEncFn(
            ctx: *anyopaque,
            _: Io,
            group_id: []const u8,
            leaf_index: u32,
        ) KS.Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const kh = hashGroupLeaf(group_id, leaf_index);
            const slot = self.findEnc(kh) orelse return;
            secureZeroSlice(&slot.secret);
            slot.* = .{};
        }

        const vtable: KS.VTable = .{
            .store_signature_key = &storeSigFn,
            .load_signature_key = &loadSigFn,
            .store_encryption_key = &storeEncFn,
            .load_encryption_key = &loadEncFn,
            .delete_encryption_key = &deleteEncFn,
        };
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

/// Minimal stub CryptoProvider for tests.
const StubP = struct {
    pub const nh: u32 = 32;
    pub const nk: u32 = 16;
    pub const nn: u32 = 12;
    pub const nsk: u32 = 32;
    pub const sign_sk_len: u32 = 64;
};

test "MemoryKeyStore: signature key store/load round-trip" {
    var store = MemoryKeyStore(StubP, 8).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    const key: [StubP.sign_sk_len]u8 = .{0xAB} ** StubP.sign_sk_len;
    try ks.storeSignatureKey(io, "alice", &key);

    var out: [StubP.sign_sk_len]u8 = undefined;
    const found = try ks.loadSignatureKey(io, "alice", &out);
    try testing.expect(found);
    try testing.expectEqualSlices(u8, &key, &out);
}

test "MemoryKeyStore: encryption key store/load round-trip" {
    var store = MemoryKeyStore(StubP, 8).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    const key: [StubP.nsk]u8 = .{0xCD} ** StubP.nsk;
    try ks.storeEncryptionKey(io, "group-1", 3, &key);

    var out: [StubP.nsk]u8 = undefined;
    const found = try ks.loadEncryptionKey(
        io,
        "group-1",
        3,
        &out,
    );
    try testing.expect(found);
    try testing.expectEqualSlices(u8, &key, &out);
}

test "MemoryKeyStore: load returns false for unknown" {
    var store = MemoryKeyStore(StubP, 4).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    var out: [StubP.sign_sk_len]u8 = undefined;
    const found = try ks.loadSignatureKey(
        io,
        "nonexistent",
        &out,
    );
    try testing.expect(!found);
}

test "MemoryKeyStore: overwrite existing key" {
    var store = MemoryKeyStore(StubP, 4).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    const k1: [StubP.sign_sk_len]u8 = .{0x11} ** StubP.sign_sk_len;
    const k2: [StubP.sign_sk_len]u8 = .{0x22} ** StubP.sign_sk_len;

    try ks.storeSignatureKey(io, "alice", &k1);
    try ks.storeSignatureKey(io, "alice", &k2);

    var out: [StubP.sign_sk_len]u8 = undefined;
    const found = try ks.loadSignatureKey(io, "alice", &out);
    try testing.expect(found);
    try testing.expectEqualSlices(u8, &k2, &out);
}

test "MemoryKeyStore: delete encryption key" {
    var store = MemoryKeyStore(StubP, 4).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    const key: [StubP.nsk]u8 = .{0xEE} ** StubP.nsk;
    try ks.storeEncryptionKey(io, "group-1", 5, &key);

    // Key is retrievable before delete.
    var out: [StubP.nsk]u8 = undefined;
    try testing.expect(
        try ks.loadEncryptionKey(io, "group-1", 5, &out),
    );
    try testing.expectEqualSlices(u8, &key, &out);

    // Delete the key.
    try ks.deleteEncryptionKey(io, "group-1", 5);

    // Key is gone after delete.
    try testing.expect(
        !try ks.loadEncryptionKey(io, "group-1", 5, &out),
    );
}

test "MemoryKeyStore: delete is idempotent" {
    var store = MemoryKeyStore(StubP, 4).init();
    defer store.deinit();
    const ks = store.keyStore();
    const io = testIo();

    // Delete non-existent key — no error.
    try ks.deleteEncryptionKey(io, "group-1", 99);
}
