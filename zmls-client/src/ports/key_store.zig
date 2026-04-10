//! KeyStore — Private key persistence port.
//!
//! Comptime-generic over `CryptoProvider` P so that key sizes
//! are known at compile time. Keys are passed via fixed-size
//! pointers — no heap allocation for key material.

const std = @import("std");
const Io = std.Io;

pub fn KeyStore(comptime P: type) type {
    return struct {
        context: *anyopaque,
        vtable: *const VTable,

        const Self = @This();

        pub const VTable = struct {
            store_signature_key: *const fn (
                context: *anyopaque,
                io: Io,
                identity: []const u8,
                key: *const [P.sign_sk_len]u8,
            ) Error!void,
            load_signature_key: *const fn (
                context: *anyopaque,
                io: Io,
                identity: []const u8,
                out: *[P.sign_sk_len]u8,
            ) Error!bool,
            store_encryption_key: *const fn (
                context: *anyopaque,
                io: Io,
                group_id: []const u8,
                leaf_index: u32,
                key: *const [P.nsk]u8,
            ) Error!void,
            load_encryption_key: *const fn (
                context: *anyopaque,
                io: Io,
                group_id: []const u8,
                leaf_index: u32,
                out: *[P.nsk]u8,
            ) Error!bool,
            delete_encryption_key: *const fn (
                context: *anyopaque,
                io: Io,
                group_id: []const u8,
                leaf_index: u32,
            ) Error!void,
        };

        pub const Error = Io.Cancelable || error{
            StorageFault,
            KeyNotFound,
        };

        pub fn storeSignatureKey(
            self: Self,
            io: Io,
            identity: []const u8,
            key: *const [P.sign_sk_len]u8,
        ) Error!void {
            return self.vtable.store_signature_key(
                self.context,
                io,
                identity,
                key,
            );
        }

        pub fn loadSignatureKey(
            self: Self,
            io: Io,
            identity: []const u8,
            out: *[P.sign_sk_len]u8,
        ) Error!bool {
            return self.vtable.load_signature_key(
                self.context,
                io,
                identity,
                out,
            );
        }

        pub fn storeEncryptionKey(
            self: Self,
            io: Io,
            group_id: []const u8,
            leaf_index: u32,
            key: *const [P.nsk]u8,
        ) Error!void {
            return self.vtable.store_encryption_key(
                self.context,
                io,
                group_id,
                leaf_index,
                key,
            );
        }

        pub fn loadEncryptionKey(
            self: Self,
            io: Io,
            group_id: []const u8,
            leaf_index: u32,
            out: *[P.nsk]u8,
        ) Error!bool {
            return self.vtable.load_encryption_key(
                self.context,
                io,
                group_id,
                leaf_index,
                out,
            );
        }

        /// Delete an encryption key for a (group, leaf) pair.
        /// Idempotent — succeeds even if no key is stored.
        /// The implementation must secureZero the key before
        /// freeing the slot.
        pub fn deleteEncryptionKey(
            self: Self,
            io: Io,
            group_id: []const u8,
            leaf_index: u32,
        ) Error!void {
            return self.vtable.delete_encryption_key(
                self.context,
                io,
                group_id,
                leaf_index,
            );
        }
    };
}

// ── Tests ──────────────────────────────────────────────────

const testing = std.testing;

fn testIo() Io {
    var threaded: Io.Threaded = Io.Threaded.init_single_threaded;
    return threaded.io();
}

/// Minimal stub CryptoProvider for key size resolution.
const StubP = struct {
    pub const nh: u32 = 32;
    pub const nk: u32 = 16;
    pub const nn: u32 = 12;
    pub const nsk: u32 = 32;
    pub const sign_sk_len: u32 = 64;
};

const StubKS = KeyStore(StubP);

const NoOpKeyStore = struct {
    fn storeSig(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: *const [StubP.sign_sk_len]u8,
    ) StubKS.Error!void {}

    fn loadSig(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: *[StubP.sign_sk_len]u8,
    ) StubKS.Error!bool {
        return false;
    }

    fn storeEnc(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: u32,
        _: *const [StubP.nsk]u8,
    ) StubKS.Error!void {}

    fn loadEnc(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: u32,
        _: *[StubP.nsk]u8,
    ) StubKS.Error!bool {
        return false;
    }

    fn deleteEnc(
        _: *anyopaque,
        _: Io,
        _: []const u8,
        _: u32,
    ) StubKS.Error!void {}

    const vtable: StubKS.VTable = .{
        .store_signature_key = &storeSig,
        .load_signature_key = &loadSig,
        .store_encryption_key = &storeEnc,
        .load_encryption_key = &loadEnc,
        .delete_encryption_key = &deleteEnc,
    };
};

test "KeyStore: no-op stub is callable" {
    var dummy: u8 = 0;
    const ks = StubKS{
        .context = @ptrCast(&dummy),
        .vtable = &NoOpKeyStore.vtable,
    };
    const io = testIo();
    const sig_key: [StubP.sign_sk_len]u8 = .{0} ** StubP.sign_sk_len;
    try ks.storeSignatureKey(io, "alice", &sig_key);

    var out_sig: [StubP.sign_sk_len]u8 = undefined;
    const found_sig = try ks.loadSignatureKey(
        io,
        "alice",
        &out_sig,
    );
    try testing.expect(!found_sig);

    const enc_key: [StubP.nsk]u8 = .{0} ** StubP.nsk;
    try ks.storeEncryptionKey(io, "group-1", 0, &enc_key);

    var out_enc: [StubP.nsk]u8 = undefined;
    const found_enc = try ks.loadEncryptionKey(
        io,
        "group-1",
        0,
        &out_enc,
    );
    try testing.expect(!found_enc);
}
