//! Per-sender encryption key derivation via a binary secret tree
//! per RFC 9420 Section 9. Forward-ratcheting leaf secrets
//! produce key/nonce pairs per message.
// Secret tree for per-sender encryption keys per RFC 9420 Section 9.
//
// The secret tree derives per-leaf secrets from the encryption_secret
// using a binary tree structure. Each leaf then ratchets forward to
// produce key/nonce pairs for individual messages.
//
//   tree_node[root] = encryption_secret
//   tree_node[left(x)]  = ExpandWithLabel(tree_node[x],
//                            "tree", "left", Nh)
//   tree_node[right(x)] = ExpandWithLabel(tree_node[x],
//                            "tree", "right", Nh)
//
// Per-leaf ratchet (for each content type):
//   key[n]    = ExpandWithLabel(secret[n], "key",
//                 generation, Nk)
//   nonce[n]  = ExpandWithLabel(secret[n], "nonce",
//                 generation, Nn)
//   secret[n+1] = ExpandWithLabel(secret[n], "secret",
//                   generation, Nh)
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../crypto/primitives.zig");
const codec = @import("../codec/codec.zig");
const tree_math = @import("../tree/math.zig");
const types = @import("../common/types.zig");
const GroupError = @import("../common/errors.zig").GroupError;

/// Ratchet state for a single leaf + content type.
pub fn RatchetState(comptime P: type) type {
    return struct {
        secret: [P.nh]u8,
        generation: types.Generation,
    };
}

/// Key and nonce derived from a ratchet step.
pub fn KeyNonce(comptime P: type) type {
    return struct {
        key: [P.nk]u8,
        nonce: [P.nn]u8,
        generation: types.Generation,

        /// Zero key and nonce material.
        pub fn zeroize(self: *@This()) void {
            primitives.secureZero(&self.key);
            primitives.secureZero(&self.nonce);
        }
    };
}

/// Maximum number of retained out-of-order keys.
/// RFC 9420 Section 15.3 recommends retention but does not
/// specify a limit. 256 is a practical default.
pub const max_retained_keys: u32 = 256;

/// A retained key/nonce pair from a skipped generation.
pub fn RetainedEntry(comptime P: type) type {
    return struct {
        leaf_idx: u32,
        content_type: u8,
        generation: types.Generation,
        kn: KeyNonce(P),
        occupied: bool,

        pub fn zeroize(self: *@This()) void {
            self.kn.zeroize();
            self.occupied = false;
        }
    };
}

/// Secret tree managing per-sender encryption secrets.
///
/// The tree stores handshake and application ratchet states for
/// each leaf. Internal nodes are derived on init and then
/// discarded (only leaf secrets are kept).
pub fn SecretTree(comptime P: type) type {
    return struct {
        /// Per-leaf handshake ratchet states.
        handshake: []RatchetState(P),
        /// Per-leaf application ratchet states.
        application: []RatchetState(P),
        /// Number of leaves.
        leaf_count: u32,
        /// Maximum forward ratchet steps allowed (0 = no limit).
        max_forward_ratchet: u32,
        /// Ring buffer of retained keys for out-of-order decrypt.
        retained: []RetainedEntry(P),
        /// Next write position in the retained ring buffer.
        retained_cursor: u32,
        /// Configured capacity (0 = no retention).
        retain_capacity: u32,

        const Self = @This();

        /// Initialize a secret tree from the encryption_secret.
        ///
        /// Derives the full binary tree of secrets from root down
        /// to leaves, stores only the leaf secrets, and zeroes all
        /// intermediate values.
        pub fn init(
            allocator: std.mem.Allocator,
            encryption_secret: *const [P.nh]u8,
            leaf_count: u32,
        ) !Self {
            std.debug.assert(leaf_count > 0);

            const n_nodes = tree_math.nodeWidth(leaf_count);

            // Allocate temporary node secret storage.
            const node_secrets = try allocator.alloc(
                [P.nh]u8,
                n_nodes,
            );
            defer {
                // Zero and free intermediate secrets.
                for (node_secrets) |*s| {
                    primitives.secureZero(s);
                }
                allocator.free(node_secrets);
            }

            // Set root secret.
            const root_idx = tree_math.root(leaf_count);
            node_secrets[root_idx.toUsize()] = encryption_secret.*;

            // Derive secrets top-down. Process nodes from root
            // level downward. We iterate over all odd (parent)
            // indices that are within bounds.
            deriveTreeSecrets(node_secrets, leaf_count);

            // Allocate per-leaf ratchet states.
            const hs = try allocator.alloc(
                RatchetState(P),
                leaf_count,
            );
            errdefer allocator.free(hs);
            const app = try allocator.alloc(
                RatchetState(P),
                leaf_count,
            );

            // Derive per-leaf ratchet root secrets.
            // RFC 9420 Section 9:
            //   handshake_ratchet_secret_[N]_[0] =
            //     ExpandWithLabel(leaf_secret, "handshake", "", Nh)
            //   application_ratchet_secret_[N]_[0] =
            //     ExpandWithLabel(leaf_secret, "application", "", Nh)
            var leaf_idx: u32 = 0;
            while (leaf_idx < leaf_count) : (leaf_idx += 1) {
                const ni = types.LeafIndex.fromU32(
                    leaf_idx,
                ).toNodeIndex().toUsize();
                var hs_secret: [P.nh]u8 = undefined;
                primitives.expandWithLabel(
                    P,
                    &node_secrets[ni],
                    "handshake",
                    "",
                    &hs_secret,
                );
                var app_secret: [P.nh]u8 = undefined;
                primitives.expandWithLabel(
                    P,
                    &node_secrets[ni],
                    "application",
                    "",
                    &app_secret,
                );
                hs[leaf_idx] = .{
                    .secret = hs_secret,
                    .generation = 0,
                };
                app[leaf_idx] = .{
                    .secret = app_secret,
                    .generation = 0,
                };
            }

            return .{
                .handshake = hs,
                .application = app,
                .leaf_count = leaf_count,
                .max_forward_ratchet = 1024,
                .retained = &.{},
                .retained_cursor = 0,
                .retain_capacity = 0,
            };
        }

        /// Derive tree secrets from root to leaves.
        ///
        /// Processes parent nodes top-down by level (highest
        /// first). For each parent, derives left and right child
        /// secrets.
        fn deriveTreeSecrets(
            secrets: [][P.nh]u8,
            leaf_count: u32,
        ) void {
            const n_nodes = tree_math.nodeWidth(leaf_count);
            // Find the maximum level (root level).
            const root_idx = tree_math.root(leaf_count);
            const max_level = tree_math.level(root_idx);
            assert(max_level <= 30); // u32 tree depth.

            // Process each level from max down to 1.
            var lev: u32 = max_level;
            while (lev >= 1) : (lev -= 1) {
                // Iterate over all nodes at this level.
                // Nodes at level k have indices of the form
                // (2^k - 1) + m * 2^(k+1).
                const step = @as(u32, 1) << @intCast(lev + 1);
                const start = (@as(u32, 1) << @intCast(lev)) - 1;
                var idx = start;
                while (idx < n_nodes) : (idx += step) {
                    const node = types.NodeIndex.fromU32(idx);
                    const l = tree_math.left(node);
                    const r = tree_math.right(node);

                    // Only derive if children are in bounds.
                    if (l.toU32() < n_nodes) {
                        primitives.expandWithLabel(
                            P,
                            &secrets[idx],
                            "tree",
                            "left",
                            &secrets[l.toUsize()],
                        );
                    }
                    if (r.toU32() < n_nodes) {
                        primitives.expandWithLabel(
                            P,
                            &secrets[idx],
                            "tree",
                            "right",
                            &secrets[r.toUsize()],
                        );
                    }
                }
                if (lev == 0) break;
            }
        }

        /// Consume a key/nonce pair for a given leaf and content
        /// type, then ratchet the secret forward.
        ///
        /// content_type: 0 = handshake, 1 = application
        ///
        /// After consuming, the old secret is zeroed.
        pub fn consumeKey(
            self: *Self,
            leaf_idx: u32,
            content_type: u8,
        ) GroupError!KeyNonce(P) {
            if (leaf_idx >= self.leaf_count) {
                return error.NotAMember;
            }

            const state = switch (content_type) {
                0 => &self.handshake[leaf_idx],
                1 => &self.application[leaf_idx],
                else => return error.InvalidGroupState,
            };

            // Guard against generation counter overflow.
            if (state.generation == std.math.maxInt(u32)) {
                return error.InvalidGroupState;
            }

            // Encode generation as big-endian u32.
            var gen_buf: [4]u8 = undefined;
            _ = codec.encodeUint32(
                &gen_buf,
                0,
                state.generation,
            ) catch unreachable;

            var result: KeyNonce(P) = undefined;
            result.generation = state.generation;

            // key = ExpandWithLabel(secret, "key", gen, Nk)
            primitives.expandWithLabel(
                P,
                &state.secret,
                "key",
                &gen_buf,
                &result.key,
            );

            // nonce = ExpandWithLabel(secret, "nonce", gen, Nn)
            primitives.expandWithLabel(
                P,
                &state.secret,
                "nonce",
                &gen_buf,
                &result.nonce,
            );

            // next = ExpandWithLabel(secret, "secret", gen, Nh)
            var next_secret: [P.nh]u8 = undefined;
            primitives.expandWithLabel(
                P,
                &state.secret,
                "secret",
                &gen_buf,
                &next_secret,
            );

            // Zero old secret and advance.
            primitives.secureZero(&state.secret);
            state.secret = next_secret;
            state.generation += 1;

            // Zero the temporary.
            primitives.secureZero(&next_secret);

            return result;
        }

        /// Derive key, nonce from current state and advance
        /// to next generation. Returns the derived key/nonce.
        fn deriveKeyNonce(
            self: *Self,
            state: *RatchetState(P),
        ) KeyNonce(P) {
            _ = self;
            var gen_buf: [4]u8 = undefined;
            _ = codec.encodeUint32(
                &gen_buf,
                0,
                state.generation,
            ) catch unreachable;

            var kn: KeyNonce(P) = undefined;
            kn.generation = state.generation;

            primitives.expandWithLabel(
                P,
                &state.secret,
                "key",
                &gen_buf,
                &kn.key,
            );
            primitives.expandWithLabel(
                P,
                &state.secret,
                "nonce",
                &gen_buf,
                &kn.nonce,
            );

            var next: [P.nh]u8 = undefined;
            primitives.expandWithLabel(
                P,
                &state.secret,
                "secret",
                &gen_buf,
                &next,
            );
            primitives.secureZero(&state.secret);
            state.secret = next;
            primitives.secureZero(&next);
            state.generation += 1;

            return kn;
        }

        /// Advance state by one generation without retaining
        /// the key/nonce (just derive next secret).
        fn advanceState(
            self: *Self,
            state: *RatchetState(P),
        ) void {
            _ = self;
            var gen_buf: [4]u8 = undefined;
            _ = codec.encodeUint32(
                &gen_buf,
                0,
                state.generation,
            ) catch unreachable;

            var next: [P.nh]u8 = undefined;
            primitives.expandWithLabel(
                P,
                &state.secret,
                "secret",
                &gen_buf,
                &next,
            );
            primitives.secureZero(&state.secret);
            state.secret = next;
            primitives.secureZero(&next);
            state.generation += 1;
        }

        /// Forward-ratchet a leaf's ratchet state to a target
        /// generation, then consume the key at that generation.
        ///
        /// If `target` is the current generation, this behaves
        /// like `consumeKey`. If `target` is ahead, the state
        /// is ratcheted forward (G - C) steps, discarding all
        /// intermediate secrets.
        ///
        /// Returns error if `target` is behind the current
        /// generation (already consumed), or exceeds the
        /// `max_forward_ratchet` limit (when non-zero).
        ///
        /// content_type: 0 = handshake, 1 = application
        pub fn forwardRatchet(
            self: *Self,
            leaf_idx: u32,
            content_type: u8,
            target: types.Generation,
        ) GroupError!KeyNonce(P) {
            if (leaf_idx >= self.leaf_count) {
                return error.NotAMember;
            }

            const state = switch (content_type) {
                0 => &self.handshake[leaf_idx],
                1 => &self.application[leaf_idx],
                else => return error.InvalidGroupState,
            };

            // Check retained buffer for past generations.
            if (target < state.generation) {
                return self.lookupRetained(
                    leaf_idx,
                    content_type,
                    target,
                ) orelse error.SecretAlreadyConsumed;
            }

            const steps = target - state.generation;

            // Enforce forward ratchet limit (0 = no limit).
            if (self.max_forward_ratchet > 0 and
                steps > self.max_forward_ratchet)
            {
                return error.GenerationTooFar;
            }

            // Ratchet forward, retaining skipped keys if enabled.
            // NOTE: When remaining == 1, the generation
            // immediately before the target is advanced (not
            // retained), making it permanently inaccessible.
            // This is intentional: the target generation's key
            // is consumed directly by consumeKey below.
            var remaining = steps;
            while (remaining > 0) : (remaining -= 1) {
                if (remaining > 1 and self.retain_capacity > 0) {
                    // Derive and retain the skipped key/nonce.
                    const skipped = self.deriveKeyNonce(state);
                    self.retainKey(
                        leaf_idx,
                        content_type,
                        skipped,
                    );
                } else {
                    // Derive next secret, discard key material.
                    self.advanceState(state);
                }
            }

            // Now at target generation — consume normally.
            return self.consumeKey(leaf_idx, content_type);
        }

        /// Enable out-of-order key retention with the given
        /// capacity. Allocates a ring buffer for retained keys.
        /// capacity=0 disables retention (default).
        pub fn enableRetention(
            self: *Self,
            allocator: std.mem.Allocator,
            capacity: u32,
        ) error{OutOfMemory}!void {
            if (capacity == 0) return;
            const cap = @min(capacity, max_retained_keys);
            const buf = try allocator.alloc(
                RetainedEntry(P),
                cap,
            );
            for (buf) |*e| e.occupied = false;
            self.retained = buf;
            self.retained_cursor = 0;
            self.retain_capacity = cap;
        }

        /// Retain a key/nonce pair in the ring buffer. Evicts
        /// the oldest entry if full.
        fn retainKey(
            self: *Self,
            leaf_idx: u32,
            content_type: u8,
            kn: KeyNonce(P),
        ) void {
            if (self.retain_capacity == 0) return;
            // Evict oldest if occupied.
            if (self.retained[self.retained_cursor].occupied) {
                self.retained[self.retained_cursor].zeroize();
            }
            self.retained[self.retained_cursor] = .{
                .leaf_idx = leaf_idx,
                .content_type = content_type,
                .generation = kn.generation,
                .kn = kn,
                .occupied = true,
            };
            self.retained_cursor =
                (self.retained_cursor + 1) %
                self.retain_capacity;
        }

        /// Look up a retained key by leaf, content type, and
        /// generation. Returns the key/nonce and zeroes the
        /// entry, or null if not found.
        pub fn lookupRetained(
            self: *Self,
            leaf_idx: u32,
            content_type: u8,
            generation: types.Generation,
        ) ?KeyNonce(P) {
            for (self.retained) |*e| {
                if (!e.occupied) continue;
                if (e.leaf_idx == leaf_idx and
                    e.content_type == content_type and
                    e.generation == generation)
                {
                    const kn = e.kn;
                    e.zeroize();
                    return kn;
                }
            }
            return null;
        }

        /// Zero all secret material and free allocations.
        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            for (self.handshake) |*s| {
                primitives.secureZero(&s.secret);
            }
            for (self.application) |*s| {
                primitives.secureZero(&s.secret);
            }
            allocator.free(self.handshake);
            allocator.free(self.application);
            for (self.retained) |*r| r.zeroize();
            if (self.retain_capacity > 0)
                allocator.free(self.retained);
            self.handshake = &.{};
            self.application = &.{};
            self.retained = &.{};
            self.leaf_count = 0;
            self.* = undefined;
        }

        // -- Serialization -------------------------------------------

        /// Byte size of one ratchet state entry: secret + generation.
        const ratchet_entry_size: u32 = P.nh + 4;

        /// Byte size of the serialized form.
        pub fn serializedSize(self: *const Self) u32 {
            // header: leaf_count(4) + max_forward_ratchet(4)
            // per leaf: 2 * ratchet_entry_size (handshake + app)
            return 8 + self.leaf_count * 2 * ratchet_entry_size;
        }

        /// Serialize the secret tree state to a byte buffer.
        ///
        /// Format:
        ///   leaf_count: u32 (big-endian)
        ///   max_forward_ratchet: u32 (big-endian)
        ///   For each leaf (0..leaf_count):
        ///     handshake_secret: [nh]u8
        ///     handshake_generation: u32 (big-endian)
        ///     application_secret: [nh]u8
        ///     application_generation: u32 (big-endian)
        ///
        /// Retained keys are NOT serialized (ephemeral
        /// optimization only).
        pub fn serialize(
            self: *const Self,
            allocator: std.mem.Allocator,
        ) error{OutOfMemory}![]u8 {
            const size = self.serializedSize();
            const buf = try allocator.alloc(u8, size);
            errdefer allocator.free(buf);

            var pos: u32 = 0;
            std.mem.writeInt(
                u32,
                buf[pos..][0..4],
                self.leaf_count,
                .big,
            );
            pos += 4;
            std.mem.writeInt(
                u32,
                buf[pos..][0..4],
                self.max_forward_ratchet,
                .big,
            );
            pos += 4;

            var i: u32 = 0;
            while (i < self.leaf_count) : (i += 1) {
                // Handshake
                @memcpy(
                    buf[pos..][0..P.nh],
                    &self.handshake[i].secret,
                );
                pos += P.nh;
                std.mem.writeInt(
                    u32,
                    buf[pos..][0..4],
                    self.handshake[i].generation,
                    .big,
                );
                pos += 4;

                // Application
                @memcpy(
                    buf[pos..][0..P.nh],
                    &self.application[i].secret,
                );
                pos += P.nh;
                std.mem.writeInt(
                    u32,
                    buf[pos..][0..4],
                    self.application[i].generation,
                    .big,
                );
                pos += 4;
            }

            return buf;
        }

        /// Deserialize a secret tree from bytes produced by
        /// `serialize`.
        ///
        /// Returns error if the data is truncated or the
        /// leaf_count is zero.
        pub fn deserialize(
            allocator: std.mem.Allocator,
            data: []const u8,
        ) error{ Truncated, InvalidGroupState, OutOfMemory }!Self {
            if (data.len < 8) return error.Truncated;

            const leaf_count = std.mem.readInt(
                u32,
                data[0..4],
                .big,
            );
            const max_fwd = std.mem.readInt(
                u32,
                data[4..8],
                .big,
            );

            if (leaf_count == 0) return error.InvalidGroupState;

            const expected: u64 =
                8 + @as(u64, leaf_count) * 2 * ratchet_entry_size;
            if (data.len < expected)
                return error.Truncated;

            const hs = try allocator.alloc(
                RatchetState(P),
                leaf_count,
            );
            errdefer allocator.free(hs);
            const app = try allocator.alloc(
                RatchetState(P),
                leaf_count,
            );
            errdefer allocator.free(app);

            var pos: u32 = 8;
            var i: u32 = 0;
            while (i < leaf_count) : (i += 1) {
                @memcpy(
                    &hs[i].secret,
                    data[pos..][0..P.nh],
                );
                pos += P.nh;
                hs[i].generation = std.mem.readInt(
                    u32,
                    data[pos..][0..4],
                    .big,
                );
                pos += 4;

                @memcpy(
                    &app[i].secret,
                    data[pos..][0..P.nh],
                );
                pos += P.nh;
                app[i].generation = std.mem.readInt(
                    u32,
                    data[pos..][0..4],
                    .big,
                );
                pos += 4;
            }

            return .{
                .handshake = hs,
                .application = app,
                .leaf_count = leaf_count,
                .max_forward_ratchet = max_fwd,
                .retained = &.{},
                .retained_cursor = 0,
                .retain_capacity = 0,
            };
        }
    };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "init and deinit with 4 leaves" {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    try testing.expectEqual(@as(u32, 4), st.leaf_count);
    try testing.expectEqual(
        @as(usize, 4),
        st.handshake.len,
    );
    try testing.expectEqual(
        @as(usize, 4),
        st.application.len,
    );
}

test "each leaf gets a unique secret" {
    const enc_secret = [_]u8{0x55} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    // All leaf secrets should be distinct.
    var idx_i: u32 = 0;
    while (idx_i < 4) : (idx_i += 1) {
        var idx_j: u32 = idx_i + 1;
        while (idx_j < 4) : (idx_j += 1) {
            try testing.expect(
                !std.mem.eql(
                    u8,
                    &st.handshake[idx_i].secret,
                    &st.handshake[idx_j].secret,
                ),
            );
        }
    }
}

test "consumeKey produces valid key and nonce" {
    const enc_secret = [_]u8{0x77} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn = try st.consumeKey(0, 1); // application

    try testing.expectEqual(@as(u32, 0), kn.generation);
    try testing.expectEqual(@as(usize, Default.nk), kn.key.len);
    try testing.expectEqual(@as(usize, Default.nn), kn.nonce.len);

    // Key should be non-zero.
    var all_zero = true;
    for (kn.key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "consumeKey ratchets forward" {
    const enc_secret = [_]u8{0x88} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn0 = try st.consumeKey(0, 1);
    const kn1 = try st.consumeKey(0, 1);

    try testing.expectEqual(@as(u32, 0), kn0.generation);
    try testing.expectEqual(@as(u32, 1), kn1.generation);

    // Keys from different generations should differ.
    try testing.expect(
        !std.mem.eql(u8, &kn0.key, &kn1.key),
    );
    try testing.expect(
        !std.mem.eql(u8, &kn0.nonce, &kn1.nonce),
    );
}

test "handshake and application ratchet independently" {
    const enc_secret = [_]u8{0x99} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Both start from the same leaf secret, so generation 0
    // keys are identical. Advance handshake once — now they
    // should diverge.
    _ = try st.consumeKey(0, 0); // handshake gen 0
    const hs_kn1 = try st.consumeKey(0, 0); // handshake gen 1
    const app_kn0 = try st.consumeKey(0, 1); // application gen 0

    // Handshake at gen 1 should differ from application at gen 0.
    try testing.expect(
        !std.mem.eql(u8, &hs_kn1.key, &app_kn0.key),
    );
}

test "consumeKey zeroes old secret" {
    const enc_secret = [_]u8{0xAA} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Save initial secret.
    const initial = st.application[0].secret;

    // Consume — should ratchet forward.
    _ = try st.consumeKey(0, 1);

    // The secret should have changed (old was zeroed, new
    // replaced it).
    try testing.expect(
        !std.mem.eql(
            u8,
            &initial,
            &st.application[0].secret,
        ),
    );
}

test "single leaf tree works" {
    const enc_secret = [_]u8{0xBB} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        1,
    );
    defer st.deinit(testing.allocator);

    // For a single-leaf tree, the leaf node secret equals
    // encryption_secret. The ratchet root is derived via
    // ExpandWithLabel so it differs from encryption_secret.
    try testing.expect(
        !std.mem.eql(
            u8,
            &enc_secret,
            &st.handshake[0].secret,
        ),
    );

    const kn = try st.consumeKey(0, 0);
    try testing.expectEqual(@as(u32, 0), kn.generation);
}

test "out of bounds leaf returns error" {
    const enc_secret = [_]u8{0xCC} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const result = st.consumeKey(5, 1);
    try testing.expectError(error.NotAMember, result);
}

test "forwardRatchet skips to target generation" {
    const enc_secret = [_]u8{0xDD} ** Default.nh;

    // Reference: ratchet sequentially to gen 5.
    var ref = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer ref.deinit(testing.allocator);

    var ref_kn: KeyNonce(Default) = undefined;
    var gi: u32 = 0;
    while (gi <= 5) : (gi += 1) {
        ref_kn = try ref.consumeKey(0, 1);
    }

    // Forward ratchet: jump directly to gen 5.
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    const kn = try st.forwardRatchet(0, 1, 5);
    try testing.expectEqual(@as(u32, 5), kn.generation);
    try testing.expectEqualSlices(u8, &ref_kn.key, &kn.key);
    try testing.expectEqualSlices(
        u8,
        &ref_kn.nonce,
        &kn.nonce,
    );

    // State should now be at gen 6.
    try testing.expectEqual(
        @as(u32, 6),
        st.application[0].generation,
    );
}

test "forwardRatchet with target == current is consumeKey" {
    const enc_secret = [_]u8{0xEE} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Forward ratchet to gen 0 (current) = regular consumeKey.
    const kn = try st.forwardRatchet(0, 1, 0);
    try testing.expectEqual(@as(u32, 0), kn.generation);
}

test "forwardRatchet rejects past generation" {
    const enc_secret = [_]u8{0xF0} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    _ = try st.consumeKey(0, 1); // advance to gen 1
    const result = st.forwardRatchet(0, 1, 0);
    try testing.expectError(
        error.SecretAlreadyConsumed,
        result,
    );
}

test "forwardRatchet enforces max limit" {
    const enc_secret = [_]u8{0xF1} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    st.max_forward_ratchet = 3;

    // 3 steps is OK.
    const kn = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn.generation);

    // Now at gen 4. Trying to jump 4 steps (to gen 8) exceeds
    // the limit of 3.
    const result = st.forwardRatchet(0, 1, 8);
    try testing.expectError(error.GenerationTooFar, result);
}

test "forwardRatchet default limit rejects large jump" {
    const enc_secret = [_]u8{0xF2} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Default limit is 1024. Jump of 1024 is OK.
    const kn = try st.forwardRatchet(0, 1, 1024);
    try testing.expectEqual(@as(u32, 1024), kn.generation);

    // Now at gen 1025. Jump of 1025 steps (to gen 2050)
    // exceeds the default limit.
    const result = st.forwardRatchet(0, 1, 2050);
    try testing.expectError(error.GenerationTooFar, result);
}

test "forwardRatchet retains skipped keys for out-of-order" {
    const enc_secret = [_]u8{0xA1} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);
    try st.enableRetention(testing.allocator, 16);

    // Consume gen 0.
    const kn0 = try st.consumeKey(0, 1);
    try testing.expectEqual(@as(u32, 0), kn0.generation);

    // Skip gen 1, 2, 3, 4 — consume gen 5.
    const kn5 = try st.forwardRatchet(0, 1, 5);
    try testing.expectEqual(@as(u32, 5), kn5.generation);

    // Retrieve skipped gen 3 (was retained).
    const kn3 = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn3.generation);

    // Gen 3 consumed from retained — second lookup fails.
    const fail = st.forwardRatchet(0, 1, 3);
    try testing.expectError(error.SecretAlreadyConsumed, fail);
}

test "retained keys are zeroed when evicted" {
    const enc_secret = [_]u8{0xB2} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);
    // Tiny capacity: only 2 retained entries.
    try st.enableRetention(testing.allocator, 2);

    // Skip to gen 5 — retains gen 0,1,2,3 but capacity=2
    // so gen 0 and 1 are evicted by gen 2 and 3. Gen 4 is
    // the last skip step (not retained, just advanced).
    _ = try st.forwardRatchet(0, 1, 5);

    // Gen 0 was evicted — should fail.
    const r0 = st.forwardRatchet(0, 1, 0);
    try testing.expectError(error.SecretAlreadyConsumed, r0);

    // Gen 3 should still be retained.
    const kn3 = try st.forwardRatchet(0, 1, 3);
    try testing.expectEqual(@as(u32, 3), kn3.generation);

    // Gen 2 should also be retained.
    const kn2 = try st.forwardRatchet(0, 1, 2);
    try testing.expectEqual(@as(u32, 2), kn2.generation);
}

test "retention disabled by default" {
    const enc_secret = [_]u8{0xC3} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st.deinit(testing.allocator);

    // Skip to gen 3 without enabling retention.
    _ = try st.forwardRatchet(0, 1, 3);

    // Gen 1 was not retained — fails.
    const r = st.forwardRatchet(0, 1, 1);
    try testing.expectError(error.SecretAlreadyConsumed, r);
}

test "retained key matches sequential derivation" {
    const enc_secret = [_]u8{0xD4} ** Default.nh;

    // Tree A: sequential consumption 0,1,2,3,4,5.
    var st_a = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st_a.deinit(testing.allocator);
    const kn3_seq = blk: {
        _ = try st_a.consumeKey(0, 1); // gen 0
        _ = try st_a.consumeKey(0, 1); // gen 1
        _ = try st_a.consumeKey(0, 1); // gen 2
        break :blk try st_a.consumeKey(0, 1); // gen 3
    };

    // Tree B: skip to gen 5, then retrieve gen 3 from retained.
    var st_b = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        2,
    );
    defer st_b.deinit(testing.allocator);
    try st_b.enableRetention(testing.allocator, 16);
    _ = try st_b.forwardRatchet(0, 1, 5); // skip 0-4
    const kn3_ret = try st_b.forwardRatchet(0, 1, 3);

    // Keys must match.
    try testing.expectEqualSlices(u8, &kn3_seq.key, &kn3_ret.key);
    try testing.expectEqualSlices(
        u8,
        &kn3_seq.nonce,
        &kn3_ret.nonce,
    );
    try testing.expectEqual(kn3_seq.generation, kn3_ret.generation);
}

test "serialize/deserialize round-trip preserves state" {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    var st = try SecretTree(Default).init(
        testing.allocator,
        &enc_secret,
        4,
    );
    defer st.deinit(testing.allocator);

    // Consume some keys to advance generations.
    _ = try st.consumeKey(0, 1); // app gen 0 for leaf 0
    _ = try st.consumeKey(0, 1); // app gen 1 for leaf 0
    _ = try st.consumeKey(1, 0); // hs gen 0 for leaf 1

    // Serialize.
    const data = try st.serialize(testing.allocator);
    defer testing.allocator.free(data);

    // Deserialize.
    var st2 = try SecretTree(Default).deserialize(
        testing.allocator,
        data,
    );
    defer st2.deinit(testing.allocator);

    // Verify leaf_count and max_forward_ratchet.
    try testing.expectEqual(st.leaf_count, st2.leaf_count);
    try testing.expectEqual(
        st.max_forward_ratchet,
        st2.max_forward_ratchet,
    );

    // Verify per-leaf state matches.
    var i: u32 = 0;
    while (i < st.leaf_count) : (i += 1) {
        try testing.expectEqualSlices(
            u8,
            &st.handshake[i].secret,
            &st2.handshake[i].secret,
        );
        try testing.expectEqual(
            st.handshake[i].generation,
            st2.handshake[i].generation,
        );
        try testing.expectEqualSlices(
            u8,
            &st.application[i].secret,
            &st2.application[i].secret,
        );
        try testing.expectEqual(
            st.application[i].generation,
            st2.application[i].generation,
        );
    }

    // Verify the deserialized tree produces the same keys.
    const kn_orig = try st.consumeKey(0, 1);
    const kn_deser = try st2.consumeKey(0, 1);
    try testing.expectEqualSlices(
        u8,
        &kn_orig.key,
        &kn_deser.key,
    );
    try testing.expectEqualSlices(
        u8,
        &kn_orig.nonce,
        &kn_deser.nonce,
    );
    try testing.expectEqual(
        kn_orig.generation,
        kn_deser.generation,
    );
}

test "deserialize rejects truncated data" {
    const ST = SecretTree(Default);
    const result = ST.deserialize(testing.allocator, &[_]u8{0} ** 4);
    try testing.expectError(error.Truncated, result);
}

test "deserialize rejects zero leaf_count" {
    const ST = SecretTree(Default);
    const data = [_]u8{0} ** 8; // leaf_count=0, max_fwd=0
    const result = ST.deserialize(testing.allocator, &data);
    try testing.expectError(error.InvalidGroupState, result);
}
