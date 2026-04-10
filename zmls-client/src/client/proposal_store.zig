//! PendingProposalStore — Client-side proposal cache that
//! survives across loadBundle/persistBundle cycles.
//!
//! The core GroupState's ProposalCache is lost on
//! serialization (it starts empty on each deserialize).
//! This store holds proposals between receive and commit
//! processing. When a commit arrives, cached proposals are
//! injected into the GroupState's cache before processing.
//!
//! Bounded, no heap allocation. Stores only the proposal
//! ref (hash), the proposal value, and the sender.

const std = @import("std");
const zmls = @import("zmls");

/// Maximum cached proposals across all groups.
const max_stored: u32 = 256;

/// Maximum group ID length for matching.
const max_group_id_len: u32 = 64;

pub fn PendingProposalStore(comptime P: type) type {
    return struct {
        const Self = @This();

        const Entry = struct {
            occupied: bool = false,
            /// True when proposal was decoded from wire and
            /// owns heap-allocated data that must be freed
            /// via Proposal.deinit on eviction.
            owns_data: bool = false,
            group_id_buf: [max_group_id_len]u8 =
                .{0} ** max_group_id_len,
            group_id_len: u32 = 0,
            ref: [P.nh]u8 = .{0} ** P.nh,
            proposal: zmls.Proposal = undefined,
            sender: zmls.Sender = undefined,

            fn matchesGroup(
                self: *const Entry,
                group_id: []const u8,
            ) bool {
                return self.occupied and
                    self.group_id_len == group_id.len and
                    std.mem.eql(
                        u8,
                        self.group_id_buf[0..self.group_id_len],
                        group_id,
                    );
            }
        };

        entries: [max_stored]Entry =
            [_]Entry{.{}} ** max_stored,
        count: u32 = 0,

        pub fn init() Self {
            return .{};
        }

        /// Store a proposal with its pre-computed ref.
        /// When `owns_data` is true, the store takes
        /// ownership of heap allocations inside the
        /// proposal and frees them on clearGroup.
        pub fn store(
            self: *Self,
            group_id: []const u8,
            ref: [P.nh]u8,
            proposal: zmls.Proposal,
            sender: zmls.Sender,
            owns_data: bool,
        ) error{CapacityExhausted}!void {
            if (group_id.len > max_group_id_len) {
                return error.CapacityExhausted;
            }
            for (&self.entries) |*e| {
                if (!e.occupied) {
                    e.* = .{
                        .occupied = true,
                        .owns_data = owns_data,
                        .group_id_len = @intCast(
                            group_id.len,
                        ),
                        .ref = ref,
                        .proposal = proposal,
                        .sender = sender,
                    };
                    @memcpy(
                        e.group_id_buf[0..group_id.len],
                        group_id,
                    );
                    self.count += 1;
                    return;
                }
            }
            return error.CapacityExhausted;
        }

        /// Inject all stored proposals for a group into
        /// the GroupState's pending_proposals cache.
        pub fn injectInto(
            self: *const Self,
            group_id: []const u8,
            cache: *zmls.ProposalCache(P),
        ) void {
            for (&self.entries) |*e| {
                if (e.matchesGroup(group_id)) {
                    _ = cache.cacheProposalWithRef(
                        e.proposal,
                        e.sender,
                        e.ref,
                    ) catch continue;
                }
            }
        }

        /// Clear all stored proposals for a group
        /// (after epoch transition). Frees heap data
        /// for proposals that own their allocations.
        pub fn clearGroup(
            self: *Self,
            allocator: std.mem.Allocator,
            group_id: []const u8,
        ) void {
            for (&self.entries) |*e| {
                if (e.matchesGroup(group_id)) {
                    if (e.owns_data) {
                        e.proposal.deinit(allocator);
                    }
                    e.* = .{};
                    self.count -= 1;
                }
            }
        }

        /// Collect proposals for a group into a
        /// caller-provided buffer. Returns the slice of
        /// proposals found (up to buffer length).
        pub fn collectProposals(
            self: *const Self,
            group_id: []const u8,
            out: []zmls.Proposal,
        ) []zmls.Proposal {
            var n: u32 = 0;
            for (&self.entries) |*e| {
                if (n >= out.len) break;
                if (e.matchesGroup(group_id)) {
                    out[n] = e.proposal;
                    n += 1;
                }
            }
            return out[0..n];
        }
    };
}

const testing = @import("std").testing;

test "clearGroup frees decoded proposal data" {
    const P = zmls.DefaultCryptoProvider;
    var store = PendingProposalStore(P).init();
    const alloc = testing.allocator;

    // Simulate a decoded Add proposal with heap data.
    const init_key = try alloc.alloc(u8, 32);
    const sig = try alloc.alloc(u8, 64);
    const ext = try alloc.alloc(zmls.Extension, 0);

    const kp = zmls.KeyPackage{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .init_key = init_key,
        .leaf_node = .{
            .encryption_key = &.{},
            .signature_key = &.{},
            .credential = zmls.Credential.initBasic(&.{}),
            .capabilities = .{
                .versions = &.{},
                .cipher_suites = &.{},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{},
            },
            .source = .key_package,
            .lifetime = .{
                .not_before = 0,
                .not_after = 0,
            },
            .parent_hash = null,
            .extensions = &.{},
            .signature = &.{},
        },
        .extensions = ext,
        .signature = sig,
    };

    const proposal = zmls.Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = kp } },
    };

    try store.store(
        "test-group",
        .{0} ** P.nh,
        proposal,
        .{ .sender_type = .member, .leaf_index = 0 },
        true,
    );
    try testing.expectEqual(@as(u32, 1), store.count);

    // clearGroup must free heap data; testing allocator
    // will fail the test if any allocation leaks.
    store.clearGroup(alloc, "test-group");
    try testing.expectEqual(@as(u32, 0), store.count);
}
