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
            group_id_hash: u64 = 0,
            ref: [P.nh]u8 = .{0} ** P.nh,
            proposal: zmls.Proposal = undefined,
            sender: zmls.Sender = undefined,
        };

        entries: [max_stored]Entry =
            [_]Entry{.{}} ** max_stored,
        count: u32 = 0,

        pub fn init() Self {
            return .{};
        }

        /// Store a proposal with its pre-computed ref.
        pub fn store(
            self: *Self,
            group_id: []const u8,
            ref: [P.nh]u8,
            proposal: zmls.Proposal,
            sender: zmls.Sender,
        ) error{CapacityExhausted}!void {
            const gid_hash = hashGroupId(group_id);
            for (&self.entries) |*e| {
                if (!e.occupied) {
                    e.* = .{
                        .occupied = true,
                        .group_id_hash = gid_hash,
                        .ref = ref,
                        .proposal = proposal,
                        .sender = sender,
                    };
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
            const gid_hash = hashGroupId(group_id);
            for (&self.entries) |*e| {
                if (e.occupied and
                    e.group_id_hash == gid_hash)
                {
                    _ = cache.cacheProposalWithRef(
                        e.proposal,
                        e.sender,
                        e.ref,
                    ) catch continue;
                }
            }
        }

        /// Clear all stored proposals for a group
        /// (after epoch transition).
        pub fn clearGroup(
            self: *Self,
            group_id: []const u8,
        ) void {
            const gid_hash = hashGroupId(group_id);
            for (&self.entries) |*e| {
                if (e.occupied and
                    e.group_id_hash == gid_hash)
                {
                    e.* = .{};
                    self.count -= 1;
                }
            }
        }

        fn hashGroupId(group_id: []const u8) u64 {
            return std.hash.Wyhash.hash(0, group_id);
        }
    };
}
