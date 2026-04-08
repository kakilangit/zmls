//! Bounded proposal cache for storing pending proposals between
//! commits, resolved by ProposalRef when a Commit arrives per
//! RFC 9420 Section 12.4.
// Proposal cache (pending proposals) per RFC 9420 Section 12.4.
//
// Proposals received between commits are stored by reference
// (ProposalRef = RefHash("MLS 1.0 Proposal Reference",
//                         AuthenticatedContent)).
// When a Commit arrives, ProposalOrRef entries with type=reference
// are resolved against this cache.
//
// Design: bounded array of entries. No heap map needed because
// the number of pending proposals per epoch is small (bounded by
// max_pending below). Managed struct — stores allocator for the
// heap-allocated proposal copies.

const std = @import("std");
const assert = std.debug.assert;
const errors = @import("../common/errors.zig");
const proposal_mod = @import("../messages/proposal.zig");
const commit_mod = @import("../messages/commit.zig");
const framing = @import("../framing/content_type.zig");
const primitives = @import("../crypto/primitives.zig");

const Proposal = proposal_mod.Proposal;
const ProposalOrRef = commit_mod.ProposalOrRef;
const Sender = framing.Sender;
const GroupError = errors.GroupError;
const ValidationError = errors.ValidationError;

/// Maximum pending proposals per epoch.
pub const max_pending: u32 = 256;

/// A cached proposal with its sender and computed reference.
fn CacheEntry(comptime nh: u32) type {
    return struct {
        ref: [nh]u8,
        proposal: Proposal,
        sender: Sender,
    };
}

/// Proposal cache for pending proposals between commits.
///
/// Generic over the CryptoProvider to derive `nh` (hash output
/// size) for ProposalRef computation.
///
/// Managed struct: stores allocator, deinit needs no args.
pub fn ProposalCache(comptime P: type) type {
    const nh = P.nh;

    return struct {
        entries: [max_pending]CacheEntry(nh),
        len: u32,

        const Self = @This();

        /// Create an empty proposal cache.
        pub fn init() Self {
            return .{
                .entries = undefined,
                .len = 0,
            };
        }

        /// Cache a proposal by computing its ProposalRef from
        /// the serialized AuthenticatedContent.
        ///
        /// Per RFC 9420 Section 12.4, the ProposalRef is:
        ///   RefHash("MLS 1.0 Proposal Reference",
        ///           AuthenticatedContent)
        /// where AuthenticatedContent =
        ///   WireFormat || FramedContent || FramedContentAuthData
        ///
        /// Returns the computed ProposalRef. Fails if full.
        pub fn cacheProposal(
            self: *Self,
            proposal: Proposal,
            sender: Sender,
            authenticated_content: []const u8,
        ) ValidationError![nh]u8 {
            const ref = primitives.refHash(
                P,
                "MLS 1.0 Proposal Reference",
                authenticated_content,
            );
            return self.cacheProposalWithRef(
                proposal,
                sender,
                ref,
            );
        }

        /// Cache a proposal with a precomputed ProposalRef.
        ///
        /// Use this when the ref is already known (e.g. in
        /// tests or when the caller computed it externally).
        ///
        /// Returns the ref. Fails if the cache is full.
        pub fn cacheProposalWithRef(
            self: *Self,
            proposal: Proposal,
            sender: Sender,
            ref: [nh]u8,
        ) ValidationError![nh]u8 {
            if (self.len >= max_pending) {
                return error.InvalidProposalList;
            }
            self.entries[self.len] = .{
                .ref = ref,
                .proposal = proposal,
                .sender = sender,
            };
            self.len += 1;
            return ref;
        }

        /// Look up a proposal by its ProposalRef.
        ///
        /// Returns the cached proposal and sender, or null if
        /// the reference is not found.
        pub fn lookup(
            self: *const Self,
            ref: *const [nh]u8,
        ) ?struct { proposal: Proposal, sender: Sender } {
            var i: u32 = 0;
            while (i < self.len) : (i += 1) {
                if (std.mem.eql(u8, &self.entries[i].ref, ref)) {
                    return .{
                        .proposal = self.entries[i].proposal,
                        .sender = self.entries[i].sender,
                    };
                }
            }
            return null;
        }

        /// Resolve a list of ProposalOrRef into proposals with
        /// per-proposal senders.
        ///
        /// Inline proposals get `commit_sender` as their sender.
        /// By-reference proposals get the cached sender.
        ///
        /// Populates both `out_buf` (proposals) and
        /// `senders_buf` (corresponding senders).
        pub fn resolveWithSenders(
            self: *const Self,
            por_list: []const ProposalOrRef,
            commit_sender: Sender,
            out_buf: *[max_pending]Proposal,
            senders_buf: *[max_pending]Sender,
        ) (GroupError || ValidationError)!u32 {
            if (por_list.len > max_pending) {
                return error.InvalidProposalList;
            }
            var resolved: u32 = 0;
            for (por_list) |por| {
                switch (por.tag) {
                    .proposal => {
                        out_buf[resolved] = por.payload.proposal;
                        senders_buf[resolved] = commit_sender;
                        resolved += 1;
                    },
                    .reference => {
                        const ref_bytes = por.payload.reference;
                        if (ref_bytes.len != nh) {
                            return error.ProposalNotFound;
                        }
                        const ref: *const [nh]u8 =
                            ref_bytes[0..nh];
                        if (self.lookup(ref)) |entry| {
                            out_buf[resolved] = entry.proposal;
                            senders_buf[resolved] = entry.sender;
                            resolved += 1;
                        } else {
                            return error.ProposalNotFound;
                        }
                    },
                    else => {
                        return error.InvalidProposalList;
                    },
                }
            }
            return resolved;
        }

        /// Clear all cached proposals (epoch transition).
        pub fn clear(self: *Self) void {
            self.len = 0;
        }

        /// Number of cached proposals.
        pub fn count(self: *const Self) u32 {
            return self.len;
        }
    };
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;
const types = @import("../common/types.zig");
const LeafIndex = types.LeafIndex;

test "ProposalCache: cache and lookup by ref" {
    var cache = ProposalCache(Default).init();

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 7 } },
    };
    const sender = Sender.member(LeafIndex.fromU32(0));
    const dummy_ref: [Default.nh]u8 = .{0x01} ** Default.nh;

    const ref = try cache.cacheProposalWithRef(
        prop,
        sender,
        dummy_ref,
    );

    // Lookup succeeds.
    const entry = cache.lookup(&ref);
    try testing.expect(entry != null);
    try testing.expectEqual(
        @as(u32, 7),
        entry.?.proposal.payload.remove.removed,
    );

    // Lookup with wrong ref fails.
    var bad_ref: [Default.nh]u8 = .{0xFF} ** Default.nh;
    try testing.expect(cache.lookup(&bad_ref) == null);
    _ = &bad_ref;
}

test "ProposalCache: resolve inline proposals" {
    var cache = ProposalCache(Default).init();

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 3 } },
    };
    const por = ProposalOrRef.initProposal(prop);
    const por_list = [_]ProposalOrRef{por};

    var out_buf: [max_pending]Proposal = undefined;
    var senders: [max_pending]Sender = undefined;
    const cs = Sender.member(LeafIndex.fromU32(0));
    const count = try cache.resolveWithSenders(
        &por_list,
        cs,
        &out_buf,
        &senders,
    );

    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectEqual(
        @as(u32, 3),
        out_buf[0].payload.remove.removed,
    );
    // Inline proposals get the commit sender.
    try testing.expectEqual(@as(u32, 0), senders[0].leaf_index);
}

test "ProposalCache: resolve by-reference proposals" {
    var cache = ProposalCache(Default).init();

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 5 } },
    };
    const sender = Sender.member(LeafIndex.fromU32(1));
    const dummy_ref: [Default.nh]u8 = .{0x05} ** Default.nh;
    const ref = try cache.cacheProposalWithRef(
        prop,
        sender,
        dummy_ref,
    );

    // Build a ProposalOrRef with the reference.
    const por = ProposalOrRef.initReference(&ref);
    const por_list = [_]ProposalOrRef{por};

    var out_buf: [max_pending]Proposal = undefined;
    var senders: [max_pending]Sender = undefined;
    const cs = Sender.member(LeafIndex.fromU32(99));
    const count = try cache.resolveWithSenders(
        &por_list,
        cs,
        &out_buf,
        &senders,
    );

    try testing.expectEqual(@as(u32, 1), count);
    try testing.expectEqual(
        @as(u32, 5),
        out_buf[0].payload.remove.removed,
    );
    // By-reference retains original sender, not commit sender.
    try testing.expectEqual(@as(u32, 1), senders[0].leaf_index);
}

test "ProposalCache: resolve fails for unknown ref" {
    var cache = ProposalCache(Default).init();

    const bad_ref = [_]u8{0xAA} ** Default.nh;
    const por = ProposalOrRef.initReference(&bad_ref);
    const por_list = [_]ProposalOrRef{por};

    var out_buf: [max_pending]Proposal = undefined;
    var senders: [max_pending]Sender = undefined;
    const cs = Sender.member(LeafIndex.fromU32(0));
    const result = cache.resolveWithSenders(
        &por_list,
        cs,
        &out_buf,
        &senders,
    );
    try testing.expectError(error.ProposalNotFound, result);
}

test "ProposalCache: clear resets cache" {
    var cache = ProposalCache(Default).init();

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1 } },
    };
    const sender = Sender.member(LeafIndex.fromU32(0));
    const dummy_ref: [Default.nh]u8 = .{0x0A} ** Default.nh;
    const ref = try cache.cacheProposalWithRef(
        prop,
        sender,
        dummy_ref,
    );

    try testing.expectEqual(@as(u32, 1), cache.count());

    cache.clear();
    try testing.expectEqual(@as(u32, 0), cache.count());

    // Lookup after clear returns null.
    try testing.expect(cache.lookup(&ref) == null);
}

test "ProposalCache: mixed inline and by-ref resolution" {
    var cache = ProposalCache(Default).init();

    // Cache a Remove by reference.
    const remove_prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 2 } },
    };
    const sender = Sender.member(LeafIndex.fromU32(0));
    const dummy_ref: [Default.nh]u8 = .{0x02} ** Default.nh;
    const ref = try cache.cacheProposalWithRef(
        remove_prop,
        sender,
        dummy_ref,
    );

    // Build mixed ProposalOrRef list.
    const inline_prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 9 } },
    };
    const por_list = [_]ProposalOrRef{
        ProposalOrRef.initReference(&ref),
        ProposalOrRef.initProposal(inline_prop),
    };

    var out_buf: [max_pending]Proposal = undefined;
    var senders: [max_pending]Sender = undefined;
    const cs = Sender.member(LeafIndex.fromU32(7));
    const count = try cache.resolveWithSenders(
        &por_list,
        cs,
        &out_buf,
        &senders,
    );

    try testing.expectEqual(@as(u32, 2), count);
    try testing.expectEqual(
        @as(u32, 2),
        out_buf[0].payload.remove.removed,
    );
    try testing.expectEqual(
        @as(u32, 9),
        out_buf[1].payload.remove.removed,
    );
    // By-ref gets original sender, inline gets commit sender.
    try testing.expectEqual(@as(u32, 0), senders[0].leaf_index);
    try testing.expectEqual(@as(u32, 7), senders[1].leaf_index);
}

test "ProposalCache: ref matches refHash of auth content" {
    var cache = ProposalCache(Default).init();

    const prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 42 } },
    };
    const sender = Sender.member(LeafIndex.fromU32(0));

    // Build a fake AuthenticatedContent blob.
    const fake_ac = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const ref = try cache.cacheProposal(
        prop,
        sender,
        &fake_ac,
    );

    // Independently compute the ref via refHash.
    const expected_ref = primitives.refHash(
        Default,
        "MLS 1.0 Proposal Reference",
        &fake_ac,
    );
    try testing.expectEqualSlices(u8, &expected_ref, &ref);
}

test "ProposalCache: multiple proposals with distinct refs" {
    var cache = ProposalCache(Default).init();
    const sender = Sender.member(LeafIndex.fromU32(0));

    const p1 = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1 } },
    };
    const p2 = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 2 } },
    };

    const ac1 = [_]u8{ 0x01, 0x02, 0x03 };
    const ac2 = [_]u8{ 0x04, 0x05, 0x06 };
    const ref1 = try cache.cacheProposal(p1, sender, &ac1);
    const ref2 = try cache.cacheProposal(p2, sender, &ac2);

    // Different proposals produce different refs.
    try testing.expect(!std.mem.eql(u8, &ref1, &ref2));
    try testing.expectEqual(@as(u32, 2), cache.count());

    // Both are resolvable.
    const e1 = cache.lookup(&ref1);
    const e2 = cache.lookup(&ref2);
    try testing.expect(e1 != null);
    try testing.expect(e2 != null);
    try testing.expectEqual(
        @as(u32, 1),
        e1.?.proposal.payload.remove.removed,
    );
    try testing.expectEqual(
        @as(u32, 2),
        e2.?.proposal.payload.remove.removed,
    );
}
