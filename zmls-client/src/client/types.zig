//! Client types — Options, results, and configuration enums.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Wire format policy for outgoing messages.
pub const WireFormatPolicy = enum {
    /// Only application messages are encrypted (Commits and
    /// Proposals use PublicMessage). This is the recommended
    /// default per RFC 9420.
    encrypt_application_only,
    /// All messages are encrypted as PrivateMessage.
    encrypt_all,
};

/// Result of inviteMember: commit + welcome bytes.
pub const InviteResult = struct {
    commit: []u8,
    welcome: []u8,
    allocator: Allocator,

    pub fn deinit(self: *InviteResult) void {
        self.allocator.free(self.commit);
        self.allocator.free(self.welcome);
        self.* = undefined;
    }
};

/// Result of externalJoin: group_id + commit bytes.
pub const ExternalJoinResult = struct {
    group_id: []u8,
    commit: []u8,
    allocator: Allocator,

    pub fn deinit(self: *ExternalJoinResult) void {
        self.allocator.free(self.group_id);
        self.allocator.free(self.commit);
        self.* = undefined;
    }
};

/// A received application message after decryption.
pub const ReceivedMessage = struct {
    sender_leaf: u32,
    data: []u8,
    allocator: Allocator,

    pub fn deinit(self: *ReceivedMessage) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};

/// Result of processIncoming: what happened?
pub const ProcessingResult = union(enum) {
    /// An application message was decrypted.
    application: ReceivedMessage,
    /// A commit was processed; epoch advanced.
    commit_applied: CommitApplied,
    /// A proposal was cached.
    proposal_cached,
};

pub const CommitApplied = struct {
    new_epoch: u64,
    removed_members: []u32,
    added_members: []u32,
    allocator: Allocator,

    pub fn deinit(self: *CommitApplied) void {
        self.allocator.free(self.removed_members);
        self.allocator.free(self.added_members);
        self.* = undefined;
    }
};

/// Information about a group member.
pub const MemberInfo = struct {
    leaf_index: u32,
    identity: []const u8,
};

/// Result of joinGroup: group_id of the joined group.
pub const JoinGroupResult = struct {
    group_id: []u8,
    allocator: Allocator,

    pub fn deinit(self: *JoinGroupResult) void {
        self.allocator.free(self.group_id);
        self.* = undefined;
    }
};
