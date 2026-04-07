// Fuzz targets for message decoding.
//
// Property: decode(random_bytes) must never panic for any
// message type — it may return errors, but must not trigger
// undefined behaviour or out-of-bounds access.
//
// Run with:  zig build test --fuzz

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const mls = @import("zmls");

// Module aliases.
const tree_node = mls.tree_node;
const tree_path = mls.tree_path;
const proposal_mod = mls.proposal;
const commit_mod = mls.commit;
const welcome_mod = mls.welcome;
const group_info_mod = mls.group_info;
const key_package_mod = mls.key_package;
const framing_mod = mls.framing;
const framed_content_mod = mls.framed_content;
const mls_message_mod = mls.mls_message;
const private_msg_mod = mls.private_msg;
const public_msg_mod = mls.public_msg;
const group_ctx_mod = mls.group_context;

// ── Helpers ─────────────────────────────────────────────────

/// Try to decode and free the result. Any error is fine.
fn tryDecodeAlloc(
    comptime T: type,
    alloc: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) void {
    const r = T.decode(alloc, data, pos) catch return;
    // If the type has a deinit, call it.
    if (@hasDecl(T, "deinit")) {
        var v = r.value;
        v.deinit(alloc);
    }
}

/// Try a non-allocating decode. Any error is fine.
fn tryDecodeSimple(
    comptime decodeFn: anytype,
    data: []const u8,
    pos: u32,
) void {
    _ = decodeFn(data, pos) catch return;
}

// ── Fuzz: node decode ───────────────────────────────────────

fn fuzzNodeDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    // LeafNode.decode
    tryDecodeAlloc(tree_node.LeafNode, alloc, data, 0);

    // ParentNode.decode
    tryDecodeAlloc(tree_node.ParentNode, alloc, data, 0);

    // Extension.decode
    tryDecodeAlloc(tree_node.Extension, alloc, data, 0);
}

test "fuzz: node decode" {
    try testing.fuzz({}, fuzzNodeDecode, .{});
}

// ── Fuzz: path decode ───────────────────────────────────────

fn fuzzPathDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    // HPKECiphertext.decode
    tryDecodeAlloc(
        tree_path.HPKECiphertext,
        alloc,
        data,
        0,
    );

    // UpdatePathNode.decode
    tryDecodeAlloc(
        tree_path.UpdatePathNode,
        alloc,
        data,
        0,
    );

    // UpdatePath.decode
    tryDecodeAlloc(tree_path.UpdatePath, alloc, data, 0);
}

test "fuzz: path decode" {
    try testing.fuzz({}, fuzzPathDecode, .{});
}

// ── Fuzz: proposal decode ───────────────────────────────────

fn fuzzProposalDecode(
    _: void,
    smith: *Smith,
) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(proposal_mod.Proposal, alloc, data, 0);
}

test "fuzz: proposal decode" {
    try testing.fuzz({}, fuzzProposalDecode, .{});
}

// ── Fuzz: commit decode ─────────────────────────────────────

fn fuzzCommitDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [1024]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(commit_mod.Commit, alloc, data, 0);
}

test "fuzz: commit decode" {
    try testing.fuzz({}, fuzzCommitDecode, .{});
}

// ── Fuzz: welcome decode ────────────────────────────────────

fn fuzzWelcomeDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [1024]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(welcome_mod.Welcome, alloc, data, 0);
}

test "fuzz: welcome decode" {
    try testing.fuzz({}, fuzzWelcomeDecode, .{});
}

// ── Fuzz: key package decode ────────────────────────────────

fn fuzzKeyPackageDecode(
    _: void,
    smith: *Smith,
) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(key_package_mod.KeyPackage, alloc, data, 0);
}

test "fuzz: key package decode" {
    try testing.fuzz({}, fuzzKeyPackageDecode, .{});
}

// ── Fuzz: group info decode ─────────────────────────────────

fn fuzzGroupInfoDecode(
    _: void,
    smith: *Smith,
) anyerror!void {
    var buf: [1024]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(group_info_mod.GroupInfo, alloc, data, 0);
}

test "fuzz: group info decode" {
    try testing.fuzz({}, fuzzGroupInfoDecode, .{});
}

// ── Fuzz: group context decode ──────────────────────────────

fn fuzzGroupContextDecode(
    _: void,
    smith: *Smith,
) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];
    const alloc = testing.allocator;

    tryDecodeAlloc(group_ctx_mod.GroupContext(32), alloc, data, 0);
}

test "fuzz: group context decode" {
    try testing.fuzz({}, fuzzGroupContextDecode, .{});
}

// ── Fuzz: framing decode ────────────────────────────────────

fn fuzzFramingDecode(_: void, smith: *Smith) anyerror!void {
    var buf: [512]u8 = undefined;
    const slen = smith.slice(&buf);
    const data = buf[0..slen];

    // Sender.decode (non-allocating)
    tryDecodeSimple(framing_mod.Sender.decode, data, 0);

    // FramedContent.decode (non-allocating)
    tryDecodeSimple(
        framed_content_mod.FramedContent.decode,
        data,
        0,
    );

    // MLSMessage.decode (non-allocating)
    tryDecodeSimple(
        mls_message_mod.MLSMessage.decode,
        data,
        0,
    );

    // PrivateMessage.decode (non-allocating)
    tryDecodeSimple(
        private_msg_mod.PrivateMessage.decode,
        data,
        0,
    );
}

test "fuzz: framing decode" {
    try testing.fuzz({}, fuzzFramingDecode, .{});
}
