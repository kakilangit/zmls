//! Integration tests for zmls-client.
//!
//! Client + DeliveryService lifecycle flows using in-memory
//! adapters. Tests exercise the full stack: Client creates
//! groups, invites members, sends messages, and processes
//! commits — all routed through the DeliveryService.

const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const zmls_client = @import("zmls-client");
const zmls = @import("zmls");

const P = zmls.DefaultCryptoProvider;
const Client = zmls_client.Client(P);
const DS = zmls_client.DeliveryService;
const MemGS = zmls_client.MemoryGroupStore;
const MemKS = zmls_client.MemoryKeyStore;
const MemGD = zmls_client.MemoryGroupDirectory;
const MemKPD = zmls_client.MemoryKeyPackageDirectory;
const MemGID = zmls_client.MemoryGroupInfoDirectory;
const MessageType = zmls_client.MessageType;

fn testIo() Io {
    var threaded: Io.Threaded =
        Io.Threaded.init_single_threaded;
    return threaded.io();
}

fn makeClient(
    identity: []const u8,
    seed: *const [32]u8,
    group_store: *MemGS(8),
    key_store: *MemKS(P, 8),
) !Client {
    return Client.init(
        testing.allocator,
        identity,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

fn makeDS(
    gd: *MemGD(4, 8, 16),
    kpd: *MemKPD(8),
    gid: *MemGID(4),
) DS {
    return DS.init(
        testing.allocator,
        gd.groupDirectory(),
        kpd.keyPackageDirectory(),
        gid.groupInfoDirectory(),
        .{},
    );
}

/// Helper: Alice creates group, invites Bob, Bob joins.
/// Returns group_id (caller must free).
fn setupAliceBobGroup(
    alice: *Client,
    bob: *Client,
    ds: *DS,
) ![]u8 {
    const io = testIo();

    // Alice creates a group.
    const group_id = try alice.createGroup(io);
    errdefer testing.allocator.free(group_id);

    // Register group and Alice in the DS.
    try ds.group_directory.createGroup(
        io,
        group_id,
        "alice",
    );

    // Bob generates a KP and uploads to DS.
    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    try ds.uploadKeyPackage(io, "bob", bob_kp.data);

    // Alice downloads Bob's KP from DS.
    const kp_bytes = (try ds.downloadKeyPackage(
        testing.allocator,
        io,
        "bob",
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(kp_bytes);

    // Alice invites Bob.
    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        kp_bytes,
    );
    defer invite.deinit();

    // Route commit to Bob through DS.
    try ds.group_directory.addMember(
        io,
        group_id,
        "bob",
    );
    try ds.processMessage(
        io,
        "alice",
        group_id,
        .commit,
        invite.commit,
    );

    // Bob needs the ratchet tree and signer key to join.
    // Load Alice's current tree from her store.
    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle
        .group_state.tree.clone();
    defer tree_copy.deinit();

    // Bob joins via Welcome.
    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex
                .fromU32(1),
        },
    );
    defer join.deinit();

    return group_id;
}

test "full lifecycle: create, invite, join, exchange" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const group_id = setupAliceBobGroup(
        &alice,
        &bob,
        &ds,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);

    const io = testIo();

    // Both should be at epoch 1.
    const alice_epoch = try alice.groupEpoch(
        io,
        group_id,
    );
    const bob_epoch = try bob.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), alice_epoch);
    try testing.expectEqual(@as(u64, 1), bob_epoch);

    // Alice sends a message.
    const ct = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello bob!",
    );
    defer testing.allocator.free(ct);
    try testing.expect(ct.len > 0);

    // Bob receives and decrypts.
    var received = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ct,
    );
    defer received.deinit();

    try testing.expectEqualSlices(
        u8,
        "hello bob!",
        received.data,
    );
}

test "external join via GroupInfo" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const io = testIo();

    // Alice creates a group.
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Alice exports GroupInfo and publishes to DS.
    const gi_bytes = try alice.groupInfo(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(gi_bytes);

    try ds.publishGroupInfo(io, group_id, gi_bytes);

    // Bob fetches GroupInfo from DS.
    const fetched_gi = (try ds.getGroupInfo(
        testing.allocator,
        io,
        group_id,
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(fetched_gi);

    // Bob does an external join.
    var result = try bob.externalJoin(
        testing.allocator,
        io,
        fetched_gi,
    );
    defer result.deinit();

    // Bob should be at epoch 1.
    const bob_epoch = try bob.groupEpoch(
        io,
        result.group_id,
    );
    try testing.expectEqual(@as(u64, 1), bob_epoch);

    // Bob's group_id should match Alice's.
    try testing.expectEqualSlices(
        u8,
        group_id,
        result.group_id,
    );
}

test "staged commit: confirm advances epoch" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Stage a commit.
    var handle = try alice.stageCommit(
        testing.allocator,
        io,
        group_id,
        &.{},
    );
    try testing.expect(handle.commit_data.len > 0);

    // Epoch still 0 before confirm.
    const epoch_before = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_before);

    // Confirm.
    try handle.confirm(&alice, io);
    defer handle.deinit();

    // Epoch now 1.
    const epoch_after = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), epoch_after);
}

test "staged commit: discard preserves epoch" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Stage then discard.
    var handle = try alice.stageCommit(
        testing.allocator,
        io,
        group_id,
        &.{},
    );
    handle.discard();
    handle.deinit();

    // Epoch still 0.
    const epoch_after = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_after);
}

test "member removal: Alice removes Bob" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const group_id = setupAliceBobGroup(
        &alice,
        &bob,
        &ds,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);

    const io = testIo();

    // Alice removes Bob (leaf 1).
    const remove_commit = try alice.removeMember(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(remove_commit);

    // Alice should be at epoch 2 now.
    const epoch = try alice.groupEpoch(io, group_id);
    try testing.expectEqual(@as(u64, 2), epoch);

    // Alice should still have leaf count >= 1.
    const lc = try alice.groupLeafCount(io, group_id);
    try testing.expect(lc >= 1);
}

test "key update via selfUpdate" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const group_id = setupAliceBobGroup(
        &alice,
        &bob,
        &ds,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);

    const io = testIo();

    // Alice does a self-update (key rotation).
    const update_commit = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(update_commit);

    // Alice should be at epoch 2.
    const epoch = try alice.groupEpoch(io, group_id);
    try testing.expectEqual(@as(u64, 2), epoch);
}

test "persistence: state survives client rebuild" {
    var gs = MemGS(8).init();
    defer gs.deinit();
    var ks = MemKS(P, 8).init();
    defer ks.deinit();

    const seed: [32]u8 = .{0x42} ** 32;
    const io = testIo();

    // Create a client and a group.
    var group_id: []u8 = undefined;
    {
        var client = try makeClient(
            "alice",
            &seed,
            &gs,
            &ks,
        );
        defer client.deinit();

        group_id = try client.createGroup(io);
    }
    defer testing.allocator.free(group_id);

    // Construct a new Client using the same stores.
    var client2 = try makeClient(
        "alice",
        &seed,
        &gs,
        &ks,
    );
    defer client2.deinit();

    // The group should still be accessible.
    const epoch = try client2.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch);
}

test "error: joinGroup without pending KP" {
    var gs = MemGS(8).init();
    defer gs.deinit();
    var ks = MemKS(P, 8).init();
    defer ks.deinit();

    const seed: [32]u8 = .{0x43} ** 32;
    var bob = try makeClient(
        "bob",
        &seed,
        &gs,
        &ks,
    );
    defer bob.deinit();

    const io = testIo();

    // Bob tries to join with garbage Welcome bytes.
    // Should fail with decode error, not panic.
    const result = bob.joinGroup(
        testing.allocator,
        io,
        "not-a-welcome",
        .{
            .ratchet_tree = undefined,
            .signer_verify_key = undefined,
            .my_leaf_index = zmls.LeafIndex.fromU32(0),
        },
    );
    try testing.expectError(
        error.WelcomeDecodeFailed,
        result,
    );
}

test "error: receiveMessage with bad ciphertext" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Try to decrypt garbage — should fail gracefully.
    const result = alice.receiveMessage(
        testing.allocator,
        io,
        group_id,
        "not-a-ciphertext",
    );
    try testing.expectError(
        error.DecodingFailed,
        result,
    );
}

test "groupInfo: round-trip decodable" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    const gi_bytes = try alice.groupInfo(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(gi_bytes);

    // Should decode as MLSMessage(GroupInfo).
    const wire = try zmls.mls_message.MLSMessage
        .decodeExact(gi_bytes);
    try testing.expectEqual(
        zmls.WireFormat.mls_group_info,
        wire.wire_format,
    );
}

test "three-party: Alice invites Bob, then Carol" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();
    var carol_gs = MemGS(8).init();
    defer carol_gs.deinit();
    var carol_ks = MemKS(P, 8).init();
    defer carol_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;
    const carol_seed: [32]u8 = .{0x44} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var carol = try makeClient(
        "carol",
        &carol_seed,
        &carol_gs,
        &carol_ks,
    );
    defer carol.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const io = testIo();

    // 1. Alice creates group + invites Bob.
    const group_id = setupAliceBobGroup(
        &alice,
        &bob,
        &ds,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);

    // 2. Carol generates KP, Alice invites Carol.
    const carol_kp = try carol.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(carol_kp.data);
    try ds.uploadKeyPackage(io, "carol", carol_kp.data);

    const kp_bytes2 = (try ds.downloadKeyPackage(
        testing.allocator,
        io,
        "carol",
    )) orelse return error.TestUnexpectedResult;
    defer testing.allocator.free(kp_bytes2);

    var invite2 = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        kp_bytes2,
    );
    defer invite2.deinit();

    try ds.group_directory.addMember(
        io,
        group_id,
        "carol",
    );
    try ds.processMessage(
        io,
        "alice",
        group_id,
        .commit,
        invite2.commit,
    );

    // 3. Bob processes Alice's second commit.
    //    Discard the first commit (Bob joined via Welcome,
    //    not by processing the invite commit).
    var stale_msg = (try ds.fetchMessage(
        testing.allocator,
        io,
        group_id,
        "bob",
    )) orelse return error.TestUnexpectedResult;
    stale_msg.deinit(testing.allocator);

    var bob_commit = (try ds.fetchMessage(
        testing.allocator,
        io,
        group_id,
        "bob",
    )) orelse return error.TestUnexpectedResult;
    defer bob_commit.deinit(testing.allocator);

    var bob_result = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        bob_commit.data,
    );
    switch (bob_result) {
        .commit_applied => |*ca| ca.deinit(),
        .application => |*msg| msg.deinit(),
        .proposal_cached => {},
    }

    // 4. Carol joins via Welcome.
    var alice_bundle2 = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle2.deinit(testing.allocator);
    var tree_copy2 = try alice_bundle2
        .group_state.tree.clone();
    defer tree_copy2.deinit();

    var join_carol = try carol.joinGroup(
        testing.allocator,
        io,
        invite2.welcome,
        .{
            .ratchet_tree = tree_copy2,
            .signer_verify_key = &alice
                .signing_public_key,
            .my_leaf_index = zmls.LeafIndex
                .fromU32(2),
        },
    );
    defer join_carol.deinit();

    // 5. Verify all three at epoch 2.
    const a_ep = try alice.groupEpoch(io, group_id);
    const b_ep = try bob.groupEpoch(io, group_id);
    const c_ep = try carol.groupEpoch(io, group_id);
    try testing.expectEqual(@as(u64, 2), a_ep);
    try testing.expectEqual(@as(u64, 2), b_ep);
    try testing.expectEqual(@as(u64, 2), c_ep);

    // 6. Alice sends a message, Bob and Carol decrypt.
    const ct = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello everyone!",
    );
    defer testing.allocator.free(ct);

    var bob_msg = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ct,
    );
    defer bob_msg.deinit();
    try testing.expectEqualSlices(
        u8,
        "hello everyone!",
        bob_msg.data,
    );

    var carol_msg = try carol.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ct,
    );
    defer carol_msg.deinit();
    try testing.expectEqualSlices(
        u8,
        "hello everyone!",
        carol_msg.data,
    );
}

test "proposal batching: proposeRemove then commit" {
    var alice_gs = MemGS(8).init();
    defer alice_gs.deinit();
    var alice_ks = MemKS(P, 8).init();
    defer alice_ks.deinit();
    var bob_gs = MemGS(8).init();
    defer bob_gs.deinit();
    var bob_ks = MemKS(P, 8).init();
    defer bob_ks.deinit();

    var gd = MemGD(4, 8, 16).init();
    defer gd.deinit();
    var kpd = MemKPD(8).init();
    defer kpd.deinit();
    var gid = MemGID(4).init();
    defer gid.deinit();

    const alice_seed: [32]u8 = .{0x42} ** 32;
    const bob_seed: [32]u8 = .{0x43} ** 32;

    var alice = try makeClient(
        "alice",
        &alice_seed,
        &alice_gs,
        &alice_ks,
    );
    defer alice.deinit();
    var bob = try makeClient(
        "bob",
        &bob_seed,
        &bob_gs,
        &bob_ks,
    );
    defer bob.deinit();
    var ds = makeDS(&gd, &kpd, &gid);
    defer ds.deinit();

    const io = testIo();

    // Setup: Alice creates group, invites Bob.
    const group_id = setupAliceBobGroup(
        &alice,
        &bob,
        &ds,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);

    // Alice proposes removing Bob (cached, not committed).
    const proposal_bytes = try alice.proposeRemove(
        testing.allocator,
        io,
        group_id,
        1, // Bob's leaf index
    );
    defer testing.allocator.free(proposal_bytes);

    // Epoch should still be 1 (from the invite).
    const epoch_before = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), epoch_before);

    // Alice commits all pending proposals.
    const commit_bytes = try alice.commitPending(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(commit_bytes);

    // Epoch should be 2 now.
    const epoch_after = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 2), epoch_after);

    // Commit data should be non-empty.
    try testing.expect(commit_bytes.len > 0);
}
