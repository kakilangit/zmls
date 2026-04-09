const std = @import("std");
const testing = std.testing;
const Io = std.Io;
const zmls = @import("zmls");

const Client = @import("client.zig").Client;
const client_types = @import("types.zig");
const KeyPackage = zmls.KeyPackage;
const Credential = zmls.Credential;

const TestP = zmls.DefaultCryptoProvider;
const MemGS = @import(
    "../adapters/memory_group_store.zig",
).MemoryGroupStore;
const MemKS = @import(
    "../adapters/memory_key_store.zig",
).MemoryKeyStore;

fn testIo() Io {
    var threaded: Io.Threaded =
        Io.Threaded.init_single_threaded;
    return threaded.io();
}

fn makeTestClient(
    group_store: *MemGS(8),
    key_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x42} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: init/deinit lifecycle" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    const seed: [32]u8 = .{0x42} ** 32;
    var client = try Client(TestP).init(
        testing.allocator,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
    defer client.deinit();

    try testing.expect(!client.closed);
    try testing.expectEqualSlices(
        u8,
        "alice",
        client.identity,
    );
}

test "Client: freshKeyPackage returns decodable bytes" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    try testing.expect(result.data.len > 0);

    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var key_package = decoded.value;
    defer key_package.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u32, @intCast(result.data.len)),
        decoded.pos,
    );

    try testing.expectEqual(
        zmls.ProtocolVersion.mls10,
        key_package.version,
    );
    try testing.expectEqual(
        zmls.CipherSuite
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        key_package.cipher_suite,
    );
    try testing.expectEqual(
        zmls.types.LeafNodeSource.key_package,
        key_package.leaf_node.source,
    );

    try testing.expect(key_package.init_key.len > 0);
    try testing.expect(
        key_package.leaf_node.encryption_key.len > 0,
    );

    try key_package.verifySignature(TestP);
    try key_package.leaf_node.verifyLeafNodeSignature(
        TestP,
        null,
        null,
    );
}

test "Client: freshKeyPackage stores keys in pending map" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    try testing.expectEqual(
        @as(u32, 1),
        client.pending_key_packages.count,
    );

    const found = client.pending_key_packages.find(
        &result.ref_hash,
    );
    try testing.expect(found != null);

    try testing.expectEqualSlices(
        u8,
        &client.signing_secret_key,
        &found.?.sign_sk,
    );
}

test "Client: freshKeyPackage ref_hash matches recomputed" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result.data);

    const decoded = try KeyPackage.decode(
        testing.allocator,
        result.data,
        0,
    );
    var key_package = decoded.value;
    defer key_package.deinit(testing.allocator);

    const recomputed = try key_package.makeRef(TestP);
    try testing.expectEqualSlices(
        u8,
        &result.ref_hash,
        &recomputed,
    );
}

test "Client: multiple freshKeyPackages get distinct refs" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();

    var client = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer client.deinit();

    const io = testIo();
    const result_one = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result_one.data);

    const result_two = try client.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(result_two.data);

    try testing.expect(!std.mem.eql(
        u8,
        &result_one.ref_hash,
        &result_two.ref_hash,
    ));

    try testing.expectEqual(
        @as(u32, 2),
        client.pending_key_packages.count,
    );
}

fn makeTestClientBob(
    group_store: *MemGS(8),
    key_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x99} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "bob",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: inviteMember produces valid commit and welcome" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var result = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer result.deinit();

    try testing.expect(result.commit.len > 0);
    try testing.expect(result.welcome.len > 0);

    const welcome_decoded = try zmls.Welcome.decode(
        testing.allocator,
        result.welcome,
        0,
    );
    var welcome = welcome_decoded.value;
    defer welcome.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u32, @intCast(result.welcome.len)),
        welcome_decoded.pos,
    );

    try testing.expectEqual(
        @as(usize, 1),
        welcome.secrets.len,
    );
}

test "Client: inviteMember persists updated group state" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var result = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer result.deinit();

    // Reload Alice's group — epoch should have advanced.
    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u64, 1),
        bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        bundle.group_state.leafCount(),
    );
}

test "Client: joinGroup via Welcome succeeds" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
        },
    );
    defer join.deinit();

    try testing.expectEqualSlices(
        u8,
        group_id,
        join.group_id,
    );

    try testing.expectEqual(
        @as(u32, 0),
        bob.pending_key_packages.count,
    );
}

test "Client: joinGroup persists group state" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
        },
    );
    defer join.deinit();

    // Bob can reload the group from his store.
    var bob_bundle = try bob.loadBundle(
        io,
        join.group_id,
    );
    defer bob_bundle.deinit(testing.allocator);

    try testing.expectEqual(
        @as(u64, 1),
        bob_bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        alice_bundle.group_state.epoch(),
        bob_bundle.group_state.epoch(),
    );
    try testing.expectEqual(
        @as(u32, 2),
        bob_bundle.group_state.leafCount(),
    );
}

test "Client: joinGroup fails without pending KP" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    // Clear Bob's pending map.
    bob.pending_key_packages.deinit();
    bob.pending_key_packages = @TypeOf(
        bob.pending_key_packages,
    ).init();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    const result = bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
        },
    );
    try testing.expectError(
        error.NoPendingKeyPackage,
        result,
    );
}

test "Client: removeMember produces commit bytes" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    const commit = try alice.removeMember(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(
        @as(u64, 2),
        bundle.group_state.epoch(),
    );
}

test "Client: selfUpdate advances epoch" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    const commit = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(commit);

    try testing.expect(commit.len > 0);

    var bundle = try alice.loadBundle(io, group_id);
    defer bundle.deinit(testing.allocator);
    try testing.expectEqual(
        @as(u64, 1),
        bundle.group_state.epoch(),
    );
}

test "Client: leaveGroup deletes state from store" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
        },
    );
    defer join.deinit();

    try bob.leaveGroup(io, join.group_id);

    const load_result = bob.loadBundle(
        io,
        join.group_id,
    );
    try testing.expectError(
        error.GroupNotFound,
        load_result,
    );
}

fn setupTwoMemberGroup(
    alice_group_store: *MemGS(8),
    alice_key_store: *MemKS(TestP, 8),
    bob_group_store: *MemGS(8),
    bob_key_store: *MemKS(TestP, 8),
    alice: *Client(TestP),
    bob: *Client(TestP),
) ![]u8 {
    const io = testIo();

    alice.* = try makeTestClient(
        alice_group_store,
        alice_key_store,
    );
    bob.* = try makeTestClientBob(
        bob_group_store,
        bob_key_store,
    );

    const group_id = try alice.createGroup(io);
    errdefer testing.allocator.free(group_id);

    const bob_key_package = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_key_package.data,
    );
    defer invite.deinit();

    var alice_bundle = try alice.loadBundle(
        io,
        group_id,
    );
    defer alice_bundle.deinit(testing.allocator);
    var tree_copy = try alice_bundle.group_state.tree.clone();
    defer tree_copy.deinit();

    var join = try bob.joinGroup(
        testing.allocator,
        io,
        invite.welcome,
        .{
            .ratchet_tree = tree_copy,
            .signer_verify_key = &alice
                .signing_public_key,
        },
    );
    defer join.deinit();

    return group_id;
}

test "Client: sendMessage + receiveMessage round-trip" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello bob",
    );
    defer testing.allocator.free(ciphertext);

    try testing.expect(ciphertext.len > 0);

    var received = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext,
    );
    defer received.deinit();

    try testing.expectEqualSlices(
        u8,
        "hello bob",
        received.data,
    );
    try testing.expectEqual(
        @as(u32, 0),
        received.sender_leaf,
    );
}

test "Client: multiple send/receive preserves ordering" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext_one = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "message one",
    );
    defer testing.allocator.free(ciphertext_one);

    const ciphertext_two = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "message two",
    );
    defer testing.allocator.free(ciphertext_two);

    var received_one = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext_one,
    );
    defer received_one.deinit();

    var received_two = try bob.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext_two,
    );
    defer received_two.deinit();

    try testing.expectEqualSlices(
        u8,
        "message one",
        received_one.data,
    );
    try testing.expectEqualSlices(
        u8,
        "message two",
        received_two.data,
    );
}

test "Client: Bob sends, Alice receives" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    const ciphertext = try bob.sendMessage(
        testing.allocator,
        io,
        group_id,
        "hello alice",
    );
    defer testing.allocator.free(ciphertext);

    var received = try alice.receiveMessage(
        testing.allocator,
        io,
        group_id,
        ciphertext,
    );
    defer received.deinit();

    try testing.expectEqualSlices(
        u8,
        "hello alice",
        received.data,
    );
    try testing.expectEqual(
        @as(u32, 1),
        received.sender_leaf,
    );
}

test "Client: processIncoming decrypts application message" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const io = testIo();

    // Alice sends via sendMessage.
    const ciphertext = try alice.sendMessage(
        testing.allocator,
        io,
        group_id,
        "via processIncoming",
    );
    defer testing.allocator.free(ciphertext);

    // Bob receives via processIncoming (not receiveMessage).
    const result = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        ciphertext,
    );

    switch (result) {
        .application => |received| {
            var msg = received;
            defer msg.deinit();
            try testing.expectEqualSlices(
                u8,
                "via processIncoming",
                msg.data,
            );
            try testing.expectEqual(
                @as(u32, 0),
                msg.sender_leaf,
            );
        },
        else => return error.TestUnexpectedResult,
    }
}

test "Client: processIncoming rejects garbage input" {
    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Too short to even contain a wire format header.
    const result_short = alice.processIncoming(
        testing.allocator,
        io,
        group_id,
        &.{ 0x00, 0x01 },
    );
    try testing.expectError(
        error.WireDecodeFailed,
        result_short,
    );

    // Valid header length but unknown wire format.
    const result_bad = alice.processIncoming(
        testing.allocator,
        io,
        group_id,
        &.{ 0x00, 0x01, 0xFF, 0xFF },
    );
    try testing.expectError(
        error.UnsupportedWireFormat,
        result_bad,
    );
}

fn makeTestClientCarol(
    group_store: *MemGS(8),
    key_store: *MemKS(TestP, 8),
) !Client(TestP) {
    const seed: [32]u8 = .{0x77} ** 32;
    return Client(TestP).init(
        testing.allocator,
        "carol",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls.credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

test "Client: processIncoming processes commit" {
    const io = testIo();

    // Set up Alice + Bob in a 2-member group (epoch 1).
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    // Verify both at epoch 1 before the commit.
    {
        var bob_bundle = try bob.loadBundle(
            io,
            group_id,
        );
        defer bob_bundle.deinit(testing.allocator);
        try testing.expectEqual(
            @as(u64, 1),
            bob_bundle.group_state.epoch(),
        );
    }

    // Alice invites Carol → wire-encoded commit.
    var carol_group_store = MemGS(8).init();
    defer carol_group_store.deinit();
    var carol_key_store = MemKS(TestP, 8).init();
    defer carol_key_store.deinit();
    var carol = try makeTestClientCarol(
        &carol_group_store,
        &carol_key_store,
    );
    defer carol.deinit();

    const carol_key_package = try carol.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(carol_key_package.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        carol_key_package.data,
    );
    defer invite.deinit();

    // Bob processes Alice's commit via processIncoming.
    const result = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        invite.commit,
    );

    switch (result) {
        .commit_applied => |applied| {
            var ca = applied;
            defer ca.deinit();
            try testing.expectEqual(
                @as(u64, 2),
                ca.new_epoch,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    // Bob's persisted state should now be at epoch 2.
    var bob_bundle = try bob.loadBundle(io, group_id);
    defer bob_bundle.deinit(testing.allocator);
    try testing.expectEqual(
        @as(u64, 2),
        bob_bundle.group_state.epoch(),
    );
    // Group should have 3 members now.
    try testing.expectEqual(
        @as(u32, 3),
        bob_bundle.group_state.leafCount(),
    );
}

test "Client: proposeRemove returns wire-encoded bytes" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    // Alice proposes removing Bob.
    const proposal_bytes = try alice.proposeRemove(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(proposal_bytes);

    try testing.expect(proposal_bytes.len > 0);

    // Verify it's a valid MLSMessage.
    const msg = zmls.mls_message.MLSMessage
        .decodeExact(proposal_bytes) catch
        return error.TestUnexpectedResult;
    try testing.expectEqual(
        zmls.types.WireFormat.mls_public_message,
        msg.wire_format,
    );
}

test "Client: processIncoming caches received proposal" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    // Alice proposes removing Bob.
    const proposal_bytes = try alice.proposeRemove(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(proposal_bytes);

    // Bob processes the proposal via processIncoming.
    const result = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        proposal_bytes,
    );

    switch (result) {
        .proposal_cached => |cached| {
            // ProposalType.remove = 3
            try testing.expectEqual(
                @as(u16, 3),
                cached.proposal_type,
            );
            // Sender is Alice (leaf 0).
            try testing.expectEqual(
                @as(u32, 0),
                cached.sender_leaf,
            );
        },
        else => return error.TestUnexpectedResult,
    }

    // Bob should have the proposal in store.
    try testing.expectEqual(
        @as(u32, 1),
        bob.proposal_store.count,
    );
}

test "Client: commitPending preserves proposals on failure" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = try setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    );
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    // Alice proposes removing Bob.
    const proposal_bytes = try alice.proposeRemove(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(proposal_bytes);

    // Bob caches the proposal.
    _ = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        proposal_bytes,
    );
    try testing.expectEqual(
        @as(u32, 1),
        bob.proposal_store.count,
    );

    // Delete Bob's group state so commitPending will fail
    // during loadBundle.
    try bob_group_store.groupStore().delete(io, group_id);
    bob.invalidateGroupCache(group_id);

    // commitPending should fail (GroupNotFound).
    const result = bob.commitPending(
        testing.allocator,
        io,
        group_id,
    );
    try testing.expectError(
        error.GroupNotFound,
        result,
    );

    // Proposals must still be cached after the failure.
    try testing.expectEqual(
        @as(u32, 1),
        bob.proposal_store.count,
    );
}

test "Client: groupEpoch returns current epoch" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Freshly created group is at epoch 0.
    const epoch0 = try alice.groupEpoch(io, group_id);
    try testing.expectEqual(@as(u64, 0), epoch0);

    // selfUpdate advances epoch to 1.
    const commit = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(commit);

    const epoch1 = try alice.groupEpoch(io, group_id);
    try testing.expectEqual(@as(u64, 1), epoch1);
}

test "Client: groupCipherSuite returns negotiated suite" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    const suite = try alice.groupCipherSuite(
        io,
        group_id,
    );
    try testing.expectEqual(
        zmls.types.CipherSuite
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        suite,
    );
}

test "Client: myLeafIndex returns own position" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Creator is always leaf 0.
    const my_leaf = try alice.myLeafIndex(io, group_id);
    try testing.expectEqual(@as(u32, 0), my_leaf);
}

test "Client: groupLeafCount returns tree size" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Single-member group has 1 leaf.
    const count1 = try alice.groupLeafCount(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u32, 1), count1);

    // Add Bob — leaf count grows to 2.
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_kp.data,
    );
    defer invite.deinit();

    const count2 = try alice.groupLeafCount(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u32, 2), count2);
}

test "Client: groupMembers returns occupied leaves" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Single-member group: just Alice.
    const members1 = try alice.groupMembers(
        testing.allocator,
        io,
        group_id,
    );
    defer client_types.freeMemberList(
        testing.allocator,
        members1,
    );

    try testing.expectEqual(@as(usize, 1), members1.len);
    try testing.expectEqual(@as(u32, 0), members1[0].leaf_index);
    try testing.expectEqualSlices(
        u8,
        "alice",
        members1[0].identity,
    );

    // Add Bob.
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();
    var bob = try makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    );
    defer bob.deinit();

    const bob_kp = try bob.freshKeyPackage(
        testing.allocator,
        io,
    );
    defer testing.allocator.free(bob_kp.data);

    var invite = try alice.inviteMember(
        testing.allocator,
        io,
        group_id,
        bob_kp.data,
    );
    defer invite.deinit();

    // Two members: Alice and Bob.
    const members2 = try alice.groupMembers(
        testing.allocator,
        io,
        group_id,
    );
    defer client_types.freeMemberList(
        testing.allocator,
        members2,
    );

    try testing.expectEqual(@as(usize, 2), members2.len);
    try testing.expectEqual(
        @as(u32, 0),
        members2[0].leaf_index,
    );
    try testing.expectEqualSlices(
        u8,
        "alice",
        members2[0].identity,
    );
    try testing.expectEqual(
        @as(u32, 1),
        members2[1].leaf_index,
    );
    try testing.expectEqualSlices(
        u8,
        "bob",
        members2[1].identity,
    );
}

test "Client: groupEpoch fails for unknown group" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const result = alice.groupEpoch(io, "nonexistent");
    try testing.expectError(
        error.GroupNotFound,
        result,
    );
}

test "Client: exportSecret derives keying material" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var out1: [32]u8 = undefined;
    var out2: [32]u8 = undefined;
    try alice.exportSecret(
        io,
        group_id,
        "test-label",
        "test-context",
        &out1,
    );
    // Same inputs produce same output.
    try alice.exportSecret(
        io,
        group_id,
        "test-label",
        "test-context",
        &out2,
    );
    try testing.expectEqualSlices(u8, &out1, &out2);

    // Different label produces different output.
    var out3: [32]u8 = undefined;
    try alice.exportSecret(
        io,
        group_id,
        "other-label",
        "test-context",
        &out3,
    );
    try testing.expect(
        !std.mem.eql(u8, &out1, &out3),
    );
}

test "Client: epochAuthenticator returns non-zero bytes" {
    const io = testIo();

    var group_store = MemGS(8).init();
    defer group_store.deinit();
    var key_store = MemKS(TestP, 8).init();
    defer key_store.deinit();
    var alice = try makeTestClient(
        &group_store,
        &key_store,
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    var auth1: [TestP.nh]u8 = undefined;
    try alice.epochAuthenticator(io, group_id, &auth1);

    // Should not be all zeros.
    const zeros: [TestP.nh]u8 = .{0} ** TestP.nh;
    try testing.expect(
        !std.mem.eql(u8, &auth1, &zeros),
    );

    // Advance epoch — authenticator should change.
    const commit = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(commit);

    var auth2: [TestP.nh]u8 = undefined;
    try alice.epochAuthenticator(io, group_id, &auth2);

    try testing.expect(
        !std.mem.eql(u8, &auth1, &auth2),
    );
}

test "Client: cancelPendingProposals clears cache" {
    const io = testIo();

    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();

    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    // Alice proposes removing Bob.
    const proposal_bytes = try alice.proposeRemove(
        testing.allocator,
        io,
        group_id,
        1,
    );
    defer testing.allocator.free(proposal_bytes);

    // Bob receives and caches it.
    _ = try bob.processIncoming(
        testing.allocator,
        io,
        group_id,
        proposal_bytes,
    );
    try testing.expectEqual(
        @as(u32, 1),
        bob.proposal_store.count,
    );

    // Bob cancels pending proposals.
    bob.cancelPendingProposals(group_id);
    try testing.expectEqual(
        @as(u32, 0),
        bob.proposal_store.count,
    );
}

test "Client: sendMessageWithAad round-trips" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();

    var alice: Client(TestP) = undefined;
    var bob: Client(TestP) = undefined;

    const group_id = setupTwoMemberGroup(
        &alice_group_store,
        &alice_key_store,
        &bob_group_store,
        &bob_key_store,
        &alice,
        &bob,
    ) catch return error.SkipZigTest;
    defer testing.allocator.free(group_id);
    defer alice.deinit();
    defer bob.deinit();

    const ciphertext = try alice.sendMessageWithAad(
        testing.allocator,
        testIo(),
        group_id,
        "hello with aad",
        "extra-context",
    );
    defer testing.allocator.free(ciphertext);

    try testing.expect(ciphertext.len > 0);
}

test "Client: groupInfo returns decodable bytes" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();

    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
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

    try testing.expect(gi_bytes.len > 0);

    // Verify it decodes as a valid MLSMessage(GroupInfo).
    const wire = try zmls.mls_message.MLSMessage
        .decodeExact(gi_bytes);
    try testing.expectEqual(
        zmls.WireFormat.mls_group_info,
        wire.wire_format,
    );

    // Decode the inner GroupInfo.
    const gi_body = switch (wire.body) {
        .group_info => |b| b,
        else => return error.SkipZigTest,
    };
    const gi_dec = try zmls.group_info.GroupInfo.decode(
        testing.allocator,
        gi_body,
        0,
    );
    var gi = gi_dec.value;
    defer gi.deinit(testing.allocator);

    // Verify signer index matches Alice (leaf 0).
    try testing.expectEqual(@as(u32, 0), gi.signer);
}

test "Client: externalJoin lifecycle" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();

    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Export GroupInfo for external joiners.
    const gi_bytes = try alice.groupInfo(
        testing.allocator,
        io,
        group_id,
    );
    defer testing.allocator.free(gi_bytes);

    // Bob does an external join.
    var bob_group_store = MemGS(8).init();
    defer bob_group_store.deinit();
    var bob_key_store = MemKS(TestP, 8).init();
    defer bob_key_store.deinit();

    var bob = makeTestClientBob(
        &bob_group_store,
        &bob_key_store,
    ) catch return error.SkipZigTest;
    defer bob.deinit();

    var result = try bob.externalJoin(
        testing.allocator,
        io,
        gi_bytes,
    );
    defer result.deinit();

    // Bob should have commit bytes to distribute.
    try testing.expect(result.commit.len > 0);

    // Bob's group_id should match Alice's group.
    try testing.expectEqualSlices(
        u8,
        group_id,
        result.group_id,
    );

    // Bob should be at epoch 1 (external commit
    // advances from epoch 0 to epoch 1).
    const bob_epoch = try bob.groupEpoch(
        io,
        result.group_id,
    );
    try testing.expectEqual(@as(u64, 1), bob_epoch);
}

test "Client: stageCommit confirm advances epoch" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();

    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Epoch should be 0 initially.
    const epoch_before = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_before);

    // Stage a commit (empty commit = key update).
    var handle = try alice.stageCommit(
        testing.allocator,
        io,
        group_id,
        &.{},
    );

    // Commit data should be non-empty.
    try testing.expect(handle.commit_data.len > 0);

    // Epoch should still be 0 — not yet confirmed.
    const epoch_staged = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_staged);

    // Confirm the staged commit.
    try handle.confirm(&alice, io);
    defer handle.deinit();

    // Epoch should now be 1.
    const epoch_after = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), epoch_after);
}

test "Client: stageCommit discard leaves epoch unchanged" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();

    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    const epoch_before = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_before);

    // Stage a commit but discard it.
    var handle = try alice.stageCommit(
        testing.allocator,
        io,
        group_id,
        &.{},
    );
    handle.discard();
    handle.deinit();

    // Epoch should still be 0.
    const epoch_after = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 0), epoch_after);
}

test "Client: stageCommit conflicting commit" {
    var alice_group_store = MemGS(8).init();
    defer alice_group_store.deinit();
    var alice_key_store = MemKS(TestP, 8).init();
    defer alice_key_store.deinit();

    var alice = try makeTestClient(
        &alice_group_store,
        &alice_key_store,
    );
    defer alice.deinit();

    const io = testIo();
    const group_id = try alice.createGroup(io);
    defer testing.allocator.free(group_id);

    // Stage a commit at epoch 0.
    var handle = try alice.stageCommit(
        testing.allocator,
        io,
        group_id,
        &.{},
    );
    try testing.expect(handle.commit_data.len > 0);

    // Meanwhile, advance the epoch with selfUpdate.
    const update_bytes = try alice.selfUpdate(
        testing.allocator,
        io,
        group_id,
    );
    testing.allocator.free(update_bytes);

    // Epoch should now be 1.
    const epoch_now = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), epoch_now);

    // Confirming the stale staged commit should fail.
    try testing.expectError(
        error.ConflictingCommit,
        handle.confirm(&alice, io),
    );

    // Cleanup: discard and deinit.
    handle.discard();
    handle.deinit();

    // Epoch should still be 1 (staged commit rejected).
    const epoch_final = try alice.groupEpoch(
        io,
        group_id,
    );
    try testing.expectEqual(@as(u64, 1), epoch_final);
}

test "Client: credential validator rejects Add" {
    const io = testIo();
    const gpa = testing.allocator;

    const CV = zmls.credential_validator;

    // Validator that rejects identities starting with
    // "evil".
    const RejectEvil = struct {
        const instance: @This() = .{};

        fn rejectEvil(
            _: *const anyopaque,
            cred: *const Credential,
        ) zmls.errors.ValidationError!void {
            const identity = switch (cred.tag) {
                .basic => cred.payload.basic,
                else => return,
            };
            if (identity.len >= 4 and
                std.mem.eql(
                    u8,
                    identity[0..4],
                    "evil",
                )) return error.InvalidCredential;
        }

        pub fn validator() CV.CredentialValidator {
            return .{
                .context = @ptrCast(&instance),
                .validate_fn = &rejectEvil,
            };
        }
    };

    var gs = MemGS(1).init();
    defer gs.deinit();
    var ks = MemKS(TestP, 1).init();
    defer ks.deinit();

    var alice = try Client(TestP).init(
        gpa,
        "alice",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &[_]u8{0x01} ** 32,
        .{
            .group_store = gs.groupStore(),
            .key_store = ks.keyStore(),
            .credential_validator = RejectEvil
                .validator(),
        },
    );
    defer alice.deinit();

    const group_id = try alice.createGroup(io);
    defer gpa.free(group_id);

    // Create Bob with "evil" identity.
    var gs2 = MemGS(1).init();
    defer gs2.deinit();
    var ks2 = MemKS(TestP, 1).init();
    defer ks2.deinit();

    var bob = try Client(TestP).init(
        gpa,
        "evil-bob",
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &[_]u8{0x02} ** 32,
        .{
            .group_store = gs2.groupStore(),
            .key_store = ks2.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    );
    defer bob.deinit();

    const kp_result = try bob.freshKeyPackage(gpa, io);
    defer gpa.free(kp_result.data);

    // inviteMember should fail due to credential.
    try testing.expectError(
        error.CredentialValidationFailed,
        alice.inviteMember(
            gpa,
            io,
            group_id,
            kp_result.data,
        ),
    );
}
