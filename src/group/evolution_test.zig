const std = @import("std");
const testing = std.testing;

const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const node_mod = @import("../tree/node.zig");
const ratchet_tree_mod = @import("../tree/ratchet_tree.zig");
const proposal_mod = @import("../messages/proposal.zig");
const key_package_mod = @import("../messages/key_package.zig");
const psk_mod = @import("../key_schedule/psk.zig");
const credential_mod = @import("../credential/credential.zig");
const evolution = @import("evolution.zig");

const LeafIndex = types.LeafIndex;
const ExtensionType = types.ExtensionType;
const CredentialType = types.CredentialType;
const Extension = node_mod.Extension;
const Capabilities = node_mod.Capabilities;
const LeafNode = node_mod.LeafNode;
const RatchetTree = ratchet_tree_mod.RatchetTree;
const Proposal = proposal_mod.Proposal;
const PreSharedKeyId = psk_mod.PreSharedKeyId;
const Credential = credential_mod.Credential;
const KeyPackage = key_package_mod.KeyPackage;

const CommitSender = evolution.CommitSender;
const validateProposalList = evolution.validateProposalList;
const validateAddsAgainstTree = evolution.validateAddsAgainstTree;
const validateUpdatesAgainstTree = evolution.validateUpdatesAgainstTree;
const validatePskProposals = evolution.validatePskProposals;
const validateGceAgainstTree = evolution.validateGceAgainstTree;
const parseRequiredCapabilities = evolution.parseRequiredCapabilities;
const validateLeafMeetsRequired = evolution.validateLeafMeetsRequired;
const validateAddsRequiredCapabilities = evolution.validateAddsRequiredCapabilities;
const validateWireFormat = evolution.validateWireFormat;
const validateNonDefaultProposalCaps = evolution.validateNonDefaultProposalCaps;
const validateReInitVersion = evolution.validateReInitVersion;
const applyProposals = evolution.applyProposals;
const sortDescending = evolution.sortDescending;

fn makeTestLeaf(id: []const u8) LeafNode {
    return .{
        .encryption_key = id,
        .signature_key = id,
        .credential = Credential.initBasic(id),
        .capabilities = .{
            .versions = &.{},
            .cipher_suites = &.{},
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{},
        },
        .source = .commit,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = id,
    };
}

fn makeTestKeyPackage(id: []const u8) KeyPackage {
    return .{
        .version = .mls10,
        .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        .init_key = id,
        .leaf_node = makeTestLeaf(id),
        .extensions = &.{},
        .signature = id,
    };
}

fn makeCommitSender(li: u32) CommitSender {
    return .{
        .sender_type = .member,
        .leaf_index = LeafIndex.fromU32(li),
    };
}

test "validateProposalList accepts valid Add" {
    const add1 = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("bob"),
            },
        },
    };
    const add2 = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("carol"),
            },
        },
    };

    const proposals = [_]Proposal{ add1, add2 };
    const result = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer result.destroy(testing.allocator);

    try testing.expectEqual(@as(u32, 2), result.adds_len);
    try testing.expectEqual(@as(u32, 0), result.updates_len);
    try testing.expectEqual(@as(u32, 0), result.removes_len);
    try testing.expect(result.gce == null);
    try testing.expect(result.reinit == null);
}

test "validate rejects duplicate Update for same leaf" {
    const update1 = Proposal{
        .tag = .update,
        .payload = .{
            .update = .{
                .leaf_node = makeTestLeaf("new-a"),
            },
        },
    };
    const update2 = Proposal{
        .tag = .update,
        .payload = .{
            .update = .{
                .leaf_node = makeTestLeaf("new-a2"),
            },
        },
    };

    const proposals = [_]Proposal{ update1, update2 };
    const result = validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    try testing.expectError(error.DuplicateProposal, result);
}

test "validate rejects duplicate Remove for same leaf" {
    const r1 = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 2 } },
    };
    const r2 = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 2 } },
    };

    const proposals = [_]Proposal{ r1, r2 };
    const result = validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    try testing.expectError(error.DuplicateProposal, result);
}

test "validate rejects ReInit combined with other proposals" {
    const reinit_prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("bob"),
            },
        },
    };

    const proposals = [_]Proposal{ reinit_prop, add_prop };
    const result = validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate rejects self-remove" {
    const rm = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 0 } },
    };

    const proposals = [_]Proposal{rm};
    const result = validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate rejects update+remove same leaf" {
    const up = Proposal{
        .tag = .update,
        .payload = .{
            .update = .{
                .leaf_node = makeTestLeaf("new"),
            },
        },
    };
    const rm = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1 } },
    };

    const proposals = [_]Proposal{ up, rm };
    const result = validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(1),
        null,
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate accepts standalone ReInit" {
    const reinit_prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };

    const proposals = [_]Proposal{reinit_prop};
    const result = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer result.destroy(testing.allocator);

    try testing.expect(result.reinit != null);
    try testing.expectEqual(@as(u32, 0), result.adds_len);
    try testing.expectEqual(@as(u32, 0), result.removes_len);
    try testing.expectEqual(@as(u32, 0), result.updates_len);
}

test "validateReInitVersion rejects version downgrade" {
    const reinit_prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .reserved, // 0 < mls10 (1)
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };

    const proposals = [_]Proposal{reinit_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);
    const result = validateReInitVersion(
        validated,
        .mls10,
    );
    try testing.expectError(error.VersionMismatch, result);
}

test "validateReInitVersion accepts equal version" {
    const reinit_prop = Proposal{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = "new-group",
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };

    const proposals = [_]Proposal{reinit_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);
    try validateReInitVersion(validated, .mls10);
}

test "applyProposals adds members to tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("bob"),
            },
        },
    };

    const proposals = [_]Proposal{add_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = try applyProposals(
        validated,
        &tree,
    );

    try testing.expectEqual(@as(u32, 1), result.added_count);
    try testing.expectEqual(
        @as(u32, 1),
        result.added_leaves[0].toU32(),
    );
    try testing.expectEqual(@as(u32, 2), tree.leaf_count);

    const leaf1 = try tree.getLeaf(LeafIndex.fromU32(1));
    try testing.expect(leaf1 != null);
}

test "applyProposals removes members from tree" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeaf("carol"),
    );

    const rm_prop = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 2 } },
    };

    const proposals = [_]Proposal{rm_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = try applyProposals(
        validated,
        &tree,
    );

    try testing.expectEqual(@as(u32, 1), result.removed_count);
    try testing.expectEqual(
        @as(u32, 2),
        result.removed_leaves[0],
    );
    // Bob is still at leaf 1.
    const leaf1 = try tree.getLeaf(LeafIndex.fromU32(1));
    try testing.expect(leaf1 != null);
}

test "applyProposals updates sender leaf" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice-old"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    const up_prop = Proposal{
        .tag = .update,
        .payload = .{
            .update = .{
                .leaf_node = makeTestLeaf("alice-new"),
            },
        },
    };

    const proposals = [_]Proposal{up_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    _ = try applyProposals(validated, &tree);

    const leaf0 = try tree.getLeaf(LeafIndex.fromU32(0));
    try testing.expect(leaf0 != null);
    try testing.expectEqualSlices(
        u8,
        "alice-new",
        leaf0.?.encryption_key,
    );
}

test "sortDescending sorts correctly" {
    var items = [_]u32{ 1, 5, 3, 2, 4 };
    sortDescending(&items);
    try testing.expectEqual(@as(u32, 5), items[0]);
    try testing.expectEqual(@as(u32, 4), items[1]);
    try testing.expectEqual(@as(u32, 3), items[2]);
    try testing.expectEqual(@as(u32, 2), items[3]);
    try testing.expectEqual(@as(u32, 1), items[4]);
}

test "validate accepts mixed Add Remove PSK" {
    const psk_id = PreSharedKeyId{
        .psk_type = .external,
        .external_psk_id = "my-psk",
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = "nonce",
    };

    const proposals = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = makeTestKeyPackage("bob"),
                },
            },
        },
        .{
            .tag = .remove,
            .payload = .{ .remove = .{ .removed = 3 } },
        },
        .{
            .tag = .psk,
            .payload = .{ .psk = .{ .psk = psk_id } },
        },
    };

    const result = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer result.destroy(testing.allocator);

    try testing.expectEqual(@as(u32, 1), result.adds_len);
    try testing.expectEqual(@as(u32, 1), result.removes_len);
    try testing.expectEqual(@as(u32, 1), result.psk_ids_len);
    try testing.expectEqual(@as(u32, 3), result.removes[0]);
}

// -- Phase 14.1: Add proposal tree-aware tests -------------------------------

test "validateAddsAgainstTree rejects duplicate encryption key" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    // Add proposal where encryption_key == "alice" (same as
    // existing leaf 0).
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("alice"),
            },
        },
    };

    const proposals = [_]Proposal{add_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateAddsAgainstTree(
        validated,
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
    try testing.expectError(error.InvalidKeyPackage, result);
}

test "validateAddsAgainstTree rejects duplicate init key among adds" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    // Two Add proposals with the same init_key.
    var kp1 = makeTestKeyPackage("bob");
    kp1.init_key = "shared-init";
    kp1.leaf_node = makeTestLeaf("bob");

    var kp2 = makeTestKeyPackage("carol");
    kp2.init_key = "shared-init";
    kp2.leaf_node = makeTestLeaf("carol");

    const proposals = [_]Proposal{
        .{ .tag = .add, .payload = .{ .add = .{ .key_package = kp1 } } },
        .{ .tag = .add, .payload = .{ .add = .{ .key_package = kp2 } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateAddsAgainstTree(
        validated,
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
    try testing.expectError(error.InvalidKeyPackage, result);
}

test "validateAddsAgainstTree rejects cipher suite mismatch" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    var kp = makeTestKeyPackage("bob");
    kp.cipher_suite = .mls_128_dhkemp256_aes128gcm_sha256_p256;

    const proposals = [_]Proposal{
        .{ .tag = .add, .payload = .{ .add = .{ .key_package = kp } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateAddsAgainstTree(
        validated,
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
    try testing.expectError(error.CipherSuiteMismatch, result);
}

test "validateAddsAgainstTree accepts valid adds" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    const proposals = [_]Proposal{
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = makeTestKeyPackage("bob"),
                },
            },
        },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    try validateAddsAgainstTree(
        validated,
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
}

test "validateAddsAgainstTree allows re-add when member removed" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    // Remove bob (leaf 1) and re-add with same keys.
    const proposals = [_]Proposal{
        .{
            .tag = .remove,
            .payload = .{ .remove = .{ .removed = 1 } },
        },
        .{
            .tag = .add,
            .payload = .{
                .add = .{
                    .key_package = makeTestKeyPackage("bob"),
                },
            },
        },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    // Should succeed because bob is being removed.
    try validateAddsAgainstTree(
        validated,
        &tree,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    );
}

// -- Phase 14.2: Update proposal tree-aware tests ----------------------------

test "validateUpdatesAgainstTree rejects committer self-update" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    var up_leaf = makeTestLeaf("alice-new");
    up_leaf.source = .update;
    const up_prop = Proposal{
        .tag = .update,
        .payload = .{ .update = .{ .leaf_node = up_leaf } },
    };

    const proposals = [_]Proposal{up_prop};
    // Sender is leaf 0, so this Update targets the committer.
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateUpdatesAgainstTree(
        validated,
        &tree,
        makeCommitSender(0),
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validateUpdatesAgainstTree rejects wrong source" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    // Update from bob (leaf 1) with wrong source (.commit).
    const up_leaf = makeTestLeaf("bob-new");
    // Default makeTestLeaf sets source = .commit, which is wrong
    // for an Update proposal.
    const up_prop = Proposal{
        .tag = .update,
        .payload = .{ .update = .{ .leaf_node = up_leaf } },
    };

    const proposals = [_]Proposal{up_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(1),
        null,
    );
    defer validated.destroy(testing.allocator);

    // Alice (leaf 0) is the committer; bob (leaf 1) sent Update.
    const result = validateUpdatesAgainstTree(
        validated,
        &tree,
        makeCommitSender(0),
    );
    try testing.expectError(error.InvalidLeafNode, result);
}

test "validateUpdatesAgainstTree rejects duplicate encryption key" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(2),
        makeTestLeaf("carol"),
    );

    // Bob updates with encryption_key = "carol" (duplicate).
    var up_leaf = makeTestLeaf("carol");
    up_leaf.source = .update;
    const up_prop = Proposal{
        .tag = .update,
        .payload = .{ .update = .{ .leaf_node = up_leaf } },
    };

    const proposals = [_]Proposal{up_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(1),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateUpdatesAgainstTree(
        validated,
        &tree,
        makeCommitSender(0),
    );
    try testing.expectError(error.InvalidLeafNode, result);
}

test "validateUpdatesAgainstTree accepts valid update" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 4);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    var up_leaf = makeTestLeaf("bob-new");
    up_leaf.source = .update;
    const up_prop = Proposal{
        .tag = .update,
        .payload = .{ .update = .{ .leaf_node = up_leaf } },
    };

    const proposals = [_]Proposal{up_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(1),
        null,
    );
    defer validated.destroy(testing.allocator);

    // Alice (leaf 0) is the committer.
    try validateUpdatesAgainstTree(
        validated,
        &tree,
        makeCommitSender(0),
    );
}

// -- Phase 14.3: PSK proposal validation tests -------------------------------

fn makeExternalPskId(
    id: []const u8,
    nonce: []const u8,
) PreSharedKeyId {
    return .{
        .psk_type = .external,
        .external_psk_id = id,
        .resumption_usage = .reserved,
        .resumption_group_id = "",
        .resumption_epoch = 0,
        .psk_nonce = nonce,
    };
}

test "validatePskProposals rejects duplicate PSK IDs" {
    const nonce = "0" ** 32;
    const psk_id = makeExternalPskId("my-psk", nonce);

    const proposals = [_]Proposal{
        .{ .tag = .psk, .payload = .{ .psk = .{ .psk = psk_id } } },
        .{ .tag = .psk, .payload = .{ .psk = .{ .psk = psk_id } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validatePskProposals(validated, 32);
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validatePskProposals rejects wrong nonce length" {
    const psk_id = makeExternalPskId("my-psk", "short");

    const proposals = [_]Proposal{
        .{ .tag = .psk, .payload = .{ .psk = .{ .psk = psk_id } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    // nh=32 but nonce is 5 bytes.
    const result = validatePskProposals(validated, 32);
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validatePskProposals rejects non-application resumption" {
    const nonce = "0" ** 32;
    const psk_id = PreSharedKeyId{
        .psk_type = .resumption,
        .external_psk_id = "",
        .resumption_usage = .reinit,
        .resumption_group_id = "group-1",
        .resumption_epoch = 5,
        .psk_nonce = nonce,
    };

    const proposals = [_]Proposal{
        .{ .tag = .psk, .payload = .{ .psk = .{ .psk = psk_id } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validatePskProposals(validated, 32);
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validatePskProposals accepts valid PSK" {
    const nonce = "0" ** 32;
    const psk_id = makeExternalPskId("my-psk", nonce);

    const proposals = [_]Proposal{
        .{ .tag = .psk, .payload = .{ .psk = .{ .psk = psk_id } } },
    };

    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    try validatePskProposals(validated, 32);
}

// -- Phase 14.4: GCE validation tests ----------------------------------------

fn makeTestLeafWithCaps(
    id: []const u8,
    exts: []const ExtensionType,
) LeafNode {
    return .{
        .encryption_key = id,
        .signature_key = id,
        .credential = Credential.initBasic(id),
        .capabilities = .{
            .versions = &.{},
            .cipher_suites = &.{},
            .extensions = exts,
            .proposals = &.{},
            .credentials = &.{},
        },
        .source = .commit,
        .lifetime = null,
        .parent_hash = null,
        .extensions = &.{},
        .signature = id,
    };
}

test "validateGceAgainstTree rejects unsupported extension" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Leaf 0 supports no extensions.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    // GCE proposes an application_id extension.
    const ext = Extension{
        .extension_type = .application_id,
        .data = "app-id",
    };
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = @as(
                    []const Extension,
                    &[_]Extension{ext},
                ),
            },
        },
    };

    const proposals = [_]Proposal{gce_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateGceAgainstTree(validated, &tree);
    try testing.expectError(
        error.UnsupportedCapability,
        result,
    );
}

test "validateGceAgainstTree accepts when all support extension" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    const supported = [_]ExtensionType{.application_id};
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeafWithCaps("alice", &supported),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeafWithCaps("bob", &supported),
    );

    const ext = Extension{
        .extension_type = .application_id,
        .data = "app-id",
    };
    const gce_prop = Proposal{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = @as(
                    []const Extension,
                    &[_]Extension{ext},
                ),
            },
        },
    };

    const proposals = [_]Proposal{gce_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    try validateGceAgainstTree(validated, &tree);
}

test "validateGceAgainstTree no-op when no GCE" {
    const proposals = [_]Proposal{};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    // No GCE → should succeed trivially.
    try validateGceAgainstTree(validated, &undefined_tree());
}

fn undefined_tree() RatchetTree {
    return .{
        .nodes = &.{},
        .leaf_count = 0,
        .allocator = testing.allocator,
        .owns_contents = false,
    };
}

// -- Phase 14.5: Required Capabilities tests ---------------------------------

// RequiredCapabilities extension data format:
//   varint(len) || extension_types[len]
//   varint(len) || proposal_types[len]
//   varint(len) || credential_types[len]
// Each element is a u16 big-endian.

test "parseRequiredCapabilities round-trip" {
    // Build extension data: ext=[0x0001], prop=[], cred=[0x0001].
    // varint(2) = 0x02, then 0x00 0x01.
    // varint(0) = 0x00.
    // varint(2) = 0x02, then 0x00 0x01.
    const data = [_]u8{
        0x02, 0x00, 0x01, // ext_types: [application_id=1]
        0x00, // prop_types: []
        0x02, 0x00, 0x01, // cred_types: [basic=1]
    };
    const rc = try parseRequiredCapabilities(&data);
    try testing.expectEqual(@as(usize, 2), rc.extension_types.len);
    try testing.expectEqual(@as(usize, 0), rc.proposal_types.len);
    try testing.expectEqual(@as(usize, 2), rc.credential_types.len);
}

test "validateLeafMeetsRequired rejects missing extension" {
    const data = [_]u8{
        0x02, 0x00, 0x01, // ext_types: [application_id=1]
        0x00, // prop_types: []
        0x00, // cred_types: []
    };
    const rc = try parseRequiredCapabilities(&data);

    // Leaf with empty capabilities.
    const caps = Capabilities{
        .versions = &.{},
        .cipher_suites = &.{},
        .extensions = &.{},
        .proposals = &.{},
        .credentials = &.{},
    };

    const result = validateLeafMeetsRequired(&caps, &rc);
    try testing.expectError(
        error.UnsupportedCapability,
        result,
    );
}

test "validateLeafMeetsRequired rejects missing credential" {
    const data = [_]u8{
        0x00, // ext_types: []
        0x00, // prop_types: []
        0x02, 0x00, 0x01, // cred_types: [basic=1]
    };
    const rc = try parseRequiredCapabilities(&data);

    // Leaf with no credentials listed.
    const caps = Capabilities{
        .versions = &.{},
        .cipher_suites = &.{},
        .extensions = &.{},
        .proposals = &.{},
        .credentials = &.{},
    };

    const result = validateLeafMeetsRequired(&caps, &rc);
    try testing.expectError(
        error.UnsupportedCapability,
        result,
    );
}

test "validateLeafMeetsRequired accepts matching caps" {
    const data = [_]u8{
        0x02, 0x00, 0x01, // ext_types: [application_id=1]
        0x00, // prop_types: []
        0x02, 0x00, 0x01, // cred_types: [basic=1]
    };
    const rc = try parseRequiredCapabilities(&data);

    const ext_list = [_]ExtensionType{.application_id};
    const cred_list = [_]CredentialType{.basic};
    const caps = Capabilities{
        .versions = &.{},
        .cipher_suites = &.{},
        .extensions = &ext_list,
        .proposals = &.{},
        .credentials = &cred_list,
    };

    try validateLeafMeetsRequired(&caps, &rc);
}

test "validateAddsRequiredCapabilities rejects non-compliant add" {
    const data = [_]u8{
        0x02, 0x00, 0x01, // ext_types: [application_id=1]
        0x00, // prop_types: []
        0x00, // cred_types: []
    };
    const ext = Extension{
        .extension_type = .required_capabilities,
        .data = &data,
    };
    const group_exts = [_]Extension{ext};

    // Add a member with no capabilities.
    const add_prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("bob"),
            },
        },
    };
    const proposals = [_]Proposal{add_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    const result = validateAddsRequiredCapabilities(
        validated,
        &group_exts,
    );
    try testing.expectError(
        error.UnsupportedCapability,
        result,
    );
}

test "validateAddsRequiredCapabilities accepts compliant add" {
    const data = [_]u8{
        0x02, 0x00, 0x01, // ext_types: [application_id=1]
        0x00, // prop_types: []
        0x00, // cred_types: []
    };
    const ext = Extension{
        .extension_type = .required_capabilities,
        .data = &data,
    };
    const group_exts = [_]Extension{ext};

    const ext_list = [_]ExtensionType{.application_id};
    const leaf = makeTestLeafWithCaps("bob", &ext_list);
    var kp = makeTestKeyPackage("bob");
    kp.leaf_node = leaf;

    const add_prop = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = kp } },
    };
    const proposals = [_]Proposal{add_prop};
    const validated = try validateProposalList(
        testing.allocator,
        &proposals,
        makeCommitSender(0),
        null,
    );
    defer validated.destroy(testing.allocator);

    try validateAddsRequiredCapabilities(
        validated,
        &group_exts,
    );
}

// -- Phase 14.6: Wire format policy tests ------------------------------------

test "validateWireFormat rejects application data in PublicMessage" {
    const result = validateWireFormat(
        .mls_public_message,
        .application,
        .encrypt_application_only,
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validateWireFormat allows handshake in PublicMessage" {
    try validateWireFormat(
        .mls_public_message,
        .commit,
        .encrypt_application_only,
    );
    try validateWireFormat(
        .mls_public_message,
        .proposal,
        .encrypt_application_only,
    );
}

test "validateWireFormat always_encrypt rejects all PublicMessage" {
    const r1 = validateWireFormat(
        .mls_public_message,
        .commit,
        .always_encrypt,
    );
    try testing.expectError(
        error.InvalidProposalList,
        r1,
    );
}

test "validateWireFormat allows PrivateMessage always" {
    try validateWireFormat(
        .mls_private_message,
        .application,
        .always_encrypt,
    );
    try validateWireFormat(
        .mls_private_message,
        .commit,
        .encrypt_application_only,
    );
}

test "validateNonDefaultProposalCaps rejects unsupported type" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 2);
    defer tree.deinit();

    // Both leaves have empty proposals capabilities.
    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );
    try tree.setLeaf(
        LeafIndex.fromU32(1),
        makeTestLeaf("bob"),
    );

    // A proposal with non-default type (0x0A0A).
    const prop = Proposal{
        .tag = @enumFromInt(0x0A0A),
        .payload = .{ .unknown = &.{} },
    };
    const proposals = [_]Proposal{prop};

    const result = validateNonDefaultProposalCaps(
        &proposals,
        &tree,
    );
    try testing.expectError(
        error.UnsupportedCapability,
        result,
    );
}

test "validateNonDefaultProposalCaps accepts default types" {
    const alloc = testing.allocator;
    var tree = try RatchetTree.init(alloc, 1);
    defer tree.deinit();

    try tree.setLeaf(
        LeafIndex.fromU32(0),
        makeTestLeaf("alice"),
    );

    // Default proposal types (1-7) should always pass, even
    // if not listed in capabilities.
    const prop = Proposal{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = makeTestKeyPackage("bob"),
            },
        },
    };
    const proposals = [_]Proposal{prop};

    try validateNonDefaultProposalCaps(&proposals, &tree);
}

test "Update and Remove for high leaf indices succeed" {
    // Leaf indices >= 256 must work (no fixed-size bitmap cap).
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = LeafIndex.fromU32(512),
    };
    // Update proposal from leaf 512.
    const update = Proposal{
        .tag = .update,
        .payload = .{
            .update = .{
                .leaf_node = makeTestLeaf("alice"),
            },
        },
    };
    const up = [_]Proposal{update};
    const result = try validateProposalList(testing.allocator, &up, sender, null);
    defer result.destroy(testing.allocator);
    try testing.expectEqual(@as(u32, 1), result.updates_len);
    try testing.expectEqual(
        @as(u32, 512),
        result.updates[0].leaf_index.toU32(),
    );

    // Remove proposal targeting leaf 1000.
    const remove = Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = 1000 } },
    };
    const rm = [_]Proposal{remove};
    const r2 = try validateProposalList(testing.allocator, &rm, sender, null);
    defer r2.destroy(testing.allocator);
    try testing.expectEqual(@as(u32, 1), r2.removes_len);
    try testing.expectEqual(@as(u32, 1000), r2.removes[0]);
}
