// Fuzz targets for proposal validation.
//
// Property: validateProposalList(random proposals) must never
// panic — it may return a ValidationError, but must not
// trigger undefined behaviour.
//
// Run with:  zig build test --fuzz

const std = @import("std");
const testing = std.testing;
const Smith = testing.Smith;
const mls = @import("zmls");
const types = mls.types;
const evolution = mls.group_evolution;
const proposal_mod = mls.proposal;
const Proposal = proposal_mod.Proposal;
const ProposalType = types.ProposalType;
const SenderType = types.SenderType;
const LeafIndex = types.LeafIndex;
const CommitSender = evolution.CommitSender;
const KeyPackage = mls.KeyPackage;
const Credential = mls.Credential;

// ── Helpers ─────────────────────────────────────────────────

/// Build an Add proposal with a minimal KeyPackage.
fn makeAdd(tag: u8) Proposal {
    const id: []const u8 = @as(
        [*]const u8,
        @ptrCast(&tag),
    )[0..1];
    const versions = comptime [_]types.ProtocolVersion{
        .mls10,
    };
    const suites = comptime [_]types.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const cred_types = comptime [_]types.CredentialType{
        .basic,
    };
    return .{
        .tag = .add,
        .payload = .{
            .add = .{
                .key_package = .{
                    .version = .mls10,
                    .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                    .init_key = id,
                    .leaf_node = .{
                        .encryption_key = id,
                        .signature_key = id,
                        .credential = Credential.initBasic(
                            id,
                        ),
                        .capabilities = .{
                            .versions = &versions,
                            .cipher_suites = &suites,
                            .extensions = &.{},
                            .proposals = &.{},
                            .credentials = &cred_types,
                        },
                        .source = .key_package,
                        .lifetime = .{
                            .not_before = 0,
                            .not_after = std.math.maxInt(
                                u64,
                            ),
                        },
                        .parent_hash = null,
                        .extensions = &.{},
                        .signature = id,
                    },
                    .extensions = &.{},
                    .signature = id,
                },
            },
        },
    };
}

/// Build a Remove proposal targeting the given leaf index.
fn makeRemove(leaf: u32) Proposal {
    return .{
        .tag = .remove,
        .payload = .{
            .remove = .{ .removed = leaf },
        },
    };
}

/// Build a PSK proposal with a dummy external PSK ID.
fn makePsk() Proposal {
    return .{
        .tag = .psk,
        .payload = .{
            .psk = .{
                .psk = .{
                    .psk_type = .external,
                    .external_psk_id = &.{0x42},
                    .psk_nonce = &.{0x00},
                    .resumption_usage = .application,
                    .resumption_group_id = &.{},
                    .resumption_epoch = 0,
                },
            },
        },
    };
}

/// Build a ReInit proposal with dummy fields.
fn makeReInit() Proposal {
    return .{
        .tag = .reinit,
        .payload = .{
            .reinit = .{
                .group_id = &.{0xAA},
                .version = .mls10,
                .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
                .extensions = &.{},
            },
        },
    };
}

/// Build a GCE proposal with empty extensions.
fn makeGCE() Proposal {
    return .{
        .tag = .group_context_extensions,
        .payload = .{
            .group_context_extensions = .{
                .extensions = &.{},
            },
        },
    };
}

// ── Fuzz: validateProposalList ──────────────────────────────

const Choice = enum(u3) {
    add,
    remove_low,
    remove_high,
    psk,
    reinit,
    gce,
};

fn fuzzValidateProposals(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Build a random list of up to 32 proposals.
    var proposals: [32]Proposal = undefined;
    var len: u32 = 0;

    while (len < 32) : (len += 1) {
        if (smith.eosWeightedSimple(3, 1)) break;

        const choice = smith.value(Choice);
        switch (choice) {
            .add => {
                const tag = smith.valueRangeAtMost(
                    u8,
                    0,
                    255,
                );
                proposals[len] = makeAdd(tag);
            },
            .remove_low => {
                const leaf = smith.valueRangeAtMost(
                    u32,
                    0,
                    7,
                );
                proposals[len] = makeRemove(leaf);
            },
            .remove_high => {
                const leaf = smith.valueRangeAtMost(
                    u32,
                    100,
                    200,
                );
                proposals[len] = makeRemove(leaf);
            },
            .psk => {
                proposals[len] = makePsk();
            },
            .reinit => {
                proposals[len] = makeReInit();
            },
            .gce => {
                proposals[len] = makeGCE();
            },
        }
    }

    // Pick a random sender.
    const sender_leaf = smith.valueRangeAtMost(u32, 0, 15);
    const sender = CommitSender{
        .sender_type = .member,
        .leaf_index = LeafIndex.fromU32(sender_leaf),
    };

    // Must not panic, even if it returns an error.
    _ = evolution.validateProposalList(
        proposals[0..len],
        sender,
        null,
    ) catch return;
}

test "fuzz: validate proposal list" {
    try testing.fuzz({}, fuzzValidateProposals, .{});
}

// ── Fuzz: proposal encode/decode round-trip ─────────────────

fn fuzzProposalCodec(
    _: void,
    smith: *Smith,
) anyerror!void {
    // Build a random proposal and encode it, then decode.
    const choice = smith.value(Choice);
    const prop: Proposal = switch (choice) {
        .add => makeAdd(
            smith.valueRangeAtMost(u8, 0, 255),
        ),
        .remove_low => makeRemove(
            smith.valueRangeAtMost(u32, 0, 255),
        ),
        .remove_high => makeRemove(
            smith.valueRangeAtMost(u32, 256, 65535),
        ),
        .psk => makePsk(),
        .reinit => makeReInit(),
        .gce => makeGCE(),
    };

    // Encode.
    var buf: [4096]u8 = undefined;
    const end = prop.encode(&buf, 0) catch return;

    // Decode.
    const alloc = testing.allocator;
    var r = Proposal.decode(alloc, &buf, 0) catch return;
    r.value.deinit(alloc);

    // Verify position matches.
    var r2 = Proposal.decode(alloc, buf[0..end], 0) catch
        return;
    defer r2.value.deinit(alloc);
    try testing.expectEqual(end, r2.pos);
}

test "fuzz: proposal encode/decode round-trip" {
    try testing.fuzz({}, fuzzProposalCodec, .{});
}
