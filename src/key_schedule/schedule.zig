//! Core key schedule per RFC 9420 Section 8. Derives all epoch
//! secrets (joiner, welcome, sender_data, encryption, exporter,
//! etc.) from init_secret, commit_secret, psk_secret, and
//! GroupContext.
// Core key schedule per RFC 9420 Section 8.
//
// Derives all epoch secrets from init_secret, commit_secret,
// psk_secret, and the serialized GroupContext.
//
// The derivation chain is:
//
//   prk = KDF.Extract(init_secret, commit_secret)
//   joiner_secret = ExpandWithLabel(prk, "joiner", gc, Nh)
//   member_prk = KDF.Extract(joiner_secret, psk_secret)
//   welcome_secret = DeriveSecret(member_prk, "welcome")
//   epoch_secret = ExpandWithLabel(member_prk, "epoch", gc, Nh)
//   <individual secrets> = DeriveSecret(epoch_secret, <label>)
//   init_secret_[n] = DeriveSecret(epoch_secret, "init")
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../crypto/primitives.zig");

/// All secrets derived for a single epoch.
pub fn EpochSecrets(comptime P: type) type {
    return struct {
        /// Joiner secret — shared with new joiners via Welcome.
        joiner_secret: [P.nh]u8,
        /// Welcome secret — encrypts GroupInfo in Welcome messages.
        welcome_secret: [P.nh]u8,
        /// Epoch secret — root of per-epoch derivation tree.
        epoch_secret: [P.nh]u8,
        /// Sender data secret — encrypts sender data in PrivateMessage.
        sender_data_secret: [P.nh]u8,
        /// Encryption secret — seeds the secret tree for message encryption.
        encryption_secret: [P.nh]u8,
        /// Exporter secret — used by MLS-Exporter for external protocols.
        exporter_secret: [P.nh]u8,
        /// External secret — derives the external init HPKE key pair.
        external_secret: [P.nh]u8,
        /// Confirmation key — computes confirmation_tag on Commits.
        confirmation_key: [P.nh]u8,
        /// Membership key — computes membership_tag on PublicMessages.
        membership_key: [P.nh]u8,
        /// Resumption PSK — can be injected into future epochs.
        resumption_psk: [P.nh]u8,
        /// Epoch authenticator — external epoch confirmation.
        epoch_authenticator: [P.nh]u8,
        /// Init secret for the next epoch.
        init_secret: [P.nh]u8,

        const Self = @This();

        /// Zero all secret material.
        pub fn zeroize(self: *Self) void {
            inline for (std.meta.fields(Self)) |field| {
                if (field.type == [P.nh]u8) {
                    primitives.secureZero(
                        &@field(self, field.name),
                    );
                }
            }
        }
    };
}

/// Derive all epoch secrets for a new epoch.
///
/// Parameters:
///   - init_secret: init_secret from the previous epoch (or
///     all-zero for epoch 0).
///   - commit_secret: the commit secret from the ratchet tree
///     update path (or all-zero if no path).
///   - psk_secret: the chained PSK secret (or all-zero if no
///     PSKs).
///   - group_context: the serialized GroupContext for the new
///     epoch.
pub fn deriveEpochSecrets(
    comptime P: type,
    init_secret: *const [P.nh]u8,
    commit_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    group_context: []const u8,
) EpochSecrets(P) {
    var result: EpochSecrets(P) = undefined;

    // Step 1: prk = KDF.Extract(init_secret, commit_secret)
    var prk = P.kdfExtract(init_secret, commit_secret);
    defer primitives.secureZero(&prk);

    // Step 2: joiner_secret = ExpandWithLabel(prk, "joiner",
    //           GroupContext, Nh)
    primitives.expandWithLabel(
        P,
        &prk,
        "joiner",
        group_context,
        &result.joiner_secret,
    );

    // Steps 3-7: derive from joiner_secret onward.
    deriveFromJoinerInner(
        P,
        &result.joiner_secret,
        psk_secret,
        group_context,
        &result,
    );

    return result;
}

/// Derive all epoch secrets starting from a joiner_secret.
///
/// Used by Welcome processing where the joiner_secret is received
/// directly (not derived from init_secret + commit_secret).
///
/// Parameters:
///   - joiner_secret: the joiner secret from GroupSecrets.
///   - psk_secret: the chained PSK secret (or all-zero if no
///     PSKs).
///   - group_context: the serialized GroupContext for the new
///     epoch.
pub fn deriveEpochSecretsFromJoiner(
    comptime P: type,
    joiner_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    group_context: []const u8,
) EpochSecrets(P) {
    var result: EpochSecrets(P) = undefined;
    result.joiner_secret = joiner_secret.*;

    deriveFromJoinerInner(
        P,
        joiner_secret,
        psk_secret,
        group_context,
        &result,
    );

    return result;
}

/// Common derivation logic from joiner_secret onward.
///
///   member_prk = KDF.Extract(joiner_secret, psk_secret)
///   welcome_secret = DeriveSecret(member_prk, "welcome")
///   epoch_secret = ExpandWithLabel(member_prk, "epoch", gc, Nh)
///   <individual secrets> = DeriveSecret(epoch_secret, <label>)
///   init_secret = DeriveSecret(epoch_secret, "init")
fn deriveFromJoinerInner(
    comptime P: type,
    joiner_secret: *const [P.nh]u8,
    psk_secret: *const [P.nh]u8,
    group_context: []const u8,
    result: *EpochSecrets(P),
) void {
    // Step 3: member_prk = KDF.Extract(joiner_secret, psk_secret)
    var member_prk = P.kdfExtract(
        joiner_secret,
        psk_secret,
    );
    defer primitives.secureZero(&member_prk);

    // Step 4: welcome_secret = DeriveSecret(member_prk, "welcome")
    result.welcome_secret = primitives.deriveSecret(
        P,
        &member_prk,
        "welcome",
    );

    // Step 5: epoch_secret = ExpandWithLabel(member_prk, "epoch",
    //           GroupContext, Nh)
    primitives.expandWithLabel(
        P,
        &member_prk,
        "epoch",
        group_context,
        &result.epoch_secret,
    );

    // Steps 6-7: Derive individual secrets from epoch_secret.
    deriveIndividualSecrets(P, result);
}

/// RFC 9420 Section 8: Derive individual epoch secrets and
/// init_secret from the epoch_secret.
///
///   <secret> = DeriveSecret(epoch_secret, <label>)
///   init_secret = DeriveSecret(epoch_secret, "init")
fn deriveIndividualSecrets(
    comptime P: type,
    result: *EpochSecrets(P),
) void {
    const es = &result.epoch_secret;
    result.sender_data_secret = primitives.deriveSecret(
        P,
        es,
        "sender data",
    );
    result.encryption_secret = primitives.deriveSecret(
        P,
        es,
        "encryption",
    );
    result.exporter_secret = primitives.deriveSecret(
        P,
        es,
        "exporter",
    );
    result.external_secret = primitives.deriveSecret(
        P,
        es,
        "external",
    );
    result.confirmation_key = primitives.deriveSecret(
        P,
        es,
        "confirm",
    );
    result.membership_key = primitives.deriveSecret(
        P,
        es,
        "membership",
    );
    result.resumption_psk = primitives.deriveSecret(
        P,
        es,
        "resumption",
    );
    result.epoch_authenticator = primitives.deriveSecret(
        P,
        es,
        "authentication",
    );
    result.init_secret = primitives.deriveSecret(
        P,
        es,
        "init",
    );
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "deriveEpochSecrets produces non-zero secrets" {
    const zero = [_]u8{0} ** Default.nh;
    const gc = "fake group context";

    const secrets = deriveEpochSecrets(
        Default,
        &zero, // init_secret (epoch 0)
        &zero, // commit_secret (no path)
        &zero, // psk_secret (no PSKs)
        gc,
    );

    // All secrets should be non-zero (extremely unlikely for
    // real HKDF to produce all zeros).
    inline for (std.meta.fields(@TypeOf(secrets))) |field| {
        if (field.type == [Default.nh]u8) {
            const val = @field(secrets, field.name);
            var all_zero = true;
            for (val) |b| {
                if (b != 0) {
                    all_zero = false;
                    break;
                }
            }
            try testing.expect(!all_zero);
        }
    }
}

test "deriveEpochSecrets is deterministic" {
    const init = [_]u8{0x01} ** Default.nh;
    const commit = [_]u8{0x02} ** Default.nh;
    const psk = [_]u8{0x03} ** Default.nh;
    const gc = "group context bytes";

    const s1 = deriveEpochSecrets(
        Default,
        &init,
        &commit,
        &psk,
        gc,
    );
    const s2 = deriveEpochSecrets(
        Default,
        &init,
        &commit,
        &psk,
        gc,
    );

    try testing.expectEqualSlices(
        u8,
        &s1.epoch_secret,
        &s2.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &s1.init_secret,
        &s2.init_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &s1.welcome_secret,
        &s2.welcome_secret,
    );
}

test "different inputs produce different epoch secrets" {
    const zero = [_]u8{0} ** Default.nh;
    const gc = "same context";

    const s1 = deriveEpochSecrets(
        Default,
        &zero,
        &zero,
        &zero,
        gc,
    );

    const commit = [_]u8{0xFF} ** Default.nh;
    const s2 = deriveEpochSecrets(
        Default,
        &zero,
        &commit,
        &zero,
        gc,
    );

    try testing.expect(!std.mem.eql(
        u8,
        &s1.epoch_secret,
        &s2.epoch_secret,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        &s1.init_secret,
        &s2.init_secret,
    ));
}

test "epoch transition: init_secret feeds next epoch" {
    const zero = [_]u8{0} ** Default.nh;
    const gc_0 = "epoch 0 context";
    const gc_1 = "epoch 1 context";

    // Epoch 0.
    const epoch0 = deriveEpochSecrets(
        Default,
        &zero,
        &zero,
        &zero,
        gc_0,
    );

    // Epoch 1 uses epoch 0's init_secret.
    const commit_1 = [_]u8{0x42} ** Default.nh;
    const epoch1 = deriveEpochSecrets(
        Default,
        &epoch0.init_secret,
        &commit_1,
        &zero,
        gc_1,
    );

    // Epoch 1 secrets should differ from epoch 0.
    try testing.expect(!std.mem.eql(
        u8,
        &epoch0.epoch_secret,
        &epoch1.epoch_secret,
    ));
    try testing.expect(!std.mem.eql(
        u8,
        &epoch0.init_secret,
        &epoch1.init_secret,
    ));
}

test "all derived secrets are distinct" {
    const init = [_]u8{0x10} ** Default.nh;
    const commit = [_]u8{0x20} ** Default.nh;
    const psk = [_]u8{0x30} ** Default.nh;
    const gc = "group context for distinct test";

    const s = deriveEpochSecrets(
        Default,
        &init,
        &commit,
        &psk,
        gc,
    );

    // Collect all Nh-sized secrets into a list and verify no
    // two are the same.
    const secrets = [_]*const [Default.nh]u8{
        &s.joiner_secret,
        &s.welcome_secret,
        &s.epoch_secret,
        &s.sender_data_secret,
        &s.encryption_secret,
        &s.exporter_secret,
        &s.external_secret,
        &s.confirmation_key,
        &s.membership_key,
        &s.resumption_psk,
        &s.epoch_authenticator,
        &s.init_secret,
    };

    for (secrets, 0..) |a, i| {
        var j: u32 = @intCast(i + 1);
        while (j < secrets.len) : (j += 1) {
            try testing.expect(
                !std.mem.eql(u8, a, secrets[j]),
            );
        }
    }
}

test "deriveEpochSecretsFromJoiner matches deriveEpochSecrets" {
    // DeriveEpochSecrets computes joiner_secret internally,
    // then derives everything from it. If we extract that
    // joiner_secret and pass it to deriveEpochSecretsFromJoiner
    // with the same psk_secret and group_context, we should get
    // identical epoch_secret, welcome_secret, etc.
    const init = [_]u8{0x01} ** Default.nh;
    const commit = [_]u8{0x02} ** Default.nh;
    const psk = [_]u8{0x03} ** Default.nh;
    const gc = "group context for joiner test";

    const full = deriveEpochSecrets(
        Default,
        &init,
        &commit,
        &psk,
        gc,
    );

    const from_joiner = deriveEpochSecretsFromJoiner(
        Default,
        &full.joiner_secret,
        &psk,
        gc,
    );

    try testing.expectEqualSlices(
        u8,
        &full.welcome_secret,
        &from_joiner.welcome_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &full.epoch_secret,
        &from_joiner.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &full.init_secret,
        &from_joiner.init_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &full.confirmation_key,
        &from_joiner.confirmation_key,
    );
    try testing.expectEqualSlices(
        u8,
        &full.sender_data_secret,
        &from_joiner.sender_data_secret,
    );
}

test "zeroize clears all secrets" {
    const zero = [_]u8{0} ** Default.nh;
    const gc = "context";

    var s = deriveEpochSecrets(
        Default,
        &zero,
        &zero,
        &zero,
        gc,
    );

    s.zeroize();

    const expected_zero = [_]u8{0} ** Default.nh;
    try testing.expectEqualSlices(
        u8,
        &expected_zero,
        &s.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &expected_zero,
        &s.init_secret,
    );
}
