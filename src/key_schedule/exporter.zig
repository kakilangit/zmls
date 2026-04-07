//! MLS-Exporter per RFC 9420 Section 8.5. Derives keying material
//! from an epoch's exporter_secret for use by external protocols.
// MLS-Exporter per RFC 9420 Section 8.5.
//
// Exports keying material from an epoch's exporter_secret for
// use by external protocols:
//
//   MLS-Exporter(Label, Context, Length) =
//     ExpandWithLabel(
//       DeriveSecret(exporter_secret, Label),
//       "exported",
//       Hash(Context),
//       Length
//     )
//
// Generic over a CryptoProvider backend (comptime).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../crypto/primitives.zig");

/// Export keying material from the current epoch.
///
/// `exporter_secret` is the epoch's exporter_secret (from
/// EpochSecrets). `label` is an application-defined string.
/// `context` is application-defined context bytes. `out`
/// receives the derived keying material of the requested length.
pub fn mlsExporter(
    comptime P: type,
    exporter_secret: *const [P.nh]u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) void {
    // derived_secret = DeriveSecret(exporter_secret, Label)
    var derived = primitives.deriveSecret(
        P,
        exporter_secret,
        label,
    );
    defer primitives.secureZero(&derived);

    // Hash(Context)
    const hashed_context = P.hash(context);

    // ExpandWithLabel(derived_secret, "exported",
    //                 Hash(Context), Length)
    primitives.expandWithLabel(
        P,
        &derived,
        "exported",
        &hashed_context,
        out,
    );
}

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const Default = @import(
    "../crypto/default.zig",
).DhKemX25519Sha256Aes128GcmEd25519;

test "mlsExporter produces non-zero output" {
    const secret = [_]u8{0x42} ** Default.nh;
    var out: [32]u8 = undefined;

    mlsExporter(
        Default,
        &secret,
        "test-label",
        "test-context",
        &out,
    );

    var all_zero = true;
    for (out) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}

test "mlsExporter is deterministic" {
    const secret = [_]u8{0x55} ** Default.nh;
    var out1: [16]u8 = undefined;
    var out2: [16]u8 = undefined;

    mlsExporter(Default, &secret, "label", "ctx", &out1);
    mlsExporter(Default, &secret, "label", "ctx", &out2);

    try testing.expectEqualSlices(u8, &out1, &out2);
}

test "different labels produce different output" {
    const secret = [_]u8{0x66} ** Default.nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    mlsExporter(Default, &secret, "label-a", "ctx", &out_a);
    mlsExporter(Default, &secret, "label-b", "ctx", &out_b);

    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));
}

test "different contexts produce different output" {
    const secret = [_]u8{0x77} ** Default.nh;
    var out_a: [32]u8 = undefined;
    var out_b: [32]u8 = undefined;

    mlsExporter(Default, &secret, "label", "ctx-a", &out_a);
    mlsExporter(Default, &secret, "label", "ctx-b", &out_b);

    try testing.expect(!std.mem.eql(u8, &out_a, &out_b));
}

test "different lengths produce consistent prefixes" {
    // Exporter with length 16 should NOT be a prefix of length
    // 32, because ExpandWithLabel includes the length in KDFLabel.
    const secret = [_]u8{0x88} ** Default.nh;
    var short: [16]u8 = undefined;
    var long: [32]u8 = undefined;

    mlsExporter(Default, &secret, "label", "ctx", &short);
    mlsExporter(Default, &secret, "label", "ctx", &long);

    // With HKDF, different output lengths in ExpandWithLabel
    // produce different KDFLabel inputs, so the first 16 bytes
    // of the 32-byte output should NOT match the 16-byte output.
    try testing.expect(
        !std.mem.eql(u8, &short, long[0..16]),
    );
}
