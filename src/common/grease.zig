//! GREASE (Generate Random Extensions And Sustain Extensibility)
//! value generation and checking per RFC 9420 Section 13.4.
// GREASE (Generate Random Extensions And Sustain Extensibility)
// per RFC 9420 Section 13.4.
//
// GREASE values follow the pattern 0x_A_A where _ is the same
// nibble, producing values like 0x0A0A, 0x1A1A, ..., 0xEAEA.
// These 15 values appear in capabilities to exercise unknown-
// type tolerance in other implementations.
//
// This module provides:
//   - isGrease: check if a u16 value is a GREASE sentinel.
//   - GREASE constants for extensions, proposals, and
//     credentials.
//   - Capability lists with GREASE values included.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("types.zig");

const ExtensionType = types.ExtensionType;
const ProposalType = types.ProposalType;
const CredentialType = types.CredentialType;

/// Check whether a u16 value is a GREASE sentinel.
///
/// GREASE values have the form 0xnAnA where n is the same
/// nibble (0x0-0xE). The full set is: 0x0A0A, 0x1A1A,
/// 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
/// 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA.
pub fn isGrease(value: u16) bool {
    // Both bytes must be equal.
    const hi: u8 = @truncate(value >> 8);
    const lo: u8 = @truncate(value);
    if (hi != lo) return false;
    // Low nibble of each byte must be 0xA.
    if (lo & 0x0F != 0x0A) return false;
    // High nibble must be 0x0-0xE (not 0xF).
    if (lo >> 4 > 0x0E) return false;
    return true;
}

/// Check whether an ExtensionType is a GREASE value.
pub fn isGreaseExtension(et: ExtensionType) bool {
    return isGrease(@intFromEnum(et));
}

/// Check whether a ProposalType is a GREASE value.
pub fn isGreaseProposal(pt: ProposalType) bool {
    return isGrease(@intFromEnum(pt));
}

/// Check whether a CredentialType is a GREASE value.
pub fn isGreaseCredential(ct: CredentialType) bool {
    return isGrease(@intFromEnum(ct));
}

// -- GREASE constants for embedding in capabilities ----------------------

/// A single GREASE ExtensionType for inclusion in capabilities.
pub const grease_extension: ExtensionType = @enumFromInt(0x0A0A);

/// A single GREASE ProposalType for inclusion in capabilities.
pub const grease_proposal: ProposalType = @enumFromInt(0x0A0A);

/// A single GREASE CredentialType for inclusion in capabilities.
pub const grease_credential: CredentialType = @enumFromInt(
    0x0A0A,
);

// -- Tests ---------------------------------------------------------------

const testing = std.testing;

test "isGrease recognizes all 15 GREASE values" {
    const expected = [_]u16{
        0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A,
        0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
        0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
        0xCACA, 0xDADA, 0xEAEA,
    };
    for (expected) |v| {
        try testing.expect(isGrease(v));
    }
}

test "isGrease rejects non-GREASE values" {
    try testing.expect(!isGrease(0x0000));
    try testing.expect(!isGrease(0x0001));
    try testing.expect(!isGrease(0x0A0B)); // bytes differ
    try testing.expect(!isGrease(0x0B0B)); // low nibble not A
    try testing.expect(!isGrease(0xFAFA)); // F > E
    try testing.expect(!isGrease(0xFFFF));
    try testing.expect(!isGrease(0x1234));
}

test "isGreaseExtension detects GREASE extension" {
    try testing.expect(isGreaseExtension(grease_extension));
    try testing.expect(!isGreaseExtension(.reserved));
    try testing.expect(!isGreaseExtension(.ratchet_tree));
}

test "isGreaseProposal detects GREASE proposal" {
    try testing.expect(isGreaseProposal(grease_proposal));
    try testing.expect(!isGreaseProposal(.add));
    try testing.expect(!isGreaseProposal(.remove));
}

test "isGreaseCredential detects GREASE credential" {
    try testing.expect(isGreaseCredential(grease_credential));
    try testing.expect(!isGreaseCredential(.basic));
}

test "GREASE values round-trip through enum" {
    // Verify non-exhaustive enums preserve GREASE values.
    const ext: ExtensionType = @enumFromInt(0x2A2A);
    try testing.expectEqual(@as(u16, 0x2A2A), @intFromEnum(ext));
    try testing.expect(isGreaseExtension(ext));

    const prop: ProposalType = @enumFromInt(0x3A3A);
    try testing.expectEqual(@as(u16, 0x3A3A), @intFromEnum(prop));
    try testing.expect(isGreaseProposal(prop));

    const cred: CredentialType = @enumFromInt(0x4A4A);
    try testing.expectEqual(@as(u16, 0x4A4A), @intFromEnum(cred));
    try testing.expect(isGreaseCredential(cred));
}
