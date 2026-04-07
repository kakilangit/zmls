//! External senders extension per RFC 9420 Section 12.1.8.1.
//! Manages non-member entities authorized to send specific
//! proposal types to the group.
// External senders extension per RFC 9420 Section 12.1.8.1.
//
// An external sender is a non-member entity authorized to send
// proposals to the group. The external_senders extension
// (type 5) carries a list of ExternalSender entries, each
// containing a signature public key and a credential.
//
// External senders may only send: Add, Remove, PSK, and ReInit
// proposals. They MUST NOT send: Update, GroupContextExtensions,
// or ExternalInit proposals.
//
// This module provides:
//   - ExternalSender struct with encode/decode.
//   - parseExternalSenders: parse extension data into a list.
//   - findExternalSenders: find and parse from extensions list.
//   - validateExternalSenderProposal: check sender index,
//     proposal type restrictions, and credential validation.

const std = @import("std");
const assert = std.debug.assert;
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const node_mod = @import("../tree/node.zig");
const cred_mod = @import("../credential/credential.zig");
const validator_mod = @import("../credential/validator.zig");

const ExtensionType = types.ExtensionType;
const ProposalType = types.ProposalType;
const SenderType = types.SenderType;
const Extension = node_mod.Extension;
const Credential = cred_mod.Credential;
const CredentialValidator = validator_mod.CredentialValidator;
const DecodeError = errors.DecodeError;
const ValidationError = errors.ValidationError;
const EncodeError = codec.EncodeError;

/// Maximum number of external senders in the extension.
const max_external_senders: u32 = 64;

// -- ExternalSender ----------------------------------------------------------

/// An external sender entry per RFC 9420 Section 12.1.8.1.
///
///   struct {
///       SignaturePublicKey signature_key;  // opaque<V>
///       Credential credential;
///   } ExternalSender;
///
/// Slices point into the original extension data bytes and
/// are only valid as long as those bytes are alive.
pub const ExternalSender = struct {
    signature_key: []const u8,
    credential: Credential,
};

/// Parsed list of external senders from the extension data.
///
/// Uses a bounded inline array to avoid heap allocation.
/// All slices point into the original extension data.
pub const ExternalSenderList = struct {
    senders: [max_external_senders]ExternalSender,
    len: u32,

    /// Get the external sender at a given index.
    pub fn get(
        self: *const ExternalSenderList,
        idx: u32,
    ) ?ExternalSender {
        if (idx >= self.len) return null;
        return self.senders[idx];
    }
};

// -- Parsing -----------------------------------------------------------------

/// Parse the external_senders extension data into a list of
/// ExternalSender entries.
///
/// The wire format is:
///   ExternalSender external_senders<V>;
///
/// This is a varint-prefixed vector of ExternalSender structs.
/// Each ExternalSender contains:
///   - opaque signature_key<V>
///   - Credential credential (CredentialType u16 + payload)
///
/// Slices in the returned entries point into `data`.
pub fn parseExternalSenders(
    data: []const u8,
) DecodeError!ExternalSenderList {
    var result: ExternalSenderList = undefined;
    result.len = 0;

    // Decode outer vector length.
    const vr = try varint.decode(data, 0);
    const total_len = vr.value;
    var pos = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (pos + total_len > data.len) return error.Truncated;

    const end = pos + total_len;

    while (pos < end) {
        if (result.len >= max_external_senders) {
            return error.VectorTooLarge;
        }

        // Decode signature_key<V> (zero-copy slice).
        const sig_r = try codec.decodeVarVectorSlice(
            data,
            pos,
        );
        pos = sig_r.pos;

        // Decode Credential. We use zero-copy decoding:
        // CredentialType (u16) + basic identity<V>.
        const cred_r = try decodeCredentialSlice(data, pos);
        pos = cred_r.pos;

        result.senders[result.len] = .{
            .signature_key = sig_r.value,
            .credential = cred_r.value,
        };
        result.len += 1;
    }

    // Must have consumed exactly the declared bytes.
    if (pos != end) return error.Truncated;

    return result;
}

/// Zero-copy credential decode for external sender parsing.
///
/// Only basic credentials can be decoded without allocation
/// (the identity is a slice into the source buffer). X.509
/// credentials require allocation for the certificate chain,
/// but for external senders in the extension data we use
/// zero-copy slices into the extension bytes.
fn decodeCredentialSlice(
    data: []const u8,
    pos: u32,
) DecodeError!struct { value: Credential, pos: u32 } {
    const type_r = try codec.decodeUint16(data, pos);
    const cred_type: types.CredentialType = @enumFromInt(
        type_r.value,
    );

    switch (cred_type) {
        .basic => {
            const id_r = try codec.decodeVarVectorSlice(
                data,
                type_r.pos,
            );
            return .{
                .value = .{
                    .tag = .basic,
                    .payload = .{ .basic = id_r.value },
                },
                .pos = id_r.pos,
            };
        },
        else => return error.InvalidEnumValue,
    }
}

/// Find and parse the external_senders extension from a list
/// of extensions.
///
/// Returns null if no external_senders extension is present.
pub fn findExternalSenders(
    extensions: []const Extension,
) DecodeError!?ExternalSenderList {
    for (extensions) |ext| {
        if (ext.extension_type == .external_senders) {
            return try parseExternalSenders(ext.data);
        }
    }
    return null;
}

// -- Validation --------------------------------------------------------------

/// Proposal types that external senders are allowed to send.
///
/// Per RFC 9420 Section 12.1.8.1, external senders may only
/// send: Add, Remove, PSK, and ReInit proposals.
fn isAllowedExternalProposalType(pt: ProposalType) bool {
    return switch (pt) {
        .add, .remove, .psk, .reinit => true,
        else => false,
    };
}

/// Validate that a proposal from an external sender is
/// authorized.
///
/// Checks:
///   1. The external_senders extension exists in the group
///      context extensions.
///   2. The sender_index is within bounds.
///   3. The proposal type is allowed for external senders.
///   4. The credential passes application-level validation
///      (via the CredentialValidator).
///
/// Returns the ExternalSender entry on success (for signature
/// verification by the caller).
pub fn validateExternalSenderProposal(
    extensions: []const Extension,
    sender_index: u32,
    proposal_type: ProposalType,
    credential_validator: ?CredentialValidator,
) (ValidationError || DecodeError)!ExternalSender {
    // 1. Find and parse the external_senders extension.
    const ext_senders = try findExternalSenders(
        extensions,
    ) orelse {
        return error.MissingExtension;
    };

    // 2. Check sender_index is in bounds.
    const sender = ext_senders.get(sender_index) orelse {
        return error.UnknownMember;
    };

    // 3. Check proposal type is allowed.
    if (!isAllowedExternalProposalType(proposal_type)) {
        return error.InvalidProposalList;
    }

    // 4. Validate credential.
    if (credential_validator) |cv| {
        try cv.validate(&sender.credential);
    }

    return sender;
}

// -- Encoding ----------------------------------------------------------------

/// Encode an ExternalSender into a buffer at the given position.
///
/// Writes: signature_key<V> || Credential.
pub fn encodeExternalSender(
    sender: *const ExternalSender,
    buf: []u8,
    pos: u32,
) EncodeError!u32 {
    var p = try codec.encodeVarVector(
        buf,
        pos,
        sender.signature_key,
    );
    p = try sender.credential.encode(buf, p);
    return p;
}

/// Encode a list of ExternalSender entries as extension data.
///
/// Writes: varint(total_len) || ExternalSender[0] || ...
///
/// Returns the number of bytes written.
pub fn encodeExternalSenderList(
    senders: []const ExternalSender,
    buf: []u8,
) EncodeError!u32 {
    // Encode senders into buffer after a gap for the varint
    // length prefix. Max varint is 4 bytes.
    const gap: u32 = 4;
    var p: u32 = gap;

    for (senders) |*s| {
        p = try encodeExternalSender(s, buf, p);
    }

    const inner_len: u32 = p - gap;

    // Encode varint length at position 0.
    var len_buf: [4]u8 = undefined;
    const len_end = try varint.encode(
        &len_buf,
        0,
        inner_len,
    );

    // Shift data if varint was smaller than 4 bytes.
    const dest_start: u32 = len_end;
    if (dest_start != gap) {
        std.mem.copyForwards(
            u8,
            buf[dest_start..][0..inner_len],
            buf[gap..][0..inner_len],
        );
    }

    // Write the length bytes.
    @memcpy(buf[0..len_end], len_buf[0..len_end]);

    return dest_start + inner_len;
}

/// Build an Extension struct for external_senders.
///
/// The caller provides `out_buf` as owned storage for the
/// encoded extension data; the returned Extension's data
/// field points into this buffer.
pub fn makeExternalSendersExtension(
    senders: []const ExternalSender,
    out_buf: []u8,
) EncodeError!Extension {
    const len = try encodeExternalSenderList(
        senders,
        out_buf,
    );
    return Extension{
        .extension_type = .external_senders,
        .data = out_buf[0..len],
    };
}

// -- Tests -------------------------------------------------------------------

const testing = std.testing;
const AcceptAllValidator = validator_mod.AcceptAllValidator;

test "parseExternalSenders empty list" {
    // Encode an empty list: varint(0).
    var buf: [4]u8 = undefined;
    const len = try varint.encode(&buf, 0, 0);

    const result = try parseExternalSenders(buf[0..len]);
    try testing.expectEqual(@as(u32, 0), result.len);
}

test "parseExternalSenders single basic entry" {
    // Manually construct extension data for one ExternalSender
    // with a basic credential.
    var buf: [256]u8 = undefined;

    // First encode the inner content (without outer varint).
    var inner_buf: [256]u8 = undefined;
    var p: u32 = 0;

    // signature_key<V> = "sig-key-1"
    p = try codec.encodeVarVector(
        &inner_buf,
        p,
        "sig-key-1",
    );

    // Credential: basic type (u16 = 1) + identity<V> = "alice"
    p = try codec.encodeUint16(&inner_buf, p, 1); // basic
    p = try codec.encodeVarVector(&inner_buf, p, "alice");

    // Now wrap in outer varint length.
    const inner_len = p;
    var pos: u32 = 0;
    pos = try varint.encode(&buf, pos, inner_len);
    @memcpy(
        buf[pos..][0..inner_len],
        inner_buf[0..inner_len],
    );

    const total = pos + inner_len;
    const result = try parseExternalSenders(buf[0..total]);

    try testing.expectEqual(@as(u32, 1), result.len);
    try testing.expectEqualSlices(
        u8,
        "sig-key-1",
        result.senders[0].signature_key,
    );
    try testing.expectEqual(
        types.CredentialType.basic,
        result.senders[0].credential.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "alice",
        result.senders[0].credential.payload.basic,
    );
}

test "encode and parse round-trip" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-alpha",
            .credential = Credential.initBasic("alpha"),
        },
        .{
            .signature_key = "key-beta",
            .credential = Credential.initBasic("beta"),
        },
    };

    var buf: [512]u8 = undefined;
    const len = try encodeExternalSenderList(
        &senders,
        &buf,
    );

    const parsed = try parseExternalSenders(buf[0..len]);
    try testing.expectEqual(@as(u32, 2), parsed.len);
    try testing.expectEqualSlices(
        u8,
        "key-alpha",
        parsed.senders[0].signature_key,
    );
    try testing.expectEqualSlices(
        u8,
        "alpha",
        parsed.senders[0].credential.payload.basic,
    );
    try testing.expectEqualSlices(
        u8,
        "key-beta",
        parsed.senders[1].signature_key,
    );
    try testing.expectEqualSlices(
        u8,
        "beta",
        parsed.senders[1].credential.payload.basic,
    );
}

test "findExternalSenders returns null when absent" {
    const exts = [_]Extension{};
    const result = try findExternalSenders(&exts);
    try testing.expect(result == null);
}

test "findExternalSenders finds and parses extension" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );

    const exts = [_]Extension{ext};
    const result = try findExternalSenders(&exts);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u32, 1), result.?.len);
    try testing.expectEqualSlices(
        u8,
        "key-1",
        result.?.senders[0].signature_key,
    );
}

test "validateExternalSenderProposal accepts valid Add" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    const es = try validateExternalSenderProposal(
        &exts,
        0,
        .add,
        AcceptAllValidator.validator(),
    );
    try testing.expectEqualSlices(
        u8,
        "key-1",
        es.signature_key,
    );
}

test "validate accepts Remove, PSK, ReInit" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    _ = try validateExternalSenderProposal(
        &exts,
        0,
        .remove,
        AcceptAllValidator.validator(),
    );
    _ = try validateExternalSenderProposal(
        &exts,
        0,
        .psk,
        AcceptAllValidator.validator(),
    );
    _ = try validateExternalSenderProposal(
        &exts,
        0,
        .reinit,
        AcceptAllValidator.validator(),
    );
}

test "validate rejects Update" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    const result = validateExternalSenderProposal(
        &exts,
        0,
        .update,
        AcceptAllValidator.validator(),
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate rejects GCE" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    const result = validateExternalSenderProposal(
        &exts,
        0,
        .group_context_extensions,
        AcceptAllValidator.validator(),
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate rejects ExternalInit" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    const result = validateExternalSenderProposal(
        &exts,
        0,
        .external_init,
        AcceptAllValidator.validator(),
    );
    try testing.expectError(
        error.InvalidProposalList,
        result,
    );
}

test "validate rejects missing extension" {
    const exts = [_]Extension{};

    const result = validateExternalSenderProposal(
        &exts,
        0,
        .add,
        AcceptAllValidator.validator(),
    );
    try testing.expectError(error.MissingExtension, result);
}

test "validate rejects out-of-bounds index" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    const result = validateExternalSenderProposal(
        &exts,
        1, // only index 0 exists
        .add,
        AcceptAllValidator.validator(),
    );
    try testing.expectError(error.UnknownMember, result);
}

test "validate rejects invalid credential" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic(""),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    // Use a validator that rejects empty identities.
    const RejectEmpty = struct {
        const self_instance: @This() = .{};

        fn check(
            _: *const anyopaque,
            credential: *const Credential,
        ) ValidationError!void {
            if (credential.tag != .basic) return;
            if (credential.payload.basic.len == 0) {
                return error.InvalidCredential;
            }
        }

        fn validator() CredentialValidator {
            return .{
                .context = @ptrCast(&self_instance),
                .validate_fn = &check,
            };
        }
    };

    const result = validateExternalSenderProposal(
        &exts,
        0,
        .add,
        RejectEmpty.validator(),
    );
    try testing.expectError(error.InvalidCredential, result);
}

test "validate with null validator skips check" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic(""),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    // null validator should not reject.
    _ = try validateExternalSenderProposal(
        &exts,
        0,
        .add,
        null,
    );
}

test "makeExternalSendersExtension produces correct type" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-1",
            .credential = Credential.initBasic("sender-1"),
        },
    };

    var ext_buf: [512]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );

    try testing.expectEqual(
        ExtensionType.external_senders,
        ext.extension_type,
    );
    try testing.expect(ext.data.len > 0);
}

test "ExternalSenderList.get returns null for out of bounds" {
    var list: ExternalSenderList = undefined;
    list.len = 0;

    try testing.expect(list.get(0) == null);
    try testing.expect(list.get(1) == null);
}

test "multiple external senders with different indices" {
    const senders = [_]ExternalSender{
        .{
            .signature_key = "key-alpha",
            .credential = Credential.initBasic("alpha"),
        },
        .{
            .signature_key = "key-beta",
            .credential = Credential.initBasic("beta"),
        },
        .{
            .signature_key = "key-gamma",
            .credential = Credential.initBasic("gamma"),
        },
    };

    var ext_buf: [1024]u8 = undefined;
    const ext = try makeExternalSendersExtension(
        &senders,
        &ext_buf,
    );
    const exts = [_]Extension{ext};

    // Validate index 0.
    const es0 = try validateExternalSenderProposal(
        &exts,
        0,
        .add,
        null,
    );
    try testing.expectEqualSlices(
        u8,
        "key-alpha",
        es0.signature_key,
    );

    // Validate index 1.
    const es1 = try validateExternalSenderProposal(
        &exts,
        1,
        .remove,
        null,
    );
    try testing.expectEqualSlices(
        u8,
        "key-beta",
        es1.signature_key,
    );

    // Validate index 2.
    const es2 = try validateExternalSenderProposal(
        &exts,
        2,
        .psk,
        null,
    );
    try testing.expectEqualSlices(
        u8,
        "key-gamma",
        es2.signature_key,
    );

    // Index 3 should fail.
    const result = validateExternalSenderProposal(
        &exts,
        3,
        .add,
        null,
    );
    try testing.expectError(error.UnknownMember, result);
}
