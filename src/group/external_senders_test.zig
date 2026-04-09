//! Tests for external_senders.zig
const std = @import("std");
const testing = std.testing;

const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const node_mod = @import("../tree/node.zig");
const cred_mod = @import("../credential/credential.zig");
const validator_mod = @import("../credential/validator.zig");

const external_senders = @import("external_senders.zig");

const ExtensionType = types.ExtensionType;
const Extension = node_mod.Extension;
const Credential = cred_mod.Credential;
const Certificate = cred_mod.Certificate;
const CredentialValidator = validator_mod.CredentialValidator;
const ValidationError = errors.ValidationError;
const AcceptAllValidator = validator_mod.AcceptAllValidator;

const ExternalSender = external_senders.ExternalSender;
const ExternalSenderList = external_senders.ExternalSenderList;
const parseExternalSenders = external_senders.parseExternalSenders;
const findExternalSenders = external_senders.findExternalSenders;
const validateExternalSenderProposal = external_senders.validateExternalSenderProposal;
const makeExternalSendersExtension = external_senders.makeExternalSendersExtension;
const encodeExternalSenderList = external_senders.encodeExternalSenderList;

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

test "parseExternalSenders x509 credential round-trip" {
    // Construct an ExternalSender with an X.509 credential
    // containing two certificates.
    var certs = [_]Certificate{
        .{ .data = "cert-der-1" },
        .{ .data = "cert-der-2" },
    };
    const senders = [_]ExternalSender{
        .{
            .signature_key = "x509-sig-key",
            .credential = Credential.initX509(&certs),
        },
    };

    var buf: [1024]u8 = undefined;
    const len = try encodeExternalSenderList(
        &senders,
        &buf,
    );

    const parsed = try parseExternalSenders(buf[0..len]);
    try testing.expectEqual(@as(u32, 1), parsed.len);
    try testing.expectEqualSlices(
        u8,
        "x509-sig-key",
        parsed.senders[0].signature_key,
    );
    try testing.expectEqual(
        types.CredentialType.x509,
        parsed.senders[0].credential.tag,
    );

    const dec_certs = parsed.senders[0].credential.payload.x509;
    try testing.expectEqual(@as(usize, 2), dec_certs.len);
    try testing.expectEqualSlices(
        u8,
        "cert-der-1",
        dec_certs[0].data,
    );
    try testing.expectEqualSlices(
        u8,
        "cert-der-2",
        dec_certs[1].data,
    );
}

test "parseExternalSenders mixed basic and x509" {
    var certs = [_]Certificate{
        .{ .data = "leaf-cert" },
    };
    const senders = [_]ExternalSender{
        .{
            .signature_key = "basic-key",
            .credential = Credential.initBasic("alice"),
        },
        .{
            .signature_key = "x509-key",
            .credential = Credential.initX509(&certs),
        },
    };

    var buf: [1024]u8 = undefined;
    const len = try encodeExternalSenderList(
        &senders,
        &buf,
    );

    const parsed = try parseExternalSenders(buf[0..len]);
    try testing.expectEqual(@as(u32, 2), parsed.len);

    // First sender: basic.
    try testing.expectEqual(
        types.CredentialType.basic,
        parsed.senders[0].credential.tag,
    );
    try testing.expectEqualSlices(
        u8,
        "alice",
        parsed.senders[0].credential.payload.basic,
    );

    // Second sender: x509.
    try testing.expectEqual(
        types.CredentialType.x509,
        parsed.senders[1].credential.tag,
    );
    const dec_certs = parsed.senders[1].credential.payload.x509;
    try testing.expectEqual(@as(usize, 1), dec_certs.len);
    try testing.expectEqualSlices(
        u8,
        "leaf-cert",
        dec_certs[0].data,
    );
}

test "validateExternalSenderProposal accepts x509 sender" {
    var certs = [_]Certificate{
        .{ .data = "leaf-cert" },
    };
    const senders = [_]ExternalSender{
        .{
            .signature_key = "x509-key",
            .credential = Credential.initX509(&certs),
        },
    };

    var ext_buf: [1024]u8 = undefined;
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
    try testing.expectEqual(
        types.CredentialType.x509,
        es.credential.tag,
    );
}
