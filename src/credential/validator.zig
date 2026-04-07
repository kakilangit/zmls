//! Credential validation interface per RFC 9420 Section 5.3.1.
//! Defines a pluggable trust model with a default always-accept
//! validator for testing.
// Credential validation interface for MLS.
//
// Per RFC 9420 Section 5.3.1: applications must validate credentials
// against their own trust model. This module defines the interface
// and provides a basic always-accept validator for testing.

const Credential = @import("credential.zig").Credential;
const errors = @import("../common/errors.zig");
const ValidationError = errors.ValidationError;

/// Interface for application-level credential validation.
///
/// Implementations decide whether a credential is acceptable for
/// a given context (e.g., check X.509 chain trust, verify that a
/// basic identity is in an allow-list, etc.).
///
/// This is a runtime interface (function pointer) because the
/// validation logic depends on external application state.
pub const CredentialValidator = struct {
    /// Opaque pointer to application-specific context.
    context: *const anyopaque,

    /// Validate a credential. Returns void on success, or
    /// ValidationError.InvalidCredential on failure.
    validate_fn: *const fn (
        context: *const anyopaque,
        credential: *const Credential,
    ) ValidationError!void,

    /// Validate a credential using this validator.
    pub fn validate(
        self: *const CredentialValidator,
        credential: *const Credential,
    ) ValidationError!void {
        return self.validate_fn(self.context, credential);
    }
};

/// A validator that accepts every credential. For testing only.
pub const AcceptAllValidator = struct {
    const instance: AcceptAllValidator = .{};

    fn acceptAll(
        _: *const anyopaque,
        _: *const Credential,
    ) ValidationError!void {}

    pub fn validator() CredentialValidator {
        return .{
            .context = @ptrCast(&instance),
            .validate_fn = &acceptAll,
        };
    }
};

// -- Tests -------------------------------------------------------------------

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

test "AcceptAllValidator accepts basic credential" {
    const v = AcceptAllValidator.validator();
    const cred = Credential.initBasic("anyone");
    try v.validate(&cred);
}

test "AcceptAllValidator accepts x509 credential" {
    const v = AcceptAllValidator.validator();
    const Certificate = @import("credential.zig").Certificate;
    var certs = [_]Certificate{.{ .data = "cert" }};
    const cred = Credential.initX509(&certs);
    try v.validate(&cred);
}

test "custom validator can reject credentials" {
    // A validator that rejects empty basic identities.
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

    const v = RejectEmpty.validator();

    // Non-empty should pass.
    const ok_cred = Credential.initBasic("alice");
    try v.validate(&ok_cred);

    // Empty should fail.
    const bad_cred = Credential.initBasic("");
    const result = v.validate(&bad_cred);
    try testing.expectError(
        error.InvalidCredential,
        result,
    );
}
