//! Server types — Options and error types.

const std = @import("std");

/// Server configuration options.
pub const ServerOptions = struct {
    /// Maximum message payload size (bytes).
    max_message_size: u32 = 4 * 1024 * 1024,
    /// Maximum KeyPackage size (bytes).
    max_key_package_size: u32 = 64 * 1024,
    /// Maximum GroupInfo size (bytes).
    max_group_info_size: u32 = 256 * 1024,
};

/// Server-specific errors (beyond port errors).
pub const ServerError = error{
    MessageTooLarge,
    KeyPackageTooLarge,
    GroupInfoTooLarge,
};
