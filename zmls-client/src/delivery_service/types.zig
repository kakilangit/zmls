//! DeliveryService types — Options and error types.

const std = @import("std");

/// DeliveryService configuration options.
pub const DeliveryServiceOptions = struct {
    /// Maximum message payload size (bytes).
    max_message_size: u32 = 4 * 1024 * 1024,
    /// Maximum KeyPackage size (bytes).
    max_key_package_size: u32 = 64 * 1024,
    /// Maximum GroupInfo size (bytes).
    max_group_info_size: u32 = 256 * 1024,
};

/// DeliveryService-specific errors (beyond port errors).
pub const DeliveryServiceError = error{
    MessageTooLarge,
    KeyPackageTooLarge,
    GroupInfoTooLarge,
};
