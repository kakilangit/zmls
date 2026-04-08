//! Integration tests for zmls-client.
//!
//! Client + Server lifecycle flows using in-memory adapters.

const std = @import("std");
const zmls_client = @import("zmls-client");

test "placeholder" {
    // Verify the module imports resolve.
    _ = zmls_client.GroupStore;
    _ = zmls_client.Transport;
    _ = zmls_client.Server;
}
