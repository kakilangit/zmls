//! Zig MLS (RFC 9420) library.
//!
//! This is the root module. Public API will be re-exported here
//! as each layer is implemented.

test {
    @import("std").testing.refAllDecls(@This());
}
