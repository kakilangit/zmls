# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-04-08

Initial release. Client and Delivery Service framework for zmls.

### Added

- **Hexagonal port interfaces** -- GroupStore, KeyStore(P), Transport,
  GroupDirectory, KeyPackageDirectory, GroupInfoDirectory. All
  vtable-based with `std.Io` for async I/O.
- **In-memory adapters** -- bounded, fixed-capacity implementations
  for all six ports. Secret material is `secureZero`'d on removal
  and deinit.
- **Client(P)** -- high-level MLS client parameterized over
  CryptoProvider. Group creation, key lifecycle, persistent storage
  via ports. PendingKeyPackageMap for invite flows.
- **DeliveryService** -- opaque byte relay (dumb delivery service).
  Message routing, KeyPackage directory, GroupInfo directory with
  size limit enforcement.
- **Wire protocol** -- versioned binary envelope framing with
  validation.
