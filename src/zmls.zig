//! Zig MLS (RFC 9420) library.
//!
//! This is the root module. Public API is re-exported here
//! as each layer is implemented.

// ── Foundation ──────────────────────────────────────────────

/// Common protocol types (LeafIndex, NodeIndex, Epoch,
/// ProtocolVersion, CipherSuite, SenderType, ContentType,
/// ExtensionType, ProposalType, CredentialType, WireFormat).
pub const types = @import("common/types.zig");

/// Error sets for all modules (CryptoError, TreeError,
/// ValidationError, GroupError, DecodeError).
pub const errors = @import("common/errors.zig");

/// GREASE (Generate Random Extensions And Sustain
/// Extensibility) -- RFC 9420 Section 13.4.
pub const grease = @import("common/grease.zig");

// ── Codec ───────────────────────────────────────────────────

/// TLS presentation language serialization/deserialization.
/// Slice-based API: `encode(buf, pos, ...)` -> new position.
pub const codec = @import("codec/codec.zig");

/// Variable-length integer encoding (RFC 9420 Section 2.1.2).
pub const varint = @import("codec/varint.zig");

// ── Crypto ──────────────────────────────────────────────────

/// CryptoProvider interface specification (comptime duck type).
pub const crypto_provider = @import("crypto/provider.zig");

/// Default provider: X25519 + AES-128-GCM + SHA-256 + Ed25519
/// (MLS cipher suite 0x0001).
pub const crypto_default = @import("crypto/default.zig");

/// Suite 0x0003: X25519 + ChaCha20-Poly1305 + SHA-256 + Ed25519.
pub const crypto_chacha20 = @import("crypto/chacha20.zig");

/// Suite 0x0002: P-256 + AES-128-GCM + SHA-256 + P-256.
pub const crypto_p256 = @import("crypto/p256.zig");

/// Suite 0x0004: P-256 + ChaCha20-Poly1305 + SHA-256 + P-256.
pub const crypto_p256_chacha20 = @import(
    "crypto/p256_chacha20.zig",
);

/// Suite 0x0006: P-384 + AES-256-GCM + SHA-384 + P-384.
pub const crypto_p384 = @import("crypto/p384.zig");

/// Labeled crypto operations: expandWithLabel, deriveSecret,
/// encryptWithLabel, decryptWithLabel, signWithLabel,
/// verifyWithLabel, refHash (RFC 9420 Section 5).
pub const crypto_primitives = @import("crypto/primitives.zig");

/// CipherSuite enum to provider mapping.
pub const cipher_suite = @import("crypto/cipher_suite.zig");

/// HPKE: encapDeterministic, decap, sealBase, openBase.
pub const hpke = @import("crypto/hpke.zig");

// ── Tree ────────────────────────────────────────────────────

/// Array-based binary tree index arithmetic (RFC 9420 Section 7.1).
pub const tree_math = @import("tree/math.zig");

/// Node types: LeafNode, ParentNode, Node, Extension.
pub const tree_node = @import("tree/node.zig");

/// RatchetTree: the array-backed left-balanced binary tree.
pub const ratchet_tree = @import("tree/ratchet_tree.zig");

/// Tree hash and parent hash computation (RFC 9420 Section 7.8-7.9).
pub const tree_hashes = @import("tree/hashes.zig");

/// Path operations: generateUpdatePath, applyUpdatePath,
/// applySenderPath, addLeaf, removeLeaf.
pub const tree_path = @import("tree/path.zig");

// ── Credentials ─────────────────────────────────────────────

/// Credential types: Basic, X.509.
pub const credential = @import("credential/credential.zig");

/// CredentialValidator port (application-provided).
pub const credential_validator = @import(
    "credential/validator.zig",
);

// ── Key Schedule ────────────────────────────────────────────

/// Epoch secret derivation (RFC 9420 Section 8).
pub const key_schedule = @import("key_schedule/schedule.zig");

/// Transcript hash computation (confirmed + interim).
pub const transcript = @import("key_schedule/transcript.zig");

/// Pre-shared key injection (RFC 9420 Section 8.4).
pub const psk = @import("key_schedule/psk.zig");

/// PSK lookup port and resumption PSK retention.
pub const psk_lookup = @import("key_schedule/psk_lookup.zig");

/// Secret tree for application key derivation (Section 9).
pub const secret_tree = @import("key_schedule/secret_tree.zig");

/// Past-epoch key retention for out-of-order decryption.
pub const epoch_key_ring = @import(
    "key_schedule/epoch_key_ring.zig",
);

/// MLS exporter: mlsExporter(P, secret, label, ctx, len).
pub const exporter = @import("key_schedule/exporter.zig");

// ── Message Framing ─────────────────────────────────────────

/// Sender, ContentType, WireFormat types.
pub const framing = @import("framing/content_type.zig");

/// FramedContent and FramedContentTBS.
pub const framed_content = @import(
    "framing/framed_content.zig",
);

/// Signing, verification, confirmation tags.
pub const framing_auth = @import("framing/auth.zig");

/// PublicMessage framing and membership tags.
pub const public_msg = @import("framing/public_msg.zig");

/// PrivateMessage: content encryption/decryption, sender data.
pub const private_msg = @import("framing/private_msg.zig");

/// MLSMessage envelope (top-level wire format).
pub const mls_message = @import("framing/mls_message.zig");

// ── Messages ────────────────────────────────────────────────

/// KeyPackage creation, signing, validation (RFC 9420 Section 10).
pub const key_package = @import("messages/key_package.zig");

/// Proposal types: Add, Remove, Update, ReInit, ExternalInit,
/// PreSharedKey, GroupContextExtensions.
pub const proposal = @import("messages/proposal.zig");

/// Commit message encoding/decoding.
pub const commit = @import("messages/commit.zig");

/// Welcome message: encrypt/decrypt group secrets for joiners.
pub const welcome = @import("messages/welcome.zig");

/// GroupInfo: sign, verify, encrypt, decrypt.
pub const group_info = @import("messages/group_info.zig");

// ── Group Operations ────────────────────────────────────────

/// GroupContext: serializable group metadata (Section 11.1).
pub const group_context = @import("group/context.zig");

/// GroupState: full mutable state of a group member.
/// createGroup: initialize a new single-member group.
pub const group_state = @import("group/state.zig");

/// Proposal validation and application (Section 12.2).
pub const group_evolution = @import("group/evolution.zig");

/// Proposal cache for pending proposals between commits.
pub const proposal_cache = @import("group/proposal_cache.zig");

/// Commit creation and processing (Section 12.4).
pub const group_commit = @import("group/commit.zig");

/// Staged commit for two-phase apply (inspect-before-apply).
pub const staged_commit = @import("group/staged_commit.zig");

/// Welcome processing for new members joining via Welcome.
pub const group_welcome = @import("group/welcome.zig");

/// External join: createExternalCommit, processExternalCommit
/// (Section 12.4.3.2).
pub const group_external = @import("group/external.zig");

/// External senders extension (Section 12.1.8.1).
pub const external_senders = @import(
    "group/external_senders.zig",
);

/// GroupState binary serialization (Section 19.3).
pub const serializer = @import("group/serializer.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
