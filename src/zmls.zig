//! Zig MLS (RFC 9420) library. Re-exports the public API
//! including group creation, commit, welcome processing, and
//! crypto provider types.
/// zmls -- Zig Messaging Layer Security (RFC 9420).
///
/// A zero-dependency MLS protocol library built on Zig's
/// `std.crypto`. All core logic is pure (no I/O, no transport,
/// no storage). Cryptographic operations are parameterized over
/// a comptime `CryptoProvider` type (duck-typed).
///
/// ## Quick start
///
/// ```zig
/// const mls = @import("zmls");
/// const P = mls.DefaultCryptoProvider;
///
/// // Create a group.
/// var gs = try mls.createGroup(
///     P, allocator, "my-group", leaf, suite, &.{},
/// );
/// defer gs.deinit();
///
/// // Add a member via commit (method API).
/// var out = try gs.commit(allocator, .{
///     .proposals = &proposals,
///     .sign_key = &sign_sk,
/// });
/// defer out.deinit();
/// // out.group_state is the new epoch's GroupState.
/// ```
///
/// ## Architecture
///
/// Hexagonal (ports & adapters). Three extension points:
///   - `CryptoProvider` (comptime): AEAD, HPKE, signing, hash.
///   - `CredentialValidator`: application-level credential check.
///   - `KeyStore`: (application-provided) persistence layer.
///
/// ## Module map
///
///   types, errors     -- common enums, error sets
///   codec             -- TLS-style encode/decode (slice-based)
///   tree_*            -- ratchet tree, tree math, hashes, paths
///   crypto_*          -- HPKE, labeled operations, default suite
///   credential        -- Credential types and validator port
///   key_schedule      -- epoch secret derivation, secret tree,
///                        transcript hashes, PSK, exporter
///   framing           -- FramedContent, PublicMessage,
///                        PrivateMessage, MLSMessage
///   messages          -- KeyPackage, Proposal, Commit, Welcome,
///                        GroupInfo
///   group_*           -- GroupState, createGroup, createCommit,
///                        processCommit, Welcome, external join

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

// ── Top-level type aliases ──────────────────────────────────

/// The default CryptoProvider: X25519 + AES-128-GCM +
/// SHA-256 + Ed25519 (cipher suite 0x0001).
pub const DefaultCryptoProvider = crypto_default
    .DhKemX25519Sha256Aes128GcmEd25519;

/// CryptoProvider for suite 0x0003: X25519 + ChaCha20-Poly1305
/// + SHA-256 + Ed25519.
pub const ChaCha20CryptoProvider = crypto_chacha20
    .DhKemX25519Sha256ChaCha20Poly1305Ed25519;

/// CryptoProvider for suite 0x0002: P-256 + AES-128-GCM +
/// SHA-256 + P-256.
pub const P256CryptoProvider = crypto_p256
    .DhKemP256Sha256Aes128GcmP256;

/// CryptoProvider for suite 0x0004: P-256 + ChaCha20-Poly1305
/// + SHA-256 + P-256.
pub const P256ChaCha20CryptoProvider = crypto_p256_chacha20
    .DhKemP256Sha256ChaCha20Poly1305P256;

/// CryptoProvider for suite 0x0006: P-384 + AES-256-GCM +
/// SHA-384 + P-384.
pub const P384CryptoProvider = crypto_p384
    .DhKemP384Sha384Aes256GcmP384;

/// Protocol version enum.
pub const ProtocolVersion = types.ProtocolVersion;

/// Cipher suite enum.
pub const CipherSuite = types.CipherSuite;

/// Leaf index in the ratchet tree.
pub const LeafIndex = types.LeafIndex;

/// Epoch number.
pub const Epoch = types.Epoch;

/// Sender type (member, external, new_member_commit, etc.).
pub const SenderType = types.SenderType;

/// Content type (application, proposal, commit).
pub const ContentType = types.ContentType;

/// Wire format (mls_public_message, mls_welcome, etc.).
pub const WireFormat = types.WireFormat;

/// Extension type identifiers.
pub const ExtensionType = types.ExtensionType;

/// LeafNode (a member's public state in the tree).
pub const LeafNode = tree_node.LeafNode;

/// Extension (type + opaque data).
pub const Extension = tree_node.Extension;

/// Credential types.
pub const Credential = credential.Credential;

/// RatchetTree.
pub const RatchetTree = ratchet_tree.RatchetTree;

/// GroupContext.
pub const GroupContext = group_context.GroupContext;

/// Proposal types.
pub const Proposal = proposal.Proposal;

// ── Top-level function aliases (prefer GroupState methods) ──
//
// These free functions are the low-level building blocks.
// For typical use, prefer the method API on GroupState:
//   gs.commit(allocator, opts)        -> CommitOutput
//   gs.applyCommit(allocator, opts)   -> ProcessOutput
//   GS.joinViaWelcome(allocator, opts)-> GroupState
//   gs.buildWelcome(allocator, opts)  -> WelcomeResult
// See GroupState in group/state.zig for the full list.

/// Create a new single-member group at epoch 0.
///
/// Returns a `GroupState(P)` with the creator at leaf 0.
///
/// Example:
/// ```zig
/// var gs = try zmls.createGroup(
///     P, allocator, "group-id", my_leaf,
///     .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
///     &.{},
/// );
/// defer gs.deinit();
/// ```
pub const createGroup = group_state.createGroup;

/// Create a Commit for a set of proposals.
///
/// Returns a `CommitResult(P)` with the serialized commit,
/// signature, confirmation tag, and new epoch secrets.
pub const createCommit = group_commit.createCommit;

/// Process an incoming Commit from another member.
///
/// Returns a `ProcessResult(P)` with the new epoch state.
pub const processCommit = group_commit.processCommit;

/// Build a Welcome message for new members after a commit.
pub const buildWelcome = group_welcome.buildWelcome;

/// Process a Welcome message to join a group.
pub const processWelcome = group_welcome.processWelcome;

/// Create an external commit to join without a Welcome.
///
/// The joiner extracts `external_pub` from GroupInfo, performs
/// HPKE Encap, and builds a Commit with ExternalInit.
pub const createExternalCommit =
    group_external.createExternalCommit;

/// Process an incoming external commit (existing member side).
///
/// Verifies the external join, applies proposals, decrypts
/// the UpdatePath, and derives new epoch secrets.
pub const processExternalCommit =
    group_external.processExternalCommit;

/// Resolve ProposalOrRef list for external commits, enforcing
/// that all proposals are inline (by-value) per RFC 9420
/// Section 12.4.3.2.
pub const resolveExternalInlineProposals =
    group_external.resolveExternalInlineProposals;

/// Validate a list of proposals per RFC 9420 Section 12.2.
pub const validateProposalList =
    group_evolution.validateProposalList;

/// Apply validated proposals to produce tree mutations.
pub const applyProposals = group_evolution.applyProposals;

/// Derive epoch secrets from the key schedule.
pub const deriveEpochSecrets =
    key_schedule.deriveEpochSecrets;

/// Export a secret from the current epoch (RFC 9420 Section 8.5).
pub const mlsExporter = exporter.mlsExporter;

/// Encrypt application content as a PrivateMessage.
pub const encryptContent = private_msg.encryptContent;

/// Decrypt a PrivateMessage to recover application content.
pub const decryptContent = private_msg.decryptContent;

/// Validate sender leaf_index is within tree bounds.
pub const validateSenderLeafIndex =
    private_msg.validateSenderLeafIndex;

/// Sign FramedContent (for PublicMessage or PrivateMessage).
pub const signFramedContent = framing_auth.signFramedContent;

/// Verify a FramedContent signature.
pub const verifyFramedContent =
    framing_auth.verifyFramedContent;

/// Compute a confirmation tag over the confirmed transcript.
pub const computeConfirmationTag =
    framing_auth.computeConfirmationTag;

/// Verify a confirmation tag.
pub const verifyConfirmationTag =
    framing_auth.verifyConfirmationTag;

/// Compute the membership tag for a PublicMessage.
pub const computeMembershipTag =
    public_msg.computeMembershipTag;

/// KeyPackage: use `KeyPackage.signKeyPackage(P, ...)` to sign.
/// (Method on KeyPackage, not a free function.)
/// Create an ExternalInit proposal (joiner-side HPKE Encap).
pub const createExternalInit =
    group_external.createExternalInit;

/// Process an ExternalInit proposal (member-side HPKE Decap).
pub const processExternalInit =
    group_external.processExternalInit;

/// Derive the external HPKE key pair from external_secret.
pub const deriveExternalKeyPair =
    group_external.deriveExternalKeyPair;

/// Build the external_pub extension for GroupInfo.
pub const makeExternalPubExtension =
    group_external.makeExternalPubExtension;

/// Parse external_senders extension data.
pub const parseExternalSenders =
    external_senders.parseExternalSenders;

/// Find and parse external_senders from extensions.
pub const findExternalSenders =
    external_senders.findExternalSenders;

/// Validate an external sender proposal.
pub const validateExternalSenderProposal =
    external_senders.validateExternalSenderProposal;

/// Build an external_senders extension.
pub const makeExternalSendersExtension =
    external_senders.makeExternalSendersExtension;

/// Sign a GroupInfo for distribution.
pub const signGroupInfo = group_info.signGroupInfo;

/// Verify a GroupInfo signature.
pub const verifyGroupInfo = group_info.verifyGroupInfo;

/// Encrypt a GroupInfo for a Welcome message.
pub const encryptGroupInfo = group_info.encryptGroupInfo;

/// Decrypt a GroupInfo from a Welcome message.
pub const decryptGroupInfo = group_info.decryptGroupInfo;

/// Update confirmed transcript hash.
pub const updateConfirmedTranscriptHash =
    transcript.updateConfirmedTranscriptHash;

/// Update interim transcript hash.
pub const updateInterimTranscriptHash =
    transcript.updateInterimTranscriptHash;

// ── Core types (high-level API) ─────────────────────────────
//
// These are the primary types most callers need.

/// GroupState parameterized by CryptoProvider.
///
/// Usage: `const MyGroupState = zmls.GroupState(P);`
pub const GroupState = group_state.GroupState;

/// EpochSecrets parameterized by CryptoProvider.
pub const EpochSecrets = key_schedule.EpochSecrets;

/// CommitResult parameterized by CryptoProvider.
pub const CommitResult = group_commit.CommitResult;

/// ProcessResult (from processCommit).
pub const ProcessResult = group_commit.ProcessResult;

/// PathParams for createCommit with UpdatePath.
pub const PathParams = group_commit.PathParams;

/// ReceiverPathParams for processCommit with UpdatePath.
pub const ReceiverPathParams =
    group_commit.ReceiverPathParams;

/// Options struct for createCommit.
pub const CreateCommitOpts = group_commit.CreateCommitOpts;

/// Options struct for processCommit.
pub const ProcessCommitOpts = group_commit.ProcessCommitOpts;

/// Options struct for processWelcome.
pub const ProcessWelcomeOpts =
    group_welcome.ProcessWelcomeOpts;

/// Options struct for buildWelcome.
pub const BuildWelcomeOpts = group_welcome.BuildWelcomeOpts;

/// Options struct for encryptContent.
pub const EncryptContentOpts =
    private_msg.EncryptContentOpts;

/// Private key for a parent node, derived from UpdatePath.
pub const PathNodeKey = group_commit.PathNodeKey;

/// PskResolver bundles external + resumption PSK lookup.
pub const PskResolver = group_commit.PskResolver;

/// ExternalCommitParams for createExternalCommit.
pub const ExternalCommitParams =
    group_external.ExternalCommitParams;

/// ExternalCommitResult from createExternalCommit.
pub const ExternalCommitResult =
    group_external.ExternalCommitResult;

/// ProcessExternalResult from processExternalCommit.
pub const ProcessExternalResult =
    group_external.ProcessExternalResult;

/// UpdatePath for path-based commits.
pub const UpdatePath = tree_path.UpdatePath;

/// KeyPackage.
pub const KeyPackage = key_package.KeyPackage;

/// Last-resort extension constant (type 10, empty payload).
pub const last_resort_extension =
    key_package.last_resort_extension;

/// Commit message.
pub const Commit = commit.Commit;

/// Welcome message.
pub const Welcome = welcome.Welcome;

/// FramedContent.
pub const FramedContent = framed_content.FramedContent;

/// Sender (member, external, new_member_commit, etc.).
pub const Sender = framing.Sender;

/// SecretTree for deriving per-message keys.
pub const SecretTree = secret_tree.SecretTree;

/// EpochKeyRing for past-epoch secret retention.
pub const EpochKeyRing = epoch_key_ring.EpochKeyRing;

/// PskLookup port for external PSK resolution.
pub const PskLookup = psk_lookup.PskLookup;

/// No-op PskLookup (returns null for all lookups).
pub const NoPskLookup = psk_lookup.NoPskLookup;

/// In-memory PSK store for testing.
pub const InMemoryPskStore = psk_lookup.InMemoryPskStore;

/// Resumption PSK retention ring.
pub const ResumptionPskRing = psk_lookup.ResumptionPskRing;

/// ProposalCache for pending proposals between commits.
pub const ProposalCache = proposal_cache.ProposalCache;

/// StagedCommit for two-phase commit apply.
pub const StagedCommit = staged_commit.StagedCommit;

/// Stage a commit for inspection before applying.
pub const stageCommit = staged_commit.stageCommit;

/// HPKE operations.
pub const Hpke = hpke.Hpke;

/// External sender entry (signature_key + credential).
pub const ExternalSender =
    external_senders.ExternalSender;

/// Parsed list of external senders.
pub const ExternalSenderList =
    external_senders.ExternalSenderList;

// ── Tests ───────────────────────────────────────────────────

test {
    // Pull in all module tests so `zig build test` covers
    // everything reachable from this root.
    @import("std").testing.refAllDecls(@This());

    // Separated test modules (not reachable via refAllDecls).
    _ = @import("group/commit_test.zig");
    _ = @import("group/evolution_test.zig");
    _ = @import("group/external_senders_test.zig");
    _ = @import("group/external_test.zig");
    _ = @import("group/welcome_test.zig");
    _ = @import("framing/private_msg_test.zig");
    _ = @import("key_schedule/secret_tree_test.zig");
    _ = @import("messages/proposal_test.zig");
    _ = @import("messages/welcome_test.zig");
    _ = @import("tree/hashes_test.zig");
    _ = @import("tree/node_test.zig");
    _ = @import("tree/path_test.zig");
}
