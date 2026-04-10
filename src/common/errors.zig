//! Unified error set definitions for the zmls library.
// Unified error set for the zmls library.
//
// Specific error values over generic ones, per RULES.md Section 6.

/// Errors produced during TLS presentation language decoding.
pub const DecodeError = error{
    /// Input was truncated before the expected end of a structure.
    Truncated,
    /// A variable-length integer had an invalid prefix (0b11).
    InvalidVarintPrefix,
    /// A variable-length integer was not minimally encoded.
    NonMinimalVarint,
    /// A decoded vector length exceeds the maximum allowed size.
    VectorTooLarge,
    /// An enum discriminator has no known variant and is not in a valid range.
    InvalidEnumValue,
    /// An optional presence byte was neither 0 nor 1.
    InvalidOptionalPrefix,
    /// Extra trailing bytes after a complete structure was decoded.
    TrailingData,
    /// An allocation required during decoding failed.
    OutOfMemory,
    /// Non-zero bytes found in padding region.
    InvalidPadding,
    /// Duplicate extension type found in an extension list.
    DuplicateExtensionType,
    /// Deserialized state contains invalid/degenerate values.
    CorruptState,
    /// A membership tag has the wrong length for the cipher suite.
    InvalidMembershipTagLength,
    /// The protocol version is not supported (must be mls10).
    UnsupportedProtocolVersion,
};

/// Errors from cryptographic operations.
pub const CryptoError = error{
    /// AEAD seal or open failed.
    AeadError,
    /// Signature verification failed.
    SignatureVerifyFailed,
    /// HPKE decapsulation or decryption failed.
    HpkeOpenFailed,
    /// HPKE encapsulation or encryption failed.
    HpkeSealFailed,
    /// KDF output length exceeds the algorithm maximum.
    KdfOutputTooLong,
    /// A public key failed validation (wrong size, not on curve, etc.).
    InvalidPublicKey,
    /// A private key failed validation.
    InvalidPrivateKey,
    /// The derived shared secret was the identity element (all zeros).
    IdentitySharedSecret,
    /// The requested cipher suite is not supported.
    UnsupportedCipherSuite,
    /// A hash output did not match the expected value.
    HashMismatch,
    /// No matching KeyPackage entry was found in the Welcome.
    KeyPackageNotFound,
};

/// Errors from ratchet tree operations.
pub const TreeError = error{
    /// A node index is out of range for the current tree size.
    IndexOutOfRange,
    /// An operation required a non-blank node but found a blank one.
    BlankNode,
    /// An operation on a leaf was attempted on a parent, or vice versa.
    WrongNodeType,
    /// Parent hash verification failed.
    ParentHashMismatch,
    /// Tree hash verification failed.
    TreeHashMismatch,
    /// The tree has no leaves.
    EmptyTree,
    /// A leaf node's signature is invalid.
    InvalidLeafSignature,
    /// An UpdatePath has the wrong number of nodes.
    MalformedUpdatePath,
};

/// Errors from proposal and commit validation.
pub const ValidationError = error{
    /// A KeyPackage failed validation per RFC 9420 Section 10.1.
    InvalidKeyPackage,
    /// A LeafNode failed validation per RFC 9420 Section 7.3.
    InvalidLeafNode,
    /// A Commit's proposal list is invalid per RFC 9420 Section 12.2.
    InvalidProposalList,
    /// A Commit is missing a required path.
    MissingPath,
    /// A Commit has a path when one is not allowed.
    UnexpectedPath,
    /// A required PSK was not available.
    MissingPsk,
    /// Duplicate proposals for the same leaf.
    DuplicateProposal,
    /// A proposal references an unknown member.
    UnknownMember,
    /// A credential failed application-level validation.
    InvalidCredential,
    /// Protocol version mismatch.
    VersionMismatch,
    /// Cipher suite mismatch.
    CipherSuiteMismatch,
    /// The confirmation tag does not match.
    ConfirmationTagMismatch,
    /// The membership tag does not match.
    MembershipTagMismatch,
    /// A required extension is missing.
    MissingExtension,
    /// A required capability is not supported.
    UnsupportedCapability,
    /// No private key available for the matched resolution node.
    MissingDecryptionKey,
};

/// Errors from high-level group operations.
pub const GroupError = error{
    /// The message epoch does not match the group's current epoch.
    WrongEpoch,
    /// The sender is not a member of the group.
    NotAMember,
    /// The group is in a state where the operation is not allowed (e.g., after ReInit).
    InvalidGroupState,
    /// A Welcome message could not be matched to any of our KeyPackages.
    NoMatchingKeyPackage,
    /// The ratchet tree extension is missing from the Welcome.
    MissingRatchetTree,
    /// A secret has already been consumed and deleted.
    SecretAlreadyConsumed,
    /// A ProposalRef in a Commit could not be resolved.
    ProposalNotFound,
    /// A required PSK secret could not be resolved.
    PskNotFound,
    /// Forward ratchet distance exceeds max_forward_ratchet.
    GenerationTooFar,
    /// The epoch counter reached u64 maximum and would overflow.
    EpochOverflow,
};
