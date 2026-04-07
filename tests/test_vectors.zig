//! Test vector data loader for RFC 9420 interop tests.
//!
//! Embeds 16 JSON files from tests/vectors/ (fetched from
//! https://github.com/mlswg/mls-implementations at commit
//! 16d05d3a5bfe7cf12f5392dd4deb65930e9c31be).
//!
//! Run `make fetch-vectors` to download them before testing.

pub const tree_math = @embedFile(
    "vectors/tree-math.json",
);

pub const crypto_basics = @embedFile(
    "vectors/crypto-basics.json",
);

pub const key_schedule = @embedFile(
    "vectors/key-schedule.json",
);

pub const transcript_hashes = @embedFile(
    "vectors/transcript-hashes.json",
);

pub const deserialization = @embedFile(
    "vectors/deserialization.json",
);

pub const secret_tree = @embedFile(
    "vectors/secret-tree.json",
);

pub const message_protection = @embedFile(
    "vectors/message-protection.json",
);

pub const psk_secret = @embedFile(
    "vectors/psk_secret.json",
);

pub const welcome = @embedFile(
    "vectors/welcome.json",
);

pub const tree_operations = @embedFile(
    "vectors/tree-operations.json",
);

pub const tree_validation = @embedFile(
    "vectors/tree-validation.json",
);

pub const treekem = @embedFile(
    "vectors/treekem.json",
);

pub const messages = @embedFile(
    "vectors/messages.json",
);

pub const passive_client_welcome = @embedFile(
    "vectors/passive-client-welcome.json",
);

pub const passive_client_handling_commit = @embedFile(
    "vectors/passive-client-handling-commit.json",
);

pub const passive_client_random = @embedFile(
    "vectors/passive-client-random.json",
);
