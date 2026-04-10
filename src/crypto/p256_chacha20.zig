//! CryptoProvider for MLS cipher suite 0xF001
//! (P-256 ECDH + ChaCha20Poly1305 + SHA-256 + ECDSA-P256).
// CryptoProvider backend for MLS cipher suite 0xF001:
// MLS_128_DHKEMP256_CHACHA20POLY1305_SHA256_P256.
//
// Hash:      SHA-256          (std.crypto.hash.sha2.Sha256)
// KDF:       HKDF-SHA256      (std.crypto.kdf.hkdf.HkdfSha256)
// AEAD:      ChaCha20Poly1305 (std.crypto.aead.chacha_poly.ChaCha20Poly1305)
// DH/KEM:    P-256 ECDH       (std.crypto.ecc.P256)
// Signature: ECDSA-P256-SHA256(std.crypto.sign.ecdsa.EcdsaP256Sha256)
//
// Same as suite 0x0002 except the AEAD is ChaCha20-Poly1305
// (32-byte key) instead of AES-128-GCM (16-byte key).
//
// Per RFC 9420 Section 5.1, Table 2.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const provider = @import("provider.zig");
const primitives = @import("primitives.zig");
const CryptoError = @import("../common/errors.zig").CryptoError;

const Sha256 = crypto.hash.sha2.Sha256;
const Hkdf = crypto.kdf.hkdf.HkdfSha256;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const P256 = crypto.ecc.P256;
const Ecdsa = crypto.sign.ecdsa.EcdsaP256Sha256;

/// Cipher suite 0xF001 backend.
pub const DhKemP256Sha256ChaCha20Poly1305P256 = struct {
    // -- Constants per RFC 9420 Table 2 -----------------------------------

    /// Hash output length (SHA-256 = 32 bytes).
    pub const nh: u32 = Sha256.digest_length;

    /// AEAD key length (ChaCha20-Poly1305 = 32 bytes).
    pub const nk: u32 = ChaCha20Poly1305.key_length;

    /// AEAD nonce length (ChaCha20-Poly1305 = 12 bytes).
    pub const nn: u32 = ChaCha20Poly1305.nonce_length;

    /// AEAD authentication tag length (16 bytes).
    pub const nt: u32 = ChaCha20Poly1305.tag_length;

    /// DH public key length (P-256 uncompressed = 65 bytes).
    pub const npk: u32 = 65;

    /// DH secret key length (P-256 scalar = 32 bytes).
    pub const nsk: u32 = 32;

    /// Signature public key length (P-256 uncompressed = 65).
    pub const sign_pk_len: u32 = 65;

    /// Signature secret key length (P-256 scalar = 32 bytes).
    pub const sign_sk_len: u32 = 32;

    /// Signature length (ECDSA r||s = 64 bytes).
    pub const sig_len: u32 = 64;

    /// Keypair seed length (P-256 scalar = 32 bytes).
    pub const seed_len: u32 = 32;

    // -- HPKE algorithm IDs per RFC 9180 ---------------------------------

    /// DHKEM(P-256, HKDF-SHA256) = 0x0010.
    pub const kem_id: u16 = 0x0010;
    /// HKDF-SHA256 = 0x0001.
    pub const kdf_id: u16 = 0x0001;
    /// ChaCha20Poly1305 = 0x0003.
    pub const aead_id: u16 = 0x0003;

    // -- Hash -------------------------------------------------------------

    pub fn hash(data: []const u8) [nh]u8 {
        var out: [nh]u8 = undefined;
        Sha256.hash(data, &out, .{});
        return out;
    }

    // -- KDF (HKDF-SHA256) ------------------------------------------------

    pub fn kdfExtract(
        salt: []const u8,
        ikm: []const u8,
    ) [nh]u8 {
        return Hkdf.extract(salt, ikm);
    }

    pub fn kdfExpand(
        prk: *const [nh]u8,
        info: []const u8,
        out: []u8,
    ) void {
        assert(out.len > 0 and out.len <= 255 * nh);
        Hkdf.expand(out, info, prk.*);
    }

    // -- AEAD (ChaCha20-Poly1305) -----------------------------------------

    pub fn aeadSeal(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[nt]u8,
    ) void {
        assert(ciphertext.len == plaintext.len);
        ChaCha20Poly1305.encrypt(
            ciphertext,
            tag,
            plaintext,
            aad,
            nonce.*,
            key.*,
        );
    }

    pub fn aeadOpen(
        key: *const [nk]u8,
        nonce: *const [nn]u8,
        aad: []const u8,
        ciphertext: []const u8,
        tag: *const [nt]u8,
        out: []u8,
    ) CryptoError!void {
        assert(out.len == ciphertext.len);
        ChaCha20Poly1305.decrypt(
            out,
            ciphertext,
            tag.*,
            aad,
            nonce.*,
            key.*,
        ) catch return error.AeadError;
    }

    // -- Signatures (ECDSA-P256-SHA256) -----------------------------------

    pub fn signKeypairFromSeed(
        seed: *const [seed_len]u8,
    ) CryptoError!struct {
        sk: [sign_sk_len]u8,
        pk: [sign_pk_len]u8,
    } {
        const kp = Ecdsa.KeyPair.generateDeterministic(
            seed.*,
        ) catch return error.InvalidPrivateKey;
        return .{
            .sk = kp.secret_key.bytes,
            .pk = kp.public_key.toUncompressedSec1(),
        };
    }

    pub fn sign(
        sk: *const [sign_sk_len]u8,
        msg: []const u8,
    ) CryptoError![sig_len]u8 {
        var secret_key = Ecdsa.SecretKey{ .bytes = sk.* };
        defer primitives.secureZero(
            std.mem.asBytes(&secret_key),
        );
        var kp = Ecdsa.KeyPair.fromSecretKey(
            secret_key,
        ) catch return error.InvalidPrivateKey;
        defer primitives.secureZero(
            std.mem.asBytes(&kp),
        );
        const sig = kp.sign(msg, null) catch {
            return error.SignatureVerifyFailed;
        };
        return sig.toBytes();
    }

    pub fn verify(
        pk: *const [sign_pk_len]u8,
        msg: []const u8,
        sig: *const [sig_len]u8,
    ) CryptoError!void {
        const public_key = Ecdsa.PublicKey.fromSec1(
            pk,
        ) catch return error.InvalidPublicKey;
        const signature = Ecdsa.Signature.fromBytes(sig.*);
        var verifier = signature.verifier(
            public_key,
        ) catch return error.SignatureVerifyFailed;
        verifier.update(msg);
        verifier.verify() catch {
            return error.SignatureVerifyFailed;
        };
    }

    // -- DH (P-256 ECDH) --------------------------------------------------

    pub fn validateDhPublicKey(
        pk: *const [npk]u8,
    ) CryptoError!void {
        _ = P256.fromSec1(pk) catch {
            return error.InvalidPublicKey;
        };
    }

    pub fn dhKeypairFromSeed(
        seed: *const [seed_len]u8,
    ) CryptoError!struct { sk: [nsk]u8, pk: [npk]u8 } {
        const kp = Ecdsa.KeyPair.generateDeterministic(
            seed.*,
        ) catch return error.InvalidPrivateKey;
        const point = P256.fromSec1(
            &kp.public_key.toUncompressedSec1(),
        ) catch return error.InvalidPrivateKey;
        return .{
            .sk = kp.secret_key.bytes,
            .pk = point.toUncompressedSec1(),
        };
    }

    pub fn dh(
        sk: *const [nsk]u8,
        pk: *const [npk]u8,
    ) CryptoError![32]u8 {
        const peer = P256.fromSec1(pk) catch {
            return error.InvalidPublicKey;
        };
        const shared = peer.mul(sk.*, .big) catch {
            return error.IdentitySharedSecret;
        };
        return shared.affineCoordinates().x.toBytes(.big);
    }

    // Compile-time validation.
    comptime {
        provider.assertValid(
            DhKemP256Sha256ChaCha20Poly1305P256,
        );
    }
};

// -- Tests ---------------------------------------------------------------

const testing = std.testing;
const P = DhKemP256Sha256ChaCha20Poly1305P256;

test "suite 0xF001 constants match RFC 9420" {
    try testing.expectEqual(@as(u32, 32), P.nh);
    try testing.expectEqual(@as(u32, 32), P.nk);
    try testing.expectEqual(@as(u32, 12), P.nn);
    try testing.expectEqual(@as(u32, 16), P.nt);
    try testing.expectEqual(@as(u32, 65), P.npk);
    try testing.expectEqual(@as(u32, 32), P.nsk);
    try testing.expectEqual(@as(u32, 65), P.sign_pk_len);
    try testing.expectEqual(@as(u32, 32), P.sign_sk_len);
    try testing.expectEqual(@as(u32, 64), P.sig_len);
}

test "suite 0xF001 aead seal/open round-trip" {
    const key = [_]u8{0x42} ** P.nk;
    const nonce = [_]u8{0x24} ** P.nn;
    const aad = "additional data";
    const plaintext = "secret message";

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    P.aeadSeal(
        &key,
        &nonce,
        aad,
        plaintext,
        &ciphertext,
        &tag,
    );

    var decrypted: [plaintext.len]u8 = undefined;
    try P.aeadOpen(
        &key,
        &nonce,
        aad,
        &ciphertext,
        &tag,
        &decrypted,
    );
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "suite 0xF001 aead rejects tampered ciphertext" {
    const key = [_]u8{0x42} ** P.nk;
    const nonce = [_]u8{0x24} ** P.nn;
    const plaintext = "secret";

    var ct: [plaintext.len]u8 = undefined;
    var tag: [P.nt]u8 = undefined;
    P.aeadSeal(&key, &nonce, "", plaintext, &ct, &tag);

    ct[0] ^= 0xFF;
    var out: [plaintext.len]u8 = undefined;
    const result = P.aeadOpen(
        &key,
        &nonce,
        "",
        &ct,
        &tag,
        &out,
    );
    try testing.expectError(error.AeadError, result);
}

test "suite 0xF001 sign/verify round-trip" {
    const seed = [_]u8{0x01} ** 32;
    const kp = try P.signKeypairFromSeed(&seed);
    const msg = "message to sign";
    const sig = try P.sign(&kp.sk, msg);
    try P.verify(&kp.pk, msg, &sig);
}

test "suite 0xF001 dh key exchange" {
    const seed_a = [_]u8{0x0A} ** 32;
    const seed_b = [_]u8{0x0B} ** 32;

    const kp_a = try P.dhKeypairFromSeed(&seed_a);
    const kp_b = try P.dhKeypairFromSeed(&seed_b);

    const shared_ab = try P.dh(&kp_a.sk, &kp_b.pk);
    const shared_ba = try P.dh(&kp_b.sk, &kp_a.pk);
    try testing.expectEqualSlices(u8, &shared_ab, &shared_ba);
}

// -- Full group lifecycle test with suite 0xF001 --

const types = @import("../common/types.zig");
const ProtocolVersion = types.ProtocolVersion;
const CipherSuite = types.CipherSuite;

const node_mod = @import("../tree/node.zig");
const LeafNode = node_mod.LeafNode;
const cred_mod = @import("../credential/credential.zig");
const Credential = cred_mod.Credential;
const kp_mod = @import("../messages/key_package.zig");
const KeyPackage = kp_mod.KeyPackage;
const prop_mod = @import("../messages/proposal.zig");
const Proposal = prop_mod.Proposal;
const gc_mod = @import("../group/context.zig");
const state_mod = @import("../group/state.zig");
const commit_mod = @import("../group/commit.zig");
const welcome_mod = @import("../group/welcome.zig");
const prim_mod = @import("primitives.zig");
const LeafIndex = types.LeafIndex;

const suite_0xF001: CipherSuite =
    .mls_128_dhkemp256_chacha20poly1305_sha256_p256;

/// Create a test LeafNode for cipher suite 0xF001
/// /// (P-256/ChaCha20Poly1305/ECDSA-P256, non-standard).
fn makeLeaf0xF001(
    enc_pk: []const u8,
    sig_pk: []const u8,
) LeafNode {
    const versions = comptime [_]ProtocolVersion{.mls10};
    const suites = comptime [_]CipherSuite{suite_0xF001};
    const ext_types = comptime [_]types.ExtensionType{};
    const prop_types = comptime [_]types.ProposalType{};
    const cred_types = comptime [_]types.CredentialType{
        .basic,
    };

    return .{
        .encryption_key = enc_pk,
        .signature_key = sig_pk,
        .credential = Credential.initBasic(sig_pk),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &ext_types,
            .proposals = &prop_types,
            .credentials = &cred_types,
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** P.sig_len,
    };
}

const TestKP0xF001 = struct {
    kp: KeyPackage,
    sig_buf: [P.sig_len]u8,
    leaf_sig_buf: [P.sig_len]u8,
    enc_sk: [P.nsk]u8,
    enc_pk: [P.npk]u8,
    init_sk: [P.nsk]u8,
    init_pk: [P.npk]u8,
    sign_sk: [P.sign_sk_len]u8,
    sign_pk: [P.sign_pk_len]u8,

    /// Initialize a test KeyPackage for suite 0xF001 from
    /// deterministic seed tags.
    fn init(
        self: *TestKP0xF001,
        enc_tag: u8,
        init_tag: u8,
        sign_tag: u8,
    ) !void {
        const enc_kp = try P.dhKeypairFromSeed(
            &([_]u8{enc_tag} ** 32),
        );
        const init_kp = try P.dhKeypairFromSeed(
            &([_]u8{init_tag} ** 32),
        );
        const sign_kp = try P.signKeypairFromSeed(
            &([_]u8{sign_tag} ** 32),
        );

        self.enc_sk = enc_kp.sk;
        self.enc_pk = enc_kp.pk;
        self.init_sk = init_kp.sk;
        self.init_pk = init_kp.pk;
        self.sign_sk = sign_kp.sk;
        self.sign_pk = sign_kp.pk;

        self.kp = .{
            .version = .mls10,
            .cipher_suite = suite_0xF001,
            .init_key = &self.init_pk,
            .leaf_node = makeLeaf0xF001(
                &self.enc_pk,
                &self.sign_pk,
            ),
            .extensions = &.{},
            .signature = &self.sig_buf,
        };
        self.kp.leaf_node.credential =
            Credential.initBasic(&self.sign_pk);
        self.kp.leaf_node.signature = &self.leaf_sig_buf;

        try self.kp.leaf_node.signLeafNode(
            P,
            &self.sign_sk,
            &self.leaf_sig_buf,
            null,
            null,
        );
        try self.kp.signKeyPackage(
            P,
            &self.sign_sk,
            &self.sig_buf,
        );
    }
};

test "suite 0xF001 full group lifecycle" {
    const alloc = testing.allocator;

    const alice_enc = try P.dhKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    );
    const alice_sign = try P.signKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    );

    var gs = try state_mod.createGroup(
        P,
        alloc,
        "p256cc-lifecycle",
        makeLeaf0xF001(&alice_enc.pk, &alice_sign.pk),
        suite_0xF001,
        &.{},
    );
    defer gs.deinit();

    try testing.expectEqual(@as(u64, 0), gs.epoch());
    try testing.expectEqual(@as(u32, 1), gs.leafCount());

    var bob: TestKP0xF001 = undefined;
    try bob.init(0xB1, 0xB3, 0xB2);

    const add_bob = Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = bob.kp } },
    };
    const proposals = [_]Proposal{add_bob};

    var cr = try commit_mod.createCommit(
        P,
        testing.allocator,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        &alice_sign.sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    );
    defer cr.tree.deinit();
    defer cr.deinit(testing.allocator);

    try testing.expectEqual(@as(u64, 1), cr.new_epoch);
    try testing.expectEqual(@as(u32, 2), cr.tree.leaf_count);

    const max_gc = gc_mod.max_gc_encode;
    var gc_buf: [max_gc]u8 = undefined;
    const gc_bytes = try cr.group_context.serialize(&gc_buf);

    var kp_buf: [4096]u8 = undefined;
    const kp_end = try bob.kp.encode(&kp_buf, 0);
    const kp_ref = prim_mod.refHash(
        P,
        "MLS 1.0 KeyPackage Reference",
        kp_buf[0..kp_end],
    );

    const eph_seed = [_]u8{0xCC} ** 32;
    const new_members =
        [_]welcome_mod.NewMemberEntry(P){
            .{
                .kp_ref = &kp_ref,
                .init_pk = &bob.init_pk,
                .eph_seed = &eph_seed,
                .leaf_index = LeafIndex.fromU32(1),
            },
        };

    var wr = try welcome_mod.buildWelcome(
        P,
        alloc,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.epoch_secrets.welcome_secret,
        &cr.epoch_secrets.joiner_secret,
        &alice_sign.sk,
        0,
        suite_0xF001,
        &new_members,
        &.{},
        null,
        0,
        null,
        0,
    );
    defer wr.deinit(alloc);

    var bob_join = try welcome_mod.processWelcome(
        P,
        alloc,
        &wr.welcome,
        &kp_ref,
        &bob.init_sk,
        &bob.init_pk,
        &alice_sign.pk,
        .{ .prebuilt = cr.tree },
        LeafIndex.fromU32(1),
        null,
    );
    defer bob_join.deinit();

    try testing.expectEqual(@as(u64, 1), bob_join.group_state.epoch());
    try testing.expectEqual(@as(u32, 2), bob_join.group_state.leafCount());

    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.epoch_secret,
        &bob_join.group_state.epoch_secrets.epoch_secret,
    );
    try testing.expectEqualSlices(
        u8,
        &cr.epoch_secrets.init_secret,
        &bob_join.group_state.epoch_secrets.init_secret,
    );
}
