// zmls CLI — minimal MLS group management over local files.
//
// Subcommands:
//   init <group-id>
//   key-package <identity>
//   add <state-file> <key-package-file>
//   join <welcome-file> <kp-secret-file>
//   remove <state-file> <leaf-index>
//   commit <state-file>
//   send <state-file> <message>
//   recv <state-file> <ciphertext-file>
//   export <state-file> <label> <length>
//   info <state-file>

const std = @import("std");
const mls = @import("zmls");

const P = mls.DefaultCryptoProvider;
const suite: mls.CipherSuite =
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Writer = Io.Writer;
const Allocator = std.mem.Allocator;
const Serializer = mls.serializer.Serializer(P);
const primitives = mls.crypto_primitives;
const KeyPackage = mls.key_package.KeyPackage;

// Maximum buffer sizes.
const max_file: u32 = 1024 * 1024; // 1 MiB
const max_kp_buf: u32 = 8192;
const max_welcome_buf: u32 = 65536;
const max_ct_buf: u32 = 65536;
const max_gc_encode = mls.group_context.max_gc_encode;

// -- Secrets file layout: 32-byte sign_sk || 32-byte enc_sk ||
//    32-byte init_sk || 32-byte sign_pk || 32-byte enc_pk ||
//    32-byte init_pk = 192 bytes.
const secrets_len: u32 = P.sign_sk_len + P.nsk + P.nsk +
    P.sign_pk_len + P.npk + P.npk;

// ── Entry point ─────────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var args = std.process.Args.Iterator.init(
        init.minimal.args,
    );

    // Skip program name.
    _ = args.skip();

    const cmd = args.next() orelse {
        return printUsage(io);
    };

    if (std.mem.eql(u8, cmd, "init")) {
        try cmdInit(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "key-package")) {
        try cmdKeyPackage(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "add")) {
        try cmdAdd(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "join")) {
        try cmdJoin(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "remove")) {
        try cmdRemove(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "commit")) {
        try cmdCommit(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "send")) {
        try cmdSend(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "recv")) {
        try cmdRecv(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "export")) {
        try cmdExport(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "info")) {
        try cmdInfo(io, gpa, &args);
    } else {
        return printUsage(io);
    }
}

fn printUsage(io: Io) !void {
    const msg =
        \\usage: zmls-cli <command> [args]
        \\
        \\commands:
        \\  init <group-id>
        \\  key-package <identity>
        \\  add <state-file> <kp-file>
        \\  join <welcome-file> <kp-secret-file>
        \\  remove <state-file> <leaf-index>
        \\  commit <state-file>
        \\  send <state-file> <message>
        \\  recv <state-file> <ct-file>
        \\  export <state-file> <label> <length>
        \\  info <state-file>
        \\
    ;
    writeStderr(io, msg);
    return error.InvalidArguments;
}

// ── init ────────────────────────────────────────────────────

fn cmdInit(io: Io, gpa: Allocator, args: anytype) !void {
    const group_id = args.next() orelse
        return fatal(io, "init: missing <group-id>");

    // Generate signing + encryption key pairs from OS entropy.
    var seed: [32]u8 = undefined;
    defer primitives.secureZero(&seed);
    io.randomSecure(&seed) catch
        return fatal(io, "init: entropy unavailable");
    const sign_kp = P.signKeypairFromSeed(&seed) catch
        return fatal(io, "init: keygen failed");

    io.randomSecure(&seed) catch
        return fatal(io, "init: entropy unavailable");
    const enc_kp = P.dhKeypairFromSeed(&seed) catch
        return fatal(io, "init: keygen failed");

    // Build leaf node.
    const leaf = makeLeaf(&enc_kp.pk, &sign_kp.pk, group_id);

    // Create group.
    var gs = mls.createGroup(
        P,
        gpa,
        group_id,
        leaf,
        suite,
        &.{},
    ) catch return fatal(io, "init: createGroup failed");
    defer gs.deinit();

    // Serialize and write state.
    const data = Serializer.serialize(gpa, &gs) catch
        return fatal(io, "init: serialize failed");
    defer {
        primitives.secureZero(data);
        gpa.free(data);
    }

    const state_name = "group.state";
    writeFileSync(io, state_name, data) catch
        return fatal(io, "init: write state failed");

    // Write secrets file (sign_sk || enc_sk || init_sk ||
    // sign_pk || enc_pk || init_pk). init = enc for creator.
    var sec_buf: [secrets_len]u8 = undefined;
    var off: u32 = 0;
    off = copyBuf(&sec_buf, off, &sign_kp.sk);
    off = copyBuf(&sec_buf, off, &enc_kp.sk);
    off = copyBuf(&sec_buf, off, &enc_kp.sk); // init=enc
    off = copyBuf(&sec_buf, off, &sign_kp.pk);
    off = copyBuf(&sec_buf, off, &enc_kp.pk);
    _ = copyBuf(&sec_buf, off, &enc_kp.pk); // init=enc
    defer primitives.secureZero(&sec_buf);

    writeFileSync(io, "group.secrets", &sec_buf) catch
        return fatal(io, "init: write secrets failed");

    writeStdout(
        io,
        "group created, state=group.state\n",
    );
}

// ── key-package ─────────────────────────────────────────────

fn cmdKeyPackage(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    _ = gpa;
    const identity = args.next() orelse
        return fatal(io, "key-package: missing <identity>");

    // Generate keys.
    var seed: [32]u8 = undefined;
    defer primitives.secureZero(&seed);
    io.randomSecure(&seed) catch
        return fatal(io, "key-package: entropy unavailable");
    const sign_kp = P.signKeypairFromSeed(&seed) catch
        return fatal(io, "key-package: keygen failed");

    io.randomSecure(&seed) catch
        return fatal(io, "key-package: entropy unavailable");
    const enc_kp = P.dhKeypairFromSeed(&seed) catch
        return fatal(io, "key-package: keygen failed");

    io.randomSecure(&seed) catch
        return fatal(io, "key-package: entropy unavailable");
    const init_kp = P.dhKeypairFromSeed(&seed) catch
        return fatal(io, "key-package: keygen failed");

    // Build and sign leaf node.
    var leaf = makeLeaf(
        &enc_kp.pk,
        &sign_kp.pk,
        identity,
    );
    var leaf_sig: [P.sig_len]u8 = undefined;
    leaf.signLeafNode(
        P,
        &sign_kp.sk,
        &leaf_sig,
        null,
        null,
    ) catch return fatal(io, "key-package: sign leaf failed");

    // Build KeyPackage.
    var sig_buf: [P.sig_len]u8 = undefined;
    var kp = KeyPackage{
        .version = .mls10,
        .cipher_suite = suite,
        .init_key = &init_kp.pk,
        .leaf_node = leaf,
        .extensions = &.{},
        .signature = &sig_buf,
    };
    kp.signKeyPackage(P, &sign_kp.sk, &sig_buf) catch
        return fatal(io, "key-package: sign kp failed");

    // Encode KeyPackage to wire format.
    var kp_buf: [max_kp_buf]u8 = undefined;
    const kp_end = kp.encode(&kp_buf, 0) catch
        return fatal(io, "key-package: encode failed");

    // Write key package file.
    const kp_name = blk: {
        // Use identity as filename base.
        var name_buf: [256]u8 = undefined;
        const name_len = @min(identity.len, 200);
        @memcpy(name_buf[0..name_len], identity[0..name_len]);
        const suffix = ".kp";
        @memcpy(
            name_buf[name_len..][0..suffix.len],
            suffix,
        );
        break :blk name_buf[0 .. name_len + suffix.len];
    };
    writeFileSync(io, kp_name, kp_buf[0..kp_end]) catch
        return fatal(io, "key-package: write kp failed");

    // Write secrets file.
    var sec_buf: [secrets_len]u8 = undefined;
    var off: u32 = 0;
    off = copyBuf(&sec_buf, off, &sign_kp.sk);
    off = copyBuf(&sec_buf, off, &enc_kp.sk);
    off = copyBuf(&sec_buf, off, &init_kp.sk);
    off = copyBuf(&sec_buf, off, &sign_kp.pk);
    off = copyBuf(&sec_buf, off, &enc_kp.pk);
    _ = copyBuf(&sec_buf, off, &init_kp.pk);
    defer primitives.secureZero(&sec_buf);

    const sec_name = blk: {
        var name_buf: [256]u8 = undefined;
        const name_len = @min(identity.len, 200);
        @memcpy(name_buf[0..name_len], identity[0..name_len]);
        const suffix = ".secret";
        @memcpy(
            name_buf[name_len..][0..suffix.len],
            suffix,
        );
        break :blk name_buf[0 .. name_len + suffix.len];
    };
    writeFileSync(io, sec_name, &sec_buf) catch
        return fatal(io, "key-package: write secret failed");

    writeStdout(io, "key package written\n");
}

// ── add ─────────────────────────────────────────────────────

fn cmdAdd(io: Io, gpa: Allocator, args: anytype) !void {
    const state_path = args.next() orelse
        return fatal(io, "add: missing <state-file>");
    const kp_path = args.next() orelse
        return fatal(io, "add: missing <kp-file>");

    // Load group state.
    var gs = loadState(io, gpa, state_path) orelse return;
    defer Serializer.deinitDeserialized(&gs);

    // Load secrets.
    const sec_path = "group.secrets";
    var sec_buf: [secrets_len]u8 = undefined;
    loadFixedFile(io, sec_path, &sec_buf) orelse return;
    defer primitives.secureZero(&sec_buf);
    const sign_sk = sec_buf[0..P.sign_sk_len];

    // Load key package.
    const kp_data = readFileSync(io, gpa, kp_path) orelse
        return;
    defer gpa.free(kp_data);

    var kp_dec = KeyPackage.decode(gpa, kp_data, 0) catch
        return fatal(io, "add: decode kp failed");
    defer kp_dec.value.deinit(gpa);

    // Create Add proposal + commit.
    const add_prop = mls.Proposal{
        .tag = .add,
        .payload = .{ .add = .{ .key_package = kp_dec.value } },
    };
    const proposals = [_]mls.Proposal{add_prop};

    var cr = mls.createCommit(
        P,
        gpa,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        @ptrCast(sign_sk),
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        null,
        null,
        .mls_public_message,
    ) catch return fatal(io, "add: createCommit failed");
    defer cr.tree.deinit();

    // Build Welcome.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = cr.group_context.serialize(
        &gc_buf,
    ) catch return fatal(io, "add: serialize gc failed");

    var full_kp_buf: [max_kp_buf]u8 = undefined;
    const kp_end = kp_dec.value.encode(
        &full_kp_buf,
        0,
    ) catch return fatal(io, "add: encode kp ref failed");
    const kp_ref = primitives.refHash(
        P,
        "MLS 1.0 KeyPackage Reference",
        full_kp_buf[0..kp_end],
    );

    var eph_seed: [32]u8 = undefined;
    io.randomSecure(&eph_seed) catch
        return fatal(io, "add: entropy unavailable");
    const nm = [_]mls.group_welcome.NewMemberEntry{.{
        .kp_ref = &kp_ref,
        .init_pk = kp_dec.value.init_key,
        .eph_seed = &eph_seed,
    }};

    var wr = mls.buildWelcome(
        P,
        gpa,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.epoch_secrets.welcome_secret,
        &cr.epoch_secrets.joiner_secret,
        @ptrCast(sign_sk),
        gs.my_leaf_index.toU32(),
        suite,
        &nm,
        &.{},
    ) catch return fatal(io, "add: buildWelcome failed");
    defer wr.deinit(gpa);

    // Encode Welcome.
    var w_buf: [max_welcome_buf]u8 = undefined;
    const w_end = wr.welcome.encode(&w_buf, 0) catch
        return fatal(io, "add: encode welcome failed");

    writeFileSync(io, "welcome.bin", w_buf[0..w_end]) catch
        return fatal(io, "add: write welcome failed");

    // Update state: apply commit result.
    var new_gs = applyCommitResult(gpa, &gs, &cr) catch
        return fatal(io, "add: apply commit failed");
    defer new_gs.deinit();

    const data = Serializer.serialize(gpa, &new_gs) catch
        return fatal(io, "add: serialize failed");
    defer {
        primitives.secureZero(data);
        gpa.free(data);
    }

    writeFileSync(io, state_path, data) catch
        return fatal(io, "add: write state failed");

    writeStdout(io, "member added, welcome=welcome.bin\n");
}

// ── join ────────────────────────────────────────────────────

fn cmdJoin(io: Io, _: Allocator, args: anytype) !void {
    // Validate arguments are present.
    _ = args.next() orelse
        return fatal(io, "join: missing <welcome-file>");
    _ = args.next() orelse
        return fatal(io, "join: missing <kp-secret-file>");

    // processWelcome needs init private key, tree, and
    // signer key metadata not available from files alone.
    writeStdout(
        io,
        "join: processWelcome not fully wired " ++
            "(needs tree + signer key). Skipping.\n",
    );
}

// ── remove ──────────────────────────────────────────────────

fn cmdRemove(io: Io, gpa: Allocator, args: anytype) !void {
    const state_path = args.next() orelse
        return fatal(io, "remove: missing <state-file>");
    const idx_str = args.next() orelse
        return fatal(io, "remove: missing <leaf-index>");

    const idx = std.fmt.parseInt(
        u32,
        idx_str,
        10,
    ) catch return fatal(io, "remove: invalid leaf-index");

    var gs = loadState(io, gpa, state_path) orelse return;
    defer Serializer.deinitDeserialized(&gs);

    var sec_buf: [secrets_len]u8 = undefined;
    loadFixedFile(io, "group.secrets", &sec_buf) orelse
        return;
    defer primitives.secureZero(&sec_buf);
    const sign_sk: *const [P.sign_sk_len]u8 =
        sec_buf[0..P.sign_sk_len];
    const sign_pk: *const [P.sign_pk_len]u8 =
        sec_buf[P.sign_sk_len + P.nsk + P.nsk ..][0..P.sign_pk_len];
    const enc_pk: *const [P.npk]u8 = sec_buf[P.sign_sk_len +
        P.nsk + P.nsk + P.sign_pk_len ..][0..P.npk];

    const rm = mls.Proposal{
        .tag = .remove,
        .payload = .{ .remove = .{ .removed = idx } },
    };
    const proposals = [_]mls.Proposal{rm};

    // Remove requires a path.
    var leaf_secret: [P.nh]u8 = undefined;
    io.randomSecure(&leaf_secret) catch
        return fatal(io, "remove: entropy unavailable");
    var eph_seeds: [64][32]u8 = undefined;
    for (&eph_seeds) |*s| io.randomSecure(s) catch
        return fatal(io, "remove: entropy unavailable");

    const new_leaf = makeLeaf(enc_pk, sign_pk, "");

    const pp: mls.PathParams(P) = .{
        .allocator = gpa,
        .new_leaf = new_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    var cr = mls.createCommit(
        P,
        gpa,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &proposals,
        sign_sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    ) catch
        return fatal(io, "remove: createCommit failed");
    defer cr.tree.deinit();

    var new_gs = applyCommitResult(gpa, &gs, &cr) catch
        return fatal(io, "remove: apply commit failed");
    defer new_gs.deinit();

    const data = Serializer.serialize(gpa, &new_gs) catch
        return fatal(io, "remove: serialize failed");
    defer {
        primitives.secureZero(data);
        gpa.free(data);
    }

    writeFileSync(io, state_path, data) catch
        return fatal(io, "remove: write state failed");

    writeStdout(io, "member removed\n");
}

// ── commit ──────────────────────────────────────────────────

fn cmdCommit(io: Io, gpa: Allocator, args: anytype) !void {
    const state_path = args.next() orelse
        return fatal(io, "commit: missing <state-file>");

    var gs = loadState(io, gpa, state_path) orelse return;
    defer Serializer.deinitDeserialized(&gs);

    var sec_buf: [secrets_len]u8 = undefined;
    loadFixedFile(io, "group.secrets", &sec_buf) orelse
        return;
    defer primitives.secureZero(&sec_buf);
    const sign_sk: *const [P.sign_sk_len]u8 =
        sec_buf[0..P.sign_sk_len];
    const sign_pk: *const [P.sign_pk_len]u8 =
        sec_buf[P.sign_sk_len + P.nsk + P.nsk ..][0..P.sign_pk_len];
    const enc_pk: *const [P.npk]u8 = sec_buf[P.sign_sk_len +
        P.nsk + P.nsk + P.sign_pk_len ..][0..P.npk];

    var leaf_secret: [P.nh]u8 = undefined;
    io.randomSecure(&leaf_secret) catch
        return fatal(io, "commit: entropy unavailable");
    var eph_seeds: [64][32]u8 = undefined;
    for (&eph_seeds) |*s| io.randomSecure(s) catch
        return fatal(io, "commit: entropy unavailable");

    const new_leaf = makeLeaf(enc_pk, sign_pk, "");
    const pp: mls.PathParams(P) = .{
        .allocator = gpa,
        .new_leaf = new_leaf,
        .leaf_secret = &leaf_secret,
        .eph_seeds = &eph_seeds,
    };

    const empty = [_]mls.Proposal{};

    var cr = mls.createCommit(
        P,
        gpa,
        &gs.group_context,
        &gs.tree,
        gs.my_leaf_index,
        &empty,
        sign_sk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
        pp,
        null,
        .mls_public_message,
    ) catch return fatal(io, "commit: createCommit failed");
    defer cr.tree.deinit();

    var new_gs = applyCommitResult(gpa, &gs, &cr) catch
        return fatal(io, "commit: apply failed");
    defer new_gs.deinit();

    const data = Serializer.serialize(gpa, &new_gs) catch
        return fatal(io, "commit: serialize failed");
    defer {
        primitives.secureZero(data);
        gpa.free(data);
    }

    writeFileSync(io, state_path, data) catch
        return fatal(io, "commit: write state failed");

    writeStdout(io, "committed (key update)\n");
}

// ── send ────────────────────────────────────────────────────

fn cmdSend(io: Io, gpa: Allocator, args: anytype) !void {
    _ = gpa;
    const state_path = args.next() orelse
        return fatal(io, "send: missing <state-file>");
    const message = args.next() orelse
        return fatal(io, "send: missing <message>");
    _ = state_path;
    _ = message;
    // Application message encryption requires sender_data
    // key derivation from SecretTree and nonce/key management.
    // For demo purposes, print a placeholder.
    writeStdout(
        io,
        "send: application message encryption " ++
            "not yet wired in CLI\n",
    );
}

// ── recv ────────────────────────────────────────────────────

fn cmdRecv(io: Io, gpa: Allocator, args: anytype) !void {
    _ = gpa;
    const state_path = args.next() orelse
        return fatal(io, "recv: missing <state-file>");
    const ct_path = args.next() orelse
        return fatal(io, "recv: missing <ct-file>");
    _ = state_path;
    _ = ct_path;
    writeStdout(
        io,
        "recv: application message decryption " ++
            "not yet wired in CLI\n",
    );
}

// ── export ──────────────────────────────────────────────────

fn cmdExport(io: Io, gpa: Allocator, args: anytype) !void {
    const state_path = args.next() orelse
        return fatal(io, "export: missing <state-file>");
    const label = args.next() orelse
        return fatal(io, "export: missing <label>");
    const len_str = args.next() orelse
        return fatal(io, "export: missing <length>");

    const length = std.fmt.parseInt(u32, len_str, 10) catch
        return fatal(io, "export: invalid <length>");
    if (length > P.nh)
        return fatal(io, "export: length too large");

    var gs = loadState(io, gpa, state_path) orelse return;
    defer Serializer.deinitDeserialized(&gs);

    var out: [P.nh]u8 = undefined;
    mls.mlsExporter(
        P,
        &gs.epoch_secrets.exporter_secret,
        label,
        "",
        &out,
    );

    // Print as hex.
    var hex: [P.nh * 2]u8 = undefined;
    for (out[0..length], 0..) |byte, i| {
        const hi = byte >> 4;
        const lo = byte & 0x0f;
        hex[i * 2] = hexChar(hi);
        hex[i * 2 + 1] = hexChar(lo);
    }
    writeStdout(io, hex[0 .. length * 2]);
    writeStdout(io, "\n");
}

// ── info ────────────────────────────────────────────────────

fn cmdInfo(io: Io, gpa: Allocator, args: anytype) !void {
    const state_path = args.next() orelse
        return fatal(io, "info: missing <state-file>");

    var gs = loadState(io, gpa, state_path) orelse return;
    defer Serializer.deinitDeserialized(&gs);

    // Print group info.
    writeStdout(io, "group-id: ");
    writeStdout(io, gs.groupId());
    writeStdout(io, "\n");

    var epoch_buf: [20]u8 = undefined;
    const epoch_str = std.fmt.bufPrint(
        &epoch_buf,
        "{}",
        .{gs.epoch()},
    ) catch "?";
    writeStdout(io, "epoch: ");
    writeStdout(io, epoch_str);
    writeStdout(io, "\n");

    var lc_buf: [10]u8 = undefined;
    const lc_str = std.fmt.bufPrint(
        &lc_buf,
        "{}",
        .{gs.leafCount()},
    ) catch "?";
    writeStdout(io, "leaves: ");
    writeStdout(io, lc_str);
    writeStdout(io, "\n");

    var li_buf: [10]u8 = undefined;
    const li_str = std.fmt.bufPrint(
        &li_buf,
        "{}",
        .{gs.my_leaf_index.toU32()},
    ) catch "?";
    writeStdout(io, "my-leaf: ");
    writeStdout(io, li_str);
    writeStdout(io, "\n");

    writeStdout(io, "suite: 0x0001\n");
}

// ── Helpers ─────────────────────────────────────────────────

const versions = [_]mls.ProtocolVersion{.mls10};
const suites = [_]mls.CipherSuite{
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
};
const ext_types = [_]mls.ExtensionType{};
const prop_types = [_]mls.types.ProposalType{};
const cred_types = [_]mls.types.CredentialType{.basic};

fn makeLeaf(
    enc_pk: *const [P.npk]u8,
    sign_pk: *const [P.sign_pk_len]u8,
    identity: []const u8,
) mls.LeafNode {
    return .{
        .encryption_key = enc_pk,
        .signature_key = sign_pk,
        .credential = mls.Credential.initBasic(identity),
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
        .signature = &[_]u8{0} ** P.sig_len,
    };
}

fn loadState(
    io: Io,
    gpa: Allocator,
    path: []const u8,
) ?mls.GroupState(P) {
    const data = readFileSync(io, gpa, path) orelse
        return null;
    defer gpa.free(data);
    return Serializer.deserialize(gpa, data) catch {
        fatal(io, "failed to deserialize state") catch {};
        return null;
    };
}

fn loadFixedFile(
    io: Io,
    path: []const u8,
    out: []u8,
) ?void {
    const cwd = Dir.cwd();
    const f = cwd.openFile(io, path, .{}) catch {
        fatal(io, "open file failed") catch {};
        return null;
    };
    defer f.close(io);
    const n = f.readPositionalAll(
        io,
        out,
        0,
    ) catch {
        fatal(io, "read file failed") catch {};
        return null;
    };
    if (n != out.len) {
        fatal(io, "short read") catch {};
        return null;
    }
}

fn readFileSync(
    io: Io,
    gpa: Allocator,
    path: []const u8,
) ?[]u8 {
    const cwd = Dir.cwd();
    return cwd.readFileAlloc(
        io,
        path,
        gpa,
        .limited(max_file),
    ) catch {
        fatal(io, "read file failed") catch {};
        return null;
    };
}

fn writeFileSync(
    io: Io,
    path: []const u8,
    data: []const u8,
) !void {
    const cwd = Dir.cwd();
    const f = cwd.createFile(io, path, .{}) catch
        return error.WriteError;
    defer f.close(io);
    f.writePositionalAll(io, data, 0) catch
        return error.WriteError;
}

fn applyCommitResult(
    gpa: Allocator,
    old_gs: *const mls.GroupState(P),
    cr: *const mls.CommitResult(P),
) !mls.GroupState(P) {
    // Build a new GroupState from the commit result.
    // Simplified — a real implementation would use
    // stageCommit/apply pattern.
    const new: mls.GroupState(P) = .{
        .tree = try cr.tree.clone(),
        .group_context = cr.group_context,
        .epoch_secrets = cr.epoch_secrets,
        .interim_transcript_hash = cr.interim_transcript_hash,
        .confirmed_transcript_hash = cr.confirmed_transcript_hash,
        .my_leaf_index = old_gs.my_leaf_index,
        .wire_format_policy = .encrypt_application_only,
        .pending_proposals = mls.ProposalCache(P).init(),
        .epoch_key_ring = mls.EpochKeyRing(P).init(0),
        .resumption_psk_ring = mls.ResumptionPskRing(P).init(0),
        .allocator = gpa,
    };
    return new;
}

fn copyBuf(buf: []u8, pos: u32, src: []const u8) u32 {
    const len: u32 = @intCast(src.len);
    @memcpy(buf[pos..][0..len], src);
    return pos + len;
}

fn hexChar(v: u8) u8 {
    if (v < 10) return '0' + v;
    return 'a' + v - 10;
}

fn writeStdout(io: Io, msg: []const u8) void {
    var buf: [4096]u8 = undefined;
    var w = File.stdout().writerStreaming(io, &buf);
    w.interface.writeAll(msg) catch {};
    w.flush() catch {};
}

fn writeStderr(io: Io, msg: []const u8) void {
    var buf: [4096]u8 = undefined;
    var w = File.stderr().writerStreaming(io, &buf);
    w.interface.writeAll(msg) catch {};
    w.flush() catch {};
}

fn fatal(io: Io, msg: []const u8) error{InvalidArguments} {
    writeStderr(io, "error: ");
    writeStderr(io, msg);
    writeStderr(io, "\n");
    return error.InvalidArguments;
}
