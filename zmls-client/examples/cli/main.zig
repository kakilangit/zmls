// zmls CLI — MLS group management over local files.
//
// Uses the zmls-client Client(P) API. State is persisted
// in binary files between invocations.
//
// Subcommands:
//   init <group-id>
//   key-package <identity>
//   add <state-file> <kp-file>
//   join <welcome-file> <kp-secret-file> <kp-file>
//   remove <state-file> <leaf-index>
//   commit <state-file>
//   send <state-file> <message>
//   recv <state-file> <ct-file>
//   export <state-file> <label> <length>
//   info <state-file>
//   group-info <state-file>
//   external-join <gi-file> <identity>
//   process <state-file> <msg-file>

const std = @import("std");
const zmls_client = @import("zmls-client");
const zmls = @import("zmls");

const P = zmls.DefaultCryptoProvider;
const suite: zmls.CipherSuite =
    .mls_128_dhkemx25519_aes128gcm_sha256_ed25519;
const Client = zmls_client.Client(P);
const MemGS = zmls_client.MemoryGroupStore;
const MemKS = zmls_client.MemoryKeyStore;
const GroupBundle = zmls_client.GroupBundle(P);
const Node = zmls.tree_node.Node;

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Allocator = std.mem.Allocator;
const primitives = zmls.crypto_primitives;

// Secret file layout: sign_sk(32) || enc_sk(32) ||
// init_sk(32) || sign_pk(32) || enc_pk(32) || init_pk(32)
const secrets_len: u32 = P.sign_sk_len + P.nsk + P.nsk +
    P.sign_pk_len + P.npk + P.npk;
const max_file: u32 = 1024 * 1024; // 1 MiB

// ── Entry point ─────────────────────────────────────────

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;
    var args = std.process.Args.Iterator.init(
        init.minimal.args,
    );
    _ = args.skip(); // program name

    const cmd = args.next() orelse
        return printUsage(io);

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
    } else if (std.mem.eql(u8, cmd, "group-info")) {
        try cmdGroupInfo(io, gpa, &args);
    } else if (std.mem.eql(
        u8,
        cmd,
        "external-join",
    )) {
        try cmdExternalJoin(io, gpa, &args);
    } else if (std.mem.eql(u8, cmd, "process")) {
        try cmdProcess(io, gpa, &args);
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
        \\  join <welcome-file> <kp-secret-file> <kp-file>
        \\  remove <state-file> <leaf-index>
        \\  commit <state-file>
        \\  send <state-file> <message>
        \\  recv <state-file> <ct-file>
        \\  export <state-file> <label> <length>
        \\  info <state-file>
        \\  group-info <state-file>
        \\  external-join <gi-file> <identity>
        \\  process <state-file> <msg-file>
        \\
    ;
    writeStderr(io, msg);
    return error.InvalidArguments;
}

// ── init ────────────────────────────────────────────────

fn cmdInit(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const group_id = args.next() orelse
        return fatal(io, "init: missing <group-id>");

    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch
        return fatal(io, "init: entropy unavailable");
    defer primitives.secureZero(&seed);

    var group_store = MemGS(1).init();
    defer group_store.deinit();
    var key_store = MemKS(P, 1).init();
    defer key_store.deinit();

    var client = Client.init(
        gpa,
        group_id,
        suite,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    ) catch return fatal(io, "init: client init failed");
    defer client.deinit();

    client.createGroupWithId(
        io,
        group_id,
        &.{},
    ) catch return fatal(io, "init: create group failed");

    // Persist state file.
    saveGroupState(
        io,
        gpa,
        &client,
        group_id,
        "group.state",
    ) catch return fatal(io, "init: save state failed");

    // Write secrets file.
    var sec_buf: [secrets_len]u8 = undefined;
    defer primitives.secureZero(&sec_buf);
    packSecrets(
        &sec_buf,
        &client.signing_secret_key,
        &seed,
        &seed,
        &client.signing_public_key,
    );
    writeFileSync(io, "group.secrets", &sec_buf) catch
        return fatal(io, "init: write secrets failed");

    writeStdout(io, "group created, state=group.state\n");
}

// ── key-package ─────────────────────────────────────────

fn cmdKeyPackage(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const identity = args.next() orelse
        return fatal(io, "key-package: missing <identity>");

    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch
        return fatal(io, "key-package: entropy");
    defer primitives.secureZero(&seed);

    var group_store = MemGS(1).init();
    defer group_store.deinit();
    var key_store = MemKS(P, 1).init();
    defer key_store.deinit();

    var client = Client.init(
        gpa,
        identity,
        suite,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    ) catch return fatal(io, "key-package: init failed");
    defer client.deinit();

    const kp = client.freshKeyPackage(gpa, io) catch
        return fatal(io, "key-package: gen failed");
    defer gpa.free(kp.data);

    // Write KP data to <identity>.kp
    var kp_path_buf: [256]u8 = undefined;
    const kp_path = fmtPath(
        &kp_path_buf,
        identity,
        ".kp",
    );
    writeFileSync(io, kp_path, kp.data) catch
        return fatal(io, "key-package: write kp failed");

    // Retrieve pending keys via ref hash.
    const pending = client.pending_key_packages.find(
        &kp.ref_hash,
    ) orelse
        return fatal(io, "key-package: pending lost");

    // Write secrets: sign_sk, enc_sk, init_sk, pubs.
    var sec_buf: [secrets_len]u8 = undefined;
    defer primitives.secureZero(&sec_buf);
    packSecrets(
        &sec_buf,
        &client.signing_secret_key,
        &pending.enc_sk,
        &pending.init_sk,
        &client.signing_public_key,
    );
    var sec_path_buf: [256]u8 = undefined;
    const sec_path = fmtPath(
        &sec_path_buf,
        identity,
        ".secret",
    );
    writeFileSync(io, sec_path, &sec_buf) catch
        return fatal(io, "key-package: write sec failed");

    writeStdout(io, "key package written\n");
}

// ── add ─────────────────────────────────────────────────

fn cmdAdd(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "add: missing <state-file>");
    const kp_path = args.next() orelse
        return fatal(io, "add: missing <kp-file>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const kp_data = readFileSync(io, gpa, kp_path) orelse
        return;
    defer gpa.free(kp_data);

    var invite = ctx.client.inviteMember(
        gpa,
        io,
        ctx.group_id,
        kp_data,
    ) catch return fatal(io, "add: invite failed");
    defer invite.deinit();

    // Write welcome.
    writeFileSync(io, "welcome.bin", invite.welcome) catch
        return fatal(io, "add: write welcome failed");

    // Write commit for other members.
    writeFileSync(io, "commit.bin", invite.commit) catch
        return fatal(io, "add: write commit failed");

    // Write tree and signer key for joiner.
    writeTreeFile(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
    ) catch return fatal(io, "add: write tree failed");
    writeFileSync(
        io,
        "signer.pub",
        &ctx.client.signing_public_key,
    ) catch return fatal(io, "add: write signer failed");

    // Persist updated state.
    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch
        return fatal(io, "add: save state failed");

    writeStdout(
        io,
        "member added, welcome=welcome.bin\n",
    );
}

// ── join ────────────────────────────────────────────────

fn cmdJoin(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const welcome_path = args.next() orelse
        return fatal(io, "join: missing <welcome-file>");
    const sec_path = args.next() orelse
        return fatal(io, "join: missing <kp-secret-file>");
    const kp_path = args.next() orelse
        return fatal(io, "join: missing <kp-file>");

    var group_store = MemGS(1).init();
    defer group_store.deinit();
    var key_store = MemKS(P, 1).init();
    defer key_store.deinit();

    var sec_buf: [secrets_len]u8 = undefined;
    loadFixedFile(io, sec_path, &sec_buf) orelse return;
    defer primitives.secureZero(&sec_buf);

    var client = makeClientFromSecrets(
        gpa,
        &group_store,
        &key_store,
        &sec_buf,
    ) catch return fatal(io, "join: client init failed");
    defer client.deinit();

    // Load KP to compute ref hash and inject pending.
    const kp_data = readFileSync(io, gpa, kp_path) orelse
        return;
    defer gpa.free(kp_data);

    injectPendingKp(
        &client,
        kp_data,
        &sec_buf,
    ) catch return fatal(io, "join: inject kp failed");

    // Load Welcome bytes.
    const welcome_bytes = readFileSync(
        io,
        gpa,
        welcome_path,
    ) orelse return;
    defer gpa.free(welcome_bytes);

    // Load tree and signer key.
    var signer_pub: [P.sign_pk_len]u8 = undefined;
    loadFixedFile(io, "signer.pub", &signer_pub) orelse
        return;

    var tree = loadTreeFile(io, gpa) orelse
        return fatal(io, "join: load tree failed");
    defer tree.deinit();

    var join = client.joinGroup(
        gpa,
        io,
        welcome_bytes,
        .{
            .ratchet_tree = tree,
            .signer_verify_key = &signer_pub,
        },
    ) catch return fatal(io, "join: process failed");
    defer join.deinit();

    // Persist joined state.
    saveGroupState(
        io,
        gpa,
        &client,
        join.group_id,
        "group.state",
    ) catch return fatal(io, "join: save state failed");

    // Copy secrets to group.secrets for future ops.
    writeFileSync(io, "group.secrets", &sec_buf) catch
        return fatal(io, "join: write secrets failed");

    writeStdout(io, "joined group via Welcome\n");
}

// ── remove ──────────────────────────────────────────────

fn cmdRemove(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "remove: missing <state-file>");
    const idx_str = args.next() orelse
        return fatal(io, "remove: missing <leaf-index>");
    const idx = std.fmt.parseInt(u32, idx_str, 10) catch
        return fatal(io, "remove: invalid leaf-index");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const commit = ctx.client.removeMember(
        gpa,
        io,
        ctx.group_id,
        idx,
    ) catch return fatal(io, "remove: failed");
    defer gpa.free(commit);

    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch return fatal(io, "remove: save failed");

    writeFileSync(io, "commit.bin", commit) catch
        return fatal(io, "remove: write commit failed");

    writeStdout(io, "member removed\n");
}

// ── commit ──────────────────────────────────────────────

fn cmdCommit(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "commit: missing <state-file>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const commit = ctx.client.selfUpdate(
        gpa,
        io,
        ctx.group_id,
    ) catch return fatal(io, "commit: failed");
    defer gpa.free(commit);

    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch return fatal(io, "commit: save failed");

    writeFileSync(io, "commit.bin", commit) catch
        return fatal(io, "commit: write commit failed");

    writeStdout(io, "committed (key update)\n");
}

// ── send ────────────────────────────────────────────────

fn cmdSend(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "send: missing <state-file>");
    const message = args.next() orelse
        return fatal(io, "send: missing <message>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const ct = ctx.client.sendMessage(
        gpa,
        io,
        ctx.group_id,
        message,
    ) catch return fatal(io, "send: encrypt failed");
    defer gpa.free(ct);

    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch return fatal(io, "send: save state failed");

    writeFileSync(io, "message.bin", ct) catch
        return fatal(io, "send: write failed");

    writeStdout(io, "message encrypted\n");
}

// ── recv ────────────────────────────────────────────────

fn cmdRecv(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "recv: missing <state-file>");
    const ct_path = args.next() orelse
        return fatal(io, "recv: missing <ct-file>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const ct = readFileSync(io, gpa, ct_path) orelse
        return;
    defer gpa.free(ct);

    var received = ctx.client.receiveMessage(
        gpa,
        io,
        ctx.group_id,
        ct,
    ) catch return fatal(io, "recv: decrypt failed");
    defer received.deinit();

    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch return fatal(io, "recv: save state failed");

    writeStdout(io, received.data);
    writeStdout(io, "\n");
}

// ── export ──────────────────────────────────────────────

fn cmdExport(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "export: missing <state-file>");
    const label = args.next() orelse
        return fatal(io, "export: missing <label>");
    const len_str = args.next() orelse
        return fatal(io, "export: missing <length>");
    const length = std.fmt.parseInt(u32, len_str, 10) catch
        return fatal(io, "export: invalid length");
    if (length > 256)
        return fatal(io, "export: length too large");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    var out: [256]u8 = undefined;
    ctx.client.exportSecret(
        io,
        ctx.group_id,
        label,
        "",
        out[0..length],
    ) catch return fatal(io, "export: failed");

    // Print as hex.
    var hex_buf: [512]u8 = undefined;
    for (out[0..length], 0..) |b, i| {
        hex_buf[i * 2] = hexChar(b >> 4);
        hex_buf[i * 2 + 1] = hexChar(b & 0xf);
    }
    writeStdout(io, hex_buf[0 .. length * 2]);
    writeStdout(io, "\n");
}

// ── info ────────────────────────────────────────────────

fn cmdInfo(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "info: missing <state-file>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const epoch = ctx.client.groupEpoch(
        io,
        ctx.group_id,
    ) catch return fatal(io, "info: load failed");
    const leaf_count = ctx.client.groupLeafCount(
        io,
        ctx.group_id,
    ) catch return fatal(io, "info: load failed");

    var buf: [256]u8 = undefined;
    var pos: usize = 0;
    pos = appendStr(&buf, pos, "epoch=");
    pos = appendInt(&buf, pos, epoch);
    pos = appendStr(&buf, pos, " leaves=");
    pos = appendInt(&buf, pos, leaf_count);
    pos = appendStr(&buf, pos, "\n");
    writeStdout(io, buf[0..pos]);
}

// ── group-info ──────────────────────────────────────────

fn cmdGroupInfo(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(
            io,
            "group-info: missing <state-file>",
        );

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const gi = ctx.client.groupInfo(
        gpa,
        io,
        ctx.group_id,
    ) catch return fatal(io, "group-info: failed");
    defer gpa.free(gi);

    writeFileSync(io, "group-info.bin", gi) catch
        return fatal(io, "group-info: write failed");

    writeStdout(io, "group info exported\n");
}

// ── external-join ───────────────────────────────────────

fn cmdExternalJoin(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const gi_path = args.next() orelse
        return fatal(
            io,
            "external-join: missing <gi-file>",
        );
    const identity = args.next() orelse
        return fatal(
            io,
            "external-join: missing <identity>",
        );

    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch
        return fatal(io, "external-join: entropy");
    defer primitives.secureZero(&seed);

    var group_store = MemGS(1).init();
    defer group_store.deinit();
    var key_store = MemKS(P, 1).init();
    defer key_store.deinit();

    var client = Client.init(
        gpa,
        identity,
        suite,
        &seed,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    ) catch return fatal(
        io,
        "external-join: init failed",
    );
    defer client.deinit();

    const gi_bytes = readFileSync(
        io,
        gpa,
        gi_path,
    ) orelse return;
    defer gpa.free(gi_bytes);

    var result = client.externalJoin(
        gpa,
        io,
        gi_bytes,
    ) catch return fatal(io, "external-join: failed");
    defer result.deinit();

    saveGroupState(
        io,
        gpa,
        &client,
        result.group_id,
        "group.state",
    ) catch return fatal(
        io,
        "external-join: save failed",
    );

    // Write secrets.
    var sec_buf: [secrets_len]u8 = undefined;
    defer primitives.secureZero(&sec_buf);
    packSecrets(
        &sec_buf,
        &client.signing_secret_key,
        &seed,
        &seed,
        &client.signing_public_key,
    );
    writeFileSync(io, "group.secrets", &sec_buf) catch
        return fatal(
            io,
            "external-join: write secrets failed",
        );

    writeFileSync(
        io,
        "external-commit.bin",
        result.commit,
    ) catch return fatal(
        io,
        "external-join: write commit failed",
    );

    writeStdout(io, "joined group via external commit\n");
}

// ── process ─────────────────────────────────────────────

fn cmdProcess(
    io: Io,
    gpa: Allocator,
    args: anytype,
) !void {
    const state_path = args.next() orelse
        return fatal(io, "process: missing <state-file>");
    const msg_path = args.next() orelse
        return fatal(io, "process: missing <msg-file>");

    var ctx = loadClientContext(
        io,
        gpa,
        state_path,
    ) orelse return;
    defer ctx.deinit(gpa);

    const msg_data = readFileSync(
        io,
        gpa,
        msg_path,
    ) orelse return;
    defer gpa.free(msg_data);

    var proc = ctx.client.processIncoming(
        gpa,
        io,
        ctx.group_id,
        msg_data,
    ) catch return fatal(io, "process: failed");
    switch (proc) {
        .commit_applied => |*ca| ca.deinit(),
        .application => |*msg| {
            writeStdout(io, msg.data);
            writeStdout(io, "\n");
            msg.deinit();
        },
        .proposal_cached => {},
    }

    saveGroupState(
        io,
        gpa,
        &ctx.client,
        ctx.group_id,
        state_path,
    ) catch return fatal(io, "process: save failed");

    writeStdout(io, "message processed\n");
}

// ── Client context helper ───────────────────────────────

/// Heap-allocated stores + Client bundle. Avoids dangling
/// pointers: stores stay at a stable address and the
/// Client's interface pointers remain valid.
const ClientContext = struct {
    client: Client,
    group_id: []u8,
    group_store: *MemGS(1),
    key_store: *MemKS(P, 1),

    fn deinit(self: *ClientContext, gpa: Allocator) void {
        gpa.free(self.group_id);
        self.client.deinit();
        self.group_store.deinit();
        self.key_store.deinit();
        gpa.destroy(self.group_store);
        gpa.destroy(self.key_store);
    }
};

/// Load secrets + state, create Client on heap-stable
/// stores, return context owning everything.
fn loadClientContext(
    io: Io,
    gpa: Allocator,
    state_path: []const u8,
) ?ClientContext {
    var sec_buf: [secrets_len]u8 = undefined;
    loadFixedFile(io, "group.secrets", &sec_buf) orelse
        return null;
    defer primitives.secureZero(&sec_buf);

    // Heap-allocate stores so their addresses are stable.
    const gs = gpa.create(MemGS(1)) catch return null;
    gs.* = MemGS(1).init();
    errdefer {
        gs.deinit();
        gpa.destroy(gs);
    }

    const ks = gpa.create(MemKS(P, 1)) catch return null;
    ks.* = MemKS(P, 1).init();
    errdefer {
        ks.deinit();
        gpa.destroy(ks);
    }

    var client = makeClientFromSecretsHeap(
        gpa,
        gs,
        ks,
        &sec_buf,
    ) catch return null;
    errdefer client.deinit();

    const loaded = loadStateIntoStore(
        io,
        gpa,
        gs,
        state_path,
    ) orelse return null;

    // Store encryption key so processPublicCommit can
    // find it. enc_sk is at offset sign_sk_len in the
    // secrets file.
    const enc_sk: *const [P.nsk]u8 =
        sec_buf[P.sign_sk_len..][0..P.nsk];
    ks.keyStore().storeEncryptionKey(
        io,
        loaded.group_id,
        loaded.my_leaf_index,
        enc_sk,
    ) catch return null;

    return .{
        .client = client,
        .group_id = loaded.group_id,
        .group_store = gs,
        .key_store = ks,
    };
}

fn makeClientFromSecrets(
    gpa: Allocator,
    group_store: *MemGS(1),
    key_store: *MemKS(P, 1),
    sec_buf: *const [secrets_len]u8,
) !Client {
    const sign_sk: *const [32]u8 = sec_buf[0..32];
    return Client.init(
        gpa,
        "cli-user",
        suite,
        sign_sk,
        .{
            .group_store = group_store.groupStore(),
            .key_store = key_store.keyStore(),
            .credential_validator = zmls
                .credential_validator
                .AcceptAllValidator.validator(),
        },
    );
}

fn makeClientFromSecretsHeap(
    gpa: Allocator,
    group_store: *MemGS(1),
    key_store: *MemKS(P, 1),
    sec_buf: *const [secrets_len]u8,
) !Client {
    return makeClientFromSecrets(
        gpa,
        group_store,
        key_store,
        sec_buf,
    );
}

/// Load a state file, extract group_id and leaf index,
/// store in MemGS. Returns owned group_id + leaf index.
const LoadedState = struct {
    group_id: []u8,
    my_leaf_index: u32,
};

fn loadStateIntoStore(
    io: Io,
    gpa: Allocator,
    group_store: *MemGS(1),
    path: []const u8,
) ?LoadedState {
    const blob = readFileSync(io, gpa, path) orelse
        return null;

    // Deserialize to extract group_id and leaf index.
    var bundle = GroupBundle.deserialize(
        gpa,
        blob,
    ) catch {
        gpa.free(blob);
        return null;
    };
    const group_id = gpa.dupe(
        u8,
        bundle.group_state.groupId(),
    ) catch {
        bundle.deinit(gpa);
        gpa.free(blob);
        return null;
    };
    const leaf_index = @intFromEnum(
        bundle.group_state.my_leaf_index,
    );

    // Store the raw blob under the real group_id.
    group_store.groupStore().save(
        io,
        group_id,
        blob,
    ) catch {
        gpa.free(group_id);
        bundle.deinit(gpa);
        gpa.free(blob);
        return null;
    };

    bundle.deinit(gpa);
    gpa.free(blob);
    return .{
        .group_id = group_id,
        .my_leaf_index = leaf_index,
    };
}

fn saveGroupState(
    io: Io,
    gpa: Allocator,
    client: *Client,
    group_id: []const u8,
    path: []const u8,
) !void {
    var bundle = client.loadBundle(
        io,
        group_id,
    ) catch return error.InvalidArguments;
    defer bundle.deinit(gpa);

    const blob = GroupBundle.serialize(
        gpa,
        &bundle.group_state,
        &bundle.secret_tree,
    ) catch return error.InvalidArguments;
    defer {
        primitives.secureZero(blob);
        gpa.free(blob);
    }

    try writeFileSync(io, path, blob);
}

fn packSecrets(
    buf: *[secrets_len]u8,
    sign_sk: *const [P.sign_sk_len]u8,
    enc_sk: *const [P.nsk]u8,
    init_sk: *const [P.nsk]u8,
    sign_pk: *const [P.sign_pk_len]u8,
) void {
    var pos: u32 = 0;
    @memcpy(buf[pos..][0..P.sign_sk_len], sign_sk);
    pos += P.sign_sk_len;
    @memcpy(buf[pos..][0..P.nsk], enc_sk);
    pos += P.nsk;
    @memcpy(buf[pos..][0..P.nsk], init_sk);
    pos += P.nsk;
    @memcpy(buf[pos..][0..P.sign_pk_len], sign_pk);
    pos += P.sign_pk_len;
    // Derive enc_pk and init_pk from sk.
    const enc_kp = P.dhKeypairFromSeed(
        enc_sk,
    ) catch unreachable;
    @memcpy(buf[pos..][0..P.npk], &enc_kp.pk);
    pos += P.npk;
    const init_kp = P.dhKeypairFromSeed(
        init_sk,
    ) catch unreachable;
    @memcpy(buf[pos..][0..P.npk], &init_kp.pk);
}

fn injectPendingKp(
    client: *Client,
    kp_data: []const u8,
    sec_buf: *const [secrets_len]u8,
) !void {
    // Compute KP ref hash.
    const ref = primitives.refHash(
        P,
        "MLS 1.0 KeyPackage Reference",
        kp_data,
    );

    const PendingKeys = @TypeOf(
        client.pending_key_packages,
    ).PendingKeys;
    const init_sk: [P.nsk]u8 =
        sec_buf[P.sign_sk_len + P.nsk ..][0..P.nsk].*;
    const enc_sk: [P.nsk]u8 =
        sec_buf[P.sign_sk_len..][0..P.nsk].*;
    const init_pk: [P.npk]u8 =
        sec_buf[P.sign_sk_len + P.nsk + P.nsk +
        P.sign_pk_len + P.npk ..][0..P.npk].*;
    const sign_sk: [P.sign_sk_len]u8 =
        sec_buf[0..P.sign_sk_len].*;

    try client.pending_key_packages.insert(
        &ref,
        PendingKeys{
            .init_sk = init_sk,
            .init_pk = init_pk,
            .enc_sk = enc_sk,
            .sign_sk = sign_sk,
        },
    );
}

fn writeTreeFile(
    io: Io,
    gpa: Allocator,
    client: *Client,
    group_id: []const u8,
) !void {
    var bundle = client.loadBundle(
        io,
        group_id,
    ) catch return error.InvalidArguments;
    defer bundle.deinit(gpa);

    // Encode tree as TLS wire format.
    const tree = &bundle.group_state.tree;
    var buf: [65536]u8 = undefined;
    var pos: u32 = 0;

    const width = tree.nodeCount();
    // First pass: compute payload size.
    var payload_size: u32 = 0;
    var tmp: [8192]u8 = undefined;
    var ni: u32 = 0;
    while (ni < width) : (ni += 1) {
        payload_size += 1; // presence byte
        if (tree.nodes[ni]) |*n| {
            const n_end = n.encode(
                &tmp,
                0,
            ) catch return error.InvalidArguments;
            payload_size += n_end;
        }
    }

    // Varint header.
    pos = zmls.varint.encode(
        &buf,
        0,
        payload_size,
    ) catch return error.InvalidArguments;

    // Encode nodes.
    ni = 0;
    while (ni < width) : (ni += 1) {
        if (tree.nodes[ni]) |*n| {
            pos = zmls.codec.encodeUint8(
                &buf,
                pos,
                1,
            ) catch return error.InvalidArguments;
            pos = n.encode(
                &buf,
                pos,
            ) catch return error.InvalidArguments;
        } else {
            pos = zmls.codec.encodeUint8(
                &buf,
                pos,
                0,
            ) catch return error.InvalidArguments;
        }
    }

    try writeFileSync(io, "tree.bin", buf[0..pos]);
}

fn loadTreeFile(
    io: Io,
    gpa: Allocator,
) ?zmls.RatchetTree {
    const data = readFileSync(
        io,
        gpa,
        "tree.bin",
    ) orelse return null;
    defer gpa.free(data);

    // Decode varint header.
    const vr = zmls.varint.decode(data, 0) catch
        return null;
    const vec_len = vr.value;
    var pos = vr.pos;
    const end = pos + vec_len;
    if (end > data.len) return null;

    const max_nodes: u32 = 4096;
    var entries: [max_nodes]?Node = undefined;
    var node_count: u32 = 0;

    while (pos < end) {
        if (node_count >= max_nodes) return null;
        const presence = zmls.codec.decodeUint8(
            data,
            pos,
        ) catch return null;
        pos = presence.pos;
        if (presence.value == 1) {
            const nr = Node.decode(
                gpa,
                data,
                pos,
            ) catch return null;
            pos = nr.pos;
            entries[node_count] = nr.value;
        } else {
            entries[node_count] = null;
        }
        node_count += 1;
    }

    const leaf_count: u32 = (node_count + 1) / 2;
    var tree = zmls.RatchetTree.init(
        gpa,
        leaf_count,
    ) catch return null;

    var idx: u32 = 0;
    while (idx < node_count) : (idx += 1) {
        tree.nodes[idx] = entries[idx];
    }
    tree.owns_contents = true;
    return tree;
}

// ── File I/O ────────────────────────────────────────────

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
    ) catch null;
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

fn loadFixedFile(
    io: Io,
    path: []const u8,
    out: []u8,
) ?void {
    const cwd = Dir.cwd();
    const f = cwd.openFile(io, path, .{}) catch
        return null;
    defer f.close(io);
    const n = f.readPositionalAll(
        io,
        out,
        0,
    ) catch return null;
    if (n != out.len) return null;
}

// ── Output helpers ──────────────────────────────────────

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

fn fatal(
    io: Io,
    msg: []const u8,
) error{InvalidArguments} {
    writeStderr(io, "error: ");
    writeStderr(io, msg);
    writeStderr(io, "\n");
    return error.InvalidArguments;
}

fn hexChar(v: u8) u8 {
    return if (v < 10) '0' + v else 'a' + v - 10;
}

fn fmtPath(
    buf: []u8,
    name: []const u8,
    ext: []const u8,
) []const u8 {
    if (name.len + ext.len > buf.len) return "";
    @memcpy(buf[0..name.len], name);
    @memcpy(buf[name.len..][0..ext.len], ext);
    return buf[0 .. name.len + ext.len];
}

fn appendStr(
    buf: []u8,
    pos: usize,
    s: []const u8,
) usize {
    if (pos + s.len > buf.len) return pos;
    @memcpy(buf[pos..][0..s.len], s);
    return pos + s.len;
}

fn appendInt(buf: []u8, pos: usize, val: u64) usize {
    var tmp: [20]u8 = undefined;
    var v = val;
    var len: usize = 0;
    if (v == 0) {
        tmp[0] = '0';
        len = 1;
    } else {
        while (v > 0) : (len += 1) {
            tmp[len] = @intCast('0' + (v % 10));
            v /= 10;
        }
        // Reverse.
        var a: usize = 0;
        var b: usize = len - 1;
        while (a < b) {
            const t = tmp[a];
            tmp[a] = tmp[b];
            tmp[b] = t;
            a += 1;
            b -= 1;
        }
    }
    return appendStr(buf, pos, tmp[0..len]);
}
