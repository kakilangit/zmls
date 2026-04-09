// Benchmark harness for zmls.
//
// Standalone executable. Run via:
//   zig build bench -Doptimize=ReleaseFast
//
// Output: one line per benchmark with timing statistics.

const std = @import("std");
const builtin = @import("builtin");
const mls = @import("zmls");

const Default = mls.DefaultCryptoProvider;

// -- Timer -----------------------------------------------------------

/// Monotonic nanosecond timestamp (no libc dependency).
fn now() u64 {
    if (comptime builtin.os.tag == .macos) {
        const t = std.c.mach_absolute_time();
        var info: std.c.mach_timebase_info_data = undefined;
        _ = std.c.mach_timebase_info(&info);
        return t * info.numer / info.denom;
    } else if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        const rc = std.os.linux.clock_gettime(
            .MONOTONIC,
            &ts,
        );
        if (rc != 0) return 0;
        return @as(u64, @intCast(ts.sec)) *
            1_000_000_000 + @as(u64, @intCast(ts.nsec));
    } else {
        @compileError("unsupported OS for benchmarks");
    }
}

// -- Harness ---------------------------------------------------------

const max_samples: u32 = 10_000;
const default_iters: u32 = 200;

const BenchResult = struct {
    name: []const u8,
    iters: u32,
    min_ns: u64,
    median_ns: u64,
    mean_ns: u64,
    max_ns: u64,
};

fn runBench(
    name: []const u8,
    iters: u32,
    comptime func: fn () void,
) BenchResult {
    const warmup: u32 = @max(1, iters / 10);
    const total = warmup + iters;
    const n: u32 = @min(total, max_samples);

    var samples: [max_samples]u64 = undefined;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const t0 = now();
        func();
        const t1 = now();
        samples[i] = t1 -| t0;
    }

    const effective = n - @min(warmup, n);
    const data = samples[n - effective .. n];
    std.mem.sort(u64, data, {}, std.sort.asc(u64));

    var sum: u64 = 0;
    var min_v: u64 = std.math.maxInt(u64);
    var max_v: u64 = 0;
    for (data) |s| {
        sum += s;
        if (s < min_v) min_v = s;
        if (s > max_v) max_v = s;
    }

    return .{
        .name = name,
        .iters = effective,
        .min_ns = min_v,
        .median_ns = data[effective / 2],
        .mean_ns = if (effective > 0) sum / effective else 0,
        .max_ns = max_v,
    };
}

fn printResult(r: BenchResult) void {
    const ops: u64 = if (r.median_ns > 0)
        1_000_000_000 / r.median_ns
    else
        0;
    std.debug.print(
        "{s:<40} {d:>5} iters  " ++
            "min={d:>9} ns  med={d:>9} ns  " ++
            "mean={d:>9} ns  max={d:>9} ns  " ++
            "{d:>8} ops/s\n",
        .{
            r.name,
            r.iters,
            r.min_ns,
            r.median_ns,
            r.mean_ns,
            r.max_ns,
            ops,
        },
    );
}

// -- Crypto primitives (39.2) ----------------------------------------

fn benchHash() void {
    const buf = [_]u8{0x42} ** 1024;
    var out: [Default.nh]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&buf, &out, .{});
    std.mem.doNotOptimizeAway(&out);
}

fn benchKdf() void {
    const salt = [_]u8{0x01} ** Default.nh;
    const ikm = [_]u8{0x02} ** Default.nh;
    var prk: [Default.nh]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(
        &prk,
        &ikm,
        &salt,
    );
    var okm: [Default.nh]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(
        &okm,
        &[_]u8{0x01},
        &prk,
    );
    std.mem.doNotOptimizeAway(&okm);
}

fn benchAeadSeal() void {
    const pt = [_]u8{0x42} ** 1024;
    var ct: [1024]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    Default.aeadSeal(&key, &nonce, &.{}, &pt, &ct, &tag);
    std.mem.doNotOptimizeAway(&ct);
}

fn benchAeadOpen() void {
    const pt = [_]u8{0x42} ** 1024;
    var ct: [1024]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    Default.aeadSeal(&key, &nonce, &.{}, &pt, &ct, &tag);
    var pt2: [1024]u8 = undefined;
    Default.aeadOpen(
        &key,
        &nonce,
        &.{},
        &ct,
        &tag,
        &pt2,
    ) catch {};
    std.mem.doNotOptimizeAway(&pt2);
}

fn benchSign() void {
    const seed = [_]u8{0x42} ** 32;
    const kp = Default.signKeypairFromSeed(
        &seed,
    ) catch return;
    const msg = [_]u8{0xAB} ** 256;
    const sig = Default.sign(&kp.sk, &msg) catch return;
    std.mem.doNotOptimizeAway(&sig);
}

fn benchVerify() void {
    const seed = [_]u8{0x42} ** 32;
    const kp = Default.signKeypairFromSeed(
        &seed,
    ) catch return;
    const msg = [_]u8{0xAB} ** 256;
    const sig = Default.sign(&kp.sk, &msg) catch return;
    Default.verify(&kp.pk, &msg, &sig) catch {};
}

fn benchDh() void {
    const seed_a = [_]u8{0x01} ** 32;
    const seed_b = [_]u8{0x02} ** 32;
    const kp_a = Default.dhKeypairFromSeed(
        &seed_a,
    ) catch return;
    const kp_b = Default.dhKeypairFromSeed(
        &seed_b,
    ) catch return;
    const ss = Default.dh(&kp_a.sk, &kp_b.pk) catch return;
    std.mem.doNotOptimizeAway(&ss);
}

fn benchHpkeEncrypt() void {
    const seed_e = [_]u8{0x01} ** 32;
    const kp = Default.dhKeypairFromSeed(
        &seed_e,
    ) catch return;
    const pt = [_]u8{0x42} ** 256;
    var ct: [256]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const eph_seed = [_]u8{0x03} ** 32;
    const kem = mls.crypto_primitives.encryptWithLabel(
        Default,
        &kp.pk,
        "bench",
        &.{},
        &pt,
        &eph_seed,
        &ct,
        &tag,
    ) catch return;
    std.mem.doNotOptimizeAway(&kem);
}

fn benchHpkeDecrypt() void {
    const seed_e = [_]u8{0x01} ** 32;
    const kp = Default.dhKeypairFromSeed(
        &seed_e,
    ) catch return;
    const pt = [_]u8{0x42} ** 256;
    var ct: [256]u8 = undefined;
    var tag: [Default.nt]u8 = undefined;
    const eph_seed = [_]u8{0x03} ** 32;
    const kem = mls.crypto_primitives.encryptWithLabel(
        Default,
        &kp.pk,
        "bench",
        &.{},
        &pt,
        &eph_seed,
        &ct,
        &tag,
    ) catch return;
    var pt2: [256]u8 = undefined;
    mls.crypto_primitives.decryptWithLabel(
        Default,
        &kp.sk,
        &kp.pk,
        "bench",
        &.{},
        &kem,
        &ct,
        &tag,
        &pt2,
    ) catch return;
    std.mem.doNotOptimizeAway(&pt2);
}

// -- Key schedule (39.3) ---------------------------------------------

fn benchDeriveEpochSecrets() void {
    const zero: [Default.nh]u8 = .{0} ** Default.nh;
    const gc_buf = [_]u8{0x42} ** 128;
    const es = mls.deriveEpochSecrets(
        Default,
        &zero,
        &zero,
        &zero,
        &gc_buf,
    );
    std.mem.doNotOptimizeAway(&es);
}

fn benchDerivePskSecret1() void {
    const secret = [_]u8{0x42} ** Default.nh;
    const nonce = [_]u8{0x01} ** 32;
    const entries = [_]mls.psk.PskEntry{
        .{
            .id = .{
                .psk_type = .external,
                .external_psk_id = "bench-psk-0",
                .resumption_usage = .application,
                .resumption_group_id = &.{},
                .resumption_epoch = 0,
                .psk_nonce = &nonce,
            },
            .secret = &secret,
        },
    };
    const r = mls.psk.derivePskSecret(
        Default,
        &entries,
    ) catch return;
    std.mem.doNotOptimizeAway(&r);
}

fn benchDerivePskSecret4() void {
    const secret = [_]u8{0x42} ** Default.nh;
    const nonce = [_]u8{0x01} ** 32;
    var entries: [4]mls.psk.PskEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = .{
            .id = .{
                .psk_type = .external,
                .external_psk_id = "bench-psk-x",
                .resumption_usage = .application,
                .resumption_group_id = &.{},
                .resumption_epoch = @intCast(i),
                .psk_nonce = &nonce,
            },
            .secret = &secret,
        };
    }
    const r = mls.psk.derivePskSecret(
        Default,
        &entries,
    ) catch return;
    std.mem.doNotOptimizeAway(&r);
}

fn benchDerivePskSecret16() void {
    const secret = [_]u8{0x42} ** Default.nh;
    const nonce = [_]u8{0x01} ** 32;
    var entries: [16]mls.psk.PskEntry = undefined;
    for (&entries, 0..) |*e, i| {
        e.* = .{
            .id = .{
                .psk_type = .external,
                .external_psk_id = "bench-psk-x",
                .resumption_usage = .application,
                .resumption_group_id = &.{},
                .resumption_epoch = @intCast(i),
                .psk_nonce = &nonce,
            },
            .secret = &secret,
        };
    }
    const r = mls.psk.derivePskSecret(
        Default,
        &entries,
    ) catch return;
    std.mem.doNotOptimizeAway(&r);
}

fn benchSecretTreeInit16() void {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    const ST = mls.SecretTree(Default);
    var st = ST.init(
        std.heap.page_allocator,
        &enc_secret,
        16,
    ) catch return;
    st.deinit(std.heap.page_allocator);
}

fn benchSecretTreeInit256() void {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    const ST = mls.SecretTree(Default);
    var st = ST.init(
        std.heap.page_allocator,
        &enc_secret,
        256,
    ) catch return;
    st.deinit(std.heap.page_allocator);
}

fn benchSecretTreeInit1024() void {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    const ST = mls.SecretTree(Default);
    var st = ST.init(
        std.heap.page_allocator,
        &enc_secret,
        1024,
    ) catch return;
    st.deinit(std.heap.page_allocator);
}

fn benchSecretTreeConsumeKey() void {
    const enc_secret = [_]u8{0x42} ** Default.nh;
    const ST = mls.SecretTree(Default);
    var st = ST.init(
        std.heap.page_allocator,
        &enc_secret,
        16,
    ) catch return;
    defer st.deinit(std.heap.page_allocator);
    var kn = st.consumeKey(0, 1) catch return;
    kn.zeroize();
    std.mem.doNotOptimizeAway(&kn);
}

// -- Group operations (39.5) -----------------------------------------

fn benchCreateGroup() void {
    const seed_s = [_]u8{0x01} ** 32;
    const seed_e = [_]u8{0x02} ** 32;
    const kp = Default.signKeypairFromSeed(
        &seed_s,
    ) catch return;
    const enc = Default.dhKeypairFromSeed(
        &seed_e,
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const leaf = mls.LeafNode{
        .encryption_key = &enc.pk,
        .signature_key = &kp.pk,
        .credential = mls.Credential.initBasic("bench"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        std.heap.page_allocator,
        "bench-group",
        leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;
    gs.deinit();
}

fn makeFc1KB() mls.FramedContent {
    return .{
        .group_id = "bench-group",
        .epoch = 1,
        .sender = mls.framing.Sender.member(
            mls.LeafIndex.fromU32(0),
        ),
        .authenticated_data = &.{},
        .content_type = .application,
        .content = &([_]u8{0x42} ** 1024),
    };
}

fn benchComputeMembershipTag() void {
    const key = [_]u8{0x01} ** Default.nh;
    const fc = makeFc1KB();
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const gc = [_]u8{0x42} ** 128;
    const tag = mls.computeMembershipTag(
        Default,
        &key,
        &fc,
        &auth,
        &gc,
    ) catch return;
    std.mem.doNotOptimizeAway(&tag);
}

fn benchVerifyMembershipTag() void {
    const key = [_]u8{0x01} ** Default.nh;
    const fc = makeFc1KB();
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const gc = [_]u8{0x42} ** 128;
    const tag = mls.computeMembershipTag(
        Default,
        &key,
        &fc,
        &auth,
        &gc,
    ) catch return;
    mls.public_msg.verifyMembershipTag(
        Default,
        &key,
        &fc,
        &auth,
        &tag,
        &gc,
    ) catch return;
}

// -- Tree operations (39.4) -------------------------------------------

const alloc = std.heap.page_allocator;

fn makeLeaf(i: u8) mls.LeafNode {
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const seed_s = [_]u8{i +| 1} ** 32;
    const seed_e = [_]u8{i +| 2} ** 32;
    const kp = Default.signKeypairFromSeed(
        &seed_s,
    ) catch unreachable;
    const enc = Default.dhKeypairFromSeed(
        &seed_e,
    ) catch unreachable;
    return .{
        .encryption_key = &enc.pk,
        .signature_key = &kp.pk,
        .credential = mls.Credential.initBasic("bench"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
}

fn buildTree(n: u32) ?mls.RatchetTree {
    var tree = mls.RatchetTree.init(
        alloc,
        1,
    ) catch return null;
    tree.setLeaf(
        mls.LeafIndex.fromU32(0),
        makeLeaf(0),
    ) catch {
        tree.deinit();
        return null;
    };
    var i: u32 = 1;
    while (i < n) : (i += 1) {
        _ = mls.tree_path.addLeaf(
            &tree,
            makeLeaf(@truncate(i)),
        ) catch {
            tree.deinit();
            return null;
        };
    }
    return tree;
}

fn benchAddLeaf16() void {
    var tree = buildTree(15) orelse return;
    defer tree.deinit();
    _ = mls.tree_path.addLeaf(
        &tree,
        makeLeaf(15),
    ) catch return;
}

fn benchAddLeaf256() void {
    var tree = buildTree(255) orelse return;
    defer tree.deinit();
    _ = mls.tree_path.addLeaf(
        &tree,
        makeLeaf(255),
    ) catch return;
}

fn benchRemoveLeaf16() void {
    var tree = buildTree(16) orelse return;
    defer tree.deinit();
    mls.tree_path.removeLeaf(
        &tree,
        mls.LeafIndex.fromU32(8),
    ) catch return;
}

fn benchRemoveLeaf256() void {
    var tree = buildTree(256) orelse return;
    defer tree.deinit();
    mls.tree_path.removeLeaf(
        &tree,
        mls.LeafIndex.fromU32(128),
    ) catch return;
}

fn benchTreeHash16() void {
    var tree = buildTree(16) orelse return;
    defer tree.deinit();
    const h = mls.tree_hashes.treeHash(
        Default,
        alloc,
        &tree,
        mls.tree_math.root(16),
    ) catch return;
    std.mem.doNotOptimizeAway(&h);
}

fn benchTreeHash256() void {
    var tree = buildTree(256) orelse return;
    defer tree.deinit();
    const h = mls.tree_hashes.treeHash(
        Default,
        alloc,
        &tree,
        mls.tree_math.root(256),
    ) catch return;
    std.mem.doNotOptimizeAway(&h);
}

fn benchVerifyParentHashes16() void {
    var tree = buildTree(16) orelse return;
    defer tree.deinit();
    _ = mls.tree_hashes.verifyParentHashes(
        Default,
        alloc,
        &tree,
    ) catch return;
}

fn makeGroupState() ?mls.GroupState(Default) {
    const seed_s = [_]u8{0x01} ** 32;
    const seed_e = [_]u8{0x02} ** 32;
    const kp = Default.signKeypairFromSeed(
        &seed_s,
    ) catch return null;
    const enc = Default.dhKeypairFromSeed(
        &seed_e,
    ) catch return null;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const leaf = mls.LeafNode{
        .encryption_key = &enc.pk,
        .signature_key = &kp.pk,
        .credential = mls.Credential.initBasic("bench"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    return mls.createGroup(
        Default,
        alloc,
        "bench-group",
        leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return null;
}

fn benchCreateCommitEmpty() void {
    var gs = makeGroupState() orelse return;
    defer gs.deinit();

    const seed_s = [_]u8{0x01} ** 32;
    const sk = Default.signKeypairFromSeed(
        &seed_s,
    ) catch return;

    const seed_e2 = [_]u8{0x03} ** 32;
    const enc2 = Default.dhKeypairFromSeed(
        &seed_e2,
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const new_leaf = mls.LeafNode{
        .encryption_key = &enc2.pk,
        .signature_key = &sk.pk,
        .credential = mls.Credential.initBasic("bench"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };

    const leaf_secret = [_]u8{0x04} ** Default.nh;
    const eph_seeds = [_][32]u8{
        [_]u8{0x05} ** 32,
    };
    var cr = gs.createCommit(alloc, .{
        .proposals = &.{},
        .sign_key = &sk.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = new_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
        },
    }) catch return;
    cr.deinit(alloc);
}

// -- Message protection (39.6) ----------------------------------------

const AuthData = mls.framing_auth.FramedContentAuthData(Default);

fn benchEncrypt1KB() void {
    const pt = [_]u8{0x42} ** 1024;
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    const aad = [_]u8{0x03} ** 32;
    var out: [2048]u8 = undefined;
    const n = mls.encryptContent(
        Default,
        &pt,
        .application,
        &auth,
        0,
        &key,
        &nonce,
        &aad,
        &out,
    ) catch return;
    std.mem.doNotOptimizeAway(&out);
    std.mem.doNotOptimizeAway(&n);
}

fn benchDecrypt1KB() void {
    const pt = [_]u8{0x42} ** 1024;
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    const aad = [_]u8{0x03} ** 32;
    var ct: [2048]u8 = undefined;
    const n = mls.encryptContent(
        Default,
        &pt,
        .application,
        &auth,
        0,
        &key,
        &nonce,
        &aad,
        &ct,
    ) catch return;
    var pt2: [2048]u8 = undefined;
    const dr = mls.decryptContent(
        Default,
        ct[0..n],
        .application,
        &key,
        &nonce,
        &aad,
        &pt2,
    ) catch return;
    std.mem.doNotOptimizeAway(&dr);
}

fn benchEncrypt64B() void {
    const pt = [_]u8{0x42} ** 64;
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    const aad = [_]u8{0x03} ** 32;
    var out: [512]u8 = undefined;
    const n = mls.encryptContent(
        Default,
        &pt,
        .application,
        &auth,
        0,
        &key,
        &nonce,
        &aad,
        &out,
    ) catch return;
    std.mem.doNotOptimizeAway(&out);
    std.mem.doNotOptimizeAway(&n);
}

fn benchDecrypt64B() void {
    const pt = [_]u8{0x42} ** 64;
    const auth = AuthData{
        .signature = [_]u8{0xAA} ** Default.sig_len,
        .confirmation_tag = null,
    };
    const key = [_]u8{0x01} ** Default.nk;
    const nonce = [_]u8{0x02} ** Default.nn;
    const aad = [_]u8{0x03} ** 32;
    var ct: [512]u8 = undefined;
    const n = mls.encryptContent(
        Default,
        &pt,
        .application,
        &auth,
        0,
        &key,
        &nonce,
        &aad,
        &ct,
    ) catch return;
    var pt2: [512]u8 = undefined;
    const dr = mls.decryptContent(
        Default,
        ct[0..n],
        .application,
        &key,
        &nonce,
        &aad,
        &pt2,
    ) catch return;
    std.mem.doNotOptimizeAway(&dr);
}

// -- Serialization (39.7) ---------------------------------------------

const Ser = mls.serializer.Serializer(Default);

fn benchSerialize() void {
    var gs = makeGroupState() orelse return;
    defer gs.deinit();
    const data = Ser.serialize(alloc, &gs) catch return;
    defer alloc.free(data);
    std.mem.doNotOptimizeAway(data.ptr);
}

fn benchDeserialize() void {
    var gs = makeGroupState() orelse return;
    const data = Ser.serialize(alloc, &gs) catch {
        gs.deinit();
        return;
    };
    gs.deinit();
    defer alloc.free(data);
    var gs2 = Ser.deserialize(alloc, data) catch return;
    defer gs2.deinit();
    std.mem.doNotOptimizeAway(&gs2);
}

fn benchMLSMessageEncode() void {
    // Encode a minimal MLSMessage (key_package body).
    const msg = mls.mls_message.MLSMessage{
        .version = .mls10,
        .wire_format = .mls_key_package,
        .body = .{ .key_package = &[_]u8{0x42} ** 256 },
    };
    var buf: [4096]u8 = undefined;
    const n = msg.encode(&buf, 0) catch return;
    std.mem.doNotOptimizeAway(&buf);
    std.mem.doNotOptimizeAway(&n);
}

fn benchMLSMessageDecode() void {
    const msg = mls.mls_message.MLSMessage{
        .version = .mls10,
        .wire_format = .mls_key_package,
        .body = .{ .key_package = &[_]u8{0x42} ** 256 },
    };
    var buf: [4096]u8 = undefined;
    const n = msg.encode(&buf, 0) catch return;
    const r = mls.mls_message.MLSMessage.decode(&buf, 0) catch return;
    std.mem.doNotOptimizeAway(&r);
    std.mem.doNotOptimizeAway(&n);
}

fn makeTestKP(
    enc_tag: u8,
    init_tag: u8,
    sign_tag: u8,
) ?TestKP {
    var tkp: TestKP = undefined;
    tkp.init(enc_tag, init_tag, sign_tag) catch return null;
    return tkp;
}

const Proposal = mls.Proposal;

const TestKP = struct {
    kp: mls.key_package.KeyPackage,
    sig_buf: [Default.sig_len]u8,
    leaf_sig_buf: [Default.sig_len]u8,
    enc_sk: [Default.nsk]u8,
    enc_pk: [Default.npk]u8,
    init_sk: [Default.nsk]u8,
    init_pk: [Default.npk]u8,
    sign_sk: [Default.sign_sk_len]u8,
    sign_pk: [Default.sign_pk_len]u8,

    fn init(
        self: *TestKP,
        enc_tag: u8,
        init_tag: u8,
        sign_tag: u8,
    ) !void {
        const s = [_]u8{enc_tag} ** 32;
        const ekp = try Default.dhKeypairFromSeed(&s);
        const s2 = [_]u8{init_tag} ** 32;
        const ikp = try Default.dhKeypairFromSeed(&s2);
        const s3 = [_]u8{sign_tag} ** 32;
        const skp = try Default.signKeypairFromSeed(&s3);
        self.enc_sk = ekp.sk;
        self.enc_pk = ekp.pk;
        self.init_sk = ikp.sk;
        self.init_pk = ikp.pk;
        self.sign_sk = skp.sk;
        self.sign_pk = skp.pk;
        const versions = [_]mls.ProtocolVersion{.mls10};
        const cs = [_]mls.CipherSuite{
            .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        };
        self.kp = .{
            .version = .mls10,
            .cipher_suite = .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
            .init_key = &self.init_pk,
            .leaf_node = .{
                .encryption_key = &self.enc_pk,
                .signature_key = &self.sign_pk,
                .credential = mls.Credential.initBasic(
                    &self.sign_pk,
                ),
                .capabilities = .{
                    .versions = &versions,
                    .cipher_suites = &cs,
                    .extensions = &.{},
                    .proposals = &.{},
                    .credentials = &.{.basic},
                },
                .source = .key_package,
                .lifetime = .{
                    .not_before = 0,
                    .not_after = 0xFFFFFFFFFFFFFFFF,
                },
                .parent_hash = null,
                .extensions = &.{},
                .signature = &self.leaf_sig_buf,
            },
            .extensions = &.{},
            .signature = &self.sig_buf,
        };
        try self.kp.leaf_node.signLeafNode(
            Default,
            &self.sign_sk,
            &self.leaf_sig_buf,
            null,
            null,
        );
        try self.kp.signKeyPackage(
            Default,
            &self.sign_sk,
            &self.sig_buf,
        );
    }
};

fn benchCreateCommitAdd() void {
    const a_sign_seed = [_]u8{0xA1} ** 32;
    const a_enc_seed = [_]u8{0xA2} ** 32;
    const a_sign = Default.signKeypairFromSeed(
        &a_sign_seed,
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &a_enc_seed,
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-add",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;
    defer gs.deinit();

    const bob_kp = makeTestKP(0xB1, 0xB2, 0xB3) orelse return;
    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{ .add = .{
            .key_package = bob_kp.kp,
        } },
    }};

    const a_enc2 = Default.dhKeypairFromSeed(
        &([_]u8{0xA3} ** 32),
    ) catch return;
    const new_leaf = mls.LeafNode{
        .encryption_key = &a_enc2.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };

    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }

    var cr = gs.createCommit(alloc, .{
        .proposals = &proposals,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = new_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
        },
    }) catch return;
    cr.deinit(alloc);
}

fn benchCreateCommitRemove() void {
    // Create a 2-member group, then commit Remove(Bob).
    const a_sign_seed = [_]u8{0xA1} ** 32;
    const a_enc_seed = [_]u8{0xA2} ** 32;
    const a_sign = Default.signKeypairFromSeed(
        &a_sign_seed,
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &a_enc_seed,
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-rm",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;

    // Add Bob first
    const bob_kp = makeTestKP(
        0xB1,
        0xB2,
        0xB3,
    ) orelse {
        gs.deinit();
        return;
    };
    const add_props = [_]Proposal{.{
        .tag = .add,
        .payload = .{ .add = .{
            .key_package = bob_kp.kp,
        } },
    }};
    const a_enc2 = Default.dhKeypairFromSeed(
        &([_]u8{0xA3} ** 32),
    ) catch {
        gs.deinit();
        return;
    };
    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }
    const add_leaf = mls.LeafNode{
        .encryption_key = &a_enc2.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const add_cr = gs.createCommit(alloc, .{
        .proposals = &add_props,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = add_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
        },
    }) catch {
        gs.deinit();
        return;
    };
    // Apply: replace gs with new epoch state.
    gs.group_context.deinit(alloc);
    gs.tree = add_cr.tree;
    gs.group_context = add_cr.group_context;
    gs.epoch_secrets = add_cr.epoch_secrets;
    gs.interim_transcript_hash =
        add_cr.interim_transcript_hash;
    gs.confirmed_transcript_hash =
        add_cr.confirmed_transcript_hash;

    defer gs.deinit();

    // Now measure: commit with Remove(leaf 1).
    const rm_props = [_]Proposal{.{
        .tag = .remove,
        .payload = .{ .remove = .{
            .removed = 1,
        } },
    }};
    const a_enc3 = Default.dhKeypairFromSeed(
        &([_]u8{0xA4} ** 32),
    ) catch return;
    const rm_leaf = mls.LeafNode{
        .encryption_key = &a_enc3.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const ls2 = [_]u8{0xC2} ** Default.nh;
    var cr = gs.createCommit(alloc, .{
        .proposals = &rm_props,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = rm_leaf,
            .leaf_secret = &ls2,
            .eph_seeds = &eph_seeds,
        },
    }) catch return;
    cr.deinit(alloc);
}

// -- Deferred benchmarks (39.4/39.5) ---------------------------------
// These include group setup in the measurement (noted in PLAN.md).

const max_gc_encode: u32 = 65536;
const FramedContent = mls.FramedContent;
const Sender = mls.Sender;

fn benchProcessCommit() void {
    // Setup: Alice creates a 2-member group, commits Add(Bob).
    const a_sign = Default.signKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-proc",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;

    const bob_kp = makeTestKP(0xB1, 0xB2, 0xB3) orelse {
        gs.deinit();
        return;
    };
    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const a_enc2 = Default.dhKeypairFromSeed(
        &([_]u8{0xA3} ** 32),
    ) catch {
        gs.deinit();
        return;
    };
    const new_leaf = mls.LeafNode{
        .encryption_key = &a_enc2.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }

    var cr = gs.createCommit(alloc, .{
        .proposals = &proposals,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = new_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
        },
    }) catch {
        gs.deinit();
        return;
    };
    defer cr.deinit(alloc);

    // Measure: Bob processes the commit.
    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.member(gs.my_leaf_index),
        .authenticated_data = "",
        .content_type = .commit,
        .content = cr.commit_bytes[0..cr.commit_len],
    };

    var pr = mls.processCommit(
        Default,
        alloc,
        .{
            .fc = &fc,
            .signature = &cr.signature,
            .confirmation_tag = &cr.confirmation_tag,
            .proposals = &proposals,
            .sender_verify_key = &a_sign.pk,
            .wire_format = .mls_public_message,
        },
        &gs.group_context,
        &gs.tree,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.init_secret,
    ) catch {
        gs.deinit();
        return;
    };
    pr.tree.deinit();
    pr.deinit(alloc);
    gs.deinit();
}

fn benchProcessWelcome() void {
    // Setup: Alice creates group, adds Bob, builds Welcome.
    const a_sign = Default.signKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-welc",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;

    var bob_kp = makeTestKP(0xB1, 0xB2, 0xB3) orelse {
        gs.deinit();
        return;
    };
    const proposals = [_]Proposal{.{
        .tag = .add,
        .payload = .{
            .add = .{ .key_package = bob_kp.kp },
        },
    }};

    const a_enc2 = Default.dhKeypairFromSeed(
        &([_]u8{0xA3} ** 32),
    ) catch {
        gs.deinit();
        return;
    };
    const new_leaf = mls.LeafNode{
        .encryption_key = &a_enc2.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }

    var cr = gs.createCommit(alloc, .{
        .proposals = &proposals,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = new_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
        },
    }) catch {
        gs.deinit();
        return;
    };

    // Build Welcome.
    var gc_buf: [max_gc_encode]u8 = undefined;
    const gc_bytes = cr.group_context.serialize(
        &gc_buf,
    ) catch {
        cr.deinit(alloc);
        gs.deinit();
        return;
    };

    const primitives = mls.crypto_primitives;
    var full_kp_buf: [4096]u8 = undefined;
    const kp_end = bob_kp.kp.encode(
        &full_kp_buf,
        0,
    ) catch {
        cr.deinit(alloc);
        gs.deinit();
        return;
    };
    const kp_ref = primitives.refHash(
        Default,
        "MLS 1.0 KeyPackage Reference",
        full_kp_buf[0..kp_end],
    );

    var eph_seed: [32]u8 = [_]u8{0xE1} ** 32;
    const nm = [_]mls.group_welcome.NewMemberEntry(Default){.{
        .kp_ref = &kp_ref,
        .init_pk = bob_kp.kp.init_key,
        .eph_seed = &eph_seed,
    }};

    var wr = mls.buildWelcome(
        Default,
        alloc,
        gc_bytes,
        &cr.confirmation_tag,
        &cr.epoch_secrets.welcome_secret,
        &cr.epoch_secrets.joiner_secret,
        &a_sign.sk,
        gs.my_leaf_index.toU32(),
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &nm,
        &.{},
    ) catch {
        cr.deinit(alloc);
        gs.deinit();
        return;
    };

    // Measure: Bob processes Welcome.
    var bob_gs = mls.processWelcome(
        Default,
        alloc,
        &wr.welcome,
        &kp_ref,
        &bob_kp.init_sk,
        &bob_kp.init_pk,
        &a_sign.pk,
        .{ .prebuilt = cr.tree },
        mls.LeafIndex.fromU32(1),
        null,
    ) catch {
        wr.deinit(alloc);
        cr.deinit(alloc);
        gs.deinit();
        return;
    };
    bob_gs.deinit();
    wr.deinit(alloc);
    cr.deinit(alloc);
    gs.deinit();
}

fn benchCreateExternalCommit() void {
    // Setup: Alice creates group.
    const a_sign = Default.signKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-ext",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;
    defer gs.deinit();

    // Bob generates keys.
    const b_sign = Default.signKeypairFromSeed(
        &([_]u8{0xB1} ** 32),
    ) catch return;
    const b_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xB2} ** 32),
    ) catch return;
    const b_leaf = mls.LeafNode{
        .encryption_key = &b_enc.pk,
        .signature_key = &b_sign.pk,
        .credential = mls.Credential.initBasic("bob"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }

    // Measure: Bob creates external commit.
    var ext_cr = mls.createExternalCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        &.{},
        &gs.interim_transcript_hash,
        .{
            .allocator = alloc,
            .sign_key = &b_sign.sk,
            .joiner_leaf = b_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
            .ext_init_seed = &([_]u8{0xE1} ** 32),
            .remove_proposals = &.{},
        },
        .mls_public_message,
    ) catch return;
    ext_cr.deinit(alloc);
}

fn benchProcessExternalCommit() void {
    // Setup: Alice creates group, Bob creates external commit.
    const a_sign = Default.signKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-pex",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;
    defer gs.deinit();

    const b_sign = Default.signKeypairFromSeed(
        &([_]u8{0xB1} ** 32),
    ) catch return;
    const b_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xB2} ** 32),
    ) catch return;
    const b_leaf = mls.LeafNode{
        .encryption_key = &b_enc.pk,
        .signature_key = &b_sign.pk,
        .credential = mls.Credential.initBasic("bob"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const leaf_secret = [_]u8{0xC1} ** Default.nh;
    var eph_seeds: [16][32]u8 = undefined;
    for (&eph_seeds, 0..) |*es, i| {
        es.* = [_]u8{@truncate(0xD0 +| i)} ** 32;
    }

    var ext_cr = mls.createExternalCommit(
        Default,
        alloc,
        &gs.group_context,
        &gs.tree,
        &.{},
        &gs.interim_transcript_hash,
        .{
            .allocator = alloc,
            .sign_key = &b_sign.sk,
            .joiner_leaf = b_leaf,
            .leaf_secret = &leaf_secret,
            .eph_seeds = &eph_seeds,
            .ext_init_seed = &([_]u8{0xE1} ** 32),
            .remove_proposals = &.{},
        },
        .mls_public_message,
    ) catch return;
    defer ext_cr.deinit(alloc);

    // Decode the commit to get proposals and path.
    const commit_data =
        ext_cr.commit_bytes[0..ext_cr.commit_len];
    var dec = mls.Commit.decode(
        alloc,
        commit_data,
        0,
    ) catch return;
    defer dec.value.deinit(alloc);

    var prop_buf: [257]Proposal = undefined;
    const ext_proposals =
        mls.resolveExternalInlineProposals(
            dec.value.proposals,
            &prop_buf,
        ) catch return;

    // Alice processes external commit.
    const fc = FramedContent{
        .group_id = gs.group_context.group_id,
        .epoch = gs.group_context.epoch,
        .sender = Sender.newMemberCommit(),
        .authenticated_data = "",
        .content_type = .commit,
        .content = commit_data,
    };

    var pr = mls.processExternalCommit(
        Default,
        alloc,
        &fc,
        &ext_cr.signature,
        &ext_cr.confirmation_tag,
        ext_proposals,
        &dec.value.path.?,
        &gs.group_context,
        &gs.tree,
        &b_sign.pk,
        &gs.interim_transcript_hash,
        &gs.epoch_secrets.external_secret,
        null,
        gs.my_leaf_index,
        &a_enc.sk,
        &a_enc.pk,
        .mls_public_message,
    ) catch return;
    pr.tree.deinit();
    pr.deinit(alloc);
}

fn benchGenerateUpdatePath() void {
    // Setup: 16-leaf tree.
    const a_sign = Default.signKeypairFromSeed(
        &([_]u8{0xA1} ** 32),
    ) catch return;
    const a_enc = Default.dhKeypairFromSeed(
        &([_]u8{0xA2} ** 32),
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
    };
    const a_leaf = mls.LeafNode{
        .encryption_key = &a_enc.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .key_package,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    var gs = mls.createGroup(
        Default,
        alloc,
        "bench-gup",
        a_leaf,
        .mls_128_dhkemx25519_aes128gcm_sha256_ed25519,
        &.{},
    ) catch return;

    // Add 15 more members to make 16-leaf tree.
    var i: u8 = 1;
    while (i < 16) : (i += 1) {
        const bob_kp = makeTestKP(
            0x10 + i,
            0x30 + i,
            0x50 + i,
        ) orelse {
            gs.deinit();
            return;
        };
        const p = [_]Proposal{.{
            .tag = .add,
            .payload = .{
                .add = .{ .key_package = bob_kp.kp },
            },
        }};
        const enc_i = Default.dhKeypairFromSeed(
            &([_]u8{0x70 + i} ** 32),
        ) catch {
            gs.deinit();
            return;
        };
        const nl = mls.LeafNode{
            .encryption_key = &enc_i.pk,
            .signature_key = &a_sign.pk,
            .credential = mls.Credential.initBasic(
                "alice",
            ),
            .capabilities = .{
                .versions = &versions,
                .cipher_suites = &suites,
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{.basic},
            },
            .source = .commit,
            .lifetime = .{
                .not_before = 0,
                .not_after = 0xFFFFFFFFFFFFFFFF,
            },
            .parent_hash = null,
            .extensions = &.{},
            .signature = &[_]u8{0xAA} ** 64,
        };
        const ls = [_]u8{0x90 + i} ** Default.nh;
        var ephs: [16][32]u8 = undefined;
        for (&ephs, 0..) |*es, j| {
            es.* = [_]u8{
                @truncate(0xA0 +| i +| j),
            } ** 32;
        }
        const cr_i = gs.createCommit(alloc, .{
            .proposals = &p,
            .sign_key = &a_sign.sk,
            .path_params = .{
                .allocator = alloc,
                .new_leaf = nl,
                .leaf_secret = &ls,
                .eph_seeds = &ephs,
            },
        }) catch {
            gs.deinit();
            return;
        };
        gs.group_context.deinit(alloc);
        gs.tree = cr_i.tree;
        gs.group_context = cr_i.group_context;
        gs.epoch_secrets = cr_i.epoch_secrets;
        gs.interim_transcript_hash =
            cr_i.interim_transcript_hash;
        gs.confirmed_transcript_hash =
            cr_i.confirmed_transcript_hash;
    }
    defer gs.deinit();

    // Now measure: one more commit (empty, path-only) on
    // the 16-member tree. This exercises generateUpdatePath.
    const enc_fin = Default.dhKeypairFromSeed(
        &([_]u8{0xF1} ** 32),
    ) catch return;
    const fin_leaf = mls.LeafNode{
        .encryption_key = &enc_fin.pk,
        .signature_key = &a_sign.pk,
        .credential = mls.Credential.initBasic("alice"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
        },
        .source = .commit,
        .lifetime = .{
            .not_before = 0,
            .not_after = 0xFFFFFFFFFFFFFFFF,
        },
        .parent_hash = null,
        .extensions = &.{},
        .signature = &[_]u8{0xAA} ** 64,
    };
    const fin_ls = [_]u8{0xF2} ** Default.nh;
    var fin_eph: [16][32]u8 = undefined;
    for (&fin_eph, 0..) |*es, j| {
        es.* = [_]u8{@truncate(0xF3 +| j)} ** 32;
    }
    const empty = [_]Proposal{};
    var cr = gs.createCommit(alloc, .{
        .proposals = &empty,
        .sign_key = &a_sign.sk,
        .path_params = .{
            .allocator = alloc,
            .new_leaf = fin_leaf,
            .leaf_secret = &fin_ls,
            .eph_seeds = &fin_eph,
        },
    }) catch return;
    cr.deinit(alloc);
}

// -- Multi-suite comparison (39.8) ------------------------------------

const ChaCha = mls.ChaCha20CryptoProvider;
const P256 = mls.P256CryptoProvider;
const P384 = mls.P384CryptoProvider;

fn suiteCreateGroup(comptime P: type, cs: mls.CipherSuite) void {
    const seed_s = [_]u8{0x01} ** P.seed_len;
    const seed_e = [_]u8{0x02} ** P.seed_len;
    const kp = P.signKeypairFromSeed(
        &seed_s,
    ) catch return;
    const enc = P.dhKeypairFromSeed(
        &seed_e,
    ) catch return;
    const versions = [_]mls.ProtocolVersion{.mls10};
    const suites = [_]mls.CipherSuite{cs};
    const leaf = mls.LeafNode{
        .encryption_key = &enc.pk,
        .signature_key = &kp.pk,
        .credential = mls.Credential.initBasic("bench"),
        .capabilities = .{
            .versions = &versions,
            .cipher_suites = &suites,
            .extensions = &.{},
            .proposals = &.{},
            .credentials = &.{.basic},
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
    var gs = mls.createGroup(
        P,
        alloc,
        "bench",
        leaf,
        cs,
        &.{},
    ) catch return;
    gs.deinit();
}

fn suiteDh(comptime P: type) void {
    const sa = [_]u8{0x01} ** P.seed_len;
    const sb = [_]u8{0x02} ** P.seed_len;
    const a = P.dhKeypairFromSeed(&sa) catch return;
    const b = P.dhKeypairFromSeed(&sb) catch return;
    const ss = P.dh(&a.sk, &b.pk) catch return;
    std.mem.doNotOptimizeAway(&ss);
}

fn suiteSign(comptime P: type) void {
    const seed = [_]u8{0x42} ** P.seed_len;
    const kp = P.signKeypairFromSeed(&seed) catch return;
    const msg = [_]u8{0xAB} ** 256;
    const sig = P.sign(&kp.sk, &msg) catch return;
    std.mem.doNotOptimizeAway(&sig);
}

fn benchDhChaCha() void {
    suiteDh(ChaCha);
}
fn benchDhP256() void {
    suiteDh(P256);
}
fn benchDhP384() void {
    suiteDh(P384);
}

fn benchSignChaCha() void {
    suiteSign(ChaCha);
}
fn benchSignP256() void {
    suiteSign(P256);
}
fn benchSignP384() void {
    suiteSign(P384);
}

fn benchCreateGroupChaCha() void {
    const cs = .mls_128_dhkemx25519_chacha20poly1305_sha256_ed25519;
    suiteCreateGroup(ChaCha, cs);
}

fn benchCreateGroupP256() void {
    const cs = .mls_128_dhkemp256_aes128gcm_sha256_p256;
    suiteCreateGroup(P256, cs);
}

fn benchCreateGroupP384() void {
    const cs = .mls_256_dhkemp384_aes256gcm_sha384_p384;
    suiteCreateGroup(P384, cs);
}

// -- Main ------------------------------------------------------------

pub fn main() !void {
    const iters = default_iters;
    std.debug.print(
        "\nzmls benchmarks ({d} iterations)\n" ++
            "{s:=<80}\n",
        .{ iters, "" },
    );

    std.debug.print(
        "\n--- Crypto Primitives (suite 0x0001) ---\n",
        .{},
    );
    printResult(runBench("sha256 1KB", iters, benchHash));
    printResult(runBench(
        "kdf extract+expand",
        iters,
        benchKdf,
    ));
    printResult(runBench(
        "aead seal 1KB",
        iters,
        benchAeadSeal,
    ));
    printResult(runBench(
        "aead open 1KB",
        iters,
        benchAeadOpen,
    ));
    printResult(runBench(
        "sign ed25519 256B",
        iters,
        benchSign,
    ));
    printResult(runBench(
        "verify ed25519 256B",
        iters,
        benchVerify,
    ));
    printResult(runBench("dh x25519", iters, benchDh));

    printResult(runBench(
        "hpke encrypt 256B",
        iters,
        benchHpkeEncrypt,
    ));
    printResult(runBench(
        "hpke decrypt 256B",
        iters,
        benchHpkeDecrypt,
    ));

    std.debug.print("\n--- Key Schedule ---\n", .{});
    printResult(runBench(
        "deriveEpochSecrets",
        iters,
        benchDeriveEpochSecrets,
    ));

    printResult(runBench(
        "derivePskSecret (1 PSK)",
        iters,
        benchDerivePskSecret1,
    ));
    printResult(runBench(
        "derivePskSecret (4 PSKs)",
        iters,
        benchDerivePskSecret4,
    ));
    printResult(runBench(
        "derivePskSecret (16 PSKs)",
        iters,
        benchDerivePskSecret16,
    ));
    printResult(runBench(
        "SecretTree.init 16 leaves",
        iters,
        benchSecretTreeInit16,
    ));
    printResult(runBench(
        "SecretTree.init 256 leaves",
        iters,
        benchSecretTreeInit256,
    ));
    printResult(runBench(
        "SecretTree.init 1024 leaves",
        iters,
        benchSecretTreeInit1024,
    ));
    printResult(runBench(
        "SecretTree.consumeKey",
        iters,
        benchSecretTreeConsumeKey,
    ));

    std.debug.print("\n--- Group Operations ---\n", .{});
    printResult(runBench(
        "createGroup",
        iters,
        benchCreateGroup,
    ));

    printResult(runBench(
        "createCommit (empty)",
        iters,
        benchCreateCommitEmpty,
    ));

    std.debug.print(
        "\n--- Message Protection ---\n",
        .{},
    );
    printResult(runBench(
        "encryptContent 64B",
        iters,
        benchEncrypt64B,
    ));
    printResult(runBench(
        "decryptContent 64B",
        iters,
        benchDecrypt64B,
    ));
    printResult(runBench(
        "encryptContent 1KB",
        iters,
        benchEncrypt1KB,
    ));
    printResult(runBench(
        "decryptContent 1KB",
        iters,
        benchDecrypt1KB,
    ));

    printResult(runBench(
        "computeMembershipTag 1KB",
        iters,
        benchComputeMembershipTag,
    ));
    printResult(runBench(
        "verifyMembershipTag 1KB",
        iters,
        benchVerifyMembershipTag,
    ));

    printResult(runBench(
        "createCommit (add)",
        iters,
        benchCreateCommitAdd,
    ));

    printResult(runBench(
        "createCommit (remove)",
        iters,
        benchCreateCommitRemove,
    ));

    std.debug.print(
        "\n--- Group Operations (incl setup) ---\n",
        .{},
    );
    printResult(runBench(
        "processCommit (add, 2-member)",
        iters,
        benchProcessCommit,
    ));
    printResult(runBench(
        "processWelcome (2-member)",
        iters,
        benchProcessWelcome,
    ));
    printResult(runBench(
        "createExternalCommit",
        iters,
        benchCreateExternalCommit,
    ));
    printResult(runBench(
        "processExternalCommit",
        iters,
        benchProcessExternalCommit,
    ));
    printResult(runBench(
        "generateUpdatePath (16-member)",
        iters,
        benchGenerateUpdatePath,
    ));

    std.debug.print("\n--- Tree Operations ---\n", .{});
    printResult(runBench(
        "addLeaf (15->16)",
        iters,
        benchAddLeaf16,
    ));
    printResult(runBench(
        "addLeaf (255->256)",
        iters,
        benchAddLeaf256,
    ));
    printResult(runBench(
        "removeLeaf (16)",
        iters,
        benchRemoveLeaf16,
    ));
    printResult(runBench(
        "removeLeaf (256)",
        iters,
        benchRemoveLeaf256,
    ));
    printResult(runBench(
        "treeHash (16)",
        iters,
        benchTreeHash16,
    ));
    printResult(runBench(
        "treeHash (256)",
        iters,
        benchTreeHash256,
    ));
    printResult(runBench(
        "verifyParentHashes (16)",
        iters,
        benchVerifyParentHashes16,
    ));

    std.debug.print(
        "\n--- Serialization ---\n",
        .{},
    );
    printResult(runBench(
        "GroupState serialize",
        iters,
        benchSerialize,
    ));
    printResult(runBench(
        "GroupState deserialize",
        iters,
        benchDeserialize,
    ));
    printResult(runBench(
        "MLSMessage encode",
        iters,
        benchMLSMessageEncode,
    ));
    printResult(runBench(
        "MLSMessage decode",
        iters,
        benchMLSMessageDecode,
    ));

    std.debug.print(
        "\n--- Multi-Suite Comparison ---\n",
        .{},
    );
    std.debug.print(
        "  DH key agreement:\n",
        .{},
    );
    printResult(runBench(
        "  0x0001 X25519",
        iters,
        benchDh,
    ));
    printResult(runBench(
        "  0x0003 X25519 (ChaCha)",
        iters,
        benchDhChaCha,
    ));
    printResult(runBench(
        "  0x0002 P-256",
        iters,
        benchDhP256,
    ));
    printResult(runBench(
        "  0x0006 P-384",
        iters,
        benchDhP384,
    ));
    std.debug.print(
        "  Signing:\n",
        .{},
    );
    printResult(runBench(
        "  0x0001 Ed25519",
        iters,
        benchSign,
    ));
    printResult(runBench(
        "  0x0003 Ed25519 (ChaCha)",
        iters,
        benchSignChaCha,
    ));
    printResult(runBench(
        "  0x0002 P-256/ECDSA",
        iters,
        benchSignP256,
    ));
    printResult(runBench(
        "  0x0006 P-384/ECDSA",
        iters,
        benchSignP384,
    ));
    std.debug.print(
        "  createGroup:\n",
        .{},
    );
    printResult(runBench(
        "  0x0001 createGroup",
        iters,
        benchCreateGroup,
    ));
    printResult(runBench(
        "  0x0003 createGroup (ChaCha)",
        iters,
        benchCreateGroupChaCha,
    ));
    printResult(runBench(
        "  0x0002 createGroup (P-256)",
        iters,
        benchCreateGroupP256,
    ));
    printResult(runBench(
        "  0x0006 createGroup (P-384)",
        iters,
        benchCreateGroupP384,
    ));

    std.debug.print("\n", .{});
}
