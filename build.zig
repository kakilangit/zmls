const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Library module: the public API for consumers of zmls.
    const mod = b.addModule("zmls", .{
        .root_source_file = b.path("src/zmls.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Library tests: run all test blocks reachable from the root module.
    const lib_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // Integration tests: end-to-end protocol flows.
    const integ_mod = b.createModule(.{
        .root_source_file = b.path(
            "tests/integration_test.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("zmls", mod);
    const integ_tests = b.addTest(.{
        .root_module = integ_mod,
    });
    const run_integ_tests = b.addRunArtifact(integ_tests);

    // Interoperability tests: RFC 9420 test vectors.
    const tv_mod = b.createModule(.{
        .root_source_file = b.path("tests/test_vectors.zig"),
    });
    const interop_mod = b.createModule(.{
        .root_source_file = b.path(
            "tests/interop_test.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    interop_mod.addImport("zmls", mod);
    interop_mod.addImport("test_vectors", tv_mod);
    const interop_tests = b.addTest(.{
        .root_module = interop_mod,
    });
    const run_interop_tests = b.addRunArtifact(interop_tests);

    // Fuzz targets: codec, tree, proposals, messages, crypto, commit.
    const fuzz_names = [_][]const u8{
        "tests/fuzz_codec.zig",
        "tests/fuzz_tree.zig",
        "tests/fuzz_proposals.zig",
        "tests/fuzz_messages.zig",
        "tests/fuzz_crypto.zig",
        "tests/fuzz_commit.zig",
    };

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_integ_tests.step);
    test_step.dependOn(&run_interop_tests.step);

    inline for (fuzz_names) |fuzz_path| {
        const fuzz_mod = b.createModule(.{
            .root_source_file = b.path(fuzz_path),
            .target = target,
            .optimize = optimize,
        });
        fuzz_mod.addImport("zmls", mod);
        const fuzz_tests = b.addTest(.{
            .root_module = fuzz_mod,
        });
        const run_fuzz = b.addRunArtifact(fuzz_tests);
        test_step.dependOn(&run_fuzz.step);
    }

    // Benchmark executable.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("benchmarks/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("zmls", mod);
    const bench_exe = b.addExecutable(.{
        .name = "zmls-bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| {
        run_bench.addArgs(args);
    }
    const bench_step = b.step(
        "bench",
        "Run benchmarks",
    );
    bench_step.dependOn(&run_bench.step);
}
