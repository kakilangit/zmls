const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Upstream zmls protocol core.
    const zmls_dep = b.dependency("zmls", .{
        .target = target,
        .optimize = optimize,
    });
    const zmls_mod = zmls_dep.module("zmls");

    // Library module: the public API for zmls-client.
    const mod = b.addModule("zmls-client", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("zmls", zmls_mod);

    // Library tests: run all test blocks reachable from root.
    const lib_tests = b.addTest(.{
        .root_module = mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // Integration tests: Client + Server lifecycle flows.
    const integ_mod = b.createModule(.{
        .root_source_file = b.path(
            "tests/integration_test.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    integ_mod.addImport("zmls-client", mod);
    integ_mod.addImport("zmls", zmls_mod);
    const integ_tests = b.addTest(.{
        .root_module = integ_mod,
    });
    const run_integ_tests = b.addRunArtifact(integ_tests);

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_integ_tests.step);

    // CLI example executable.
    const cli_mod = b.createModule(.{
        .root_source_file = b.path("examples/cli/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_mod.addImport("zmls-client", mod);
    cli_mod.addImport("zmls", zmls_mod);
    const cli_exe = b.addExecutable(.{
        .name = "zmls-cli",
        .root_module = cli_mod,
    });
    b.installArtifact(cli_exe);
}
