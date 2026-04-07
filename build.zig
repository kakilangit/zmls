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

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_tests.step);
}
