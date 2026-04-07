.PHONY: all fmt check build test clean

ZIG := zig
SRC_DIR := src

# Default target.
all: fmt check build test

# Format all Zig source files.
fmt:
	$(ZIG) fmt $(SRC_DIR)

# Check formatting without modifying files. Useful in CI.
check:
	$(ZIG) fmt --check $(SRC_DIR)

# Build the library in debug mode.
build:
	$(ZIG) build

# Build the library in release-safe mode.
build-safe:
	$(ZIG) build -Doptimize=ReleaseSafe

# Build the library in release-fast mode.
build-fast:
	$(ZIG) build -Doptimize=ReleaseFast

# Run all tests.
test:
	$(ZIG) build test

# Run tests with a name filter. Usage: make test-filter TEST_FILTER="tree_math"
test-filter:
	$(ZIG) build test -- --test-filter "$(TEST_FILTER)"

# Run tests with verbose output.
test-verbose:
	$(ZIG) build test -- --verbose

# Remove build artifacts.
clean:
	rm -rf zig-out .zig-cache
