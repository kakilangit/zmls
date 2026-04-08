.PHONY: all fmt check build test test-filter test-cli clean

ZIG := zig
SRC_DIR := src

# Default target.
all: fmt check build test

# Format all Zig source files.
fmt:
	$(ZIG) fmt $(SRC_DIR)
	$(ZIG) fmt examples

# Check formatting without modifying files. Useful in CI.
check:
	$(ZIG) fmt --check $(SRC_DIR)
	$(ZIG) fmt --check examples

# Build the library and CLI in debug mode.
build:
	$(ZIG) build

# Build the library in release-safe mode.
build-safe:
	$(ZIG) build -Doptimize=ReleaseSafe

# Build the library in release-fast mode.
build-fast:
	$(ZIG) build -Doptimize=ReleaseFast

# Run all tests (unit + integration).
test:
	$(ZIG) build test

# Run tests with a name filter. Usage: make test-filter TEST_FILTER="Client"
test-filter:
	$(ZIG) build test -- --test-filter "$(TEST_FILTER)"

# Run tests with verbose output.
test-verbose:
	$(ZIG) build test -- --verbose

# Run CLI end-to-end tests (builds CLI first).
test-cli: build
	examples/cli/test_e2e.sh "$(CURDIR)/zig-out/bin/zmls-cli"

# Remove build artifacts.
clean:
	rm -rf zig-out .zig-cache
