.PHONY: all fmt check build test test-cli bench bench-filter fetch-vectors clean \
       fmt-client check-client build-client test-client clean-client

ZIG := zig
SRC_DIR := src
CLIENT_DIR := zmls-client
BENCH_FILTER ?=

# Pinned commit for RFC 9420 test vectors.
TV_COMMIT := 16d05d3a5bfe7cf12f5392dd4deb65930e9c31be
TV_BASE := https://raw.githubusercontent.com/mlswg/mls-implementations/$(TV_COMMIT)/test-vectors
TV_DIR := tests/vectors
TV_FILES := \
	crypto-basics.json \
	deserialization.json \
	key-schedule.json \
	message-protection.json \
	messages.json \
	passive-client-handling-commit.json \
	passive-client-random.json \
	passive-client-welcome.json \
	psk_secret.json \
	secret-tree.json \
	transcript-hashes.json \
	tree-math.json \
	tree-operations.json \
	tree-validation.json \
	treekem.json \
	welcome.json

# Default target.
all: fmt check build test

# Format all Zig source files (core + client).
fmt: fmt-client
	$(ZIG) fmt $(SRC_DIR)

# Check formatting without modifying files. Useful in CI.
check: check-client
	$(ZIG) fmt --check $(SRC_DIR)

# Build the library in debug mode.
build: build-client
	$(ZIG) build

# Build the library in release-safe mode.
build-safe:
	$(ZIG) build -Doptimize=ReleaseSafe

# Build the library in release-fast mode.
build-fast:
	$(ZIG) build -Doptimize=ReleaseFast

# Fetch RFC 9420 test vectors from GitHub (skips existing files).
fetch-vectors:
	@mkdir -p $(TV_DIR)
	@for f in $(TV_FILES); do \
		if [ ! -f "$(TV_DIR)/$$f" ]; then \
			echo "fetching $$f"; \
			curl -sfL -o "$(TV_DIR)/$$f" "$(TV_BASE)/$$f" || exit 1; \
		fi; \
	done

# Run all tests (fetches test vectors first if missing).
test: fetch-vectors test-client
	$(ZIG) build test

# Run tests with a name filter. Usage: make test-filter TEST_FILTER="tree_math"
test-filter: fetch-vectors
	$(ZIG) build test -- --test-filter "$(TEST_FILTER)"

# Run tests with verbose output.
test-verbose: fetch-vectors
	$(ZIG) build test -- --verbose

# Run CLI end-to-end tests (via zmls-client).
test-cli:
	@$(MAKE) -C $(CLIENT_DIR) test-cli

# Run all benchmarks (ReleaseFast for meaningful results).
bench:
	$(ZIG) build bench -Doptimize=ReleaseFast

# Run benchmarks with filter. Usage: make bench-filter BENCH_FILTER="hash"
bench-filter:
	$(ZIG) build bench -Doptimize=ReleaseFast -- $(BENCH_FILTER)

# Remove build artifacts.
clean: clean-client
	rm -rf zig-out .zig-cache

# ── zmls-client ─────────────────────────────────────────────

fmt-client:
	@$(MAKE) -C $(CLIENT_DIR) fmt

check-client:
	@$(MAKE) -C $(CLIENT_DIR) check

test-client:
	@$(MAKE) -C $(CLIENT_DIR) test

build-client:
	@$(MAKE) -C $(CLIENT_DIR) build

clean-client:
	@$(MAKE) -C $(CLIENT_DIR) clean
