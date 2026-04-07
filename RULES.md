# zmls — Coding Rules

Adapted from [TigerBeetle's Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md)
and NASA's Power of Ten, tailored for a cryptographic protocol library.

Design goals, in order: **correct, simple, foolproof, fast**.

---

## 0. Foolproof APIs

- Every function, struct, and public interface must be hard to misuse. If the
  caller can forget a step, the design is wrong.
- Never require the caller to juggle pointers, call fixup methods, or satisfy
  invisible prerequisites after construction. If a struct is valid after `init`,
  it must stay valid without manual intervention.
- Prefer value types and owned arrays over slices that alias mutable memory.
  When a struct logically owns data of known size, store it as `[N]u8`, not
  `[]const u8` pointing elsewhere.
- If two pieces of state must be kept in sync, make the struct enforce it.
  Do not rely on the caller to call a second function after every mutation.
- Construction must produce a fully usable value. No two-phase init. No
  "call `fixup()` after move." If Zig's copy semantics invalidate interior
  pointers, redesign the struct so it does not have interior pointers.
- Test helpers follow the same rule. If a test helper requires the caller to
  remember a manual step, the helper is wrong.

---

## 1. Control Flow

- Use only simple, explicit control flow. Prefer `switch` over chains of `if/else if`.
- Do not use recursion. Ratchet trees are walked iteratively with bounded loops.
- Split compound conditions into nested `if/else` branches. Every `if` should have a
  corresponding `else` that either handles the case or asserts it cannot happen.
- State invariants positively. Prefer `if (index < length)` over `if (!(index >= length))`.

## 2. Bounds

- Put a limit on everything. Every loop must have a fixed upper bound. Every buffer must
  have a maximum size. Every queue must have a capacity.
- Use `for` with slices or bounded ranges. When `while` is necessary, assert a maximum
  iteration count.
- All vectors decoded from the wire must be checked against a maximum length before
  allocation.

## 3. Types

- Use explicitly sized types: `u8`, `u16`, `u32`, `u64`. Avoid `usize` except where Zig
  APIs require it (slice indexing, allocator interfaces). Convert to/from `usize` at the
  boundary with an explicit cast.
- Distinguish `LeafIndex`, `NodeIndex`, `Epoch`, and `Generation` as distinct named types
  (via `enum(u32)` or wrapper structs), not bare integers. This prevents accidental mixing.
- Use `enum` and `union(enum)` to make invalid states unrepresentable.

## 4. Assertions

- Assert all function arguments, return values, preconditions, postconditions, and
  invariants. Target a minimum of two assertions per non-trivial function.
- Pair assertions: assert validity both when producing data and when consuming it. For
  example, assert a leaf index is in range both when writing it into an UpdatePath and when
  reading it out.
- Split compound assertions: prefer `assert(a); assert(b);` over `assert(a and b);`.
- Assert compile-time constants and type sizes with `comptime { ... }` blocks.
- Assert both the positive space (what we expect) and the negative space (what we reject).
  Encode both in tests.

## 5. Secrets and Memory

- Zero all secret material before freeing. Use `secureZero(buf)` (which delegates to
  `std.crypto.secureZero` with a volatile cast) in a `defer` immediately after
  allocation or derivation. Never use `@memset` for secrets — the compiler may
  optimize it away.
- Group allocation and its corresponding `defer` deallocation together, separated by a
  blank line from surrounding code, so leaks are visible at a glance.
- Never log, print, or format secret key material. Not in debug builds, not in tests.
- After encrypting or decrypting, immediately delete intermediate secrets that are no
  longer needed (RFC 9420 Section 9.2 deletion schedule).
- Prefer stack-allocated fixed-size buffers (`[N]u8`) for secrets with known maximum size.
  Fall back to allocator only when size is truly dynamic.

## 6. Error Handling

- All errors must be handled. Never discard an error with `_ = foo() catch {};`.
- Use Zig error unions (`!T`) for operations that can fail due to external input or
  resource exhaustion.
- Use `assert` / `unreachable` only for programmer errors and proven-impossible states.
- Validate all external input (wire data, user-supplied parameters) and return a proper
  error. Never assert on external input.
- Prefer specific error values (`error.InvalidLeafIndex`) over generic ones
  (`error.InvalidArgument`).

## 7. Functions

- Hard limit: **70 lines per function**. If it does not fit, split it.
- Good function shape: few parameters, simple return type, dense logic in the body.
- Push `if`s up and `for`s down. Parent functions handle branching; leaf functions are
  pure computation.
- Centralize state mutation. Prefer helpers that compute a value over helpers that
  mutate state directly.
- For structs larger than 16 bytes, pass as `*const T` to avoid accidental copies.
- Construct large structs in-place via an out-pointer `init` pattern:

  ```zig
  pub fn init(self: *Self, allocator: Allocator) !void {
      self.* = .{
          // ...
      };
  }
  ```

## 8. Naming

- `snake_case` for all function, variable, and file names.
- `PascalCase` for types (`LeafNode`, `GroupContext`, `CryptoProvider`).
- Do not abbreviate. Write `encryption_key`, not `enc_key`. Write `leaf_index`, not `li`.
- Put units and qualifiers last, sorted by descending significance:
  `generation_count_max`, not `max_generation_count`.
- Name related variables with equal character counts where possible so they align in
  columns: `source` / `target`, not `src` / `dest`.
- Prefix helper/callback functions with the caller's name: `apply_commit` and
  `apply_commit_path`.
- Use RFC 9420 terminology directly. A Commit is a `Commit`, not a `StateChange`. A
  LeafNode is a `LeafNode`, not a `Member`. Match the spec names so the code reads as a
  direct translation of the RFC.

## 9. Comments

- Comments are sentences. Capital letter, full stop. Space after `//`.
- Always say **why**, not just what. The code shows what; the comment explains the
  rationale.
- Reference RFC sections: `// Per RFC 9420 Section 7.8, tree hashes are computed...`
- When a test exists, describe its goal and methodology at the top of the test block.
- Comments after the end of a line can be phrases without punctuation.

## 10. Formatting

- Run `zig fmt` on every file. No exceptions.
- 4 spaces indentation.
- Hard limit: **100 columns per line**. No horizontal scrolling.
- To wrap long signatures or struct literals, add a trailing comma and let `zig fmt`
  handle the rest.
- Add braces to `if` unless the entire statement fits on one line.

## 11. File Organization

- One primary type per file. The file is named after the type: `leaf_node.zig` defines
  `LeafNode`.
- Order within a file: fields, then nested types, then public methods, then private
  methods.
- Put important things near the top. Public API first.
- Keep test blocks in the same file as the code they test, at the bottom.
- If a nested type grows beyond ~50 lines, extract it to its own file.

## 12. Dependencies

- Zero external dependencies beyond the Zig toolchain. All cryptographic primitives
  come from `std.crypto` or are implemented in-tree.
- If `std.crypto` lacks a required algorithm, implement it in `src/crypto/` with tests
  against known-answer vectors.
- No C dependencies, no libc linking, no system-specific calls in the core library.

## 13. Testing

- Every public function has at least one test.
- Test both the positive space (valid inputs) and the negative space (invalid inputs,
  boundary conditions, malformed wire data).
- Use RFC test vectors for interoperability validation. Test vectors are checked in and
  loaded at comptime or test time.
- Test names describe the scenario: `test "tree_math.parent returns root for direct child of root"`.
- Fuzz the codec: random bytes must never cause a panic, only errors.
- Fuzz crypto operations: random inputs must never cause undefined behavior.

## 14. Commits

- Write descriptive commit messages. First line is a concise summary. Body explains why.
- A commit should compile and pass tests on its own. No "WIP" commits on main.
- Keep commits atomic: one logical change per commit.

## 15. Cryptographic Discipline

- Never reuse a nonce. The secret tree ratchet (Section 9) guarantees unique
  key/nonce pairs; assert this property.
- Never compare secrets with `==`. Use constant-time comparison
  (`std.crypto.timing_safe.eql`).
- Validate all public keys before use (point-on-curve checks, key size checks).
- After KEM decapsulation, verify the resulting shared secret is not all zeros.
- Signature verification must always precede any processing of message content.
- Treat signature and AEAD tag verification failures identically: return error, discard
  all derived state, zero temporaries.

## 16. No Workarounds

- No version has been published. Every breaking change is free. There are no users to
  protect, no backwards compatibility to maintain, no migration paths to provide.
- Never work around a bad design. If the current implementation is wrong, delete it and
  rewrite it correctly. A clean rewrite is always preferable to a patch on top of a
  flawed foundation.
- Never preserve an existing API, data structure, or control flow solely because it
  already exists. If a better approach is known, replace the old one entirely.
- Do not add compatibility shims, feature flags, or conditional paths to support both
  old and new behavior. Pick the correct behavior and enforce it everywhere.
- When a fix requires changing function signatures, struct layouts, file organization,
  or test expectations across the entire codebase, do it. Surgical half-measures that
  leave inconsistencies are worse than a large coordinated change.
- The nuclear option — deleting and rewriting a module from scratch — is always
  acceptable. Prefer it over accumulating debt in a module that has drifted from the
  design.

## 17. Allocator Positioning

### 17.1 The "First Argument" Rule

In standalone functions or initialization methods (`init`), the `std.mem.Allocator`
must be the **first argument** (after any `comptime` parameters). This provides
immediate visual feedback to the user that the function will perform memory allocation.

```zig
// Correct
fn parseData(allocator: Allocator, raw: []const u8) !Data { ... }

// Incorrect
fn parseData(raw: []const u8, allocator: Allocator) !Data { ... }
```

### 17.2 The "Managed" Pattern

If a struct owns its memory and needs to free it later, it should store the allocator
in a field. This allows the `deinit` function to clean up without requiring the user
to pass the allocator again.

- **Init:** Pass allocator as first argument.
- **Storage:** Store a copy of the allocator in the struct.
- **Deinit:** No allocator argument needed (uses the stored field).

### 17.3 The "Unmanaged" Pattern

For high-performance or memory-constrained scenarios, use the "Unmanaged" pattern.
The struct does **not** store the allocator, reducing its size by 8-16 bytes.

- **Every Method:** The allocator must be passed as the **first argument** (after
  `self` and any `comptime` parameters) to every single method that allocates,
  resizes, or frees memory (including `deinit`).
- **Naming:** By convention, these types are suffixed with `Unmanaged`
  (e.g., `ArrayListUnmanaged`).

### 17.4 Explicit Over Implicit

Never rely on a global allocator. In Zig, "hidden" allocations are considered an
anti-pattern. If a function needs to allocate, the signature **must** reflect it by
requiring an allocator. This allows the caller to use specific allocation strategies,
such as:

- **ArenaAllocator:** For "bulk" freeing at the end of a scope.
- **FixedBufferAllocator:** For stack-based allocation with no heap overhead.

### Comparison Summary

| Feature               | Managed Struct (Standard) | Unmanaged Struct         |
| :---                  | :---                      | :---                     |
| **`init` Position**   | First Argument            | N/A (usually `.empty`)   |
| **Methods Position**  | Not required (stored)     | **First Argument**       |
| **`deinit` Position** | No arguments              | **First Argument**       |
| **Memory Overhead**   | Includes Allocator pointer| Zero overhead            |


---

## 18. Code Quality References

Two Zig codebases serve as examples of the quality bar this project
targets:

- **[ghostty](https://github.com/ghostty-org/ghostty)** --
  GPU-accelerated terminal emulator. Exemplifies clean module
  boundaries, disciplined error handling, and production-grade
  Zig style.
- **[tigerbeetle](https://github.com/tigerbeetle/tigerbeetle)** --
  Distributed financial transactions database. The origin of
  Tiger Style (the basis for these rules). Exemplifies deterministic
  control flow, assertion discipline, and zero-tolerance for
  ambiguity.

When the two codebases contradict each other, TigerBeetle
takes precedence — it is the origin of Tiger Style, which is the
foundation of these rules. Ghostty is a secondary reference for
module layout and error handling patterns.
