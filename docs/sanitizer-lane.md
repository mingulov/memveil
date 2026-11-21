<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Sanitizer lane (AddressSanitizer)

Evidence-only lane: build the host workspace with AddressSanitizer
and run the named coverage over the instrumented binaries. The lane
changes no product code; any product fix it forces is reported as a
separate finding and fixed in its own change, never silently here.

## Toolchain pin

- Host lane toolchain: `nightly-2026-11-18`
  (`rustc 1.102.0-nightly (59cbdee2e 2026-11-17)`), with the
  `rust-src` component (`-Zbuild-std` rebuilds the sysroot from it).
- Install: `rustup toolchain install nightly-2026-11-18
  --component rust-src --profile minimal`.
- The `nightly-2026-05-20` (1.97) pin stays where it belongs: it is
  the eBPF child toolchain (`crates/ebpf/rust-toolchain.toml` plus
  `BPF_TOOLCHAIN` in the root `build.rs`) and is rejected for the
  host lane, which requires >= 1.100.
- Record `rustup run nightly-2026-11-18 rustc -Vv` with every run.

## Why a wrapper instead of RUSTFLAGS

The root `build.rs` forwards `CARGO_ENCODED_RUSTFLAGS` into the
child eBPF cargo invocation, so a sanitizer flag in `RUSTFLAGS`
would leak to the BPF target. The lane therefore passes NO
sanitizer flags via `RUSTFLAGS` (keep it unset) and instruments
through `RUSTC_WRAPPER` instead: `tools/asan-rustc-wrapper.sh`
adds `-Zsanitizer=address` only to invocations for the lane
target (`x86_64-unknown-linux-gnu`, overridable via
`ASAN_LANE_TARGET`). Host tooling (build scripts, proc macros and
their dependency rlibs) passes through uninstrumented: rustc
rejects sanitizer flags for proc-macro crates, and instrumented
host rlibs break proc-macro loading. All product code, test
targets, and the rebuilt sysroot build for the lane target and
are instrumented. `build.rs` strips
`RUSTC_WRAPPER`/`RUSTC_WORKSPACE_WRAPPER` from the child eBPF
cargo environment, so the child never sees the wrapper.

## Rerun

From the repository root, with `RUSTFLAGS` unset:

```sh
export CARGO_TARGET_DIR=$PWD/target/asan
export RUSTC_WRAPPER=$PWD/tools/asan-rustc-wrapper.sh
export ASAN_WRAPPER_LOG=$PWD/target/asan/invocations.log
rm -f "$ASAN_WRAPPER_LOG"
rustup run nightly-2026-11-18 cargo build --locked -Zbuild-std \
    --target x86_64-unknown-linux-gnu
```

Then the named coverage (workspace unit tests, `faults`, the Rust
`cli_parity` target, `wire_compat`):

```sh
LANE="rustup run nightly-2026-11-18 cargo"
$LANE test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --workspace --lib
$LANE test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --test faults
$LANE test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --test cli_parity
$LANE test --locked -Zbuild-std --target x86_64-unknown-linux-gnu --test wire_compat
```

Reader-adversarial on the instrumented binary: route this
leg through `tools/test` with `MEMVEIL_BIN` set to the
lane binary. When `MEMVEIL_BIN` holds a slash path naming
an executable file, `tools/test` canonicalizes it against
the caller directory first (so later directory changes
cannot lose it), then uses the absolute path: `memveil_bin`
returns it and `rust_bin_setup` skips its release relink
(`tools/test:192-252`, called at `tools/test:2117`); a
set-but-missing or non-executable value fails closed, as
does a bare name that resolves to nothing on PATH. The CLI
Python drivers
resolve the same knob through
`tests/cli/memveil_bin.py`, so the blessed binary is the
executed binary by construction — no manual
`build/memveil` pre-pointing.

```sh
export ASAN_OPTIONS=detect_leaks=0
LANE_BIN="$PWD/target/asan/x86_64-unknown-linux-gnu/debug/memveil"
MEMVEIL_BIN="$LANE_BIN" tools/test reader-adversarial
```

Prove the instrumented binary actually ran (all required):

```sh
MEMVEIL_BIN="$LANE_BIN" python3 tests/cli/test_memveil_bin.py   # knob contract: knob binary == executed binary
readlink -f "$LANE_BIN"   # canonical path of the executed file
sha256sum "$LANE_BIN"     # identity of the executed bytes
nm "$LANE_BIN" | grep -c __asan   # nonzero (__asan symbols linked into the lane binary)
```

`build/memveil` is untouched by the lane leg now (the
knob bypasses the link entirely), so there is no link to
restore afterwards.

Do not bypass `tools/test` for this leg, and do not
pre-point `build/memveil` at the lane binary: the
`MEMVEIL_BIN` knob routes the leg through the real
dispatch, and the drivers resolve the same knob, so the
link stays untouched.

`detect_leaks=0` applies to the reader leg only: one of its cases
drives the binary under `strace`, and LeakSanitizer cannot run
under ptrace (fatal LSan init error, unrelated to product code).
AddressSanitizer itself stays fully active; the cargo legs above
run with default options, leak detection included. The
`build/shim/*.so` fault adapters stay uninstrumented by design
(see `tests/cli/prepare_capture_failures.py`); build them with
`python3 tests/cli/prepare_capture_failures.py` when the build
tree lacks them.

Expected: zero sanitizer reports on every leg. An AddressSanitizer
report aborts with a nonzero exit, so any report fails its leg.

## Proving the eBPF child stays clean

Three independent checks, all required:

1. Wrapper log: every invocation records its target and whether
   the flag was added. Assert no `bpfel-unknown-none` line carries
   `added=yes` (normally the child never reaches the wrapper, so
   no `bpfel` line appears at all).
2. Lane environment: `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS`
   are unset, so the flags `build.rs` forwards cannot carry a
   sanitizer flag. Print both with the run.
3. BPF artifacts: the three `memveil-ebpf-*` objects under the
   lane `OUT_DIR` contain no `__asan` symbols
   (`nm`/`llvm-objdump` check) and the child build succeeds.
   Negative control: passing `-Zsanitizer=address` for
   `--target bpfel-unknown-none` with the pinned BPF nightly
   fails loudly, so a leak would break the build rather than
   ship a silently instrumented object.
