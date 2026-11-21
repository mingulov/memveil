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

Reader-adversarial on the instrumented binary: NEVER route this
leg through `tools/test`: every non-help dispatch runs
`rust_bin_setup` first (`tools/test:129-143`, called at
`tools/test:2004-2006`), which unconditionally relinks
`build/memveil` at the plain `target/release/memveil` before
the suite starts. A pre-pointed lane link is silently
replaced, so the suite would test the wrong binary; there is
no override knob (`memveil_bin` hardcodes the release path
and the Python suites hardcode `build/memveil`). Invoke the
suite body directly instead. These three lines replicate
`suite_reader_adversarial` exactly: re-verify them against
`tools/test` if that suite body ever changes.

```sh
export ASAN_OPTIONS=detect_leaks=0
LANE_BIN="$PWD/target/asan/x86_64-unknown-linux-gnu/debug/memveil"
mkdir -p build
ln -sfn "$LANE_BIN" build/memveil
# Suite body, in dispatch order:
python3 tests/cli/prepare_capture_failures.py \
&& python3 tests/cli/test_adversarial_cli.py \
&& python3 tests/cli/test_checkpoint_recovery.py
```

Prove the instrumented binary actually ran (all required):

```sh
readlink build/memveil   # before AND after the leg: the lane path, never the release path
nm "$LANE_BIN" | grep -c __asan   # nonzero (__asan symbols linked into the lane binary)
```

Then restore the normal release link (guarded: a missing
release binary must not leave a dangling link):

```sh
if [ -x "$PWD/target/release/memveil" ]; then ln -sfn "$PWD/target/release/memveil" build/memveil; fi
```

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
