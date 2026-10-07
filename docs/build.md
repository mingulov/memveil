<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build and toolchain guide

This repository builds with a pinned Mojo toolchain managed by pixi, plus
system C tooling for eBPF programs and test fixtures. Pinned versions live
in `toolchain.lock.json` (cmake carries a minimum floor, the rest are
exact); the `pixi.lock` file carries authoritative conda package hashes.

## Prerequisites

- `pixi` 0.81.0 exactly, to create the Mojo environment.
- System `clang` and `bpftool` at the locked versions, for C eBPF programs.
- `python3` for development-only validation tooling.
- `patchelf` for `tools/package` RUNPATH normalization (`apt install patchelf`).

Run `pixi install` once after cloning. Every Mojo command below runs inside
that environment; the `tools/` wrappers do this for you.

## Layout and wrappers

| Path | Purpose |
|---|---|
| `tools/build` | Single supported build path; also `--check-toolchain` |
| `tools/test <suite>` | Suite runner; `--help` lists suites |
| `tools/package` | Standalone artifact builder |
| `tools/validate-schemas` | Schema and capture validator (Python standard library only) |
| `src/memveil/` | CLI, platform, capture, model, analysis, and render modules |
| `bpf/` | MemVeil-only wire declarations and metadata-only C probes |
| `schemas/`, `profiles/` | External format contracts and kernel semantic profiles |
| `tests/` | Unit, fixture, native, VM, kernel, and confidential suites |

Wrappers print their underlying pinned commands to the build log and return
nonzero on failure. A skipped privileged test is reported as skipped, never
as success evidence. Public build/test suites work from a standalone clone
using only this repository.

## Verified toolchain probes

The following was verified against Mojo 1.1.0 by compiling and running
small probes; skill guidance alone was not trusted. Probe sources were
disposable development checks, not shipped tests.

- Integers: `UInt64`/`Int` are exact, including values above 2^53 and
  round-trips through `String`. Unsigned overflow **wraps silently** even
  in unoptimized builds.
- CLI input: `std.sys.argv` works (first element is the program name);
  `std.sys.exit` and `std.sys.stderr` compile.
- There is no `std.json`: importing it fails to resolve.
- `std.ffi.external_call` calls linked C (a `getpid` probe returned the
  caller's PID). `std.ffi.OwnedDLHandle` loads a named `.so` at runtime
  and a missing library raises a catchable error.
- Files: `open()` read/write round-trips; `std.pathlib.Path.exists()`
  works; `std.os` provides `mkdir`, `listdir`, `remove`, and `getenv`.
  `os.rename` does not exist.
- `std.time.perf_counter_ns` and `std.time.sleep` compile; there is no
  `std.time.now`.
- `mojo build` offers `-O` levels (default 3), `-g` levels (default
  none), and `--sanitize address|thread`. There is no Mojo UBSan flag.

## Application behavior

Implemented in `src/memveil/` with owning tests per feature:

- Capture parsing and report generation in owned Mojo modules with
  explicit size, depth, and nesting bounds; parsing and accounting are
  never moved into C or Python.
- Explicit checked u64 arithmetic helpers that fail closed instead of
  wrapping.
- Lazy bridge loading through `OwnedDLHandle`, so offline commands work
  without the bridge library present. String arguments to retrieved
  callables must use `as_c_string_span()`, never a raw `String`.
- Atomic no-replace publication through an inline `renameat2`
  FFI call with `RENAME_NOREPLACE`: if the target already
  exists the run refuses to overwrite it instead of
  replacing it.
- Signal handling through centralized FFI: `record` re-execs once under
  an inherited mask and consumes signals via signalfd; teardown runs in
  normal control flow.
- Sanitizer evidence is recorded per task; `mojo build --sanitize`
  needs a root-owned compiler cache outside unprivileged containers.

## Compiler settings

- Shipped builds keep the compiler's normal safety checks enabled.
  Explicit input validation never depends on debug assertions.
- Optimization and debug info use `-O` and `-g` levels recorded in the
  build log. Test builds add `mojo --sanitize address` where supported.
- The Mojo driver offers address and thread sanitizers only; native C
  additionally builds with address/undefined-behavior sanitizers. Each
  result is separate evidence.
- No compiler internals, unfinished async, or unstable APIs are used.
  `mojo format` keeps sources canonical.

## Dependencies

`libbpf-mojo` is consumed as a pinned bundle, vendored at
`third_party/libbpf-mojo-<version>.tar.gz` and verified against the
`tarball_sha256` pin in `toolchain.lock.json` on every build; release
builds never use an implicit sibling path. The bundle carries the
prebuilt native bridge plus Mojo wrapper sources and the C
interface header (no native implementation sources); the build
links the prebuilt bridge, it never compiles it. `LMB_PACKAGE`
overrides the vendored bytes with another tarball, which must
match the same pin before the build accepts it.
