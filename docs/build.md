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
- `python3-pytest` (`apt install python3-pytest`): the pytest-driven suites fail loudly without it.
- `strace` for the package clean-room audit (`apt install strace`).
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

## Source sealing

`tools/build` settles resolved dependency inputs (the
libbpf-mojo wrappers and libbpf headers compilers consume)
before sealing, then seals the source inventory plus the
resolved inputs (`tools/source_inventory.py`) and finalizes
`build/build-receipt.json` after compiling: any mid-build
input change (content, mode, membership, or a touch restoring
identical bytes, in sources or resolved dependencies) fails
the build. Restore detection assumes the mutation and the
restore land in distinct timestamp quanta. `tools/package`
loads one pinned receipt baseline and verifies every phase
against those same bytes (never re-reading the receipt path),
checks every staged source-derived and build-output copy
against its seal (missing expected copies fail as well as
differing bytes or modes; staged symlinks are rejected), and
reads manifest lock metadata from seal-checked bytes. The
manifest records the verification reads, and every archived
file binds to those verified bytes as consumed, so bytes
changed after verification fail the package instead of
shipping. The manifest records the full inventory and its
digest next to the descriptive git revision. A failed run
leaves no staging directory and no final candidate for its
tag: the archive digest is computed while writing the
verified bytes, then the tarball hashes, renames into place,
and hashes again with every read bound to the write digest,
and any failure drops the tag's bundle and tarball. Explicit
bundle tags validate before any failure cleanup can act, so
cleanup only ever drops candidates for a valid tag.

## Runtime provenance

The Mojo runtime closure ships from the pixi environment, which
the source seal does not cover, so `tools/package` verifies
every staged runtime file except the natively built bridge
against pinned package bytes (`tools/runtime_provenance.py`).
The packager downloads the locked `.conda` archives (cached
under `build/deps/runtime/`), verifies each against the
seal-checked `pixi.lock` bytes, parses each archive from one
verified in-memory snapshot, and compares staged bytes against
archive members: exact match, or match through a declared conda
prefix relocation whose original and staged digests are both
recorded. Binary relocations follow the installer c-string
transform (the prefix takes the placeholder's place, the
suffix stays, zeros pad the field end). Symlink chains resolve
on both sides, staged symlinks fail, and staged runtime license
texts must equal their archive members. The manifest records
owner package, archive digest, member, digests, and
transformation per file; the staged tree check re-binds staged
bytes to the verified digests, and any unowned, missing, or
mismatched payload fails the package. Archive streams
decompress with the `zstd` CLI, a packaging prerequisite like
patchelf.
