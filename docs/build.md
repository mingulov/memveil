<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Build and toolchain guide

This repository builds with a pinned Rust toolchain plus
system C tooling for test shims and fixtures. Pinned
versions live in `rust-toolchain.toml` (Rust 1.100.0),
`crates/ebpf/rust-toolchain.toml` (nightly-2026-05-20 for
the eBPF child build), `Cargo.lock` plus
`crates/ebpf/Cargo.lock` (exact dependency closures), and
`build.rs` (`BPF_TOOLCHAIN`, `BPF_LINKER_VERSION`).
`cargo build --locked` refuses any drift from the locks.

If your environment forces `RUSTUP_TOOLCHAIN`, unset it
first so the repository pins win (`env -u
RUSTUP_TOOLCHAIN cargo ...`).

## Prerequisites

- Rust 1.100.0 via rustup (`rust-toolchain.toml`
  selects it automatically), plus the nightly-2026-05-20
  toolchain and `bpf-linker` 0.10.4 for the eBPF child
  build (`build.rs` refuses anything else).
- A native `clang` for the C test shims, the C wire
  oracles, and the perf pacing adapters (compiled
  on demand by the suites that use them).
- `python3` for the packagers, doc generators, and the
  harness runner; `python3-pytest` for the pytest-driven
  suites.
- `readelf` (ELF inspection in tests), `sha256sum`,
  `dpkg-deb`, `rpmbuild`, `rpm2cpio`, and `cpio` for the
  packaging suites; on Fedora the same set comes from
  `dnf`.
- `strace` for the offline-environment audit.
- `bpftool`, QEMU/KVM, and passwordless `sudo` only for
  the armed VM lanes.

## Layout and wrappers

| Path | Purpose |
|---|---|
| `Cargo.toml`, `build.rs` | Workspace root; the build script compiles the eBPF channels |
| `src/` | CLI, platform, capture, model, analysis, and render modules |
| `crates/ebpf/` | Aya eBPF channel programs (attempt, lifecycle, copy) |
| `crates/ebpf-common/` | Shared eBPF-side decode tables |
| `scripts/` | `package-tarball.py`, `package-deb.py`, `package-rpm.py`, `gen-man.py`, `gen-completions.py`, `gen-docs.py` |
| `packaging/` | deb templates, rpm spec, and the pinned libgcc provider |
| `tools/test <suite>` | Harness suite runner; `--help` lists suites |
| `tools/validate-schemas` | Schema and capture validator (Python standard library only) |
| `bpf/include/memveil_events.h` | Shared wire-contract header for the C oracles |
| `schemas/`, `profiles/` | External format contracts and kernel semantic profiles |
| `tests/` | Rust integration suites, harness suites, fixtures, and native oracles |

Build, test, package, and document generation:

```sh
export RUSTC="$(rustup which --toolchain 1.100.0 rustc)"  # one rustc for nested builds (see below)
env -u RUSTUP_TOOLCHAIN cargo build --release --locked
env -u RUSTUP_TOOLCHAIN cargo test --workspace --locked --no-fail-fast
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings
./tools/test fast                # contributor gate: build + Rust tests + offline suites
./tools/test --help              # list harness suites
./tools/test reports             # one harness suite
python3 scripts/package-tarball.py --out dist
python3 scripts/gen-docs.py --out /tmp/docs --build
```

The `RUSTC` pin matters on hosts with more than one Rust
toolchain installed: some Rust tests spawn nested cargo
builds, and nested cargo resolves `rustc` next to its own
shim, which can mix compiler versions and fail the build
with `E0514`. Pointing `RUSTC` at the pinned toolchain's
`rustc` keeps every build on one compiler; the eBPF child
build still selects its own pinned nightly.
`./tools/test fast` sets this pin itself, builds in-tree
(an exported `CARGO_TARGET_DIR` elsewhere breaks profile
lookup beside the binary, so the lane ignores it), and
runs the full workspace tests plus the offline suites
(schemas, reports, privacy, reader-adversarial, docs) in
one invocation. `./tools/test fast-full` adds the
examples suite, whose fixed real-time replay costs about
two minutes.

Public build/test suites work from a standalone clone
using only this repository. A skipped privileged test is
reported as skipped, never as success evidence.

See [offline fixture generation](fixture-generation.md)
for compiler-bound provisional fixtures and the complete
isolated-runner preflight.

## Application behavior

Implemented in `src/` with owning tests per feature:

- Capture parsing and report generation in owned Rust
  modules with explicit size, depth, and nesting bounds;
  parsing and accounting are never moved into C or Python.
- Explicit checked `u64` arithmetic helpers that fail
  closed instead of wrapping.
- A statically linked Aya loader: offline commands work
  with no bridge library, and `--bridge` names only a
  file whose bytes bind receipt checks.
- Atomic no-replace publication: if the target already
  exists the run refuses to overwrite it instead of
  replacing it.
- Signal handling through a centralized guard: `record`
  re-execs once under an inherited mask and consumes
  signals via signalfd; teardown runs in normal control
  flow.

## Compiler settings

- Shipped builds keep the compiler's normal safety checks
  enabled. Explicit input validation never depends on
  debug assertions.
- Edition 2024, `rust-version 1.100`. Optimization and
  debug info follow the release profile recorded by
  `cargo build --release --locked`.
- No sanitizer lane is wired into CI. `unsafe` is
  confined to FFI boundaries (Aya helpers, libc calls,
  signal handling) with a `SAFETY` note on each block;
  new `unsafe` needs a bound it cannot exceed and a test
  that trips the bound.
- No compiler internals or unstable APIs are used on the
  stable toolchain. `cargo fmt` keeps sources canonical;
  `cargo clippy --locked --all-targets -- -D warnings`
  must stay clean.

## Dependencies

Rust crates come from the crates.io registry pinned by
`Cargo.lock` and `crates/ebpf/Cargo.lock`; there are no
vendored or patched dependencies. `cargo-deny` gates
advisories, bans, licenses, and sources for both
manifests (see `deny.toml` and
`crates/ebpf/deny.toml`). The eBPF crates link no
libbpf: Aya loads through its own statically linked
runtime.

The one shipped shared library, `libgcc_s.so.1` for the
Rust unwinder, comes from the pinned Debian archive in
`packaging/libgcc/` (see `PROVENANCE.txt` there), never
from the build host. The packager refuses on any pin
mismatch. See the root `THIRD-PARTY-NOTICES.md` for the
full third-party inventory.

## Source sealing

The packagers seal what they consume: every staged file
is read through a verified digest, the staged tree is
compared byte-for-byte against those digests (missing
and extra files fail as well as differing bytes), and a
failed run leaves no staging directory and no final
candidate. The release binary embeds its three channel
objects at build time; the packager binds the staged
objects to the exact bytes the binary embeds
(`--embedded-manifest`) and refuses a mix of builds.
`MANIFEST.json` records the source digest, receipt
hash, and dependency identities next to the descriptive
git revision.

## Runtime provenance

The bundle carries no toolchain runtime: the only
shipped shared object is the pinned libgcc above, and
the manifest records its provider archive, member, and
digests. Crate provenance comes from the locked
registries (`Cargo.lock` shas), not from archives. Staged
symlinks fail; staged license texts must equal their
locked sources.

## Pinned executable inputs

Build and automation inputs have explicit admission
rules. Immutable pins are verified before use; selected
system tools are checked against exact versions or
minimum floors. The native `cc` chain and packaging
helpers are availability-checked ambient inputs whose
observed identities are retained. Their recorded hashes
expose changes but do not automatically refuse version
drift or qualify a resulting artifact.

| Input | Immutable identity | Verified by |
|---|---|---|
| Automation actions | Full commit SHA plus the tag comment in `.github/workflows/*.yml` | Provenance gate |
| Rust toolchains | `rust-toolchain.toml` plus `crates/ebpf/rust-toolchain.toml`, cross-checked against `mise.toml` and `build.rs` | Provenance gate, build refusal |
| Crate closures | `Cargo.lock` plus `crates/ebpf/Cargo.lock` with `--locked` builds | `cargo build`, provenance gate |
| `bpf-linker` | Version pin in `build.rs` | Build refusal |
| `cargo-deny` | 0.21.0, validated in-tree | CI deny jobs |
| libgcc provider | `.deb` plus member pins in `packaging/libgcc/PROVENANCE.txt` | Packager refusal |
| rpm Source0 | Owned selection: an owning checkout contributes tracked plus unignored-untracked files, never a parent's set | Packager refusal |
| Native `cc` and linker | Ambient, availability checked | Tests compile shims and oracles on demand |
| Packaging helpers (`dpkg-deb`, `rpmbuild`, `readelf`, `sha256sum`) | Ambient, availability checked | Packager refusal, manifest records versions |

Refresh routes, one input at a time with the affected
lanes re-run:

- Actions: resolve the tag to its commit with `git
  ls-remote` against the action repository (corroborate
  with the published tag listing), then update the SHA
  and the tag comment together.
- Toolchains, crates, linker: update the pins, locks,
  and recorded hashes together; the build and the
  provenance gate re-verify each side.
- libgcc: re-run the adoption proofs in
  `packaging/libgcc/PROVENANCE.txt`, then update the
  pins; the packager refuses anything else.
- Ambient tools: re-qualify the new versions; builds
  keep refusing absences.

The bundle `MANIFEST.json` carries the source digest,
receipt hash, and dependency identities, and the `.deb`
control fields (`X-` entries) carry the revision, cargo
lock digest, and observed tool versions into the
artifacts.

## Canonical runtime packages

Build the canonical bundle once from clean source, then
pass its directory to both package adapters:

```sh
cargo build --release --locked
python3 scripts/package-tarball.py --out dist
python3 scripts/package-deb.py --bundle "$PWD/dist/memveil-0.2.0" --out dist
python3 scripts/package-rpm.py --work build/rpm --out dist \
    --bundle "$PWD/dist/memveil-0.2.0"
```

These commands prepare local, unqualified artifacts and
do not publish them. Missing qualification still blocks
release. Candidate custody and release promotion require
their separately documented evidence.

The runtime uses `bin/memveil`, `lib/memveil/*.so*`,
`bpf/`, and `profiles/`. The executable RUNPATH is
`$ORIGIN/../lib/memveil`. Debian and RPM map the same
bytes to `/usr/bin`, `/usr/lib/memveil` and
`/usr/share/memveil/profiles`. The manifest's file
inventory contains all runtime entries with normalized
path, type, size and SHA-256. Verification rejects
missing, added, changed and escaping entries.

The minimum runtime CPU eligibility is **x86-64-v3**.
Code generation stays at the compiler default, which is
x86-64 baseline for the pinned toolchain (rustc 1.100.0
enables fxsr/sse/sse2 only, per `--print cfg`); the v3
eligibility is a loader declaration, separate from the
emitted instruction set. Its single link adds the
`GNU_PROPERTY_X86_ISA_1_NEEDED` v3 declaration. The build
and bundle verifier inspect the actual loadable property
and refuse an absent, weaker or stronger declaration. A compatible glibc loader checks the
declaration before library constructors execute. An
incompatible CPU produces `CPU ISA level is lower than
required` and exits 127 on the verified loaders. This
is a pre-CLI loader refusal, separate from MemVeil
command exits. CPU eligibility and recorded tool
identities do not qualify an artifact or environment.
The artifact's libc floor is derived from its complete
ELF closure; the vendor's development-system minimum
alone is insufficient.

`--bundle DIR` is the package-adapter interface for a
retained canonical tree. Adapters retain its verified
complete file manifest before copying. They compare
every copied runtime, license, notice, manual and
example at its installed destination before executing
the staged engine and again before assembly. Generated
package metadata, man pages and completions are
separate outputs. Matching bytes do not grant
qualification. Keep the matching source export
alongside distributable archives.

For package-only verification of a retained bundle,
build the packages from that bundle directory and run
the packaging suites against them; an explicit bundle
input never triggers a product rebuild. Debian and RPM
install/collection journeys require their designated
isolated environments; offline extraction equality
does not satisfy those live gates.

The source-export gate archives the tree Git-free and
runs the provenance gate from the export itself, then
packages from the export to prove the release candidate
needs no repository metadata.

RPM assembly compares the current source inventory
(content, membership and modes) with the sealed build
inputs before constructing Source0 or invoking rpmbuild.
File timestamps may differ across identical exports.
Foreign or changed source inputs refuse; no build
fallback or qualification inference is permitted.
The finished .rpm names the fixed placeholder
`build.invalid` as its build host instead of the
builder's hostname; `rpm -qp --queryformat
'%{BUILDHOST}'` on the artifact must print the
placeholder on any host. No wider reproducibility is
claimed: the Release tag still carries the distro
`%{?dist}` expansion, so the same source built on
different distributions yields different Release tags
and file names.
