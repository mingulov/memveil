<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# memveil

Attempt, lifecycle, and copy capture for swiotlb bounce analysis
on x86-64 Linux: record real `swiotlb_bounced` tracepoint
activity, mapping lifetimes, and executed copies into a
self-describing capture directory, then replay it offline as
text, JSON, or Markdown. Attempt counts are try-counts with
requested bytes; actual copies come from the copy channel.
Pool pressure and diagnostic findings reduce offline over
captures that carry the corresponding events.

Status: attempt/lifecycle/copy development bundle 0.2.0, with runnable
build, test, and tarball packaging wrappers. The shipping collector
records attempts, mapping lifetimes, and executed copies on the
admitted profile, plus optional readable default-pool samples at
start, on a best-effort 1 s cadence, and close. `top` observes live
or replays finished captures; samples alone cannot diagnose
sustained pressure. Laboratory probes and offline reducers do not
qualify shipping
collection, successful DMA, sustained pressure, or
confidential-memory collection. The original lifecycle preview and
full confidential first-release gates remain open.

> **What this RnD release is — and is not**
>
> MemVeil 0.2.0 is a research-and-development preview for
> explaining SWIOTLB bounce behaviour from inside an ordinary
> x86-64 Linux guest. It records bounce *attempts* (try-counts
> and requested bytes), mapping lifetimes, and executed bounce
> copies, and replays captures offline. Read this before relying
> on any number it prints:
>
> - **Not qualified on confidential VMs.** Collection is not
>   qualified on AMD SEV-SNP, Intel TDX, or Hyper-V confidential
>   guests. One historical SEV-SNP run exists (older binary);
>   TDX has not been run. Ordinary-Linux results do not transfer.
>   MemVeil performs **no attestation** and its output is **not evidence about what a host or hypervisor did or could read**, and not a verdict on guest confidentiality.
>   `doctor`'s guest line (e.g. `guest: snp`) is a kernel-reported
>   signal, not platform proof.
> - **Attempts are not copies, and inner success is not DMA
>   success.** `bounce_attempts` counts tries; only the copy
>   channel reports bytes actually copied. A successful inner
>   allocation can still be followed by outer DMA failure.
>   **Unmapping is not erasure or re-privatization**: an
>   unmap/release ends a mapping lifetime; it says nothing about
>   later accessibility of the underlying pages.
> - **Exit 0 does not mean a complete measurement.** `record`,
>   `report`, and `top` exit 0 for valid output with *partial*
>   evidence (live terminal quality is partial by design). Read
>   the `verdict:` line, or pass `--strict` in scripts (exit 4
>   unless the verdict is `complete`). Rows shown as
>   `unavailable`/`withheld` mean "not measured" — never zero.
>   "No findings" means no diagnostic fired, not that the
>   condition was absent.
> - **Only the exact tested artifact is tested.** Kernel-matrix
>   results name one binary by hash (see release notes); the
>   matrix ran the `.deb` install of the canonical binary. Rows
>   not listed as PASS for this build were not run on this build.
>   A machine-local `qualify` receipt records that a smoke
>   capture worked on one host; it is not release qualification
>   and does not hash the memveil executable — re-run `qualify`
>   after any reinstall. Pool samples cannot diagnose sustained
>   pressure, and saturation (~153k records/s, lower pre-6.7)
>   degrades to partial/unknown rather than blocking.
> - **Metadata only, with fingerprints.** Captures contain
>   allowlisted measurement metadata only — no payload bytes,
>   keys, PINs, content hashes, raw addresses, full command
>   lines, or environment dumps (the shipped collector also never
>   writes process names/ids; the format reserves a
>   never-rendered execution-context block for other producers —
>   check a foreign capture before sharing it). Captures *do*
>   contain a per-boot identifier, device PCI names, and
>   kernel/build hashes: share a capture like you would share a
>   `dmesg` — deliberately, not anonymously.
> - **Privilege.** Recording needs root in the initial user
>   namespace (BPF load + tracefs); there is no supported
>   capabilities-only mode. Replay (`report`, `top DIR`) and
>   passive `doctor` are unprivileged and make no network
>   connections. This is an RnD prerelease: verify downloads with
>   the signed `SHA256SUMS.txt`; build from source if you need a
>   stronger chain — signed release custody returns at 1.x.

The [support table](docs/support.md#capabilities-by-mode) defines the
capabilities by mode. Two reference profiles ship; kernels are
admitted through live interface checks, and a bound document
additionally requires its exact config/BTF/object bindings.
The VM gates themselves run on any
host kernel: they mint an unvalidated gate profile for the kernel
under test (see [VM gate kernel](docs/recipes/ordinary-linux.md#vm-gate-kernel)),
which exercises the code but qualifies nothing.
A rebuilt package or matching kernel name alone earns no qualification.

## Use (tested .deb first)

Only the `.deb` binary ran on the kernel matrix; the tarball
and the `.rpm` carry builds of the same source with
separately linked binaries that were not matrix-run (see
[Known issues](docs/release-notes.md#known-issues) and
[installed packages](docs/install.md)).

    sudo dpkg -i memveil_0.2.0-1_amd64.deb
    memveil doctor                            # passive host check
    sudo memveil record --output /tmp/cap1 --duration 10
    memveil report --format text /tmp/cap1   # unprivileged replay

**Exit 0 does not mean complete measurement. Read the `verdict:` line, or pass `--strict` in scripts.**

## Use (from the tarball)

    tar -xzf memveil-0.2.0.tar.gz && cd memveil-0.2.0
    ./bin/memveil doctor                            # passive host check
    sudo ./bin/memveil record --output /tmp/cap1 --duration 10
    # BPF objects are embedded in the binary with the loader
    # statically linked, so plain sudo works; --bridge and
    # --object are optional overrides for non-embedded artifacts.
    sudo cp -r /tmp/cap1 ~/cap1 && sudo chown -R $USER ~/cap1
    ./bin/memveil report --format text ~/cap1       # unprivileged replay
    ./bin/memveil top --interval 1s ~/cap1          # finished-capture replay

`docs/quickstart.md` walks the five-minute test;
`docs/support.md` states the tested envelope and exit codes;
`docs/privacy.md` lists exactly what a capture contains.
`docs/permissions.md` details privilege separation and the
record refusal gates; `docs/troubleshooting.md` is the
symptom-to-fix index; `docs/profiles.md` walks
bound-reference authoring from `doctor` to `qualify`.
`docs/evidence-retention.md` states what gate and matrix
evidence is kept and how a receipt re-derives its verdict.
`docs/policy.md` states the evolution and support policy.
`examples/real-capture` is a reviewed 30-event capture with
expected outputs. `CONTRIBUTING.md` is the contributor
workflow, `RELEASING.md` the release process,
`SECURITY.md` the vulnerability route, and
`CHANGELOG.md` the version history.

## Build and test (from source)

Pinned Rust 1.100.0 toolchain (plus nightly-2026-05-20
for the eBPF child build); see `docs/build.md`,
`rust-toolchain.toml`, and `Cargo.lock`. No bridge
library, no vendored native dependencies.

    cargo build --release --locked          # build everything
    cargo test --workspace --locked         # Rust suites
    ./tools/test --help                     # list harness suites

`report`, replay `top`, and `doctor` run anywhere; `record`
and live `top` load the embedded probes at session open,
and `qualify` checks artifact bindings when proving the
host.

## Licensing

MemVeil is GPL-3.0-or-later (`LICENSE`), except the eBPF
programs (`crates/ebpf/`, GPL-2.0-only), the shared
eBPF-side tables (`crates/ebpf-common/`,
GPL-2.0-or-later), and the test-only oracle kernel
modules (`tests/kernel/memveil_dma_oracle.c`,
`tests/kernel/memveil_region_oracle.c`, and
`tests/kernel/Makefile`, GPL-2.0-only); texts in
`LICENSES/`. Every first-party source file carries an
SPDX header. Redistributed third-party components, with
their staged license texts, are listed in
`THIRD-PARTY-NOTICES.md`; per-artifact crate texts ship
under the bundle's `licenses/crates/`.
