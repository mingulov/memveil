<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Rust binary parity: harness suite triage

Every `tools/test` suite triaged against the Rust binary
(`cargo build --release` in `rust/`, run via
`MEMVEIL_RUST_BIN=1 tools/test <suite>`). The selector lives in
`tools/test`: `memveil_bin()` switches the shell binary path,
`rust_bin_setup()` links `build/memveil` at the Rust binary so the
Python suites (which hardcode that path) exercise it, and refuses to
shadow a real Mojo build. Mojo-mode behavior is unchanged.

Binary under test: `memveil-0.1.0`, `rust/target/release/memveil`,
sha256 `70c937792b49b5f61551223a294af4136315ff8853845d868b69ee91eeaab775`
(release profile, `cargo 1.100.0` / `rustc 1.100.0`, pinned toolchain
file). Mojo oracle for divergence checks: `build/mojo-memveil-compare`
(Mojo `1.2.0` build of this tree) plus `mojo run` of current sources.

Classes: `rust-binary` (exercises the binary), `harness`
(mode-independent checks), `retired-with-replacement` (Mojo/C/shim
internals; the named Rust tests carry the coverage),
`needs-port` (packaging suites owned by the packagers task),
`vm-gated` (needs armed VM prerequisites).
Verdicts: PASS / FAIL / SKIP (exit 77, prerequisite named) /
DEFERRED (another task owns it). FAIL entries name the cause; none
is a silent narrowing.

## rust-binary suites

| Suite | Verdict | Evidence |
|---|---|---|
| schemas | PASS | 98 checks pass under the selector (validator only). |
| reports | PASS | 142/142: golden bytes, exit codes, oracle counts. |
| doctor | PASS | Mojo units 42+11+9 pass; all live `--json`/text/`--capability`/`--load-check`/hostile-env checks pass after the profiles-discovery fix below. |
| record | PASS | 14 Mojo unit files + 13 CLI cases pass; `no-object`/`no-bridge` are documented Rust-mode skips (embedded objects, static loader). See conflict 1 (resolved). |
| qualify | PASS | Mojo units 47+9, 12 CLI refusal cases, oracle-accepted fixture mint. |
| top | PASS | Mojo unit plus full CLI harness incl. live-refusal cases. |
| oracle-ledger | PASS | 12/12 pytest. |
| quality | PASS | 32/32 on both binaries after the conflict-2 expectation update (integrity-aware `partial`, byte-identical JSON). See conflict 2 (resolved). |
| reader-adversarial | PASS | Mojo unit 15/15, capture-integrity 13/13 (incl. 1 documented Rust-mode skip), adversarial own-checks 24/24, checkpoint-recovery 7/7. See conflict 3 (resolved). |
| fuzz-smoke | PASS | Oracle 4/4, 200 cases 0 failures. |
| fuzz-campaign | PASS | Oracle 4/4, 10000 cases 0 failures (31.6s). |
| record-failures | PASS | Mojo stdout unit, stdout-errors, capture-failure and durability oracles (LD_PRELOAD shims fire on Rust). |
| output-paths | PASS | Path-swap cases plus symlink/fifo case. |
| privacy | PASS | Canaries, metadata allowlist, skip codes, pytest guard. |
| render-escaping | PASS | All escaping checks. |
| offline-environment | PASS | Exit/identical/traced checks. |
| perf-replay | PASS | Full (600k), prefix, paced, and sealed checks pass: full 4.3s wall at 141k records/s (budget 60s), RSS inside 256MB; paced 600k lines over 60s via the `read` lane (3269 calls, max 64KiB, error 0, exact counts). Sealed: verified, 6.1s. See conflict 4 (resolved). |
| perf-region | PASS | 234/234 incl. wall/RSS budgets (active-ceiling 2.1s, peak 122.6MB). |
| soak | PASS | Un-bypassed full 30-min run on the updated expectation: 1326 stable cycles, peak 33.8MB, max cycle 0.7s, zero failures; binary hash `70c93779...` identical pre/post (no mid-run rebuild). History: the earlier bypassed triage (1282 cycles) spanned two hashes after a concurrent packaging rebuild (`d6bc688`, semantics-preserving); that run is superseded. Wrapper note: the long run's shell wrapper exited 2 on a trailing re-read parse error caused by an in-place `tools/test` edit landing mid-flight (process bug, mine); the suite evidence above is unaffected (recorded in-process before the wrapper error), and a 1-min wrapper re-run exits 0. See conflict 2 (resolved). |
| perf-workload | SKIP | pytest 21/21 pass (comparison logic, binary-free); `workloads.py` needs `MEMVEIL_VM_PERF=1` with qualified probes. |
| perf-overhead | SKIP | pytest 66/66 pass; `overhead.py` needs `MEMVEIL_VM_PERF=1` with qualified probes. |
| profiles | PASS | Source-layering greps, 7 Mojo unit files, `emit-core-layouts` fixture and built-object checks (local clang-22 objects reproduce the canonical layouts). Binary-independent. |
| docs | PASS | 33 files incl. `--help` cross-checks against the Rust binary. |
| examples | PASS | All example checks against the Rust binary. |
| provenance | PASS | Provenance, selftest, input pins (engine version matches via the link). |

## Harness and VM-gated suites

| Suite | Verdict | Evidence |
|---|---|---|
| confidential-hooks | PASS | 5/5 hook checks (live reads, binary-independent). |
| confidential-ranges | SKIP | Needs `MEMVEIL_CONFIDENTIAL_RANGES=1` plus admitted guest evidence. |
| confidential-inventory | PASS | 3/3 inventory checks. |
| confidential-real | SKIP | Needs `MEMVEIL_CONFIDENTIAL_REAL=1` plus admitted guest evidence. |
| confidential-late-attach | SKIP | Needs `MEMVEIL_CONFIDENTIAL_LATE_ATTACH=1` with an admitted guest. |
| profile-semantics | PASS | 843 passed, 1 skipped (VM-harness unit tests). |
| vm-attempts | SKIP | Needs `MEMVEIL_VM_ATTEMPTS=1`. |
| vm-oracle | SKIP | Needs `MEMVEIL_VM_ORACLE=1` with qualified probes. |
| vm-lifecycle | SKIP | Needs `MEMVEIL_VM_LIFECYCLE=1` with qualified probes. |
| vm-copy | SKIP | Needs `MEMVEIL_VM_LIFECYCLE=1` with qualified probes. |
| vm-real-io | SKIP | Needs `MEMVEIL_VM_LIFECYCLE=1` with qualified probes. |
| vm-topwalk | SKIP | Needs `MEMVEIL_VM_LIFECYCLE=1` with qualified probes. |
| vm-kernels | SKIP | Needs `MEMVEIL_VM_KERNELS=1`. |
| vm-scenarios | SKIP | Needs `MEMVEIL_VM_SCENARIOS=1`. |
| vm-stop | SKIP | Needs `MEMVEIL_VM_STOP=1` with qualified probes. |
| vm-saturation | SKIP | Needs `MEMVEIL_VM_SATURATION=1` with qualified probes. |
| vm-cleanup | SKIP | Needs `MEMVEIL_VM_CLEANUP=1` with qualified probes. |

All SKIP verdicts above are the harness's own exit-77 path, verified by
running each suite under the selector.

## Retired suites (Mojo/C/shim internals)

Each retires with the named Rust replacement; `cargo test --workspace`
runs them. Report-replay assertions inside mixed suites duplicate the
`reports` suite, which runs green against the Rust binary.

| Suite | Replacement |
|---|---|
| unit (`test_reader`, `test_attempts`, `test_report`, `test_verdict`, `test_runtime`, `test_evidence_containment`) | `cargo test --lib` `capture::reader`, `analysis::attempts`, `model::report`, `model::validate` verdict tests, `platform::runtime`, `platform::evidence` |
| native-decode (C reference + Mojo differential) | `rust/tests/wire_compat.rs` (`attempts_payload_matches_c_dump`, `lifecycle_copy_matches_c_dump`) plus `crates/ebpf-common` corpus tests |
| attempts (C/mojo differential, counter flow, Mojo collector matrix) | `wire_compat.rs`, `capture::collector` tests, `rust/tests/probe_differential.rs`; replay checks duplicate `reports` |
| writer (Mojo encode/round-trip/shim probes, `mvshim.so`) | `model::encode`, `capture::writer` tests, `cli_parity.rs` `checkpoint_*`; checkpoint behavior also runs in `reader-adversarial` (7/7) and `record-failures` |
| signals (Mojo `signal_probe`) | `platform::signal` tests |
| identity | `model::identity` tests |
| correlation | `capture::correlation` tests |
| mappings | `analysis::mappings`, `analysis::engine`, `model::metric` tests |
| lifetimes | `capture::lifecycle` (wire/events/capture) tests |
| pools | `capture::pools`, `analysis::pools` tests |
| regions | `analysis::regions`, `capture::regions`, `model::regions` tests |
| conversion-normalize | `capture::normalize` tests |
| region-resolution | `analysis::regions`, `model::identity` tests |
| baseline | `platform::baseline` tests |
| diagnostics | `analysis::diagnostics` tests |
| stop | `capture::stop` tests |
| budgets | `render::*`, `analysis::*` ceiling tests; live ceilings proven by `perf-region` `active-ceiling-*` on the Rust binary |
| buildcache | No replacement: Mojo build-cache healing is deleted with the Mojo build; cargo verifies `Cargo.lock` offline. |

Also retired: `tests/perf/bench_encode.mojo` (referenced by no suite;
encode is covered by `model::encode` tests) and
`tests/package/test_mojo_link.py` (Mojo-linkage packaging check, in the
packagers' scope below).

## Needs-port suites (packagers own them; not run here)

`package`, `deb`, `rpm-journey`, `payload-gate`, `sbom`,
`release-runtime`, `preview-package`, `source-export`,
`extracted-robustness`. Verdict: DEFERRED. They build Mojo packages via
`tools/package*` / `tools/build-rpm`; the Rust packagers replace those
entry points and port the assertions.

## Packaging-tool gap lines (not suites; no binary contact)

- `tools/source_inventory.py`: RETIRED from parity scope (no port).
  Nothing in Rust mode executes it against the binary: it is
  binary-independent stdlib Python, and its only Rust-mode consumer,
  the `provenance` suite, passes green without depending on the Mojo
  input set (git `ls-files` in checkouts; the layout-agnostic
  `take_tree_inventory` whole-tree walk in archive mode, which already
  covers `rust/`). The Mojo-layout `INPUT_DIRS` admitted set is
  consumed only by `tools/package` and `test_source_export`, both in
  the packagers' needs-port scope, which owns the input-set decision
  at cutover.
- `tools/canonical_runtime.py`: UNPORTED. The v1 (`memveil-runtime/1`)
  Mojo-built bytes stay the canonical runtime baseline; no Rust-mode
  suite seals or verifies runtime bytes. The perf verdict (Rust replay
  141k records/s vs Mojo 35k/s on the same 600k input, both exact)
  decides the v3 Rust runtime seal, owned by the packagers.

## Rust fixes made for parity

1. Cargo-checkout profiles discovery (`rust/src/cli/doctor.rs`,
   `rust/src/platform/profiles.rs`). The Mojo layout contract assumes
   the executable one directory below the tree root, so the Rust binary
   at `rust/target/release/memveil` resolved a nonexistent profiles dir
   and `doctor`/`record`/`qualify`/`top`-live failed before doing
   anything. `resolve_profiles_dir` now prefers an adjacent readable
   manifest, then probes `<project>/profiles` and `<project>/../profiles`
   when the kernel-resolved executable sits under `target/{debug,release}`
   (covers the current `rust/` nesting and the post-cutover layout).
   Installed (`/usr/bin`) and packaged (`bin/`) layouts keep exact Mojo
   behavior; `default_profiles_dir` vectors are unchanged. Tests:
   `cli::doctor::tests::cargo_checkout_*` (5),
   `platform::profiles::tests::manifest_readable_probes_presence`.
   Proved by: `doctor` suite green (was: every live check exit 2).

## Assertion conflicts (all four resolved per controller ruling)

1. `record` `no-object` / `no-bridge` (`tools/test`, `suite_record`).
   RESOLVED (ruling C1: Rust-mode skip, `9ca52a4`): exactly these two
   cases skip in Rust mode with a documented cause (embedded objects
   cannot be absent; the static loader has no bridge to discover;
   refusals stay covered by `record-failures` plus the explicit-path
   record cases). Mojo path untouched (original conditions preserved).
   Evidence: `record` suite green in Rust mode with both skips printed.
2. Stale integrity expectations (5 in `tests/cli/test_uncertainty.py`,
   1 in `tests/perf/soak.py`). RESOLVED (ruling C2: approved update,
   `13276b5`): each expectation now asserts the true behavior both
   binaries exhibit (byte-identical JSON, hashes below; Rust
   `70c93779...` vs Mojo `5f1021ee...`). Per-expectation record:
   - `test_producer_correlation` (both subtests): `bounce_attempts`
     coverage `complete_for_scope` → `partial` (value stays `1`).
     Report sha256 `258c28aa717b...` / `a7f01302d9c5...`.
   - `test_relations_copy_only_preserves_occupancy`: live occupancy
     coverage → `partial` (value stays `4096`), and the
     `mapping_release` relation status → `partial` (loss `0`;
     previously hidden behind the first failure). `59d7f7574c84...`.
   - `test_relations_lost_release_withholds_occupancy`: copy-bytes
     coverage → `partial` (value stays `5120`). `fd079aba31f7...`.
   - `test_region_aggregate_gap_preserves_state`: shared-region
     coverage → `partial` (value stays `8192`). `0f4f06e4dc2d...`.
   - soak `soak-quality`: detail status → `partial`, loss stays `0`.
     `7fce051086f7...`.
   Cause in every case: capture-integrity verification withholds
   `complete_for_scope` for unverified captures
   (`Capture integrity unverified`); values are unchanged, only the
   coverage/status label was stale. Mojo path re-proved green on the
   updated expectations: `quality` 32/32 plus a 3-cycle unmodified
   soak, both without the selector.
3. `reader-adversarial` `test_stream_creation_failure_is_reported_after_regular_open`
   (`tests/cli/test_capture_integrity.py`, `report`+`top` verbs).
   RESOLVED (ruling C3: Rust-mode skip, `02f01e4`): skips in Rust mode
   with cause (no `fdopen` calls to interpose; exit 0 is correct) and a
   comment pointer to the equivalent native fault tests
   (`rust/src/capture/writer.rs` `faults::FaultPlan`
   pwrite/fsync/truncate/rename faults, `rust/src/capture/reader.rs`
   refusal tests). Open-failure refusals stay covered by
   `test_finalized_special_files_refuse_before_reading` (green on Rust).
   Evidence: capture-integrity 13/13 (12 pass + 1 skip) in Rust mode.
4. `perf-replay` paced phase (`tests/perf/replay.py`,
   `tests/perf/test_paced_reads.py`). RESOLVED (ruling C4:
   read-interposing lane, `7ee238f`): new `tests/perf/paced_reads_rust.c`
   interposes `read` (same env contract and receipt schema as the
   `fread` adapter, which is untouched); `replay.py` gains a
   mode-selecting `paced_adapter()` used by the paced phase and the
   gate test. No assertion changes. Design evidence: strace shows the
   Rust binary reading the stream with plain 64 KiB `read`s in one pass
   (sealed and unsealed). Evidence: paced gate 2/2 plus full
   `perf-replay` green in Rust mode (paced 600k lines over 60s, 3269
   calls, max 64 KiB, error 0, exact counts/bytes).

## Findings for follow-up (not suite-scoped fixes)

A. Embedded channel objects fail `.maps` verification
   (`platform::narrow`: `object refused: no .maps section`). The
   Aya/bpf-linker objects carry `maps`, not libbpf-style `.maps`, so
   `record` without `--object` (and privileged `doctor --load-check`)
   refuse at verification on every host. Live collection via embedded
   objects needs a design ruling (Aya-shape lane or pinned-hash trust)
   plus privileged/VM proof; not changed here.
B. Rust eBPF CO-RE layouts are a strict superset of the shipped
   profiles: `emit-core-layouts --check` against the Rust-built objects
   reports 17 extras, 0 missing. Cutover must re-extract `profiles/`
   from the shipped objects; `profiles/*.json` are untouched here (the
   Mojo `profiles` suite depends on them).

## Perf numbers (same host/inputs, single runs)

| Workload | Rust | Mojo | Budget |
|---|---|---|---|
| replay full 600k | 3.8s wall, 73MB RSS, 156k/s | 17.0s wall, 127MB RSS, 35k/s | 60s, 256MB |
| replay sealed 600k | 5.3s wall, 73MB RSS, verified | 20.4s wall, 126MB RSS | 60s, 256MB |
| region active-ceiling | 2.1s wall, peak 122.6MB | not measured | 60s, 256MB |
| soak full 30 min (un-bypassed) | 1326 cycles stable, peak 33.8MB, max cycle 0.7s | not measured | 256MB envelope |

Absolute thresholds (not Mojo-relative) gate the suites; Rust meets
every runnable gate with headroom.

## Environment used for the runs

Toolchain-proving commands were run as `env -u RUSTUP_TOOLCHAIN cargo`.
Test prerequisites were built with the tree's own commands into
ignored `build/`: `libbpf-mojo` cache via the `prepare_lmb` function
from `tools/build` (vendored tarball, digest matches the lock pin),
C native/shim targets via the `tools/build` clang lines, BPF objects
via the `build_bpf` function. Suite files changed only per the four
controller rulings above (2 Rust-mode skips, 6 approved expectation
updates, 1 Rust-mode skip with pointer, 1 test-side paced lane); no
fixture file was modified.

