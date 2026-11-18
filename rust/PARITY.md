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
| record | FAIL | 14 Mojo unit files + 13 CLI cases pass. `no-object` and `no-bridge` fail: premises impossible for the Rust binary (embedded objects, statically linked loader). See conflict 1. |
| qualify | PASS | Mojo units 47+9, 12 CLI refusal cases, oracle-accepted fixture mint. |
| top | PASS | Mojo unit plus full CLI harness incl. live-refusal cases. |
| oracle-ledger | PASS | 12/12 pytest. |
| quality | FAIL | 27/32 pass. 5 failures are stale pre-integrity expectations, byte-identical on the Mojo binary/sources. See conflict 2. |
| reader-adversarial | FAIL | Mojo unit 15/15, capture-integrity 11/13, adversarial own-checks 24/24, checkpoint-recovery 7/7. The `fdopen`-injection case cannot fire on Rust (no C stdio). See conflict 3. |
| fuzz-smoke | PASS | Oracle 4/4, 200 cases 0 failures. |
| fuzz-campaign | PASS | Oracle 4/4, 10000 cases 0 failures (31.6s). |
| record-failures | PASS | Mojo stdout unit, stdout-errors, capture-failure and durability oracles (LD_PRELOAD shims fire on Rust). |
| output-paths | PASS | Path-swap cases plus symlink/fifo case. |
| privacy | PASS | Canaries, metadata allowlist, skip codes, pytest guard. |
| render-escaping | PASS | All escaping checks. |
| offline-environment | PASS | Exit/identical/traced checks. |
| perf-replay | FAIL | Full (600k) and prefix checks pass: 3.8s wall / 73MB RSS (budgets 60s / 256MB). Sealed phase passes standalone: verified, 5.3s / 73MB. Paced phase blocked on the `fread` adapter. See conflict 4. |
| perf-region | PASS | 234/234 incl. wall/RSS budgets (active-ceiling 2.1s, peak 122.6MB). |
| soak | FAIL | `soak-quality` cycle 0 fails identically on Mojo (stale expectation). Bypassed triage: full 30-min run, 1282 stable cycles, peak 34MB, max cycle 1.4s, zero failures. See conflict 2. |
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

## Assertion conflicts (need an explicit decision; none worked around)

1. `record` `no-object` / `no-bridge` (`tools/test`, `suite_record`).
   Expects exit 3 `no object: pass --object PATH` when no `--object`
   and no bundle/system object file, and exit 3 `no bridge` when no
   bridge source. The Rust binary embeds its channel objects and links
   its loader statically, so neither premise can hold: observed exit 3
   `object refused: no .maps section` (embedded verification, see
   finding A) and exit 3 `tracefs denied (privilege)` (precheck refusal
   past discovery), both residue-free. No Rust change can satisfy the
   assertions without deleting the embedded fallback. Proposal: skip
   these two cases in Rust mode; discovery coverage stays in
   `cli_parity.rs` record vectors.
2. Stale integrity expectations (5 in `tests/cli/test_uncertainty.py`,
   1 in `tests/perf/soak.py`). `test_producer_correlation` (2 subtests),
   `test_relations_copy_only_preserves_occupancy`,
   `test_relations_lost_release_withholds_occupancy`,
   `test_region_aggregate_gap_preserves_state`, and soak `soak-quality`
   expect `complete_for_scope` where both binaries now report `partial`
   (`Capture integrity unverified`), since capture-integrity
   verification landed after the test was last touched. Proven
   Mojo-identical: same 5 failures via the Mojo binary and via `mojo run`
   of current sources; same `soak-quality` failure via the Mojo binary.
   Making Rust report `complete_for_scope` would diverge from Mojo.
   Proposal: update the six expectations to the integrity-aware behavior.
3. `reader-adversarial` `test_stream_creation_failure_is_reported_after_regular_open`
   (`tests/cli/test_capture_integrity.py`, `report`+`top` verbs).
   Expects an LD_PRELOAD `fdopen` failure on `events.ndjson` to yield
   exit 2 `cannot open stream`. The Rust reader never calls `fdopen`
   (proven: marker absent, exit 0, normal output; Mojo marker present,
   exit 2). Routing Rust file reads through C stdio to trip the hook
   would contort production I/O for the test. Proposal: skip in Rust
   mode; open-failure refusals stay covered by
   `test_finalized_special_files_refuse_before_reading` (passes on Rust).
4. `perf-replay` paced phase (`tests/perf/replay.py`,
   `tests/perf/test_paced_reads.py`). The pacing adapter interposes
   `fread` only, so no receipt is ever written for the Rust binary and
   the paced checks plus the `test_paced_reads.py` gate fail. Full,
   prefix, and sealed checks all pass (numbers below). Proposal: port
   the adapter to interpose `read` for a Rust-mode paced lane (test-side
   change).

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
| soak full 30 min (bypassed stale line) | 1282 cycles stable, peak 34MB, max cycle 1.4s | not measured | 256MB envelope |

Absolute thresholds (not Mojo-relative) gate the suites; Rust meets
every runnable gate with headroom.

## Environment used for the runs

Toolchain-proving commands were run as `env -u RUSTUP_TOOLCHAIN cargo`.
Test prerequisites were built with the tree's own commands into
ignored `build/`: `libbpf-mojo` cache via the `prepare_lmb` function
from `tools/build` (vendored tarball, digest matches the lock pin),
C native/shim targets via the `tools/build` clang lines, BPF objects
via the `build_bpf` function. No suite or fixture file was modified.

