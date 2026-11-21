<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Rust-native negative copy objects (test-only)

The kernel-matrix scenario mode stages four negative copy
objects (`swiotlb_copy-<name>.bpf.o`) that must refuse or
degrade honestly: one load refusal plus three honest
degradations. The pre-cutover C recipe is retired; this
directory holds the test-only deterministic producer that
rebuilds the four objects as Rust-native Aya probes, plus the
offline proofs and the run-input manifest a later run verifies
staged bytes against.

No live VMs, no boots, no privileged calls anywhere here:
builds, file writes under `build/bpf-negative/`, and static
proofs only.

## Recovered specs (pre-cutover C recipe)

Each C wrapper included the product copy probe with one macro
override (`tests/bpf/negative/*.bpf.c` at the recipe commit):

| name | override | intended defect |
|---|---|---|
| `renamed_field` | `#define nslabs mvt_nslabs` | pool field renamed: load must refuse |
| `widened_layout` | `mv_layout_ok(g,w)` compares `w==4` as `8` | widened local width: copies stay unknown |
| `wrong_shift` | `mv_slot_index(s,e,n,t,i)` called with `n*2` | doubled slot count: geometry never matches |
| `wrong_argcnt` | `#define MV_ARGS_BOUNCE 4` | wrong hook arity: bounce hooks stay out |

The retired proof (`tests/bpf/test_negative_objects.py`)
showed: the renamed object relocates `mvt_nslabs` and is
otherwise identical; the guard-only variants keep the product
relocation records exactly, differ in the bounce sections,
stay identical in the sync sections, and carry the exact
immediates (mask width 8 vs 4, bounce arity 4 vs 5 with sync
still 5).

## Aya re-expression

The Aya probe (`crates/ebpf/src/copy.rs`) emits no field
relocations: every kernel offset resolves at runtime from the
host-installed `mv_copy_offs` table, and the loader pins
attach targets in frozen specs (`src/bpf/attach.rs`
`copy_specs`) instead of reading the object. The four
mutations re-express the same defects under that shape:

| name | Aya delta (one anchored hunk in `copy.rs`) | effect |
|---|---|---|
| `renamed_field` | `nslabs` bindings renamed to `mvt_nslabs`; the renamed read bypasses the trusted helper path with a direct kernel dereference | kernel verifier rejects the bounce programs at `PROG_LOAD` (`EACCES`); load refuses exactly as prescribed |
| `widened_layout` | `tab.mask_size != 4` becomes `!= 8` | layout guard never matches the real 4-byte field: copies stay unknown with reason `LAYOUT` |
| `wrong_shift` | `slot_index` called with `nslabs.wrapping_mul(2)` | span guard never matches real geometry: copies stay unknown with reason `SHIFT` |
| `wrong_argcnt` | `MV_ARGS_BOUNCE` 5 becomes 4 (`MV_ARGS_SYNC` stays 5) | bounce entry/exit raise the arg-count flag and stay out; sync hooks unchanged |

Why the renamed defect changed mechanism: no object-local
rename can refuse load through the relocation path anymore.
The loader ignores the object's section suffix (frozen spec
targets always resolve on an admitted kernel), and renames
of programs, maps, or section kinds land in the open/geometry
gates (`load-failed`), never the verifier. The one
load-judged layer that reads program text is the kernel
verifier, so the renamed field is expressed there: a
reference the verifier cannot validate. The prescription
(`copy-actual` load `unavailable` / `verifier-rejected`) is
reached through the product's own chain: `Session::open`
plus maps/programs gates pass (`src/bpf/session.rs`), the
first bounce `PROG_LOAD` fails `EACCES`
(`src/capture/loadcheck.rs` `diagnose_program_loads`, whose
errno-less failures also default to `EINVAL`), and
`memveil doctor --load` maps `EACCES`/`EINVAL` to
`verifier-rejected` (`src/cli/doctor.rs`). The base helper-path
object loads, proved as the positive control below.

## Files

- `producer.py` — the deterministic builder. Verifies every
  probe input against its pinned sha256, stages one mutant
  tree per name under `build/bpf-negative/src/`, applies the
  exact-once anchors, builds with the pinned nightly recipe
  from `tests/vm/fixtures/aya/README.md`, and writes the
  canonical outputs plus `run-input-manifest.json`. Refuses
  on drifted inputs, missing anchors/toolchains, or
  unexpected occupants (known retired C bytes move aside to
  `*.retired-c.bpf.o`, never deleted).
- `proof.py` — the offline proofs (script or import): per
  object, the Aya ABI legs (section set, declared maps,
  program exact-set, sync identical, bounce differs, no
  CO-RE relocations, no path leaks, loader-parse agreement
  through the oracle) plus the defect leg (renamed: one
  fewer probe read and exactly one added scalar deref per
  bounce function against pinned windows; layout/argcnt:
  single-immediate swaps anchored on the width load and the
  arg-count call; shift: doubling shift plus span shift
  `0xc`), plus the frozen-target BTF resolution control.
- `oracle/` — a tiny crate pinned to the product's `aya-obj`
  `0.3.0`: the loader's own parser as an unarmed
  parse-only oracle (declared maps, programs, BTF
  relocations).
- `run-input-manifest.json` — the run-input manifest: four
  name-to-sha256 entries, producer revision, build pins,
  baseline copy hash, and the candidate manifest digest it
  binds to. A later run verifies staged bytes (host and
  guest) against this file.
- `../test_bpf_negatives.py` — the unarmed self-tests:
  producer determinism (rebuild twice, identical shas),
  manifest round-trip and committed-manifest check, base
  reproduction control, and proof re-runs.

## Use

Build all four plus the manifest (from the repository root):

    python3 tests/vm/negatives/producer.py

Prove the staged bytes:

    python3 tests/vm/negatives/proof.py

Self-tests (also wired into `tools/test profile-semantics`):

    python3 -m pytest tests/vm/test_bpf_negatives.py -q

## Rerun wiring still needed (not this producer)

Staging plus host-and-guest manifest verification belong to
the future armed rerun, outside this directory: copy the
four canonical objects to the run root's `build/bpf-negative/`,
verify each sha256 against `run-input-manifest.json` on the
host before booting, re-verify the same shas inside the guest
from the exported `neg/` directory, and record the manifest
digest with the scenario receipt. That wiring is specified,
not implemented, here.
