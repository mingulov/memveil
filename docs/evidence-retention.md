# Evidence retention and row receipts

Gate runs and matrix runs prove themselves with retained evidence
plus a receipt that re-derives the verdict. This document states
what is kept, what the receipts carry, and which refusals keep a
missing or drifted file from becoming a qualification claim.

## Gate evidence

When `MEMVEIL_EVIDENCE_DIR` names a workflow-owned directory, each
VM gate copies its verified exports there, into
`<evidence>/gates/<gate>/`, with a `receipt.json` of schema
`memveil-gate-evidence/1`. Sources are read exactly once into a
staging directory outside the gates tree; grammar validation and
the receipt proof run against those staged bytes, and the finished
directory is published atomically, so a failure leaves no partial
gate directory behind.

The receipt records the gate identity, the disposition
(`passed`, `failed`, `skipped`, `cleanup-uncertain`), a
completeness flag, the hashed file inventory, per-file errors, and
an allowlisted detail object. `complete` is true only for a passed
gate with verified files and no file errors. Per-file errors use
fixed tokens: `missing sidecar`, `hash mismatch`, `unreadable
source`, `copy failed`, `missing export`, `no verified exports`.
A passed gate without verified exports raises instead of
publishing; lane receipts for suites that ran no gate exports can
never pass.

Only allowlisted metadata crosses into retained evidence: file
hashes, counts, flags, and short tokens. Payloads, keys, raw
addresses, full command lines, and environment text are refused;
see `docs/privacy.md` for the capture privacy rules.

## Matrix row receipts

`tools/kernel-matrix` writes one evidence directory per kernel
plus a `receipt.json` of schema `memveil-matrix-row/1` inside
it. The receipt carries the full qualification fields:

- `source`: the memveil commit and dirty flag plus the pinned
  libbpf-mojo version and tarball hash.
- `toolchain`: the toolchain lock pins and the lock hash.
- `artifacts`: the guest-measured binary hash, dpkg version, BPF
  object hashes, and bpftrace/bpftool versions (never paths).
- `kernel`: release, boot label, uname, modules, version,
  lockdown, config and BTF hashes with their measurement
  status, hook presence, the lock source, and the expected
  harness tools.
- `profile`: matrix rows assert lock expectations and doctor
  verdicts, not shipped profiles; the receipt says so and names
  the validated profile for the release when one exists.
- `workload` and `command`: the executed workload
  (duration, dd count, deb or bundle kind) and the sanitized
  invocation selector. Raw command lines and paths never
  cross; the boot command file stays out of the inventory.
- `expected` and `actual`: the lock verdicts plus the row
  checks (or per-scenario statuses) with the row verdict.
- `oracle`: the oracle mode, text hash, stderr presence, and
  lost perf-event count; absent is recorded as absent, never
  as zero.
- `losses`: the structured per-channel loss bounds, shortfalls,
  allowances, and attribution behind the channel verdicts.
- `cleanup`: the timeout flag plus fixed tokens for busy-tree
  errors, never raw error text with paths.
- `files`: the hashed inventory of every sibling evidence file.

A row is labeled `smoke` when its workload differs from the
qualification workload (60 s, dd count 128). Label and verdict
are recomputed from the receipt fields, not trusted from them.

## Refuse-to-qualify rules

- An existing evidence directory refuses overwrite; use a fresh
  `--out`.
- An unverified kernel cache fails the row instead of booting.
- A row whose receipt cannot be written fails with the
  `receipt` check; the console names the reason.
- Merging a summary refuses rows whose evidence dir is gone,
  so a verdict never outlives its row.
- `tools/kernel-matrix --out <dir> --verify-out` re-derives
  every row receipt under the directory without booting: it
  verifies each hash, cross-checks every transcribed claim
  against the sibling bytes, matches each row against its
  `<id>.json` rec and `summary.json` entry, and recomputes
  each verdict. It exits nonzero on any drift, addition,
  absence, or mismatch.

## Retention policy

A support claim keeps, per row: the row directory with its
`receipt.json`, the `<id>.json` rec, `summary.json`,
`harness.json`, and the tested artifact identity (the deb or
bundle hash plus the binary and BPF hashes in the receipt).
The [Kernel generations](support.md#kernel-generations) table
is such a claim: every `PASS` there traces to one retained
row of this shape.

Delete none of these parts while the claim stands.
`--verify-out` fails on any drift, addition, or absence, and
the row's `PASS` stops being a claim the moment it stops
re-deriving. Keep each set until the qualified artifact is
superseded by a newer qualified run.

## Re-deriving one row elsewhere

1. Copy the row directory (`receipt.json` plus its siblings)
   to a machine with this repository checked out. No build
   tree, raw run directories, or VM host is needed.
2. Run `tools/kernel-matrix --out <parent> --verify-out`
   and expect exit 0 with `row re-derived PASS from the
   receipt` for the row.
3. Any tampered, added, or missing file fails with its
   reason. The verdict is recomputed from the receipt
   instead of trusted from it.

Re-derivation re-proves transcription, provenance, evidence
integrity, and consistency. It does not re-execute the
verdict predicates, whose host-transient inputs (live
validator runs, pre-shrink captures) no longer exist.
