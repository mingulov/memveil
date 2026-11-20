<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Qualification records

This directory holds the committed qualification records for a
release candidate. The seal binds the policy digest at the source
commit C; the qualification commit Q carries the records below
plus `packaging/tested-payload.sha256`. Nothing else may change
between C and Q (see the evidence-only rule).

## Layout at Q

| Path | Schema | Written by |
|---|---|---|
| `packaging/candidate-policy.json` (at C) | `memveil-candidate-policy/1` | release owner, before the seal |
| `packaging/qualifications/candidate.json` | `memveil-candidate/2` | `release` workflow seal job |
| `packaging/qualifications/qualification.json` | `memveil-qualification/1` | qualifier, with the campaign |
| `packaging/tested-payload.sha256` | checksum lines | `release` workflow qualify job |
| `packaging/qualifications/remote.json` | `memveil-remote-custody/1` | operator, after a clean import |

`candidate.json` is a byte copy of the sealed manifest: its
SHA-256 must equal the dispatched `candidate_sha256`, and its
`source.commit` must equal C. `qualification.json` binds one
signed gate receipt per required gate plus the evidence archive
record (`qualification-evidence.tar.gz`). The digest record
lives beside the archive file, never inside it; consumers
refuse an inner copy. `remote.json` binds the
import run that staged the candidate: repository, run, artifact,
signer commit, and custody digests.

## Evidence-only rule

Q must descend from C with no merges, and every changed path in
every commit between them must be `packaging/tested-payload.sha256`
or a single-level `packaging/qualifications/*.json` file (lowercase
`.json`, nonempty stem, no subdirectories). The custody CLI
re-checks this rule on every run; anything else fails closed.

## Schemas

The `/2` documents are the sealed-candidate family:

- `memveil-candidate/2`: the sealed manifest (source, toolchain,
  build receipt, bundle manifest, policy, file closure, and the
  six artifacts: bundle, deb, rpm, source, SBOM, provenance).
- `memveil-local-build/2`: the provenance artifact (truthful
  build origin, receipt outputs, subject digests).
- `memveil-matrix-input/2`: the signed matrix gate inputs
  (`matrix_directory` plus the evidence inventory digest).

The `/1` documents are the qualification family:
`memveil-qualification/1` (per-gate bindings),
`memveil-gate-receipt/1` (signed inputs binding per gate),
`memveil-gate-input/1` (non-matrix measurements),
`memveil-candidate-policy/1` (claim, required gates, trusted
signing-key digests, campaign retention), plus the custody pair
`memveil-candidate-import/1` (holding-draft statement) and
`memveil-remote-custody/1` (import-run receipt).

Sizes are canonical unsigned decimal strings, digests are
lowercase hex, and every JSON record the verifiers consume is
canonical bytes (sorted keys, compact separators, one trailing
newline).

## Rendezvous names

- Holding draft release tag: `candidate-<candidate_sha256>`
  (exactly eight assets: the six sealed artifacts plus
  `qualification-evidence.tar.gz` and `qualification.json`
  beside it).
- Stored workflow artifact name: `candidate-<candidate_sha256>`.
- Final release tag: `v<version>` from `Cargo.toml` at C.
- Campaign retention is 30 to 90 days; workflow artifacts keep
  90 days so the evidence outlives the campaign.

## Dispatch order

One `mode: seal` dispatch runs seal, sign, and qualify
(the holding draft with the campaign evidence must exist
before dispatching); then walk one custody stage per
dispatch with the ref at Q: `import`, `dry-run`, `promote`.
Dry-run refuses when the final tag already exists; after it
is green, the owner creates `v<version>` on C and only then
dispatches promote with the matching authorization. Promote
requires the tag to resolve to C. Custody dispatches consume
stored bytes only and never rebuild the candidate.
