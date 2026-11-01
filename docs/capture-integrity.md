<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Capture integrity and recovery

New captures emit session 0.1.4 with literal event-byte SHA-256, contiguous
sequences, and exact kind counts. Offline readers verify these bindings while
streaming and emit report 0.1.4. Verification detects accidental changes; it
does not authenticate a capture against an actor who can rewrite its digest.

Checkpoint recovery and finalization reserves are implemented. Legacy session
0.1.1/0.1.2/0.1.3 inputs remain readable, but reports label their arithmetic
`legacy_unverified`, withhold completeness, and return 4 under `--strict`.
Event 0.1.2 is unchanged. See the [current release limitations](release-notes.md#known-issues).

The later session/event/report 0.2.0 journal must preserve these guarantees.
Legacy session 0.1.1/0.1.2/0.1.3 and event 0.1.1/0.1.2 remain accepted, without
inventing integrity evidence. Versions are independent of the product,
BPF wire and bridge ABI; see [format compatibility](format-compatibility.md).

## Committed-byte record

Session 0.1.4 requires `capture.integrity` with:

| Field | Meaning |
| --- | --- |
| `algorithm` | Exactly `sha256` |
| `events_bytes` | Number of committed literal event bytes, including newlines |
| `line_count` | Number of committed event records |
| `first_seq`, `last_seq` | Nullable canonical u64 strings; null for the empty stream |
| `events_sha256` | SHA-256 of those literal bytes, never reserialized JSON |
| `kinds` | Exactly every kind admitted by the capture's event schema, each with a count including zero |

All u64 measurements use canonical decimal strings in the range
0..18446744073709551615; reject signs, leading zeros, fractions and overflow.
For event 0.1.2 the exact kind keys are `bounce_attempt`, `map_result`,
`unmap`, `copy`, `sync_request`, `transition_result`, `pool_sample`, `gap`,
`marker`, and `counter_snapshot`. Unknown, missing and extra kind keys fail.
An empty stream has zero bytes, lines and kind counts, null first/last
sequence, and SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Otherwise persisted sequence numbers are exactly 0..N-1, with first 0 and
last N-1, not merely increasing. Kind counts sum to the line count.

Normalization or encoding failure consumes no persisted sequence. Roll back
a torn append before advancing counts or digest; failed rollback poisons
the writer and prevents a finalized-valid claim. Incremental
`Sha256.update` and non-destructive `copy_finish` must support snapshots;
an `Integrity` snapshot includes only committed bytes. Check arithmetic
before updating any field. A capture-file digest hashes allowlisted metadata,
not observed memory contents. It detects accidental edits and truncation;
an actor able to rewrite both stream and digest defeats it.
It supplies no authenticity, attestation or host-access verdict.

## Reader and report behavior

Replay inputs are regular files: this applies to session metadata and event
streams in every supported format version. Open nonblocking, validate the type
on the same descriptor used for reading, and reject FIFOs, devices and directories
with exit 2. Finalized legacy/current regular symlinks and hardlinks remain
readable; checkpoint recovery keeps its stricter ownership and no-symlink rules.
A finalized capture is not an ongoing producer stream. The performance harness's
former FIFO pacing transport is replaced by bounded, test-only regular-file read
pacing; see [the performance protocol](performance.md#replay-protocol-and-targets).

Verify streams incrementally with bounded memory. A finalized 0.1.4 byte,
line, sequence, kind count or digest mismatch is `READ_INVALID` (exit 2),
with the discrepancy named. `--allow-partial` never repairs, bypasses or
falls back from a corrupt finalized session. A valid final session takes
precedence over a checkpoint; a present but corrupt final session fails.

Report 0.1.4 exposes integrity status `verified`, `legacy_unverified`, or
`checkpoint_prefix`, plus canonical `verified_bytes` and `verified_events` strings. Legacy inputs
have zero verified bytes/events. Text, Markdown and JSON explain the status.
Recovery emits `checkpoint_prefix` and `unverified_bytes` for the excluded suffix. Unverified integrity prevents
`complete`/`complete_for_scope` in every evidence channel. Legacy arithmetic
may still be displayed explicitly unverified, and legacy examples remain
readable. Verified integrity is necessary but never sufficient for complete
evidence: detail, aggregate, correlation, baseline and terminal quality stay
independent. Unknown is not zero, and finalized is not settled.

The following table applies to implemented report behavior.

| Input | Normal report | Strict report | Evidence rule |
| --- | --- | --- | --- |
| Valid finalized 0.1.4, complete evidence | 0 | 0 | Integrity alone does not prove completeness |
| Valid finalized 0.1.4, partial evidence | 0 | 4 | Preserve each quality channel and partial verdict |
| Valid finalized legacy session 0.1.1/0.1.2/0.1.3, event 0.1.1/0.1.2 | 0 | 4 | `legacy_unverified`, never complete |
| Altered finalized 0.1.4, with or without the partial flag | 2 | 2 | No checkpoint fallback |
| No final session, valid checkpoint, no partial flag | 2 | 2 | Explain recovery command and verified prefix size |
| No final session, valid checkpoint, `--allow-partial` | 4 | 4 | Only the verified checkpoint prefix contributes metrics |
| Missing both, invalid checkpoint, or unknown version | 2 | 2 | Never guess a reconstruction |

Current `record`, `report`, replay/live `top` already return 0 for valid
finalized output even when evidence is partial; `--strict` returns 4 unless
the verdict is complete. Current legacy tail recovery can return 0 normally
and 4 under strict mode. Runtime/internal or output failures return 1,
invalid usage/input/schema returns 2, and explicitly requested unavailable
collection returns 3. Findings do not by themselves change the exit code.
The checkpoint-recovery exit 4 is unconditional, including normal
mode. Invalid finalized evidence remains exit 2 in both modes.

Interim live `top` blocks say `unverified live stream`; replay refreshes say
`unverified replay prefix`. These text-only views withhold completeness and
do not claim a finalized file or durable checkpoint. Final blocks use the
fully consumed reader's verified or legacy status. Arithmetic is calculated
before the integrity quality overlay, preserving independent channel facts.

`tools/seal-capture SOURCE TARGET` is a development fixture tool, excluded from
runtime packages. It accepts only finalized synthetic sources and creates a
new `tests/fixtures/reader/sealed-*` directory. It refuses existing targets,
symlink paths and special source files, records source/output/tool hashes,
and explicitly renumbers the derivative from zero. Legacy originals remain
unchanged. Never seal observed data to manufacture qualification evidence.

## Checkpoint publication and locking

Before readiness, durably publish a zero-or-more-event checkpoint. Publish
another every 10 seconds or 1,000 committed events of a progressing poll loop. A checkpoint is a
session-shaped 0.1.4 snapshot with `finalized=false`,
`end_reason="checkpoint"`, prefix integrity, a monotonic checkpoint
generation and partial quality. It does not claim a closed measurement
window. A stalled loop does not promise at most ten seconds of loss.

Preserve held-directory-fd identity checks and no-replace final-session
publication. Refuse an existing target, symlink traversal, a concurrent
writer or a special-file target as a fresh capture. Use a verified dirfd,
owned regular files, `O_NOFOLLOW`, exclusive temporary creation and mode
0600 within the mode 0700 capture directory. Stale temporary files never
authorize overwriting unrelated files. Hold an exclusive nonblocking
directory advisory lock from verified creation through close; a recovery
reader takes a shared nonblocking lock on that verified directory and
refuses an active writer. Locking supplements identity/no-overwrite checks.
Races and swapped directory entries need explicit failure tests.

Commit order is append events, sync the prefix, write and sync a private
temporary checkpoint, atomically rename it, and sync its containing
directory. Also sync the capture directory's parent before announcing
readiness. A failed checkpoint preserves the last durable checkpoint and
increments `stop.checkpoint_failures` when a later checkpoint/final session
can persist that counter. It never upgrades quality.

Recovery verifies the exact prefix, session identity and counts. Ignore all
later bytes for metrics, including complete valid-looking lines; report
their byte extent as unverified. Never extend the stored digest to bless a
suffix. Invalid checkpoints, identity mismatches and missing evidence fail
rather than trigger raw suffix salvage.

## Reserve, finalization and signals

Allocate a real non-sparse **17 MiB reserve** before readiness: 16 MiB for
the maximum session plus 1 MiB margin. Establish an owned finalization
staging file before recording. Unsupported allocation must use actual writes
or refuse startup; verify allocation and sync it before readiness. Release
reserved space during finalization. Sync events, write and sync the final
session, rename without replacing another final session, then sync the
directory and its parent before announcing success. Only then remove the
checkpoint and sync that removal.

A controlled full-disk test must finalize on the admitted test filesystem.
If I/O or metadata failure still prevents finalization, return failure and
preserve the last durable checkpoint. There is no filesystem-independent
promise against storage failure. Failed fsync cannot pass. Process-SIGKILL
recovery and filesystem crash durability are distinct gates: a controlled
ext4 guest disk must survive hard power-cut after readiness/checkpoint,
remount and independent prefix verification. Other filesystems need their
own durability admission.

SIGHUP must follow SIGINT/SIGTERM's orderly stop latch. Ignore SIGPIPE before
the existing re-exec boundary. After durable capture publication, a failed
final stdout summary reports the capture path on stderr and preserves the
capture exit. Failure to create a requested report output remains an output
error. A lost final summary preserves the capture exit; standalone report output failures still return 1.

## Bounds and evidence

Preserve 64 KiB per event line including newline, 16 MiB per session/report,
JSON depth 64, default duration 60 seconds and event cap 1 GiB. Streaming
verification stays within the 256 MiB reference userspace RSS target;
report BPF memory separately. Existing rings remain 8 MiB for attempts and
32 MiB each for lifecycle/copy.

Implementation and qualification must independently recount bytes, lines,
kinds, sequence and digest, including empty captures and values above 2^53.
Exercise first/middle/last deletion, edit, append, reorder, duplicate, torn
line, count/kind/hash mismatch and unknown version in normal, strict and
partial modes. Exercise every write/sync/rename failure boundary, readiness
and successive checkpoints, stale temporary files, active writers, symlink
and directory swaps, unverified suffixes, SIGKILL, storage exhaustion and
hard power-cut. Synthetic tests prove their own boundaries; live filesystem
and exact packaged-artifact receipts remain separate requirements.

Checkpoint generations are positive canonical u64 values and increase on every attempted checkpoint, so failures may leave gaps. Checkpoints carry `finalized=false`, `end_reason="checkpoint"`, and partial terminal evidence. New final sessions and checkpoints record `stop.checkpoint_failures`; older 0.1.4 documents without that field remain readable. Recovery requires owned regular files and refuses symlinks, active writers, and replaced directory entries. Storage admission still requires separate full-filesystem and power-cut tests.

Replacement uses an atomic exchange and checks the displaced checkpoint identity before retiring it. Checkpoints are forbidden inside a rollback group; final publication commits a successfully completed closing group. Reserve release precedes the final events sync. A failed checkpoint rollback or rollback sync poisons the writer and prevents a finalized-success claim.
