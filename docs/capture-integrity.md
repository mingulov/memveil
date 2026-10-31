<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Capture integrity and recovery

This is a **planned contract, not implemented behavior**. Current writers
emit session 0.1.3 and event 0.1.2; current reports emit 0.1.3. They do not
seal event bytes, publish recovery checkpoints, or reserve finalization
space. Edited or truncated legacy captures can still look complete, and a
missing final `session.json` is unreadable even with `--allow-partial`.
See the [current release limitations](release-notes.md#known-issues).

Session/report 0.1.4 are reserved for this contract; event 0.1.2 is unchanged.
The later session/event/report 0.2.0 journal must preserve these guarantees.
Legacy session 0.1.1/0.1.2/0.1.3 and event 0.1.1/0.1.2 remain accepted, without
inventing integrity evidence. Versions are independent of the product,
BPF wire and bridge ABI; see [format compatibility](format-compatibility.md).

## Committed-byte record (planned)

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
an actor able to rewrite both stream and digest defeats it. It supplies no
authenticity, attestation or host-access verdict.

## Reader and report behavior (planned)

Verify streams incrementally with bounded memory. A finalized 0.1.4 byte,
line, sequence, kind count or digest mismatch is `READ_INVALID` (exit 2),
with the discrepancy named. `--allow-partial` never repairs, bypasses or
falls back from a corrupt finalized session. A valid final session takes
precedence over a checkpoint; a present but corrupt final session fails.

Report 0.1.4 exposes integrity status `verified`, `legacy_unverified`, or
`checkpoint_prefix`, plus verified bytes/events. Text, Markdown and JSON
renderers must explain the status. Unverified integrity prevents
`complete`/`complete_for_scope` in every evidence channel. Legacy arithmetic
may still be displayed explicitly unverified, and legacy examples remain
readable. Verified integrity is necessary but never sufficient for complete
evidence: detail, aggregate, correlation, baseline and terminal quality stay
independent. Unknown is not zero, and finalized is not settled.

The following is the authoritative planned report exit table. It is not a
claim that current 0.1.3 readers perform verification or recovery.

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
The planned checkpoint-recovery exit 4 is unconditional, including normal
mode. Invalid finalized evidence remains exit 2 in both modes.

## Checkpoint publication and locking (planned)

Before readiness, durably publish a zero-or-more-event checkpoint. Publish
another every 10 seconds of a progressing poll loop. A checkpoint is a
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

## Reserve, finalization and signals (planned)

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
error. These are future changes; the current record summary write failure
returns 1.

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
