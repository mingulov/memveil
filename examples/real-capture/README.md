# Worked example: real bounce-attempt capture

Thirty real `swiotlb_bounced` tracepoint events plus four counter
snapshots, captured live in a disposable virtme-ng guest (pcnet32
NIC with a 32-bit DMA mask, 30 adaptive pings, 20 s window,
kernel 7.0.0-34-generic, validated profile
`linux-x86_64-7.0.0-34-generic`). The guest ftrace oracle matched
the persisted detail exactly (event count and byte totals), with
zero loss on every channel.

## Files

- `events.ndjson` — 30 `bounce_attempt` detail events and 4
  `counter_snapshot` aggregates (never added together).
- `session.json` — capture envelope: window, provenance,
  device catalog, quality. `detail` and `aggregate` are
  `complete_for_scope` with `loss_count` 0; `terminal` stays
  `partial` because settlement after detach is unproven.

Reviewed before inclusion: allowlisted attempt metadata only
(synthetic device id, observed PCI name scope, byte counts,
timestamps, force flags). No payloads, keys, raw addresses,
command lines, or host identifiers.

## Try it

From the bundle root (or a source checkout, with
`build/memveil` in place of `bin/memveil`):

    bin/memveil report --format text examples/real-capture
    bin/memveil report --format json examples/real-capture
    bin/memveil report --format markdown examples/real-capture

Expected: exit 4 (materially incomplete: terminal quality is
partial by design), `bounce_attempts = 30`, detail loss 0.
Lifecycle, copy bytes, and sharing transitions render as
unavailable: this capture proves attempts only.
