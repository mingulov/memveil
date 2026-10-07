<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil privacy: what a capture contains

A capture directory holds exactly two files: `session.json`
(envelope, provenance, quality) and `events.ndjson` (one JSON
record per line). Both are allowlisted metadata; there is no
free-form payload channel.

## Persisted per bounce attempt

- Monotonic timestamp (`ts_ns`), sequence number.
- Requested byte count (`requested_bytes`).
- Force flag (`forced`: normal vs forced bounce path).
- Synthetic device id (`d000001`, ...) plus the observed PCI
  name scope (`0000:00:0c.0`) with unresolved driver identity.
  The catalog admits a name verbatim only when it matches the
  canonical `DDDD:BB:DD.F` scope; any other observed name keeps
  its distinct id but persists as `unresolved`. Distinct devices
  never merge; only the human-readable label degrades.
- Hook identity (`swiotlb:swiotlb_bounced`), backend, profile,
  measurement mode.

## Persisted per capture

- Session id, window bounds, end reason, finalized flag.
- Counter snapshots (bounded u64 attempt/byte counters).
- Default-pool allocator counters (`io_tlb_used`,
  `io_tlb_nslabs`, `io_tlb_used_hiwater`) sampled at
  capture start and close: aggregate slot counts only, no
  addresses or device state. Unreadable counters persist
  as unavailable halves with a reason, never as zeros.
  Transient and dynamic pools are not sampled.
- Quality per channel (detail, aggregate, correlation,
  baseline, terminal) with loss counts and reasons.
- Provenance: identity hashes of the admission inputs (BPF
  object, bridge library, kernel BTF/config/image/build-id,
  tracepoint format), attach/detach timestamps, output
  filesystem type, guest-mode signals. These identify the
  toolchain and kernel, never captured traffic.

## Never persisted

Payload bytes, encryption keys, PINs, hashes of captured
content, raw virtual or DMA addresses, full command lines,
environment dumps, hostnames, usernames, or IP/MAC addresses.
Diagnostics on stderr are sanitized the same way, and every
slash-bearing token keeps only its final path component, so
loader messages, refused paths, and echoed arguments cannot
smuggle home directories or machine layout into logs.
Basenames survive as operational identifiers; diagnostics must
not rely on slashes in prose. (`doctor` stdout keeps the full
probe paths from the operator's own profile: naming the denied
path is that report's operational purpose.)

## Handling notes

- Capture files are mode 0600 in a mode 0700 directory.
- The worked example (`examples/real-capture`) was reviewed
  field by field before inclusion; it contains a disposable
  VM boot id and nothing linkable to any real host.
- Report output inherits these bounds: it renders capture
  bytes and adds engine version plus computed counts only.
- MemVeil makes no network connections and runs no daemon;
  copying a capture directory is the only export path.

## Preview evidence

- `privacy-canary` fixture: control bytes, terminal
  sequences, and markdown-active punctuation in device names,
  drivers, and observer context replay neutralized in every
  format; observer context never renders; opaque identities
  refuse hostile punctuation at parse.
- `canary` close-out case: address-shaped, path-shaped,
  overlong, and interface-style wire names yield distinct
  `d00000N` ids with `unresolved` labels; the canary bytes
  appear in neither capture file nor any replayed report.
- Stderr canary: an echoed argument path keeps only its
  basename on stderr; the username and home prefix never
  appear.
- The metadata allowlist audits schemas (no
  payload/key/address/cmdline/environment property), BPF
  (pinned per-file read-site triples across probe, CO-RE
  macro, and relocating builtin reads; no user-memory or
  debug helpers), environment reads (two names), and the
  frozen fifteen CLI flags.
- Offline replay is byte-identical under a scrubbed
  environment, and a syscall audit proves no network, BPF,
  BTF, tracefs, or checkout access.
- Owned-map inspection during live capture stays a live-gate
  item: it needs privileged capture on qualified probes and
  is not covered offline.
