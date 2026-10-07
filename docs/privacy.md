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
- Hook identity (`swiotlb:swiotlb_bounced`), backend, profile,
  measurement mode.

## Persisted per capture

- Session id, window bounds, end reason, finalized flag.
- Counter snapshots (bounded u64 attempt/byte counters).
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
Diagnostics on stderr are sanitized the same way.

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
- The metadata allowlist audits schemas (no
  payload/key/address/cmdline/environment property), BPF
  (exactly the two admitted kernel reads, no user-memory or
  debug helpers), environment reads (two names), and the
  frozen fifteen CLI flags.
- Offline replay is byte-identical under a scrubbed
  environment, and a syscall audit proves no network, BPF,
  BTF, tracefs, or checkout access.
- Owned-map inspection during live capture stays a live-gate
  item: it needs privileged capture on qualified probes and
  is not covered offline.
