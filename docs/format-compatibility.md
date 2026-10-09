<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Format compatibility

Capture, event, session, and report schemas are versioned
independently; the frozen set (events 0.1.1, profiles 0.1.1;
session, report, doctor 0.1.0) is the only supported input.
The replay path treats every capture as untrusted and stays
offline: it never loads BPF objects, touches tracefs or
BTF, opens the network, or requires privileges.

## Reader policy (events 0.1.1, profiles 0.1.1, rest 0.1.0)

- Unknown schema major, unknown event kind, unknown field, or
  duplicated key: refused, exit 2. There is no last-wins, no
  silent field drop, and no minor-version tolerance in this
  release; compatible minor additive fields stay a documented
  future policy, never an implemented leniency.
- Exact byte bounds: session document 16 MiB, single line
  64 KiB including its newline, events total 256 MiB, JSON
  depth 64. Over-bound input is refused before it is parsed.
- Cross-record rules: every event matches the session id,
  sequence numbers strictly increase, timestamps land inside
  the half-open session window. Violations exit 2.
- Canonical integers: no leading zeros, no whitespace, no
  sign on u64 spellings; out-of-range and overflowing sums
  are refused, never wrapped.

`copy` records describe actual executed CPU copies and require
`source.measurement=observed`. Estimated or derived copy records
are refused with exit 2, including streams mixing them with observed
copies. Other event kinds retain their supported measurement enum.

## Partial mode

`report --allow-partial` recovers exactly one shape: a final
record that is a clean truncation (the tail classifier says
incomplete and no complete byte already proves it invalid).
Recovery drops the tail, reports through exit 4, and never
repairs JSON. A final record that parses but lacks its
newline, an unterminated tail that is corrupt rather than
truncated, and any interior corruption exit 2 in both modes.

## Fuzzing

`tests/fuzz/run.py` mutates seed captures deterministically
and replays each case through the built binary: exits stay in
{0, 2, 4}, exit 2 keeps stdout empty with a stderr reason,
exit 0 JSON parses, and no crash marker appears. The smoke
lane runs 200 seeds; the campaign lane runs 10,000 seeds
(`MEMVEIL_FUZZ_SEEDS` overrides) and records the binary hash.
Violations retain their seed and input; promoted regressions
become named adversarial fixtures. Campaign time is sampling,
not exhaustive proof.
