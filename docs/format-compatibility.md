<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Format compatibility

Capture, event, session, and report schemas are versioned
independently; the frozen set (events 0.1.1 and 0.1.2,
profiles 0.1.1, session 0.1.1 and 0.1.2; report 0.1.1,
doctor 0.1.0) is the only supported input. Events 0.1.2
adds the true-only copy markers `pool_private` and
`offset_past_allocation`; 0.1.1 stays frozen and accepted.
Session 0.1.1 adds the required terminal
stop object; 0.1.0 session documents are refused, never
tolerated. Session 0.1.2 adds the optional correlation
relations object; 0.1.1 stays frozen and accepted.
The replay path treats every capture as untrusted and stays
offline: it never loads BPF objects, touches tracefs or
BTF, opens the network, or requires privileges.

## Reader policy (events 0.1.1/0.1.2, profiles 0.1.1, session 0.1.1/0.1.2, report 0.1.1, rest 0.1.0)

- Unknown schema major, unknown event kind, unknown field, or
  duplicated key: refused, exit 2. There is no last-wins, no
  silent field drop, and no minor-version tolerance in this
  release; compatible minor additive fields stay a documented
  future policy, never an implemented leniency.
- Exact byte bounds: session document 16 MiB, single line
  64 KiB including its newline, events total 1 GiB by default, JSON
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

## Correlation relations (session 0.1.2, report 0.1.1)

The producer splits correlation evidence into three relation
classes (`mapping_release`, `copy_attribution`, `sync_attribution`)
under `quality.correlation.relations`, keeping the aggregate rollup
as the channel body. The rollup is `complete_for_scope` only when
every class is, `not_applicable` only when every class is, else
`partial`, and its reason names every non-complete class in fixed
class order with a bounded summary of their causes.

Relations in a `0.1.1` document are refused whatever the key order,
so the frozen schema needs no new parser. A `0.1.2` document without
relations, like every `0.1.1` document, expands
legacy-conservatively: the aggregate applies to every class, and
analysis keeps its coarse degradation. Only a present relations
object narrows uncertainty to one class: copy-attribution-only loss
preserves proven occupancy, while unknown or lost releases still
withhold it, and a dangling copy reference never excuses a dangling
sync reference.

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
