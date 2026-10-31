<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Format compatibility

Product versions, BPF wire versions, native bridge ABI versions and each
external schema family are independent. The current exact contracts are:

| Family | Accepted runtime input | Current output | Other versions / retained contracts |
| --- | --- | --- | --- |
| Session | 0.1.1, 0.1.2, 0.1.3 | 0.1.4 | 0.1.0 refused (not shipped) |
| Event | 0.1.1, 0.1.2 | 0.1.2 | 0.1.0 refused (not shipped) |
| Profile | 0.1.1, 0.1.2 | Authored profile documents | 0.1.0 refused (not shipped) |
| Report | None (output only) | 0.1.3 | 0.1.0, 0.1.1, 0.1.2 |
| Doctor | None (output only) | 0.1.1 | 0.1.0 |
| Receipt | 0.1.0 | 0.1.0 | None |

The runtime constants and `toolchain.lock.json` define the implemented set;
retained schema files alone do not admit an input. All listed legacy session
and event inputs remain readable. A capture's event version is checked per
record; a session version does not silently upgrade its event records.

Events 0.1.2 adds true-only copy markers `pool_private` and
`offset_past_allocation`. Profile 0.1.2 adds CO-RE-derived layouts checked by
kind and size instead of exact offsets. Session 0.1.1 requires terminal
`stop` evidence; 0.1.2 adds optional correlation relations; 0.1.3 adds the
optional record verdict and `drain_completed`/`submit_after_drain` stop keys.
Fields introduced in a later version are refused in older documents. Session
0.1.1/0.1.2/0.1.3 can carry optional `boot_id`. Report 0.1.2 adds the required
verdict, and 0.1.3 adds `LONG_LIVED_NOT_EVALUATED`. Reports are output only;
the renderer emits the current version and does not read older reports.

## Integrity implementation boundary

Session 0.1.4 is emitted by the collector and accepted by the structural
parser. Offline readers refuse it until event-file verification is available.
Legacy re-encoding keeps session 0.1.3. This intermediate writer-only support
is not a release candidate.

## Reserved versions (planned, unavailable)

- Report 0.1.4 and durable recovery remain planned. Session 0.1.4 writing
  is implemented as described above. Event 0.1.2 stays unchanged.
- Session, event and report 0.2.0 are reserved for the opt-in conversion
  request/result journal. It must retain integrity and recovery guarantees;
  successful API results cannot establish physical state or range lifetimes.
- The reserved report/journal versions are not accepted or produced and have
  no schema files yet. Old schema files remain immutable. Product 0.1.1 is
  the planned hardened ordinary-Linux preview; product 0.2.0 is the planned
  journal and real-SNP qualification target. Neither name is a qualification
  receipt. The later 0.3.0 security milestone is separate from these formats.

The [integrity and recovery contract](capture-integrity.md) specifies the
required fields, literal-byte verification, quality demotion, durable
publication ordering and authoritative exit table for those planned readers.

The replay path treats every capture as untrusted and stays
offline: it never loads BPF objects, touches tracefs or
BTF, opens the network, or requires privileges.

## Current reader policy

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

## Current legacy partial mode

`report --allow-partial` recovers exactly one shape: a final
record that is a clean truncation (the tail classifier says
incomplete and no complete byte already proves it invalid).
Recovery drops the tail, reports through exit 0 with a
partial verdict, and never repairs JSON. A final record
that parses but lacks its
newline, an unterminated tail that is corrupt rather than
truncated, and any interior corruption exit 2 in both modes.

This tail behavior does not verify capture-file integrity. It will not apply
to an altered finalized 0.1.4 capture: that input must fail with exit 2, even
with the partial flag. Planned unfinalized recovery uses only a verified
checkpoint prefix and returns 4 in normal and strict modes.

## Planned conversion-journal boundary

The planned selector is `record --capability conversion-journal`, with the
same selector on live `top`. Journal-only collection must work without attempt
hooks; an omitted capability keeps the current attempt-only default. Lists
containing existing capabilities preserve their implicit attempt requirement,
including mixed journal/ordinary lists. `--journal-object PATH` is an optional
object override, with normal discovery when absent. An explicitly requested
unavailable journal refuses with exit 3; journal-only `--device` is invalid
(exit 2) because conversion scope is global. These options are planned and
are absent from current help.

The journal observes admitted `set_memory_decrypted`/`set_memory_encrypted`
requests and native results, preferring fexit arguments/results with bounded
entry/exit window membership. A kprobe fallback needs its own profile and
equivalence evidence. Records describe direction/target, requested pages/bytes,
native result and operation token, with optional observed path label/class.
The shipping wrapper adapter must leave `region` unavailable and `effect`
`request_only` (or `unknown` when evidence is insufficient). Exact journal
field shapes and wire layout need a separate source-admitted schema freeze;
this reservation does not invent that layout.

`--journal-callers` is separately opt-in, requires the journal, and is off by
default: caller status is `disabled` and no stack is collected. When enabled,
resolve at most 16 frames in memory to bounded allowlisted `symbol [module]`
labels. Unresolved/truncated/ambiguous paths stay explicit. Never persist raw
addresses, raw stack frames, symbol offsets, task names, kallsyms dumps,
payloads, keys or memory-content hashes, including diagnostic artifacts.
Capture-file hashes remain allowed. A label describes an observed path,
not proved causal origin. The ordinary channels retain their existing
[metadata allowlist](privacy.md).

Native failures and censored in-flight calls stay distinct. Never net
conversion counts into shared bytes, infer a reverted range or claim a state
union. Ordinary-Linux no-op API calls prove transport only. Quiet rings,
detached links or a global in-flight count alone do not prove a settled window.
Every journal report must name boot/pre-attach, MMIO, kexec/accept and
unobserved-path exclusions. Real SNP I/O and owned conversion/reversion tests
must qualify the exact packaged artifact before a confidential support claim.

## Fuzzing

`tests/fuzz/run.py` mutates seed captures deterministically
and replays each case through the built binary: exits stay in
{0, 2} (the harness never passes --strict), exit 2 keeps
stdout empty with a stderr reason, exit 0 JSON parses, and
no crash marker appears. The smoke
lane runs 200 seeds; the campaign lane runs 10,000 seeds
(`MEMVEIL_FUZZ_SEEDS` overrides) and records the binary hash.
Violations retain their seed and input; promoted regressions
become named adversarial fixtures. Campaign time is sampling,
not exhaustive proof.
