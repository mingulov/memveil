<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# External schema notes

These are **producer contracts**, not a generated description of existing
software. The schemas are self-contained JSON Schema Draft 2020-12 files;
validation never fetches references from the network. Each family is
versioned independently of the product version, the native bridge
ABI, and the BPF wire version: events are at `0.1.1` (wire
generations and unknown sync offsets); profiles are at `0.1.1`
(tracing-hook bindings); session is at `0.1.1` (terminal stop
evidence); report and doctor stay at `0.1.0`.

## Files and integer representation

A capture directory contains `session.json`, `events.ndjson`, and optionally
`report.json`. Validate each line of the event stream separately. Every
record has a session ID and schema version. The session and report carry an
explicit `synthetic` flag, which must survive every reporting/export path.
Event records inherit that flag from their session; a detached event is not
a complete capture.

All counts, byte lengths, offsets, monotonic nanoseconds and sequence values
use canonical unsigned 64-bit **decimal strings**. No signs, leading zeros,
fractions, scientific notation or JSON-number substitutions are allowed. The
maximum is `18446744073709551615`; JSON Schema checks the representation and
the application must also check the range. Ordinary bounded identifiers such
as CPU/PID numbers, signed API result codes and schema ABI versions are not
this numeric class.

Intermediate sums and interval arithmetic must be checked before conversion
to external fields. Overflow makes a dependent metric unavailable or
terminates that calculation with an explicit diagnostic; it must never wrap,
saturate silently or pass through floating point. Metrics use integral base
units.

A non-integral mean is rounded down to the nearest base unit, with
`aggregation = mean` and the completed `sample_count` retained. Quantiles
use the nearest-rank definition, rank `ceil(p*n)` after ordering valid
completed samples; computed without overflowing `p*n`. Any histogram
approximation must be labeled `measurement = estimated`, identify its
resolution, and retain the completed sample count. Do not manufacture
precision from a histogram.

The initial bounded lifetime histogram uses 65 integer-nanosecond buckets:
bucket 0 contains 0; bucket `b` from 1 through 64 contains
`[2^(b-1), 2^b-1]`. Find the bucket containing nearest rank `ceil(p*n)` and
report its upper edge. Exact mean/count/min/max remain separate metrics.

## Source, environment and quality

`source` identifies the exact hook, backend and semantic profile plus
measurement and correlation strength. `correlation = direct` is direct
within the recorded semantic model, not proof of host access, application
origin, or attestation. A normalized `map_result.return_code = null` is
valid when the underlying allocator returns a buffer identity/failure
sentinel rather than an errno. Do not serialize that address as an error
code. Conversion wrappers with an observable integer status should preserve
it. `copy` means actual executed CPU bytes and therefore requires
`source.measurement = observed`; estimated or derived copy records are
invalid, even when mixed with observed copies. Other event kinds keep
their measurement options.

A capability's `verified` status describes tested **product support**, not
platform security assurance. For live probe-based observations it requires a
tested profile and successful runtime attachment; synthetic fixtures can
describe a fictional successful state only when explicitly marked synthetic.
Unavailable and disabled capabilities remain visible rather than disappearing
from the manifest.

Quality channels are independent: `detail`, `aggregate`, `correlation`,
`baseline`, and `terminal`. Their `loss_count` is null when unobservable,
zero only when measured as zero. The device catalog preserves resolvable
device labels and driver information behind session-local IDs. Reports copy
that catalog; each metric has `dimensions.device_id` and
`dimensions.pool_id` for machine-readable grouping. Null dimensions mean the
metric's explicitly described global/non-device scope. Unresolved devices
retain their token and an explicit identity status.

`baseline.region_observations` contains actual initial region observations
with provenance. It must be empty when that initial state is unknown; do not
construct a transition to encode a late-attach baseline.

`complete_for_scope` is always relative to the named supported paths and
capture filters. A metric with null value must use measurement
`unavailable`; its coverage and notes explain whether the cause is absent
support, incomplete data or inapplicability. No metric may use a numeric
zero to encode an unknown value.

## Event meanings

| Kind | What its data represents |
|---|---|
| `bounce_attempt` | A covered request reaching the bounce-attempt source, not an allocation result |
| `map_result` | An internal bounce-allocation result, with a generation-specific mapping ID on success |
| `unmap` | A covered release boundary; unmatched identity may remain null |
| `copy` | An observed actual CPU bounce copy; direction is separate from the DMA request direction |
| `sync_request` | A synchronization request, not a substitute for the copy that might follow |
| `transition_result` | A covered conversion API result and requested target state, subject to platform/profile interpretation |
| `pool_sample` | Contemporaneous values for one explicitly identified allocator scope |
| `gap` | A known detail, aggregate, or correlation-quality failure; count can be unknown |
| `marker` | A bounded, sanitized workflow annotation, never arbitrary payload data |
| `counter_snapshot` | A cumulative independent counter reading, with stable identity, reset epoch, device and scope |

Counter snapshots are authoritative only for their explicitly supported
source. Compute a delta between compatible readings within the same epoch; a
reset, absent baseline or unavailable reading prevents a full-window claim.
A counter delta and detailed events describing the same activity are
alternative measurements, not values to add. This lets an offline report
preserve a valid aggregate even when the separate detailed-event channel
lost records.

`operation_id` can identify work before a `mapping_id` exists. A copy inside
allocation may therefore reference the allocation operation with
`mapping_id = null`; correlate it when the result arrives. A failed
allocation must not acquire a successful mapping ID. Never manufacture
mappings or success from attempt events.

Region references expose opaque session tokens, relative byte offsets,
lengths, an address-space namespace and resolution. `physical_span`
computations require `guest_physical` and a normalization adapter that
actually resolved the identity. The schema does not make a guessed identity
true. `identity_only` and unresolved virtual/IOVA observations cannot
establish a physical interval union. An interval must have positive length
and a checked representable end offset; zero-sized requests may exist
without becoming intervals.

Region identity is the (token, namespace, generation) triple. Both
`transition_result` events and `baseline.region_observations` carry an
optional `generation` member (absent means 1); intervals split and merge
only within one lineage, so a token reused under a new generation never
merges with its earlier lineage.

## Cross-record checks

Schemas alone cannot validate the whole state machine. Readers must also
check: session consistency; increasing normalized sequence IDs; referenced
mapping generations; duplicate successful IDs; release pairing;
operation/result relationships; interval identity and overflow;
status/return-code consistency; source authority; capture filters; synthetic
provenance; and metric/finding references. Preserve legitimate nested
copies that precede their allocation result.

Timestamps need not be strictly ordered across unrelated CPUs. Preserve
documented source ordering and direct correlation rather than sorting
timestamps and assuming causality. For finalized captures, timestamps use
the same monotonic epoch and lie in the half-open declared observation
window `[start_ns, end_ns)`; wall-clock creation time is metadata, not an
ordering source. The window's optional `baseline_start_ns` vouches the
start-cut read that predates readiness: `counter_snapshot` records are
admissible from the baseline, every other record from `start_ns`.

## Size and depth bounds

Enforce bounds before unbounded parsing. An NDJSON event line is limited to
64 KiB (65536 bytes) including its newline; a session or report JSON file is
limited to 16 MiB (16777216 bytes); JSON nesting is limited to depth 64. A
truncated final line may be recovered only in explicit partial-capture mode;
no guessed JSON repair.

## Enforcement split

Strict schema validation is for producers and CI. Three layers share the
work, and each is tested separately:

1. These schema files state the contract in standard Draft 2020-12 for any
   compliant validator and for human review.
2. `tools/validate-schemas` (Python standard library only) enforces the
   critical subset — canonical integers with range checks, required fields,
   size/depth bounds, session/sequence/window/identity cross-record rules —
   and independently recomputes the fixture's expected report. It validates
   local files only.
3. The product reader (Mojo) strictly parses and cross-validates untrusted
   captures at runtime; its bounds and rejection behavior have their own
   tests.

The package validator exercises schemas and selected synthetic invariants
only. It is not a replacement implementation of the reducers, and passing
it does not establish kernel-hook correctness.

Canonical-form strictness beyond JSON Schema: the validator additionally
requires canonical JSON number forms for integer fields (a value such as
`1.0` is rejected even though Draft 2020-12 classifies it as an integer),
rejects duplicate object keys, requires the report's environment and
device catalog to equal the session's, and requires synthetic flags to
agree with the capture mode. These rules keep every reader's
interpretation identical.

## Reconstruction notes

These schemas were reconstructed from the specification's field-meaning
notes after the original companion files proved absent. The following
choices resolve points the notes left open; they are versioned with the
schemas and any incompatible change requires the documented version policy:

- `source.backend` is a bounded free string (examples: `tracepoint`,
  `tracing`, `synthetic`) rather than a closed enum, so new backends do
  not break the major version.
- `source.correlation` is `direct` or `unpaired`. No weaker in-between
  strength is representable in 0.1.0.
- `observer_context.cpu/pid/tgid` are bounded JSON integers, not decimal
  strings, because they are identifiers outside the u64 measurement class.
- `pool_sample.unit` is `bytes` or `unknown`; unknown units disable ratio
  rules. Wider unit vocabularies need a minor version with reader rules.
- `capture.end_reason` enumerates `duration`, `size_limit`, `signal`,
  `error`, and `unknown`; null means the capture was not finalized with a
  recorded reason.
- Report `aggregation` is nullable for metrics (such as unavailable ones)
  where no aggregation applies.
- Mean/quantile/histogram conventions above are part of this contract:
  floor means, nearest-rank quantiles, and the 65-bucket estimated
  histogram with stated resolution and sample count.
