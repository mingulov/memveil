<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Exposure coverage beyond SWIOTLB

This document freezes what the planned 0.3.0 security
capabilities cover, what each claim requires, and what
stays unknown. The machine-readable companion is the
[exposure catalog](../profiles/exposure/catalog.json):
capability, source, platform, record, reason, reservation,
exit and scenario entries. The two stay in lockstep; when
they disagree, the catalog wins and this document is fixed.

None of the capabilities below ship yet. Requesting a
planned exposure capability rejects it as unknown (exit
2) until its adapter lands with test evidence on an
admitted cell; the reserved journal names parse but
refuse as having no record channel (exit 3).
Ordinary-Linux evidence never qualifies a
confidential-guest claim.

## Capability families

| Capability | Covers | Minimum positive proof |
| --- | --- | --- |
| `census` | Existing sharing and an honest late-attach baseline | Exact owned increase/decrease deltas with interval, alias and race bounds |
| `object-lifetimes` | Region and object identity, lifetime and expected cleanup | One live owned shared-to-private lifecycle against an independent ledger |
| `dma-paths` | Persistent coherent DMA, virtio queues and operation paths | One real persistent queue path plus bounced and admitted non-bounced cases |
| `shared-buffers` | Explicit shared heaps and DMA-BUF retention | Shared-origin allocation with multi-reference retention and release |
| `host-interfaces` | Guest/host interface metadata | Covered activity on the matching cell with a rejection-source catalog |
| `mapping-inventory` | MMIO, device and DAX mapping inventory | Supported mapping-class observation plus presence, absence and unsupported fixtures |
| `exposure-context` | Egress, control and configuration facts | Independently configured swap, dump, driver and NIC-mode facts |

The `conversion-journal` capability stays reserved: it
parses but refuses, has no record channel and no 0.2.0
schema files. Journal-sourced rows below depend on it and
are unavailable until it ships.

## Claim strength and limits

A census is a guest-view inventory, never hardware truth.
Coherent memory is not synonymous with host-shared, and a
generic buffer object never implies confidential sharing.
Allocation is not conversion, release is not erasure, and
a wrapper result alone never establishes state. Smaller
or fewer buffers alone never improve any safety reading;
no report says the guest is secure, the host read
something, or no attack happened. Payloads, keys,
content hashes, raw addresses, command lines and
environment dumps are never collected; see
[privacy](privacy.md).

## Sources and cells

Every fact names its catalog source, the exact admitted
platform cell, and the address namespace of its fields.
Namespaces never mix: guest_virtual, guest_physical,
session_token, interface_register and channel_relid
values stay separate, and no token is a physical
address. The required cells
are one exact SNP guest, one standalone TDX guest and
one Hyper-V guest with its paravisor topology; ordinary
Linux is the reference cell for ordinary capabilities
only. No confidential cell is admitted yet, so every
confidential row below is explicitly unproven rather
than quietly absent.

## Fail, partial and not-applicable rules

A denied channel, quiet stream, lost final event or
clock mismatch makes the affected required rule
inconclusive, never conforming. A platform
not-applicable decision needs a catalog reason; denied
access, unknown topology, an unimplemented adapter or
mere absence of events cannot be relabeled
not-applicable. Exhaustion produces an explicit scoped
partial result with the bound named. Unknown required
evidence always blocks conformity; loss is never
converted to zero.

## Records, bounds and versions

Exposure records (`CoverageSource`, `ExposureFact`,
`ExposureObject`, `BaselineSample`, `PolicyResult`,
`ComparisonResult`) share the durable capture protocol:
no unsealed sidecar can supply policy evidence, and
quality stays independent per detail, aggregate,
identity, baseline and terminal channel. Scans stay
bounded: 65,536 live objects, 262,144 reference edges,
1,048,576 visited entries and 65,536 returned records
per inventory scan, with census inside one second on
its admitted reference cell.

Session, event and report 0.3.0 plus standalone policy
0.1.0 are reserved for this milestone; no schema files
ship yet and current readers refuse them. See
[format compatibility](format-compatibility.md) and the
[schema notes](../schemas/README.md).

## Capture comparison compatibility

Two persisted captures compare metric by metric. Each
metric first passes the compatibility predicate below;
only a compatible metric gets an exact delta (right
minus left, in the shared unit). A refused metric
carries its typed reason and no numeric delta, and one
refused metric never hides the comparable unaffected
metrics beside it.

Before any row runs, both captures validate; an invalid
input refuses the whole comparison with no rows and no
repaired or guessed result. The left capture validates
first, then the right; within a capture, in order:

| Order | Reason | Meaning |
| --- | --- | --- |
| V1 | `duplicate-metric` | A metric id repeats on one side |
| V2 | `invalid-window` | The window ends before it starts |
| V3 | `invalid-value` | A known value carries a reason, or an unknown value lacks one; a blank reason counts as lacking one |

A blank string is invalid everywhere it carries
meaning: a string expected to be non-empty that is
empty or whitespace-only counts as missing where its
content is interpreted. A blank source meaning is
unknown, never equal to another blank and never a
change; a blank value reason explains nothing, so
the capture refuses as `invalid-value`.

Checks run in order; the first failure names the reason:

| Order | Reason | Meaning |
| --- | --- | --- |
| 1 | `metric-missing` | Metric absent on one side; reported `unavailable` |
| 2 | `unit-mismatch` | Units differ; no delta across units |
| 3 | `scope-mismatch` | Scopes differ; scan scopes stay distinct |
| 4 | `legacy-input` | One side predates integrity metadata |
| 5 | `epoch-mismatch` | Epochs differ; counters restarted |
| 6 | `device-binding-mismatch` | Bound devices differ |
| 7 | `profile-mismatch` | Profiles differ; every metric refuses |
| 8 | `workload-mismatch` | Workloads differ under an equal profile |
| 9 | `source-mismatch` | The metric names different sources per side |
| 10 | `source-meaning-unknown` | A side records no meaning for the source; a blank meaning counts as no meaning |
| 11 | `source-meaning-change` | The metric's source changed meaning |
| 12 | `clock-mismatch` | Clock domains differ |
| 13 | `window-mismatch` | Window bounds differ |
| 14 | `partial-census` | Census-derived on either side with a bounded scan on either side |
| 15 | `compatible` | Predicate passed; delta rules below apply |

Compatible rows carry `delta` except when a side is
unknown (`value-unknown`, null delta with reason) or
the difference overflows the signed range
(`delta-overflow`, null delta with reason).

Row quality derives from the row itself across the five
channels (detail, aggregate, identity, baseline,
terminal). Only a row with an exact delta reports
`complete`; unknown and refused rows never do:

| Row | Quality on every channel |
| --- | --- |
| Exact delta | `complete` |
| Compatible with null delta | `unknown` |
| `incompatible` | `refused` |
| `unavailable` | `refused`, except identity is `unknown` |

Incomplete journal events never enter a delta: the
comparator reads finalized metric values only. A
comparison whose requested metrics include refused rows
exits 4 with per-metric reasons; counts stay counts and
never become verdicts about the guest.
