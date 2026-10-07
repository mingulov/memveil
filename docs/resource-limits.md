<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Resource limits and loss channels

Every bounded store refuses past its budget with an explicit
quality change and a visible limitation note. Nothing is
silently evicted, and no refusal corrupts unrelated state.

## Capacity table

| Store | Budget | Overflow behavior |
|---|---|---|
| Ring reservation (live) | 8 MiB default | submit fails count in `submit_fail`; detail degrades, counters survive |
| Native staging (live) | bridge bound | malformed/dropped counts; see the bridge contract |
| Pending operations | 65,536 | `pending table exhausted`; event unpaired |
| Active mappings | 65,536 | `active table exhausted`; event unpaired |
| Nested copies per operation | 8 | `nesting budget exceeded`; event unpaired |
| Retired identities | 16,384 tombstones | oldest tombstone cycles; repeat release unpaired |
| Device identities | 4,096 | `device table exhausted`; event unpaired |
| Pool table | 1,024 | sample refused; `pool table exhausted` note |
| Pool detail rows | 256 | extra pools withheld from per-pool rows, counted |
| Mapping devices (detail) | 512 | extra devices folded out of per-device rows |
| Report metric rows | 4,096 | prefix kept in order; withheld count recorded |
| Reader line | 64 KiB | `line too large`; capture rejected (exit 2) |
| Reader session document | 16 MiB | `session.json too large`; capture rejected |
| Reader events total | 256 MiB | `events.ndjson too large`; capture rejected |
| Reader tracked identities | 4,194,304 | operations plus mappings plus distinct copy/sync references; past budget, `too many tracked identities` and the capture is rejected |
| Reader JSON depth | 64 | parse error; capture rejected |
| Diagnostics findings | ≤ 8 per report | fixed code set; stateless by construction |
| Region table | 4,096 | `region table exhausted`; observation refused, counted |
| Region interval segments | 65,536 | `interval budget exceeded`; affected region excluded, counted |

The `budgets` lane proves N/N+1 at the exact production
ceilings for pending (65,536/65,537), active (65,536/65,537
with raised pending), and devices (4,096/4,097), plus retired
churn with small live occupancy, tracker refusals with
limitation notes, exact row truncation (4,096/4,097), and the
findings bound. The active-ceiling case takes about a minute;
that cost is the proof.

## Loss-channel matrix

Detail events and counter deltas are alternative measurements,
never additive totals. The `quality` lane proves each cell:

| Detail | Counters | Result |
|---|---|---|
| loss (known count) | intact pair | detail partial with loss count; counter delta valued |
| intact | reset/decrease | detail complete; aggregate partial, no delta |
| loss (unknown count) | — | detail partial without loss count; counts are lower bounds |
| gap | mapping open | live bytes withheld; completed lifetimes exclude open |
| clean | mapping open | live bytes valued as observed; completed lifetimes null, never a leak |

A refused mapping, an orphan release, or an unpaired event
withholds the affected live totals and records a limitation;
it never quietly lowers a sum.

## Live saturation

Ring and staging exhaustion under load are proved by the
`vm-saturation` gate on qualified probes; unarmed runs skip.
Until that gate passes on an admitted profile, live
saturation behavior on that profile stays unqualified.
