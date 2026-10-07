<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

# Region state and conversion metrics

Region tracking reduces `transition_result` events and retained
baseline observations into conversion request counts and
guest-physical state unions. It runs offline over any capture
that carries those records; live conversion probes are not
qualified, so live captures carry no region source and every
region row stays unavailable with its reason.

## Interval model

Each (region identity, address-space namespace, generation)
triple names one proved lineage. Offsets are relative to the
region identity, never raw kernel addresses. Half-open
intervals split and merge only within that lineage; the same
token under another namespace never merges, and a token
reused across namespaces refuses the later namespace with a
visible limitation. Mapping, copy, unmap, pool, and counter
events never mutate region state.

A successful resolved guest-physical transition moves its
interval to the requested state. A failure without rollback
proof leaves its interval unknown; the untouched remainder
keeps its state. Unresolved, identity-only, or ordinary-kernel
no-op requests count as requests without any state
transition. Baseline observations seed initial state in
listed order; late attach invents no transitions.

## Metric rows

| Row | Meaning |
|---|---|
| `conversion_requests` | Observed conversion API results (count). |
| `conversion_failures` | Failed requests (count); feeds `CONVERSION_FAILED`. |
| `conversion_request_bytes` | Sum of requested lengths (bytes), not unique bytes. |
| `known_shared_region_bytes` | Union of known-shared guest-physical intervals. |
| `known_private_region_bytes` | Union of known-private guest-physical intervals. |
| `unknown_region_bytes` | Union of unknown-state guest-physical intervals. |

Unions sum disjoint tracked intervals per proved identity and
cover guest-physical intervals only; other namespaces track
without entering the unions. Known subsets report with
explicit partial scope whenever unknown, refused, or
invalidated state exists in scope. A total that would cover
unknown intervals stays unavailable: no whole-guest total is
emitted. Zero appears only with an available source and a
valid measured window.

Conversions on a profile where they are ordinary-kernel
no-ops record requests and results but apply no state
transition. An incomplete baseline likewise keeps every
state union unavailable while request counts stay valid.

## Budgets

At most 4096 region lineages and 65536 interval segments.
A lineage beyond budget is refused with a limitation while
its requests still count. A split beyond the segment budget
invalidates the affected lineage: its state is excluded,
never merged into a different state. All refusals and
invalidations degrade union coverage to partial with a
visible reason.
