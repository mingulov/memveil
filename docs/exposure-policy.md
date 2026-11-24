<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Authored sharing policy

This document freezes the planned policy file format,
its evaluation rules and the comparison contract. Policy
files are local, authored and immutable for a run. There
is no learning and no automatic broadening of an
allowlist. Nothing here ships yet: the planned report
policy option and the offline compare verb do not exist,
and requesting policy evaluation refuses until they
land with test evidence.

## File format

A policy file carries schema and version, a policy id, a
subject scope, platform and profile applicability, the
required sources, a clock contract, logical-role
bindings, rules and bounded exceptions:

```json
{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "example-snp-virtio",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "sev-snp", "profile": "pinned"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest-monotonic-active",
  "role_bindings": {"queue": "snapshot-role-1"},
  "rules": [
    {
      "rule_id": "no-unexpected-queue",
      "selector": {"operation": "create", "direction": "shared"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": null
    }
  ],
  "exceptions": []
}
```

Rules have stable ids, selector AND constraints over
finite enumerated fields and exact labels, a permitted
operation and direction, per-operation or window limits,
and an optional admitted lifecycle obligation. There
are no arbitrary expressions and no unrestricted
patterns. All applicable rules intersect; an exception
names one rule and one constraint and cannot bypass
others.

## Evaluation

Duplicate keys, conflicting rules, unknown kinds, an
empty required scope and unresolved selectors can never
produce a vacuous pass. An unknown selector is
inconclusive, never an allowlist match. Known
out-of-allowlist activity inside a closed declared
scope is a violation; activity outside the scope is
shown separately. Result precedence is violates, then
inconclusive, then deviates-known, then conforms, and
an unavailable required source counts as inconclusive.
Known positive findings survive unrelated data loss
with the remaining gaps visible. Capture validity,
source quality, policy outcome and external trust
context stay separate fields.

## Exits

Invalid capture, policy, schema or output refuses
without a guessed result. Explicitly requested but
unavailable required collection refuses naming the
missing capability. A recovered unfinalized capture
stays partial. A valid finalized strict evaluation
with a proved violation reports the violation; without
a violation but with required evidence incomplete it
reports incomplete, never conforming; complete scope
with no violation conforms or explicitly permits a
known deviation. The exact exit numbers live in the
[exposure catalog](../profiles/exposure/catalog.json)
exit table.

## Comparison

The planned offline compare verb emits compatible
per-metric deltas with typed refusals. Every requested
metric checks identity, profile, workload, window and
unit compatibility first; incomparable fields refuse
individually with a reason and carry no numeric delta.
Cross-capture selectors use the explicit logical-role
binding of each snapshot, never equal opaque ids.

## Bounds

A policy file is at most 1 MiB with at most 1,024
rules and 64 exceptions per rule; identifiers are at
most 64 ASCII characters. These are initial
constraints, not permission to relax budgets after a
failure. See [exposure coverage](exposure-coverage.md)
for the capabilities a policy can require.
