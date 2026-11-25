<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Authored policy examples

Three small `policy-v0.1.0` documents showing the shape
defined in the authored sharing policy manual
(`docs/exposure-policy.md`):
a closed scope with one bounded exception, a queue
lifetime boundary, and an independently authored
configuration rule. Each file carries its own
prerequisites and expected findings; the offline
evaluation of the same shapes is pinned by the golden
cases under `tests/exposure/fixtures/policy/`.

## closed-scope.json

[closed-scope policy](closed-scope.json) admits nothing
except requests from the named device peer.

- prerequisites: platform cell `ordinary-linux`, workload
  "synthetic offline bundle with virtio queue requests".
- expected findings: an uncovered queue request is a
  violation; a request from the admitted device peer is a
  known deviation; an empty finalized capture with
  complete sources conforms.
- golden cases: `case-conforms`, `case-deviates`,
  `case-violates-loss`, `case-inconclusive-peer`,
  `case-unavailable`.

## lifecycle-boundary.json

[lifecycle-boundary policy](lifecycle-boundary.json)
requires every selected queue to reach `released`.

- prerequisites: platform cell `ordinary-linux`, workload
  "synthetic offline bundle with queue lifetime records".
- expected findings: a queue still live at a finalized
  capture is a violation; released queues conform; an
  unfinalized capture is inconclusive, never teardown.
- golden case: `case-boundary-ok`.

## config-deviation.json

[config-deviation policy](config-deviation.json) flags
configuration state records outside the authored
constraints.

- prerequisites: platform cell `ordinary-linux`, workload
  "synthetic offline bundle with configuration state
  records".
- expected findings: an unexpected configuration state
  record is a violation; the constraints never widen from
  observation.
- golden case: `case-config-deviation`.
