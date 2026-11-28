# Memveil report `journal-censored`

- summary: conversion journal 1 requests (1 successes, 0 failures), 0 unmatched exits in 1.50 s
- summary scope: proves conversion requests were counted; does not prove conversions took effect, state changed, or bytes were shared
- synthetic: yes
- engine: memveil-0.2.0
- integrity: verified (verified bytes=683, events=1); literal capture bytes match SHA-256; no authenticity claim
- verdict: partial_unknown_loss (loss >=0.00%, 0 delivered)
- window: [1000000000,2500000000)
- duration: 1.500000000 s (1500000000 ns)
- environment: mode=unknown detection=unverified attestation=not_performed (recorded, not verified by memveil) evidence=0
- recorded kernel.release: unavailable (no captured provenance)
- recorded profile.decision: unavailable (no captured provenance)
- recorded measurement\_scope: unavailable (no captured provenance)
- devices: 0

## Devices

| device_id | name | driver | identity |
| --- | --- | --- | --- |

## Capabilities

| capability | status | grade | reason |
| --- | --- | --- | --- |
| bounce\_attempts | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| mapping\_lifecycle | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| copy\_bytes | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| sync\_requests | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| conversion\_results | verified | none | Synthetic contract fixture only. |
| region\_state | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| pool\_stats | unavailable | none | No source for this channel in this synthetic request-only fixture. |
| task\_context | unavailable | none | No source for this channel in this synthetic request-only fixture. |

## Quality

| channel | status | loss | scope | reason |
| --- | --- | --- | --- | --- |
| detail | complete_for_scope | 0 | synthetic journal results | Authored metadata; never a real-platform admission. |
| aggregate | unavailable | unknown | counter snapshots | No counter snapshots in this fixture. |
| correlation | unavailable | unknown | region lifetimes | No region lifetime source. |
| baseline | unavailable | unknown | global journal baseline | Request-only source; pre-window state and global closure are unproved. |
| terminal | unavailable | unknown | global journal terminal | Request-only source; pre-window state and global closure are unproved. |

## Journal

| measure | value |
| --- | --- |
| requests | 1 |
| successes | 1 |
| failures | 0 |
| unmatched exits | 0 |
| censored | 1 |
| requested bytes | 4096 |
| shared bytes | unavailable (request_only_source) |
| unreverted ranges | unavailable (request_only_source) |

## Regions

| measure | value |
| --- | --- |
| established | 0 (request-only source; no region identity) |
| observed results | 1 (request-only; no lifetime netting) |

## Findings

none

## Limitations

- Synthetic request/results only; no persistent region identity, baseline or global closure.
- Boot and pre-attach conversions are excluded.
- MMIO conversions are excluded.
- Kexec and accept paths are excluded.
- Unobserved conversion paths are excluded.
