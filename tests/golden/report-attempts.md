# Memveil report `attempts-3-session`

- synthetic: yes
- engine: memveil-0.1.0
- window: [1000000000,4000000000)
- duration: 3.000000000 s (3000000000 ns)
- environment: mode=unknown detection=unverified attestation=not_performed evidence=0
- recorded kernel.release: unavailable (no captured provenance)
- recorded profile.decision: unavailable (no captured provenance)
- recorded measurement\_scope: unavailable (no captured provenance)
- devices: 1

## Devices

| device_id | name | driver | identity |
| --- | --- | --- | --- |
| dev-1 | testdev0 | synthetic-test | resolved |

## Quality

| channel | status | loss | scope | reason |
| --- | --- | --- | --- | --- |
| detail | complete_for_scope | 0 | 3 bounce\_attempt events | Authored fixture: no loss. |
| aggregate | unavailable | unknown | counter snapshots | No counter snapshots in this fixture. |
| correlation | complete_for_scope | 0 | attempt counting | Attempt counting needs no cross-event correlation. |
| baseline | not_applicable | unknown | attempt metrics | Attempt metrics need no baseline. |
| terminal | complete_for_scope | 0 | authored fixture finalization | Authored fixture: finalized. |

## Metrics

| name | dimensions | value | unit | measurement | coverage | confidence | scope | notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| bounce\_attempts | all | 3 | count | observed | complete_for_scope | high | window \[1000000000,4000000000), all devices, detail channel | 3 detail events; no counter snapshots to compare. |
| bounce\_attempts | device=dev-1 | 3 | count | observed | complete_for_scope | high | window \[1000000000,4000000000), device dev-1, detail channel | All 3 attempts observed device dev-1. |
| requested\_bounce\_bytes | all | 9216 | bytes | observed | complete_for_scope | high | window \[1000000000,4000000000), all devices, detail channel | 4096 + 4096 + 1024 requested bytes across 3 attempts; allocation outcomes are unavailable in this fixture. |
| requested\_bounce\_bytes | device=dev-1 | 9216 | bytes | observed | complete_for_scope | high | window \[1000000000,4000000000), device dev-1, detail channel | 4096 + 4096 + 1024 requested bytes on device dev-1. |
| successful\_allocations | all | unavailable | count | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No map\_result source in this fixture; attempts are not successes. |
| copy\_original\_to\_bounce\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No copy source in this fixture. |
| copy\_bounce\_to\_original\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No copy source in this fixture. |
| live\_observed\_allocation\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No lifecycle source in this fixture. |
| observed\_mapping\_lifetime\_ns | all | unavailable | nanoseconds | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No lifecycle source in this fixture. |
| conversion\_request\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No conversion source in this fixture. |
| known\_shared\_region\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No region source in this fixture. |
| pool\_used\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No pool source in this fixture. |
| pool\_capacity\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No pool source in this fixture. |
| pool\_hiwater\_bytes | all | unavailable | bytes | unavailable | unavailable | high | window \[1000000000,4000000000), all devices | No pool source in this fixture. |

## Findings

none

## Limitations

- Synthetic fixture: every value is authored test data; no guest was booted and no hook attached.
- This analyzer reduces bounce attempts and counter deltas only; lifecycle, copy, sync, conversion, region, pool, and task-context metrics are unavailable.
- No counter snapshots: attempt totals rest on the detail channel alone.
