# Confidential-guest admission and owned request checks

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

This recipe separates native owned-allocation safety, ordinary transport,
real platform admission and product request/result comparison. It does not
provision infrastructure, authorize spending, change system policy or load
anything by default. SNP, standalone TDX, Hyper-V SNP and Hyper-V TDX require
separate source and environment admission. I/O qualification is separate.
No request/result comparison establishes persistent region state or what a
host read.

Machine-readable requirements are in `tests/confidential/recipe.json`.
Journal eligibility starts at Linux 6.11, with BTF required and a qualification
ceiling of 7.3. The version alone never admits a kernel. Review the exact
kernel conversion wrapper, callback, partial-failure and full-range restore
semantics before any real platform run. Inventory flags alone are insufficient.

## Safety and ordinary transport first

Read the [owned oracle operation and safety contract](../../tests/kernel/README.md#test-only-region-oracle-module).
Run its offline native failure matrix, obtain an independent allocation,
conversion, unwind and unload review, and build against the selected guest
headers. The ordinary guest runner then exercises per-CPU bpftrace counters,
zero-retention control, retained/revert and repeated normal load/unload.
A successful host-header compile is not an ordinary guest transport receipt.
Missing matching headers or an unexecuted guest gate remains pending.

The oracle owns one zeroed 1 to 256 page allocation and one test epoch per
load. It serializes nonnested native calls. A module reference pins any
potentially exposed allocation. Failed decryption triggers full-range restore;
failed restoration retains the allocation and module until guest reboot.
Never force unload. Never deliberately force a fatal SNP restore failure.
Injected failures belong to the offline stub tests only. After two failed
safety fix rounds, stop this oracle and require a separately safe equivalent;
a report-only attestation stimulus is not a substitute.

## Real platform prerequisites

Run `python3 tests/confidential/inventory.py /owned-export/inventory.json`
for the supported inventory checks. Its existing SNP/TDX inventory does not
admit Hyper-V variants. Each selected cell needs independent enabled-platform
proof, boot/kernel/config/BTF identity, permitted attachment, exact oracle and
product artifacts, and a source-reviewed profile and bounded caller label.
No profile is admitted by this recipe or by a passing synthetic fixture.

During an authorized real run, start the separately admitted product collector
with caller processing before issuing oracle commands. Collect zero-retention
and retained/revert cases with unique epochs, preserve native ledger rows
before unload, and verify normal unload. Product observations must remain
independent of the native ledger. Their ordered `(direction, pages, result)`
tuples must agree one-to-one within the admitted module/caller scope.
Missing, duplicate, foreign, ambiguous, lost or censored observations fail.
A wrapper return must never be promoted to an allocation lifetime or
persistent-state observation.

## Evidence validators

`tools/test confidential-ranges` and `tools/test confidential-real` are
implemented evidence validators. They neither collect a live journal nor
boot, load or provision a guest. The product journal-to-projection adapter
is not implemented here; it needs separate integration and qualification.
The historical `confidential-ranges` name now checks the controlled owned
request sequence, without inferring persistent range identity.

Unarmed wrappers return 77 (SKIPPED). An armed wrapper with missing or invalid
required evidence returns 1 (FAIL), never a successful skip:

```sh
MEMVEIL_CONFIDENTIAL_RANGES=1 MEMVEIL_OWNED_EVIDENCE=/owned-export/evidence \
  tools/test confidential-ranges
MEMVEIL_CONFIDENTIAL_REAL=1 MEMVEIL_OWNED_EVIDENCE=/owned-export/evidence \
  tools/test confidential-real
```

The evidence directory contains these independently produced files:

| File | Required content |
|---|---|
| `admission.json` | `memveil-owned-admission/1`; exact mode, profile and bounded caller, `restore_contract=whole_range_native_success`, independent safety-review and ordinary transport digests |
| `native.json` | `memveil-owned-native/1`; zero-retention then retained/revert native cases, unique canonical decimal epoch/page/retention fields, exact sysfs ledger text and `cleanup=unloaded` |
| `observations.json` | `memveil-owned-observations/1`; separately extracted ordered product cases, capture digest, zero lost/censored/ambiguous/foreign counts, settled closure and admitted callers |
| `events.ndjson` | The independently retained product capture bytes whose digest the projection names |
| `transport.json` and `cycle-*.json` | Ordinary runner receipts and their referenced hashes, at least three zero-retention/retained cycles of the same oracle source |
| `safety-review.txt` | The independently reviewed safety argument bound by admission digest |

All three primary documents repeat the exact mode, profile, kernel release,
kernel source/config/BTF hashes, oracle source/module hashes, product hash
and profile hash. Ordinary and real modules may differ because they target
different kernels; their exact bytes are identified separately and their
oracle source must match. Admission remains a reviewed input, not a signature
or attestation generated by these validators.

A native case has exactly `epoch`, `pages`, `retained_seconds`, `ledger`
and `cleanup`. Observation `cases` is an array of two arrays; every row has
exactly `direction`, `pages`, signed integer `result` and `caller`.
The observation `quality` object has exactly `lost`, `censored`, `ambiguous`,
`foreign` (all canonical decimal `"0"`), `closure="settled"` and
`callers="admitted"`. The tests in
`tests/confidential/test_owned_qualification.py` give a complete authored
format example; they are synthetic validator tests, not guest evidence.
Extra fields and mismatched identities are rejected. The validator does not
independently rederive the projection from the capture: that adapter and its
provenance review remain necessary before any live qualification claim.

Do not retain PFNs, pointers, raw addresses, stack frames, task names,
payloads, content hashes or full kernel/boot logs. Capture-file hashes are
allowed. Keep the exact command, artifact identities, native outcomes,
independent counts, losses and cleanup in the surrounding qualification
receipt. No real SNP/TDX/Hyper-V run or support claim follows from this recipe.
