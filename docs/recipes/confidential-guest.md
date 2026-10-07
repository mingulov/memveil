# Confidential-guest dry-run recipe

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

This recipe admits one real SNP or TDX guest for
confidential-memory qualification: observed device I/O plus,
where claimed, controlled owned-region conversion evidence
and known shared/private region state. It performs no
provisioning, spending, image-policy change, or conversion;
every step below is a read-only check until the separately
authorized live gates run.

Machine-readable requirements live in
`tests/confidential/recipe.json`. One exact technology per
qualification: SNP evidence never qualifies TDX, and I/O-only
evidence never qualifies conversion or state claims.
Ordinary forced bouncing is never confidentiality evidence.

## Prerequisites

- x86-64 guest, kernel >= 7.0, actually SNP- or
  TDX-enabled (not merely a willing CPU or VM name).
- Readable BTF (`/sys/kernel/btf/vmlinux`) and kallsyms.
- Trace or fentry attach permission for the admitted hooks
  (none admitted yet: conversion observation is blocked on
  kernel-source inspection).
- The owned-region test mechanism from `tests/kernel/`
  building against the guest kernel, restoring its memory
  on unload.
- Environment: `MEMVEIL_CONFIDENTIAL_RANGES=1` (ranges),
  plus the real-guest arming in `confidential-real` and
  `confidential-late-attach` when they ship.

Without these, every gate below skips fast with exit 77
and names the missing piece. A skip is never a pass.

## Gates

| Lane | What it proves |
|---|---|
| `tools/test confidential-inventory` | The inventory runs, the manifest is well-formed, and the mode verdict follows the conservative rules (flags alone never verify). |
| `tools/test confidential-hooks` | Candidate conversion-API names are detected or honestly absent; admission stays refused without kernel-source evidence. |
| `tools/test confidential-ranges` | Owned live range-identity checks on the admitted guest (skipped until armed). |
| `tools/test confidential-real` | Controlled shared-to-private owned-region sequence with independent API and range evidence (skipped until armed). |
| `tools/test confidential-late-attach` | Baseline-vs-new-conversion separation on a late attach (skipped until armed). |

Run the inventory first on any candidate guest:

```
python3 tests/confidential/inventory.py /tmp/coco-manifest.json
```

An `enabled: true` verdict with `sev-snp` or `tdx` mode is
the entry ticket for the armed gates; `none` and
`unverified` stop here with their reasons. Keep the
manifest: it records the kernel, boot, device, permission,
and restriction identities the later gates re-check.

## Evidence

Each armed gate records the guest technology and profile,
kernel source/config/BTF identities, probe and oracle
hashes, workload, command, frozen per-capability
expectations, expected and actual results, losses, cleanup,
and artifact hashes. Distinguish PASS, FAIL, BLOCKED,
SKIPPED, and NOT RUN. Re-run evidence invalidated by a
relevant change; never relabel an older receipt as current.

## Current status

The offline region model, resolver, baseline handling,
inventory, hook evidence, region oracle module, and all
five gate harnesses are implemented and tested. No SNP/TDX
guest is admitted and no conversion hook is qualified, so
the inventory reports `none` here and the live gates skip.
No public support or coexistence claim follows from this
recipe alone.
