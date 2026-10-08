# Ordinary-Linux laboratory lifecycle checks

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

This recipe runs laboratory lifecycle/copy comparisons in a disposable VM.
It does not qualify shipping lifecycle, successful outer DMA, per-device
effective copying or sustained pool pressure. Shipping collection is the
attempt collector with optional pool boundary samples; see the
[support table](../support.md#capabilities-by-mode) and
[oracle boundaries](../oracles.md).

## Prerequisites

- The frozen harness from `tools/vm-attempts` (virtme-ng,
  qemu, kvm, passwordless sudo where the wrapper asks).
- Laboratory lifecycle probes:
  `build/bpf/swiotlb_lifecycle.bpf.o` and
  `build/bpf/swiotlb_copy.bpf.o`, each admitted through the
  hook-definition rules in `tests/vm/semantics.py`.
- The oracle module source in `tests/kernel/` building
  against the guest kernel (`tools/vm-oracle` proves this).
- Environment: `MEMVEIL_VM_LIFECYCLE=1`.

Without all four, every gate below skips fast with exit 77
and names the missing piece. A skip is never a pass.

## Gates

| Lane | What it proves |
|---|---|
| `tools/test vm-lifecycle` | Scripted low-rate matrix comparing decoded laboratory records against independent module facts; no shipping report qualification. |
| `tools/test vm-copy` | Scripted request/copy comparisons using laboratory probe records; no per-device shipping effective-copy claim. |
| `tools/test vm-real-io` | Laboratory real-I/O hook exercise in the guest; its decoded records do not establish shipping lifecycle report semantics. |

`tools/vm-lifecycle` runs all three in one invocation.

## Evidence

Each gate records the kernel release, BTF identity, probe
object hashes, oracle module source hash, workload, command,
expected and actual results, losses, cleanup, and artifact
hashes. Distinguish PASS, FAIL, BLOCKED, SKIPPED, and NOT
RUN. Re-run evidence invalidated by a relevant change; never
relabel an older receipt as current.

## Current status

The reducers, probes, independent module, admission checks and wrappers
exist. Armed historical laboratory runs and unarmed skips are distinct;
these wrappers do not always skip. Neither outcome qualifies the shipping
collector's missing lifecycle source. The oracle report translator uses
synthetic provenance and partial correlation/terminal evidence. Shipping
integration still needs real identity-preserving normalization, outer-success
separation, independent per-device witnesses and exact-artifact qualification.
