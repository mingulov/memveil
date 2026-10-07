# Ordinary-Linux lifecycle qualification

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

This recipe qualifies the lifecycle slice (map, copy, sync,
release, pool pressure) on ordinary x86-64 Linux before any
wider claim. It runs only in a disposable VM; nothing here
touches the host kernel except through the frozen virtme-ng
harness.

## Prerequisites

- The frozen harness from `tools/vm-attempts` (virtme-ng,
  qemu, kvm, passwordless sudo where the wrapper asks).
- Qualified lifecycle probes:
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
| `tools/test vm-lifecycle` | Low-rate matrix (1, 10, 100 maps/s): every report matches the oracle ledger with zero mismatches, and effective-copy equality holds at each step. |
| `tools/test vm-copy` | Request-vs-copy semantics on live traffic: syncs add no copy bytes, nested copies survive, copies under a failed mapping stay counted. |
| `tools/test vm-real-io` | Real block and vnet guest I/O through the swiotlb path: no orphan releases, reconcilable live bytes, sane completed lifetimes. |

`tools/vm-lifecycle` runs all three in one invocation.

## Evidence

Each gate records the kernel release, BTF identity, probe
object hashes, oracle module source hash, workload, command,
expected and actual results, losses, cleanup, and artifact
hashes. Distinguish PASS, FAIL, BLOCKED, SKIPPED, and NOT
RUN. Re-run evidence invalidated by a relevant change; never
relabel an older receipt as current.

## Current status

The offline reducers, the oracle ledger comparator, the
admission rules, and the gate harnesses are implemented and
tested. The lifecycle BPF probes are not yet qualified, so
all three gates skip. The oracle module builds against
7.0.0-34-generic; guest comparison awaits the probes.
