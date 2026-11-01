# Test-only DMA oracle module

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

`memveil_dma_oracle.c` (GPL-2.0-only, like all kernel-side sources)
drives a scripted sequence of DMA map, sync, and unmap calls
against a synthetic platform device and logs every raw call to
the kernel log with an `mv-oracle:` prefix. The VM harness
replays that log into the independent oracle ledger
(`tests/vm/oracle_ledger.py`) and compares it against MemVeil
reports over the same window.

Safety rules:

- The module refuses to load without `mv_oracle_arm=1`.
- It binds no real hardware and performs no DMA to real
  devices; all traffic targets its own platform device.
- It never imports MemVeil code and never applies reducer
  math. Ground truth only.
- Build with `make -C tests/kernel`; the makefile never
  installs or loads. Loading happens only inside the
  disposable VM gate, after the lifecycle probes it validates
  against are qualified.

The scripted traffic covers four operations (512, 1024, 2048,
4096 bytes): clean map/unmap cycles, a double sync, and one
mapping held open until unload to model an open mapping at the
horizon.

# Test-only region oracle module

`memveil_region_oracle.c` is an independent native request/result oracle.
It allocates exactly 1 to 256 contiguous owned pages with `__GFP_ZERO`.
It never reads or writes payloads after exposure, and neither the module
nor its harness logs addresses, PFNs, stacks, task names or kernel logs.
The product never consumes its ledger.

Build only, without installing or loading:

```sh
make -C /path/to/guest/kernel/build M="$PWD/tests/kernel" memveil_region_oracle.ko
python3 tests/kernel/test_region_oracle.py
python3 -m unittest discover -s tests/confidential -p 'test_owned*.py'
```

The offline test compiles the actual module against a native-operation
stub. It injects allocation, decryption, restoration and module-reference
failures, checks every free against an independent uncertainty flag,
checks zeroing and full-range operations, and tests concurrent commands.
ASan/UBSan cover the operation matrix. Mutations prove that removing the
free guard, releasing the pin on failure or omitting zeroing is detected.
This does not exercise a real kernel's memory encryption implementation.

## Ownership and operation

Only inside an explicitly authorized disposable guest, load with
`mv_region_oracle_arm=1 mv_region_oracle_pages=N mv_region_oracle_epoch=TOKEN`.
The token is a nonzero unsigned 64-bit decimal unique to this load. Loading
only allocates memory; it does not invoke a conversion API. Invalid parameters
and allocation failure occur before exposure. Initialization publishes the
allocation under the same mutex used by commands and unload.

The root-only parameters are under
`/sys/module/memveil_region_oracle/parameters/`:

- Write `share` to `command` once. A module reference is acquired before
  calling `set_memory_decrypted` on all N pages. Successful return retains
  the owned allocation for the declared observation interval.
- Write `restore` once. `set_memory_encrypted` receives the entire range.
  Its successful return releases the module reference. Normal `rmmod`
  subsequently frees the allocation. Unload never performs a conversion.
- Read `ledger` before removal. It contains at most two rows:
  `epoch=7 ordinal=1 direction=shared pages=3 result=0` followed by
  `epoch=7 ordinal=2 direction=private pages=3 result=0`.
  These are native call results, not a persistent state ledger.

The command mutex serializes concurrent writers. There is one allocation,
one epoch, one decryption attempt and at most one full-range restoration
attempt per load. Early, repeated or unknown commands are refused.

If decryption fails, the module immediately attempts a full-range restore:
a failure may have changed some pages. If restoration fails, it retains
the allocation and module reference permanently. No further conversion is
attempted, normal unload is blocked, and the guest must be rebooted.
Never force unload or deliberately inject a fatal failure on real SNP
hardware. The uncertainty guard also prevents freeing if unload is entered
unexpectedly, but forced removal destroys the ownership guarantee and is
prohibited. A native failure, missing ledger or uncertain cleanup fails the gate.

The lifetime mechanism follows Linux's documented
[sysfs active-reference and module-reference contract](https://github.com/torvalds/linux/blob/v6.11/include/linux/module.h).
The full-range failure policy follows the kernel's
[partial-update warning](https://www.kernel.org/doc/html/next/mm/kernel-page-tables.html#failures-and-partial-updates).
Each real guest still needs source review of its selected conversion and
restore semantics. Successful calls on ordinary Linux may be no-ops.

## Ordinary disposable-guest transport

After an independent safety review, boot an owned ordinary guest with
matching module bytes, readable BTF and the bpftrace version pinned in
`tests/vm/kernels.lock.json`. Inside that guest:

```sh
MEMVEIL_OWNED_REGION_GUEST=1 python3 tests/confidential/owned_region.py \
  --module tests/kernel/memveil_region_oracle.ko \
  --output /owned-export/region-transport --pages 3 --cycles 3 --retain-seconds 1
```

The output directory must not exist. The runner does not boot guests,
change policy, install packages, read kernel logs or force module removal.
It refuses an existing oracle module and confidential CPU capabilities.
The arming variable expresses explicit disposable-guest authorization; it
is not a detector of isolation and must never be set on a host.

Each cycle runs a zero-retention control and a retained/revert case in
separate loads with unique epochs. bpftrace starts the worker only after
attachment and uses per-CPU `count()` at both native entries and successful
returns, restricted to the worker process. Exactly one call per direction
must agree with the independently read native ledger. Every worker must
confirm ordinary unload and module disappearance. Tracer errors, missing
or extra counts, loss records, native failures and unproved cleanup fail.
Only parsed allowlisted metadata is retained; tracer diagnostics stay
unpersisted. On interruption, inspect cleanup receipts and reboot the guest
if cleanup is missing or unproved. Never replace cleanup uncertainty with PASS.

The receipt records module/source/runner/BTF/tracer hashes and kernel release.
The surrounding guest qualification must additionally bind the booted image,
config and kernel source identities, matching headers and tool locks.
A host-header build does not qualify the guest module. bpftrace shares the
conversion hooks with collection, so agreement has a shared-hook blind spot.
Transport PASS never proves a confidential transition or real guest admission.
