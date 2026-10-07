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

`memveil_region_oracle.c` (GPL-2.0-only, like all kernel-side
sources) allocates two of its own contiguous pages, converts
them shared then private again with the native
`set_memory_decrypted`/`set_memory_encrypted` APIs, and logs
every native return code plus the owned PFN range with an
`mv-region-oracle:` prefix. The confidential-guest harness
replays that log into its independent ledger and compares it
against MemVeil's observed conversion records.

Safety rules:

- The module refuses to load without `mv_region_oracle_arm=1`.
- It converts only its own pages and restores them before
  freeing; a failed restore is a loud test failure, and the
  pages still return to the allocator on unload. Disposable
  test VMs only.
- It never imports MemVeil code and never applies reducer
  math. Ground truth only.
- Build with `make -C tests/kernel`; the makefile never
  installs or loads. Loading happens only inside the
  admitted confidential guest gate.

On ordinary kernels both conversion calls are no-ops
returning 0; the log records that honestly, and the
comparison expects requests without state transitions.
