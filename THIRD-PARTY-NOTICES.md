<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Third-party notices (memveil 0.1.0)

This bundle redistributes the following third-party components
alongside MemVeil's own files (whose texts are `LICENSE` and
`LICENSES/`, and whose BPF object `bpf/swiotlb_attempt.bpf.o`
is MemVeil's own GPL-2.0-only build, not third-party). All
paths below are bundle-relative.

Shipped libraries come from two origins: the pinned
libbpf-mojo bundle (the bridge plus its upstream inventory
below) and this bundle's own pixi build environment (the
remaining `lib/*.so*`, resolved by the NEEDED closure walk
in `tools/package`). The two origins are told apart in each
entry.

- `lib/libbpf_mojo.so.1` from libbpf-mojo 0.2.1 (source
  commit `1ce369b`, an independent project; the exact
  tarball is named by sha256 in `MANIFEST.json` under
  `libbpf_mojo`).
  The bridge is GPL-3.0-or-later; its first-party texts are
  staged as `licenses/libbpf-mojo-LICENSE` and
  `licenses/libbpf-mojo-LICENSES/`, and its own notices are
  staged verbatim as `THIRD-PARTY-NOTICES.libbpf-mojo.md`.
  MemVeil consumes libbpf-mojo only through the pinned
  tarball named above, never through a sibling checkout.

- `lib/libbpf_mojo.so.1` statically links libbpf 1.7.0.
  BSD-2-Clause; full text in
  `licenses/LICENSE.BSD-2-Clause.libbpf`. Upstream:
  https://github.com/libbpf/libbpf (tag v1.7.0).

- `lib/libgcc_s.so.1` from this bundle's own pixi
  environment: conda-forge package libgcc 16.2.0
  (ha9f2e26_7).
  GPL-3.0-only WITH GCC-exception-3.1; full texts in
  `licenses/GPL-3.0.txt` plus
  `licenses/RUNTIME.LIBRARY.EXCEPTION`.
  Binary: https://conda.anaconda.org/conda-forge/linux-64/libgcc-16.2.0-ha9f2e26_7.conda
  sha256: e031634c3a928f9594eba868bc46ef5230d6571a364a0c63215b06c4563bfcea
  (Package identities come from this repository's
  `pixi.lock`; the upstream bundle happens to resolve the
  same frozen builds -- see
  `THIRD-PARTY-NOTICES.libbpf-mojo.md` for its own copy.)

- `lib/libstdc++.so.6` from this bundle's own pixi
  environment: conda-forge package libstdcxx 16.2.0
  (h934c35e_7).
  GPL-3.0-only WITH GCC-exception-3.1; full texts in
  `licenses/GPL-3.0.txt` plus
  `licenses/RUNTIME.LIBRARY.EXCEPTION`.
  Binary: https://conda.anaconda.org/conda-forge/linux-64/libstdcxx-16.2.0-h934c35e_7.conda
  sha256: fa7018298629fc429971fffd6ecba3d27a7b02e4e890d6a93ea01ffebe8cb745

- `lib/libAsyncRTRuntimeGlobals.so`,
  `lib/libKGENCompilerRTShared.so`,
  `lib/libMSupportGlobals.so` from this bundle's own pixi
  environment: conda package mojo-compiler 1.1.0 (release).
  Binary: https://conda.modular.com/max/linux-64/mojo-compiler-1.1.0-release.conda
  sha256: 1ff52b39a0d2a1bedb8c4705aadc460205ca62fc19f63426bc545e4b60a31aa0
  These ship under the Modular MAX SDK license staged as
  `licenses/LICENSE.mojo-compiler` with
  `licenses/Third-Party-Notices.mojo-compiler`; provenance
  notes are in `licenses/NOTICE.mojo-runtime.md`. MemVeil is
  an application that adds material functionality on top of
  the Mojo toolchain, and redistributes these object-code
  libraries under the MAX Community License redistribution
  terms (section 1.2 of the staged license), with this
  Notice and the staged attribution the license requires.
  Caveat: Modular's texts do not enumerate these three
  library files by name, and no static-link option was
  found in Mojo 1.1.0, so the libraries ship as shared
  objects. Confirm the redistribution reading with the
  staged license texts before republishing beyond this
  owner handoff.

- zlib (`libz.so.1`) is a host-provided system library,
  not shipped in `lib/` (it is in `MANIFEST.json` under
  `system_libraries`). `licenses/LICENSE.zlib` is staged
  only because the upstream libbpf-mojo bundle -- whose
  notices are staged verbatim -- ships its own copy; it
  documents the upstream inventory, not this bundle.

- Other host system libraries (`libc`, `libm`, `libdl`,
  `libpthread`, `libelf`, `libzstd`, the dynamic loader;
  enumerated in `MANIFEST.json` under `system_libraries`)
  are not shipped: the bundle links them from the host at
  run time.

License texts: `LICENSE`, `LICENSES/` (MemVeil);
`licenses/libbpf-mojo-LICENSE`,
`licenses/libbpf-mojo-LICENSES/` (libbpf-mojo);
`licenses/LICENSE.BSD-2-Clause.libbpf` (libbpf);
`licenses/GPL-3.0.txt` plus
`licenses/RUNTIME.LIBRARY.EXCEPTION` (GCC runtimes);
`licenses/LICENSE.zlib` (upstream-bundle copy only);
`licenses/LICENSE.mojo-compiler`,
`licenses/Third-Party-Notices.mojo-compiler`,
`licenses/NOTICE.mojo-runtime.md` (Mojo runtimes).
