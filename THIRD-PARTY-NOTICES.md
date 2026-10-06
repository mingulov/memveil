<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Third-party notices (memveil 0.1.0)

This bundle redistributes the following third-party components
alongside MemVeil's own files (whose texts are `LICENSE` and
`LICENSES/`). All paths below are bundle-relative.

- `lib/libbpf_mojo.so.1`, `bpf/*.bpf.o` toolchain aside, from
  libbpf-mojo 0.2.1 (source commit `4e586be`, an independent
  project; the exact tarball is named by sha256 in
  `MANIFEST.json` under `libbpf_mojo`).
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

- `lib/libgcc_s.so.1`, `lib/libstdc++.so.6` from conda-forge
  GCC runtime packages (libgcc / libstdcxx 16.2.0).
  GPL-3.0-only WITH GCC-exception-3.1; full texts in
  `licenses/GPL-3.0.txt` plus
  `licenses/RUNTIME.LIBRARY.EXCEPTION`. Exact package
  identities and hashes are in
  `THIRD-PARTY-NOTICES.libbpf-mojo.md`.

- `lib/libz.so.1` from conda-forge libzlib 1.3.2.
  Zlib; full text in `licenses/LICENSE.zlib`. Exact package
  identity and hash are in
  `THIRD-PARTY-NOTICES.libbpf-mojo.md`.

- `lib/libAsyncRTRuntimeGlobals.so`,
  `lib/libKGENCompilerRTShared.so`,
  `lib/libMSupportGlobals.so` from conda package
  mojo-compiler 1.1.0 (release):
  https://conda.modular.com/max/linux-64/mojo-compiler-1.1.0-release.conda
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

- Host system libraries (`libc`, `libm`, `libdl`,
  `libpthread`, `libelf`, `libz`, `libzstd`, the dynamic
  loader; enumerated in `MANIFEST.json` under
  `system_libraries`) are not shipped: the bundle links
  them from the host at run time.

License texts: `LICENSE`, `LICENSES/` (MemVeil);
`licenses/libbpf-mojo-LICENSE`,
`licenses/libbpf-mojo-LICENSES/` (libbpf-mojo);
`licenses/LICENSE.BSD-2-Clause.libbpf` (libbpf);
`licenses/GPL-3.0.txt` plus
`licenses/RUNTIME.LIBRARY.EXCEPTION` (GCC runtimes);
`licenses/LICENSE.zlib` (zlib);
`licenses/LICENSE.mojo-compiler`,
`licenses/Third-Party-Notices.mojo-compiler`,
`licenses/NOTICE.mojo-runtime.md` (Mojo runtimes).
