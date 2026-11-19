<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Third-party notices (memveil 0.1.0)

Third-party inputs to this source tree. Per-artifact
notices are generated at package time and enumerate the
exact staged set; this file names the sources they come
from. MemVeil's own texts are `LICENSE` and `LICENSES/`.

- `packaging/libgcc/libgcc-s1_14.2.0-19_amd64.deb`
  (Debian trixie, GCC 14.2.0): the bundle's one shipped
  shared library, `libgcc_s.so.1`, for the Rust unwinder.
  The packager takes it from this directory, never from
  the build host, and refuses on any pin mismatch; see
  `packaging/libgcc/PROVENANCE.txt` for the adoption
  proofs.
  GPL-3.0-only WITH GCC-exception-3.1; texts staged per
  artifact as `licenses/GPL-3.0.txt` plus
  `licenses/RUNTIME.LIBRARY.EXCEPTION`.

- The crates.io dependency closure pinned by `Cargo.lock`
  and `crates/ebpf/Cargo.lock`: every Rust crate below
  comes from the registry at its locked version. The
  packager stages each crate's license text under
  `licenses/crates/` from the locked sources and refuses
  a crate that ships no text. No vendored or patched
  dependencies.

- Host system libraries (`libc`, `libm`, `libdl`,
  `libpthread`, the dynamic loader) are not shipped: the
  bundle links them from the host at run time.

The Rust product links no libbpf, ships no toolchain
runtime, and stages no bridge: the Aya loader is
statically linked into the engine binary.

License texts: `LICENSE`, `LICENSES/` (MemVeil);
`packaging/libgcc/GPL-3.txt` plus
`packaging/RUNTIME.LIBRARY.EXCEPTION` (GCC runtimes,
staged per artifact); per-crate texts under the
artifact's `licenses/crates/`.
