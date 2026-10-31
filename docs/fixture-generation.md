<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Reproducing offline BPF fixtures

The build accepts the system clang floor in `toolchain.lock.json`. Different
accepted compiler builds can emit different instruction, BTF and DWARF bytes.
A compiler floor is not an exact object identity or kernel qualification.

Historical fixtures under `tests/fixtures/` and qualified profiles under
`profiles/` retain their recorded identities. In particular, the committed
CO-RE kind object records `Ubuntu clang version 21.1.8 (6ubuntu1)` in DWARF.
The repository does not pin a downloadable archive of that complete Ubuntu
compiler environment. `tools/emit-core-fixtures --check` still requires exact
historical bytes; it is appropriate when recreating that environment. A
mismatch is not permission to replace a historical hash with the local one.

For offline tests on another accepted compiler, generate separate provisional
fixtures after the normal build has fetched the pinned libbpf headers:

```sh
pixi install
./tools/build
./tools/emit-test-fixtures
./tools/emit-test-fixtures --check
./tools/test profile-semantics
```

The default destination is `build/fixtures/provisional/`. Use `--out` for an
explicit destination and `--clang /path/to/clang` for an isolated compiler.
Inside the checkout, output must stay below `build/`. Generation never writes
historical fixtures or shipped profiles. An exclusive directory lock refuses
concurrent generation/checks. Symlink, directory and FIFO output entries are
refused; regular partial output may be explicitly regenerated. Each file is
replaced atomically through a held directory descriptor, with the manifest
published last. Interrupted generation requires regeneration or a successful
check before its output is used. To exercise just the kind generator
without replacing its historical object:

```sh
./tools/emit-core-fixtures --output build/fixtures/provisional/kinds-check.o
./tools/emit-core-fixtures --output build/fixtures/provisional/kinds-check.o --check
```

The provisional manifest records SHA-256 identities for sources, generator
implementations, product/UAPI/libbpf headers, compiler resource headers,
compiler driver and invoker, loaded compiler configuration, and loaded
compiler shared libraries. Configuration paths and effective compiler commands
come from dry-runs of each actual BPF compilation, including its target and flags;
the untargeted version query alone cannot identify target-specific configurations.
Checkout and output locations are normalized in those recorded commands. It also
records the compiler version, per-object flags, and output hashes.

Configuration support is deliberately bounded to flat files: text containing
`@` or `--config` is refused, including ambiguous occurrences in comments or
literals. Flatten nested configuration before using this generator. Clang can
expand nested response/configuration files without reporting each filename;
this tool does not claim to inventory such hidden inputs. Ordinary flat default
configurations remain enabled. `ldd` identifies the compiler's shared-library
inputs; a static compiler records an empty set. Include-path spelling is
preserved because it affects DWARF bytes even with checkout prefix mapping.
No claim is made that these metadata constitute a hermetic compiler sandbox
or authenticate a malicious compiler.

`--check` first refuses input identity drift, then freshly compiles all five
objects, regenerates the profile, and requires exact bytes and manifest
agreement. Inputs are checked again after compilation. Tests also compare
fresh production objects against the normal build, check literal expected
CO-RE requirements independently for both historical and generated objects,
and reject changed source/header/compiler identity, object bytes, profile
bindings, and unsupported relocation kinds. Compiler-independent historical
profile fields are compared in full; only the three compiler-dependent object
bindings are normalized for that comparison and checked separately against
the fresh objects.

Generated profiles remain `reference-unvalidated`, with a distinct
`test-narrow-provisional` identity and a manifest marked `synthetic-only`.
Recompilation, relocation checks, and fixture tests establish offline test
coverage only. They do not promote profiles or qualify rebuilt artifacts.

## Isolated VM runner preflight

Provision the exact versions in `tests/vm/harness.lock.json` and
`tests/vm/kernels.lock.json` in a container, guest, or local tool prefix. Put
that prefix first on `PATH` and verify all four tools without booting:

```sh
PYTHONPATH=tests/vm python3 -c \
  'from harness_env import check_harness_versions; print(check_harness_versions("vng"))'
```

The preflight checks virtme-ng 1.41, QEMU 10.2.1, bpftrace 0.25.0 and
bpftool 7.7.0. QEMU packaging attribution after the exact generation remains
accepted; the other identities must equal their locked first lines. Missing,
failing, timed-out or mismatched commands refuse the preflight. This check
runs before the existing VM boot helpers. The sudo boot path preserves the
preflight PATH order; a separate vng helper directory is appended, so it cannot
shadow the selected QEMU or oracle executables. The prefix must also be available
to the guest; matching host versions alone does not establish that the guest
executes the same tools.

The VM suite lease must be held by the designated runner before starting a
boot. A successful preflight or smoke boot proves environment readiness only.
Artifact qualification still requires the exact packaged objects and the
applicable kernel/config/BTF/profile/workload/oracle receipts.
