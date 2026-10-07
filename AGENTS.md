<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Agent instructions for MemVeil

## Purpose and status

MemVeil is a guest-side Linux CLI for explaining covered DMA/SWIOTLB activity and, on qualified confidential guests, observed private/shared-memory operations. Use `MemVeil` for the product and `memveil` for the executable, repository, and module. The earlier SharedVeil name is historical; do not introduce compatibility aliases for it.

As of 2026-10-05, this repository contains its initial README and contributor instructions only. The architecture and commands below are implementation requirements, not existing functionality. Update this status and the README as runnable pieces land.

This repository must be usable independently. Keep the source, tests, schemas, semantic profiles, build inputs, and usage/contributor documentation needed by a standalone clone here. All documentation, comments, generated text, and release material must be self-contained. References to other public projects, their published APIs, and documented dependencies are allowed when relevant. Describe contributor requirements and contracts directly in this repository.

## Before changing code

- Read the README, relevant public contracts, and any more specific directory instructions. Inspect the branch, HEAD, worktrees, and existing changes; preserve unrelated work.
- Establish the bounded task and its acceptance criteria. For bootstrap work, resolve toolchain pins and contracts before relying on them. Referenced files that do not exist are prerequisites to implement, not successful checks.
- Use the official Modular Mojo guidance when available, and verify syntax/FFI against the pinned compiler's documentation and actual builds. Agent skills are development guidance, never build dependencies.
- Keep changes and authorized commits scoped to this repository. Coordinate a library ABI change with an explicit dependency revision and matching tests; do not patch a sibling library invisibly.

## Architecture and ownership

The selected architecture is **Mojo userspace → small C/libbpf bridge → clang-built C eBPF**. Mojo is the chosen userspace language and a practical systems-language experiment. Early FFI, ownership, safety, and packaging gates remain required. Reproduce blockers and obtain a new owner decision before changing language.

Mojo owns collection orchestration, normalization, correlation/accounting, CLI, trace parsing, reducers, and renderers. `libbpf-mojo` owns native resource lifetimes and bounded transport. MemVeil owns its BPF programs, event meanings, schemas, kernel profiles, and measurement claims. Keep C wrappers in the bridge and one internal Mojo FFI boundary. Python may support development validation; production collection and replay remain Mojo.

Target module boundaries, to create as needed:

| Path | Responsibility |
|---|---|
| `src/memveil/cli/` | Argument handling and command dispatch |
| `src/memveil/platform/` | Platform evidence and profile selection |
| `src/memveil/capture/` | Collector, normalization, framing, and capture writer |
| `src/memveil/model/`, `analysis/`, `render/` | Versioned types, pure state/metric logic, and presentation |
| `bpf/include/`, `bpf/programs/` | Explicit wire declarations and metadata-only C probes |
| `profiles/`, `schemas/` | Source-backed kernel semantics and external format contracts |
| `tests/`, `tools/`, `docs/` | Tests/fixtures, public build/test/package entry points, and public documentation |

Analysis and replay must not import collection, libbpf, or live environment readers. Lazily load the native bridge so offline reports work without it. No direct Mojo eBPF compiler, GPU dependency, live-path SIMD requirement, plugin framework, daemon, or dashboard in the initial scope. Shared architecture with other observers is later work with demonstrated consumer requirements.

## Kernel and probe rules

- Initial collection targets x86-64 Linux ≥ 7.0. Older-kernel collection is deferred. Help, version, passive diagnostics, and offline reporting do not require that kernel or collection privileges.
- A release string does not prove support. Record exact source/config/BTF/event layout, hook signatures, parameter/return semantics, successful attachment, and validation evidence. Keep availability, attachment, and semantic qualification distinct.
- Prefer semantic tracepoints for attempts and validated fentry/fexit or other justified kernel hooks for lifecycle data. `uprobe_multi` is a userspace-function attachment mechanism, not a DMA probe substitute.
- Use bounded maps, explicit exhaustion/loss accounting, bounded records and loops, and allowlisted metadata reads. Do not silently evict correctness state with an LRU map.
- Load only packaged, version-matched product BPF objects. Passive `doctor` must not attach; an active owned-fixture check must be explicitly selected.
- Unknown profiles or missing hooks must produce explicit limits. Never promote an unvalidated adapter to supported based solely on successful load or verifier acceptance.

## Measurement invariants

- Distinguish an attempt, internal bounce allocation, final DMA success, actual CPU copy, mapping lifetime, and private/shared region state. Allocation in a shared pool is not a conversion. Release/unmap is not erasure or reprivatization.
- DMA direction is not CPU-copy direction. A helper's requested length may be clamped or skipped; actual-copy totals require proven effective executed lengths. Copies can occur even when a later outer operation fails.
- Keep operation IDs, mapping generations, and address namespaces explicit. Kernel virtual, guest physical, and IOVA values are not interchangeable. Count a physical union only with resolved identity; never guess a virtual-to-physical mapping.
- Treat the current task/PID/cgroup as execution context unless origin is proven. Filtering must not discard completion events needed to maintain state.
- Maintain separate quality for detail events, aggregates, correlation, baseline, and terminal settlement. Unknown is not zero. A counter delta is not added to the same events; lost releases can invalidate state totals rather than make them lower bounds.
- Separate capture finalization from observation completeness. Startup establishes readiness and a measurement epoch. Shutdown closes admission, proves or explicitly fails quiescence, settles transport, samples counters, and records quality. Quiet rings and detached links alone do not prove completeness.
- Failed conversions with unknown rollback invalidate affected state. Ordinary-Linux no-op APIs cannot establish a confidential-memory transition.

## Formats and user behavior

Keep the BPF wire contract, native bridge ABI, external schema, and product version independent. Assert fixed-width layouts, alignment, byte order, bounds, and version compatibility. External format starts at `0.1.0`; captures use `session.json`, `events.ndjson`, and optional `report.json`. Preserve synthetic provenance on every export.

Serialize unsigned 64-bit counts, lengths, timestamps, offsets, and sequences as canonical decimal strings; preserve values above 2^53 exactly and reject overflow beyond u64. Keep signed native errors separate. Use checked arithmetic and null plus a reason for unavailable values. Stream bounded input; reject malformed or unsupported data. Recover a truncated final line only under explicit partial-input mode.

Initial resource requirements are an 8 MiB ring, 4,096 device records, and later 65,536 active mappings with visible exhaustion. Capture defaults are 60 seconds and 1 GiB of event data, with overwrite refused. Bound each serialized line to 64 KiB including newline, session/report documents to 16 MiB, and JSON nesting to 64. Report BPF memory separately from the 256 MiB userspace RSS target on the reference workload.

Implement `doctor`, `record`, offline `report`, and replay `top` with text/Markdown/JSON presentation as appropriate. Reports lead with mode, profile, window, quality, and measured scope; unavailable metrics display a reason. Device filters are exact literal names. Keep global conversion evidence separate from device-scoped DMA metrics.

Exit codes: 0 sufficient evidence for the requested operation; 1 runtime/internal failure; 2 invalid usage/input/schema; 3 requested collection unavailable; 4 completed output with materially incomplete requested evidence. Optional unrequested capabilities do not force exit 4. Findings are evidence-linked observations, not security verdicts.

## Privacy and scope

Do not collect or persist payloads, keys, PINs, content hashes, raw addresses, full process command lines, or environment dumps. No arbitrary page reads, outbound telemetry, enforcement, or attestation/host-access verdicts. Internal identities must not leak through debug logs, errors, fixtures, or exports. Fixed test patterns may belong to an independent oracle but never enter observer output. Pseudonymous metadata is not a guarantee of anonymity.

## Build, test, and evidence

There is no build system or test runner yet. Bootstrap work must provide exact compiler/dependency locks and documented standalone wrappers such as `tools/build`, `tools/test`, and `tools/package`. Check the actual wrapper help and selected compiler's runner; do not invent `mojo test` or report planned commands as passing. Release builds must resolve a pinned library artifact/source without an implicit sibling path.

Choose verification that proves the changed behavior:

- Contracts/reducers/readers: independent expected results, exact large integers, malformed input, schema/version rejection, loss/unknown propagation, mapping reuse, ordering, and bounded state. Synthetic fixtures must stay visibly synthetic.
- Native integration: C/Mojo layout and ownership agreement, short-buffer record retention, partial-failure cleanup, and native sanitizer/FD checks. Native sanitizers do not validate BPF semantics.
- Kernel adapters: a controlled VM workload and independent oracle, exact profile identity, verifier/attach diagnostics, failures, saturation, and stop behavior. A mock or quiet workload is not evidence of real capture.
- Packaging: execute the extracted artifact in a clean runtime without a compiler; run offline reporting without collection privileges or the bridge library. Verify included licenses, BPF files, and dependency resolution.
- Advertised confidential-memory behavior: real SNP/TDX evidence for each claimed capability. Ordinary Linux supports the initial preview, not confidential-guest qualification.

Use the designated isolated environment for privileged tests and respect existing resource locks. Test alongside other observers only with per-tool oracles, combined overhead measurements, and cleanup/isolation checks; matching outputs are not an oracle when tools observe different events.

Record exact source/tree state, toolchain, binary/BPF identities, environment/profile, command/workload, expected and actual outcomes, losses, cleanup, and evidence location. Distinguish failed, skipped, blocked, and unrun checks from passing checks. Rerun affected gates after relevant changes. For documentation-only edits, check links, accuracy, scope, and whitespace instead of adding implementation-mirroring tests.

Update public contracts and usage with behavior changes. Report what changed, what was tested, and remaining limitations. Preserve unrelated work and source/license attribution; publication, infrastructure provisioning, and changes to another repository require authorization for those actions, not merely their mention in a plan.
