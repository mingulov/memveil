<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Conversion-hook feasibility kit

This test-only Python/bpftrace kit prepares an operator to measure both
`set_memory_decrypted` and `set_memory_encrypted`. It is separate from MemVeil's
Mojo/C/libbpf runtime, product wire formats, and profile admission. Local tests
use authored synthetic streams and processes. They do not attach BPF, load a
module, resolve a real caller, or qualify a confidential platform.

`journal_spike.py --help` lists the implemented interface. Unarmed execution
returns 77 without creating output. Armed missing prerequisites return 1.
The operator must assign an exclusive disposable x86-64 guest with 4 KiB pages,
readable BTF, the repository's pinned bpftrace/bpftool, and a source review of
the exact booted kernel/configuration. Do not run this on the host.

## Source-reviewed provisional inputs

The following source snapshot supports this prototype, **not** any installed
distribution image: Linux stable `v7.0.14`, commit
`458c6079fc1d41d564c37679c8ace02cd83ee817`. The two wrappers have the prototype
`int (unsigned long addr, int numpages)` in
[set_memory.c](https://github.com/gregkh/linux/blob/458c6079fc1d41d564c37679c8ace02cd83ee817/arch/x86/mm/pat/set_memory.c).
The address argument is never emitted. Pages are requested 4 KiB pages; native
results are signed 32-bit values. Ordinary Linux may return zero without a
conversion. Encryption callbacks, partial changes, aliases and failure paths
prevent interpreting wrapper success as a persistent physical-state proof.

The generator follows bpftrace `v0.25.0`, commit
`18a5ccb8c6a5c6c5dc21c818a58b797ee60df163`, specifically its
[probe/argument contracts](https://github.com/bpftrace/bpftrace/blob/18a5ccb8c6a5c6c5dc21c818a58b797ee60df163/docs/language.md),
[bounded stack interface](https://github.com/bpftrace/bpftrace/blob/18a5ccb8c6a5c6c5dc21c818a58b797ee60df163/docs/stdlib.md),
[JSON formatter](https://github.com/bpftrace/bpftrace/blob/18a5ccb8c6a5c6c5dc21c818a58b797ee60df163/src/output/json.cpp),
and [attachment/child ordering](https://github.com/bpftrace/bpftrace/blob/18a5ccb8c6a5c6c5dc21c818a58b797ee60df163/src/bpftrace.cpp).
`BEGIN` executes before attachment; readiness therefore requires the exact
six-probe attachment notification followed by the queued begin record. The
traced child starts after the four kernel hooks attach. This source reasoning
still requires validation against the exact executable and booted cell.

| Mode | Observation | Unproved boundary |
|---|---|---|
| `--hook fentry` | Both fentry requests and fexit arguments/native results | Actual BTF argument names, load and attach under effective lockdown |
| `--hook kprobe` | Both entry requests and return results; exit page count unavailable | Separate fallback equivalence; no global entry/exit pairing inferred |
| `--mode owned` | PID-scoped serial native-ledger tuple agreement | Requires reviewed oracle, ordinary transport evidence, and exact-cell restoration safety |
| `--mode observe` | Global bounded counts and optional observed-path classes | Boundary censoring, early boot, native return/entry correlation and causal origin |
| `--mode refusal` | Recognized permission/missing-hook refusal, exit and cleanup | Refusal is at tracer load-or-attach; it does not isolate a particular kernel syscall |

Counts from per-CPU `count()` maps are compared with independently parsed detail
counts. They are alternative measurements, never added. Both still share the
same wrapper-hook blind spot. Owned mode separately compares all four ordered
entry/return records to the native worker's two rows. Natural zero counts are
valid observations; zero samples do not pass the 95% caller criterion.

## Caller policy

Caller processing is disabled unless `--callers` is supplied. Enabled probes
request at most 16 kernel frames. bpftrace resolves them transiently in memory;
its raw diagnostics, frames and offsets remain inside bounded pipes. The
sanitizer emits only the following exact labels and aggregate counts.

| Provisional class | Allowed observed-path labels | Source |
|---|---|---|
| `owned` | `mv_command_set [memveil_region_oracle]`, `mv_restore [memveil_region_oracle]` | [Owned oracle](../../kernel/memveil_region_oracle.c) |
| `swiotlb` | `swiotlb_init_late`, `swiotlb_alloc_tlb`, `swiotlb_free_tlb`, `swiotlb_exit` | [swiotlb.c](https://github.com/gregkh/linux/blob/458c6079fc1d41d564c37679c8ace02cd83ee817/kernel/dma/swiotlb.c) |
| `direct_dma` | `dma_set_decrypted`, `dma_set_encrypted`, `dma_direct_alloc`, `dma_direct_free` | [direct.c](https://github.com/gregkh/linux/blob/458c6079fc1d41d564c37679c8ace02cd83ee817/kernel/dma/direct.c) |

This deliberately small table makes no device attribution or completeness
claim. Inlining can remove these frames. Early init paths may be unavailable
to late attachment; a label's presence in the table does not establish coverage.
One class wins only when the retained labels identify exactly one class.
Multiple classes are `ambiguous`, no class is `unresolved`, and a full 16-frame
sample is conservatively `truncated`. Truncated samples never count as classified.

bpftrace can omit module names. For every entry sample the sanitizer streams
the current `/proc/kallsyms` in memory, retaining only the allowed symbol/module
identities, never addresses or a dump. Duplicate names are unresolved. Module
unload before resolution can cause unknowns; the kit does not invent a module.
The actual kernel's symbol identity/source review must approve this table anew.
Labels describe observed call paths, not causal actors. The >=95% metric uses
all entry samples as denominator and remains a measured real-cell requirement.

## Operator inputs and execution

The controller authors `input.json` after observing the guest and reviewing its
exact source. All digests below are canonical lowercase SHA-256 strings. Do not
use zero placeholders. Manifest hashes bind evidence; they are not signatures
or independent proof that the review was performed.

```json
{
  "schema": "memveil-journal-spike-input/1",
  "platform": "ordinary",
  "kernel_release": "EXACT_OBSERVED_RELEASE",
  "lockdown": "none",
  "btf_sha256": "REPLACE_WITH_OBSERVED_SHA256",
  "config_sha256": "REPLACE_WITH_OBSERVED_SHA256",
  "source_evidence_sha256": "REPLACE_WITH_REVIEWED_SHA256",
  "source_review_sha256": "REPLACE_WITH_REVIEWED_SHA256",
  "bpftrace_sha256": "REPLACE_WITH_TOOL_SHA256",
  "bpftool_sha256": "REPLACE_WITH_TOOL_SHA256",
  "owned": null
}
```

`platform` is `ordinary` or `sev-snp`, and `lockdown` is the observed selected
`none`, `integrity`, or `confidentiality`. The helper does not attest or detect
enabled SNP; the external platform evidence supplies that fact. `--config`
binds the exact booted config supplied by the controller. `--source-evidence`
names a reviewed manifest of source/package/config identities, and
`--source-review` names the review of wrapper signatures, native semantics,
caller table, selected image and loader safety. None may be inferred from a
release family. The current BTF and running release are compared directly.

```sh
python3 tests/confidential/spikes/journal_spike.py --help
MEMVEIL_JOURNAL_SPIKE_GUEST=1 python3 tests/confidential/spikes/journal_spike.py \
  --arm --manifest /owned/input.json --config /owned/kernel.config \
  --source-evidence /owned/source-manifest.json --source-review /owned/source-review.txt \
  --mode observe --hook fentry --seconds 60 --output /owned/idle-fentry
```

The output directory must be absent. Retain `receipt.json`; it contains only
validated identifiers, digests, counts, classes, statuses and resource usage.
Supervisor start/readiness/finish monotonic tokens identify observation timing;
no raw tracer or kernel log is written. Repeat explicitly with `--callers` for
the caller experiment. Use a fresh directory for each command.

For an approved I/O experiment, start the separately owned scratch-fio or peer
iperf stimulus only after the `READY` line, then retain its independent
sanitized workload counters and timing beside the observer receipt. `READY`
does not prove a settled global window. Late attachment must retain an unknown
baseline. Early-boot coverage is excluded unless separately demonstrated.
The kit does not launch arbitrary commands, reset NICs, change lockdown, load
unrelated modules, request reports/attestation or operate cloud infrastructure.
Unassigned disruptive stimuli stay NOT_RUN; the idle runner is not their oracle.

Owned mode additionally requires `owned` to be this object (all hashes replaced):

```json
{
  "module_sha256": "REPLACE_WITH_EXACT_MODULE_SHA256",
  "oracle_source_sha256": "REPLACE_WITH_EXACT_ORACLE_SOURCE_SHA256",
  "safety_review_sha256": "REPLACE_WITH_EXACT_CELL_REVIEW_SHA256",
  "transport_sha256": "REPLACE_WITH_ORDINARY_TRANSPORT_SHA256",
  "restore_contract": "whole_range_native_success"
}
```

Add `--mode owned --module /owned/memveil_region_oracle.ko
--safety-review /owned/safety-review.txt --transport /owned/ordinary-transport
--pages 3 --retain-seconds 1` to the same base invocation. `--transport` contains
the reviewed ordinary runner's `transport.json` and all cycle receipts. Its
existing strict validator runs before any module action. The exact module,
source, safety review, ordinary evidence and native restoration contract are
required even on an ordinary guest. The existing serial worker owns the entire
module lifecycle; this helper never force-removes or retries uncertain pages.
Exercise 1 and 3 pages, zero retention and 1..3 seconds retention, with at least
three independent cycles and fresh directories. Each accepted case must have
exactly one successful shared and one private native request and four matching
probe records. A module left present fails cleanup and requires controller
recovery/reboot according to the safety review.
With `--callers`, each owned entry must also carry class `owned` and a nonempty
allowed owned-module label. Unresolved, foreign, ambiguous or truncated entries
fail this controlled join, even when pages/results match. Caller-disabled
transport and global caller-quality measurements remain separate; this check
does not grant real caller admission or force the global 95% metric to pass.

After a genuine fentry refusal, run `--mode refusal --hook fentry` to capture a
bounded refusal receipt. Then explicitly try `--mode observe --hook kprobe`;
this is a separate experiment, never an automatic fallback. If both refuse,
stop admission. No policy bypass is supplied. An unexpected refusal in observe
or owned mode fails; refusal mode must reach the tracer and recognize a narrow
diagnostic class with no readiness and verified cleanup. A failed prerequisite
does not count as a passed negative test.

## Bounds, cleanup and remaining qualification

Input/trace/receipt lines are at most 64 KiB with JSON depth at most 64. Trace transport totals at most
16 MiB per invocation; stderr is at most 64 KiB. Only summary counters and at
most four owned event tuples survive parsing. Symbol scans stop at two million
lines and 4096 bytes per line, retaining at most the finite label table.
Probe maps allow 64 keys, at most eight probes/programs, and 64 ring pages;
these are experiment settings, not product ring changes. Raw child output is
never included in exceptions. Core dumps are disabled for armed runs and their
children; inherited bpftrace debugging/config environment is removed.

`bpftool` program/map/link IDs are compared before and after execution in
memory. A changed inventory, remaining child process group, or surviving owned
module fails cleanup. Exclusive guest ownership is required because unrelated
BPF changes also fail this check. On failure, the receipt can distinguish only
resource absence from complete owned cleanup; it never declares a quiet ring
settled. Every pipe outcome checks the group independently of tracer-leader
exit, allows 10 seconds after SIGINT, then escalates remaining descendants to
SIGKILL with a five-second bound. The direct child is reaped and group absence
is checked. Cleanup signals are latched during this bounded operation, then
the original handlers are restored. A primary transport failure is preserved
alongside any process-cleanup failure. The separate `process_cleanup` receipt
field must be verified before absent BPF resources can satisfy cleanup.
Killing a worker cannot authorize freeing a quarantined allocation. No module
force-unload occurs.

`maxrss_kib` is this Python helper's peak; `children_maxrss_kib` is the highest
child peak across tools, not their simultaneous sum. Actual BPF charge remains
`not_measured` and needs an independent live resource receipt. None of these
helper measurements qualifies the runtime's 256 MiB budget. Real verification
must retain exact tools/source/config/BTF, per-command exits, controlled counts,
losses, native and resource cleanup, caller-quality measurements and final
artifact identities. Upstream source review, synthetic tests and a successful
attach each prove only their own boundary.

Run local checks without privileges:

```sh
python3 tests/confidential/spikes/test_journal_spike.py
```

The synthetic process tests cover both positive and refusal transports, native
joins, count mismatch, malformed input, privacy, timeouts and cleanup failure.
All actual fentry/fexit/kprobe attachment, native caller resolution, I/O stimuli,
ordinary transport integration and real SNP admission still require operator
execution. No persistent state, byte netting, leak verdict or host-read claim
is produced. This kit does not freeze any product wire or runtime profile.
