<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Capture storage admission

`capture_durability.py` runs four separate ext4 scenarios against the supplied
candidate: observed collector readiness, a nonempty periodic checkpoint,
physical block exhaustion, and physical inode exhaustion. The first two kill
the owned QEMU process group after a successful product fsync boundary, then
boot a fresh kernel and remount the same disk. Killing a collector process is
covered separately by `tools/test record-failures`.

Run only in an assigned disposable ordinary guest environment. The host needs
unprivileged KVM access, the locked virtme-ng/QEMU/bpftrace/bpftool versions,
a readable selected kernel, and at least 2 GiB spare storage. The guest needs
ext4, virtio block, BTF, mount, mkfs.ext4, blkid, and an admitted attempt profile
matching that kernel and object. An earlier attach refusal fails the gate.
The profile is supplied explicitly; this runner does not admit a profile.
Before each boot the host verifies the bound kernel image and modules
manifest and binds the launch to those verified paths. Before any guest disk
mutation the guest must show the expected release, the bound module manifest,
and the pinned live BTF. A guest exposing `/proc/config.gz` must match the
staged config bytes exactly; a guest without it is accepted only on the one
approved release named in the runner, and every receipt records
`config_status` (`measured` or `absent`). The staged config is then kept as a
separate publisher-supplied provenance record, never merged into the absent
claim. The absent-row binding is explicitly weaker than a direct config match:
an image digest proves image identity, not the exact build config.

Build the test adapter with `python3 tests/cli/prepare_capture_failures.py`.
Then supply exact candidate inputs and an absent evidence directory:

```sh
MEMVEIL_VM_CAPTURE_FAILURES=1 python3 tests/vm/capture_durability.py \
  --binary /path/to/candidate/bin/memveil \
  --binary-sha256 ACTUAL_EXECUTABLE_SHA256 \
  --object /path/to/candidate/bpf/swiotlb_attempt.bpf.o \
  --bridge /path/to/candidate/lib/memveil/libgcc_s.so.1 \
  --profile /path/to/admitted-profile.json \
  --kernel /path/to/selected-vmlinuz --kernel-config /path/to/selected.config \
  --modules /path/to/selected-modules --expected-release EXPECTED_UNAME_RELEASE \
  --expected-kernel-sha256 PINNED_IMAGE_SHA --expected-modules-sha256 PINNED_MANIFEST_SHA \
  --expected-btf-sha256 PINNED_LIVE_BTF_SHA \
  --out /path/to/new-evidence-directory
```

(The pre-cutover Mojo candidate kept objects under `lib/memveil/`
with a `lib/libbpf_mojo.so.1` bridge; Rust candidates stage
`bpf/*.bpf.o` inspection objects with a statically linked
loader, so any shipped file fills the `--bridge` slot.)

The runner acquires the existing VM suite lease and creates four exclusive
128 MiB disk images. It never formats or mounts a host device. Guest mutation
requires the command-line ownership nonce and exactly one matching virtio
serial. Images and logs remain in the evidence directory for inspection;
all owned guest processes are reaped. Do not run another exclusive VM suite
concurrently. Unarmed exit 77 is SKIP; armed failures return 1 and retain the
failure reason, commands, available logs, and images.

Evidence binds executable/object/bridge/profile/test-adapter hashes, kernel
image/release/modules-manifest/BTF pins with the observed guest values, boot IDs,
filesystem UUID, reached boundary, allocated reserve,
checkpoint digest/counts, product exits, and independent report validation.
The full-filesystem cases stop the ready writer and verify its unfinalized
checkpoint before filling only the owned guest image. The writer stays stopped
through ENOSPC; the runner rechecks that checkpoint, queues shutdown, then
resumes the writer. Earlier successful finalization fails the gate. They require
successful durable finalization while the same filler remains present. The power-cut cases require a
fresh boot, the exact promised prefix, and recovered-report exit 4. These
results admit only that exact artifact and filesystem/environment; they make
no confidential-platform, authenticity, or other-filesystem claim.

Host-only negative controls run in `tools/test record-failures`. They do not
boot a guest or establish physical filesystem durability. A runner that has
only passed those controls is ready for live execution, not qualified.
The nonempty checkpoint case also needs a reproducible owned I/O workload
arranged and recorded by the operator; an idle guest does not establish it.

## Operator phase (checkpoint leg)

Before the checkpoint capture boot, the runner retains an operator plan
(`operator-plan.json`) naming the one arranged sweep: 64 deterministic
64 KiB blocks streamed to a file on the owned disk and read back. While
the collector records, the guest runs that sweep and appends window
markers to the oracle log (`oracle.log`): one `window-start` and one
`window-end` carrying the workload id, the run nonce, monotonic
timestamps, byte counts, and the sweep content hash. The host judges
the window before the power cut: markers present and ordered, plan
binding exact, byte counts equal to the arranged totals (an idle
zero-byte window fails), and the content hash equal to the
deterministically re-derived sweep hash.

After remount, the guest judges the operator verdict
(`operator-verdict.json`) with two predicates: same-UUID recovery
(promised vs remounted filesystem UUID) and the durable prefix
independently re-verified from raw capture bytes against the promised
integrity. The host re-judges the retained verdict before the leg can
pass. Sampling evidence alone, without operator records, leaves the
leg NOT RUN -- never PASS.

The verdict logic runs offline against recorded fixtures without
guests, armed variables, or privileges:

```sh
python3 tests/vm/capture_durability_operator.py \
  --fixture tests/vm/fixtures/durability-operator/good \
  --out /tmp/operator-dry-run
```

Exit 0 on PASS, 1 on FAIL, 3 when operator evidence is absent
(NOT RUN). Fixture cases live under
`tests/vm/fixtures/durability-operator/` (see its README).
