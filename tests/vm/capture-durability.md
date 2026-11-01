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
ext4, virtio block, BTF, readable `/proc/config.gz`, mount, mkfs.ext4, blkid, and an admitted attempt profile
matching that kernel and object. An earlier attach refusal fails the gate.
The profile is supplied explicitly; this runner does not admit a profile.

Build the test adapter with `python3 tests/cli/prepare_capture_failures.py`.
Then supply exact candidate inputs and an absent evidence directory:

```sh
MEMVEIL_VM_CAPTURE_FAILURES=1 python3 tests/vm/capture_durability.py \
  --binary /path/to/candidate/bin/memveil \
  --binary-sha256 ACTUAL_EXECUTABLE_SHA256 \
  --object /path/to/candidate/lib/memveil/swiotlb_attempt.bpf.o \
  --bridge /path/to/candidate/lib/libbpf_mojo.so.1 \
  --profile /path/to/admitted-profile.json \
  --kernel /path/to/selected-vmlinuz --kernel-config /path/to/selected.config \
  --out /path/to/new-evidence-directory
```

The runner acquires the existing VM suite lease and creates four exclusive
128 MiB disk images. It never formats or mounts a host device. Guest mutation
requires the command-line ownership nonce and exactly one matching virtio
serial. Images and logs remain in the evidence directory for inspection;
all owned guest processes are reaped. Do not run another exclusive VM suite
concurrently. Unarmed exit 77 is SKIP; armed failures return 1 and retain the
failure reason, commands, available logs, and images.

Evidence binds executable/object/bridge/profile/test-adapter hashes, kernel
image/config/BTF, boot IDs, filesystem UUID, reached boundary, allocated reserve,
checkpoint digest/counts, product exits, and independent report validation.
The full-filesystem cases fill only the owned guest image after actual collector
readiness and require ENOSPC before stopping. They require successful durable
finalization while the filler remains present. The power-cut cases require a
fresh boot, the exact promised prefix, and recovered-report exit 4. These
results admit only that exact artifact and filesystem/environment; they make
no confidential-platform, authenticity, or other-filesystem claim.

Host-only negative controls run in `tools/test record-failures`. They do not
boot a guest or establish physical filesystem durability. A runner that has
only passed those controls is ready for live execution, not qualified.
