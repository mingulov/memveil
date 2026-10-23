# Ordinary-Linux three-channel recording

<!-- SPDX-License-Identifier: GPL-3.0-or-later -->

This recipe records bounce attempts, mapping lifecycle, and
actual executed copies on the admitted ordinary-Linux
kernel, with an independent oracle module checking the
scripted slices. It qualifies attempt/lifecycle/copy
collection on the shipped reference profile named below.
It does not
qualify per-device reconstruction, confidential-memory
transitions, or sustained pool pressure; see the
[support table](../support.md#capabilities-by-mode) and
[oracle boundaries](../oracles.md). The worked result is
`examples/lifecycle-copy/README.md`:
1,804 events over 150.18 s with zero oracle mismatches.

## Prerequisites

- The admitted kernel files: image, config, and headers for
  `7.0.0-34-generic` (the guest identity check verifies
  exact image, config, BTF, tracepoint-format, and
  build-id bytes).
  The headers must include a built tree at
  `/lib/modules/7.0.0-34-generic/build` with `make` on
  PATH, so the oracle module builds for the guest kernel.
- The frozen harness: `vng` 1.41, `qemu-system-x86_64`
  10.2.1, `/dev/kvm`, and passwordless sudo for the guest
  runner.
- Artifacts from a single build: use one build's binary,
  BPF objects, and bridge throughout. A rebuilt object
  needs fresh evidence; building never earns collection
  qualification by itself.
- The oracle module source in `tests/kernel` (module
  0.4.0), built for the kernel the guest runs (step 1).
- A root shell inside the guest for module loading,
  networking, and block-device setup (steps 3-7).

## VM gate kernel

Every armed VM gate first selects the kernel it tests
(`tests/vm/gate_kernel.py`). A validated shipped profile
that names the guest release and whose bindings hold
against the measured identity and the current objects is
used as is. Otherwise, when the guest boots the host
kernel, the host measures the identity with the guest's
rules and mints `build/vm/gate-profiles/<release>/gate.json`
(status `reference-unvalidated`) plus a saturation
candidate; the selection is copied to
`build/vm/gate-profile.json` for guest-side readers. The
guest measures again and every exact assertion compares
against the selection, so minting names the kernel under
test without relaxing any check. Lanes that load probes
without record's admission also require `memveil doctor`
to report every capability live-verified on that kernel.
Doctor cannot reach a foreign guest kernel from the host;
there the shipped qualification stands in, because the
guest verifies the identity it was qualified on and any
drift of the objects from its bindings is refused.

A different guest release with no holding shipped profile
fails closed. `MEMVEIL_VM_REQUIRE_SHIPPED=1` refuses minted
mode; use it for runs that confirm a shipped claim. A
minted run proves the code on that kernel and qualifies no
collection.

## Guest kernel when the host differs

Guests normally boot the host kernel. When the host runs a
newer kernel than the admitted guest kernel, select the
admitted image through the VNG path with an argv-preserving
wrapper:

    #!/bin/sh
    REAL_VNG=/path/to/vng
    KIMG=/boot/vmlinuz-7.0.0-34-generic
    export PATH="$(dirname "$REAL_VNG"):$PATH"
    if [ "${1:-}" = "--run" ]; then
        shift; exec "$REAL_VNG" --run "$KIMG" "$@"
    fi
    exec "$REAL_VNG" "$@"

Point `VNG` at the wrapper; the module in step 1 still
builds against the guest kernel's headers through `KDIR`.
A cross-release `MEMVEIL_ORACLE_KVER` override needs a
validated profile pin for that release, which the 0.1.0
bundle does not ship, so cross-release runs fail closed.
The guest kernel identity (image, config, BTF, format,
build-id) still verifies inside the guest on every run;
the wrapper selects the kernel, it never bypasses a check.
A release with no validated shipped profile fails closed.

## Record

Run steps 1-2 on the host and steps 3-8 in the disposable
guest (steps 3-8 as root unless noted). Every command below
is literal except `$VNG` (the `vng` binary or the wrapper
above), `$ROOT` (the absolute checkout or extracted bundle
root), and `$KO` (the built oracle module from step 1).
`$ROOT` is the source checkout; from an extracted bundle
the same relative `bin`, `bpf`, `lib`, and `profiles`
paths apply, except step 1, which needs the module
source. From a checkout without packaging, the binary is
`build/memveil`, the objects are under `build/bpf/`, and
the bridge is `build/deps/lmb/lib/libbpf_mojo.so.1`. The
guest sees the host tree read-only, with private overlays
for `/tmp`, `/dev`, `/proc`, `/sys`, and `/run`: all
guest outputs below go under `/tmp/rec/`, which step 2
maps to the host directory `build/vm/rec-shared/` (files
may land root-owned; that is normal). Never write
elsewhere under guest `/tmp`: the private overlay is lost
on exit. The shipped reference profile is used as is; no
substitution step is needed.

1. Build the oracle module for the guest kernel and prepare
   the host-backed output directory:

       mkdir -p "$ROOT/build/vm/oracle-manual"
       cp "$ROOT/tests/kernel/Makefile" \
           "$ROOT/tests/kernel/memveil_dma_oracle.c" \
           "$ROOT/tests/kernel/memveil_region_oracle.c" \
           "$ROOT/build/vm/oracle-manual/"
       make -C "$ROOT/build/vm/oracle-manual" \
           KDIR=/lib/modules/7.0.0-34-generic/build
       modinfo -F vermagic \
           "$ROOT/build/vm/oracle-manual/memveil_dma_oracle.ko"
       sudo -n rm -rf "$ROOT/build/vm/rec-shared"
       mkdir -p "$ROOT/build/vm/rec-shared"

   Expect vermagic `7.0.0-34-generic ...`. The build never
   installs or loads the module. The output directory is
   cleared with sudo because a previous run's files may be
   root-owned (step 2 already needs passwordless sudo).

2. Boot the disposable guest on the admitted kernel with
   forced bounce buffering, an owned pcnet NIC, and the
   output directory mapped read-write:

       sudo -n true
       sudo -n "$VNG" --run -m 6G --append swiotlb=force \
           --network user --qemu-opts='-cpu host' \
           --qemu-opts='-device pcnet,netdev=pcnet0 -netdev user,id=pcnet0,net=10.0.3.0/24' \
           --rwdir=/tmp/rec="$ROOT/build/vm/rec-shared"

   (With the wrapper above, `$VNG` inserts the admitted
   image after `--run`.) The guest drops to a root shell;
   confirm `uname -r` prints `7.0.0-34-generic` and that
   `/tmp/rec/` is writable (`touch /tmp/rec/.w && rm
   /tmp/rec/.w`), then continue inside the guest.

3. Bring up the owned pcnet link and prove the gateway:

       IFACE=""
       for IF in /sys/class/net/*; do
           case $(readlink "$IF/device/driver" 2>/dev/null) in
               *pcnet32) IFACE=${IF##*/} ;;
           esac
       done
       echo "pcnet interface: $IFACE"
       sysctl -w "net.ipv6.conf.$IFACE.disable_ipv6=1"
       ip link set "$IFACE" up
       ip addr add 10.0.3.15/24 dev "$IFACE"
       ping -c 1 -W 3 10.0.3.2

   The interface name is discovered, never assumed; the
   single gateway ping must succeed before continuing.

4. Start the three-channel capture from the bundle (or
   built) tree and wait for readiness. The capture itself
   goes on guest-local storage: the recorder finalizes
   with a rename that the host-backed share refuses:

       mkdir -p /tmp/work
       "$ROOT/bin/memveil" record --duration 150 \
           --output /tmp/work/cap \
           --object "$ROOT/bpf/swiotlb_attempt.bpf.o" \
           --lc-object "$ROOT/bpf/swiotlb_lifecycle.bpf.o" \
           --cp-object "$ROOT/bpf/swiotlb_copy.bpf.o" \
           --bridge "$ROOT/lib/libbpf_mojo.so.1" \
           --profile "$ROOT/profiles/linux-x86_64-7.0-reference.json" \
           --capability attempt-trace,mapping-lifecycle,copy-actual \
           >/tmp/rec/record.out 2>/tmp/rec/record.err &
       REC=$!
       for _ in $(seq 1 60); do
           grep -q "ready session=" /tmp/rec/record.out && break
           sleep 1
       done
       grep "ready session=" /tmp/rec/record.out

   The `ready session=` line proves the window is open;
   run no workload before it appears. Without `--profile`,
   the first covering reference admits through the live
   checks; extra channels never run partial, so an
   interface mismatch refuses with exit 3 instead of
   recording.

5. Record the oracle phase (2 scripted operations, 4,096 +
   1,024 bytes) with its monotonic window:

       now_ns() {
           python3 -c "import time; print(time.monotonic_ns())"
       }
       dmesg -C
       O0=$(now_ns)
       insmod "$KO" mv_oracle_arm=1 mv_oracle_witness=1 \
           mv_oracle_delay_ms=100 mv_oracle_scenario=1
       sleep 8
       rmmod memveil_dma_oracle
       sleep 2
       O1=$(now_ns)
       echo "oracle window: $O0 $O1"
       dmesg | grep "mv-oracle:" >/tmp/rec/o-oracle.log

   `mv_oracle_witness=1` proves every executed-copy byte by
   bounce readback; scenario 1 is the fixed nested script.

6. Record the fail phase (4 operations; op 2 fails outer
   mapping after a healthy inner allocation):

       dmesg -C
       F0=$(now_ns)
       insmod "$KO" mv_oracle_arm=1 mv_oracle_witness=1 \
           mv_oracle_delay_ms=100 mv_oracle_fail_op=2 \
           mv_oracle_inner_probe=1
       sleep 10
       rmmod memveil_dma_oracle
       sleep 2
       F1=$(now_ns)
       echo "fail window: $F0 $F1"
       dmesg | grep "mv-oracle:" >/tmp/rec/f-oracle.log

7. Drive owned traffic (200/200 pings plus 1,048,576
   scsi_debug disk bytes) with its window:

       I0=$(now_ns)
       timeout 60 ping -A -c 200 -q 10.0.3.2
       ls /sys/module/scsi_debug 2>/dev/null && {
           echo "scsi_debug already present; refusing"; exit 1; }
       BEFORE=$(ls /dev | grep -E '^sd[a-z]$' || true)
       modprobe scsi_debug dev_size_mb=64
       DISK=""
       for _ in $(seq 1 30); do
           AFTER=$(ls /dev | grep -E '^sd[a-z]$' || true)
           for D in $AFTER; do
               case " $BEFORE " in
                   *" $D "*) ;;
                   *) DISK=$D; break ;;
               esac
           done
           [ -n "$DISK" ] && break
           sleep 0.5
       done
       echo "owned disk: $DISK"
       grep -q scsi_debug "/sys/block/$DISK/device/model"
       dd "if=/dev/$DISK" of=/dev/null bs=64k count=8 \
           iflag=direct
       dd if=/dev/zero "of=/dev/$DISK" bs=64k count=8 \
           oflag=direct
       echo 1 >"/sys/block/$DISK/device/delete"
       for _ in $(seq 1 50); do
           [ -e "/sys/block/$DISK" ] || break
           sleep 0.1
       done
       [ -e "/sys/block/$DISK" ] && {
           echo "owned disk never left"; exit 1; }
       for _ in $(seq 1 10); do
           rmmod scsi_debug 2>/dev/null && break
           sleep 0.5
       done
       ls /sys/module/scsi_debug 2>/dev/null && {
           echo "scsi_debug never unloaded"; exit 1; }
       I1=$(now_ns)
       echo "traffic window: $I0 $I1"

   The disk is proven owned by its `scsi_debug` model
   string before any I/O; teardown deletes the owned disk,
   waits for its node to leave, then unloads the module.

8. Close the capture, copy it to the host-backed share,
   and render it:

       wait $REC
       echo "record exit: $?"
       cp -r /tmp/work/cap /tmp/rec/cap
       chmod -R a+rX /tmp/rec
       "$ROOT/bin/memveil" report --format text /tmp/rec/cap
       "$ROOT/bin/memveil" report --format json /tmp/rec/cap \
           >/tmp/rec/report.json
       "$ROOT/bin/memveil" top /tmp/rec/cap \
           >/tmp/rec/top.txt

   Expect record exit 4: the capture finalizes with
   materially incomplete terminal evidence (quiescence
   after detach stays unproven), which the report states
   explicitly.

## Compare against the oracle

Still in the guest (or on the host afterwards with
`build/vm/rec-shared/` in place of `/tmp/rec/`), check
every scripted slice against its oracle log with this
standard-library checker. It takes the capture directory,
the two oracle logs, and the three windows from steps 5-7,
and fails loudly on the first mismatch:

    python3 - /tmp/rec/cap /tmp/rec/o-oracle.log \
        /tmp/rec/f-oracle.log "$O0" "$O1" "$F0" "$F1" \
        "$I0" "$I1" <<'EOF'
    import json, re, sys
    cap, olog, flog = sys.argv[1:4]
    (o0, o1, f0, f1, i0, i1) = map(int, sys.argv[4:10])
    bad = []
    def check(want, got, tag):
        if want != got:
            bad.append("%s: want %r got %r" % (tag, want, got))
    def olog_facts(path):
        att, outc, rel, comp, inner = {}, {}, set(), None, {}
        for raw in open(path):
            m = re.search(r"mv-oracle: (.*)$", raw)
            if not m:
                continue
            b = m.group(1).strip()
            m2 = re.match(r"^op=(\d+) attempt requested=(\d+)", b)
            if m2:
                att[int(m2.group(1))] = int(m2.group(2)); continue
            m2 = re.match(r"^op=(\d+) outcome=(success|failure)", b)
            if m2:
                outc[int(m2.group(1))] = m2.group(2); continue
            m2 = re.match(r"^mapping=(\d+) release ", b)
            if m2:
                rel.add(int(m2.group(1))); continue
            m2 = re.match(r"^script complete ops=(\d+)$", b)
            if m2:
                comp = int(m2.group(1)); continue
            m2 = re.match(r"^op=(\d+) inner=(healthy|unknown)", b)
            if m2:
                inner[int(m2.group(1))] = m2.group(2); continue
        return att, outc, rel, comp, inner
    att, outc, rel, comp, _ = olog_facts(olog)
    check({0: 4096, 1: 1024}, att, "oracle attempts")
    check({0: "success", 1: "success"}, outc, "oracle outcomes")
    check(2, comp, "oracle completion")
    att, outc, rel, comp, inner = olog_facts(flog)
    check(4, len(att), "fail op count")
    check("failure", outc.get(2), "fail op outcome")
    check("healthy", inner.get(2), "fail inner health")
    check(False, 2 in rel, "fail op released")
    check(4, comp, "fail completion")
    evs = [json.loads(line) for line in
           open(cap + "/events.ndjson") if line.strip()]
    def win(ev, lo, hi):
        return [e for e in ev if lo <= int(e["ts_ns"]) <= hi]
    def kinds(ev):
        d = {}
        for e in ev:
            d.setdefault(e["kind"], []).append(e)
        return d
    o, f, io = win(evs, o0, o1), win(evs, f0, f1), win(evs, i0, i1)
    ko, kf, ki = kinds(o), kinds(f), kinds(io)
    check(2, len(ko.get("map_result", [])), "oracle maps")
    check(2, len(ko.get("unmap", [])), "oracle unmaps")
    check(2, len(ko.get("sync_request", [])), "oracle syncs")
    check(2, len(ko.get("copy", [])), "oracle copies")
    check(2, len(ko.get("bounce_attempt", [])), "oracle attempts")
    check(["1024", "4096"], sorted(
        e["data"]["mapped_bytes"]
        for e in ko.get("map_result", [])),
        "oracle map sizes")
    check([("original_to_bounce", "1024"),
           ("original_to_bounce", "4096")], sorted(
        (e["data"]["direction"], e["data"]["bytes"])
        for e in ko.get("copy", [])),
        "oracle copy direction+bytes")
    check(5, len(kf.get("map_result", [])), "fail maps")
    check(5, len(kf.get("unmap", [])), "fail unmaps")
    check(8, len(kf.get("sync_request", [])), "fail syncs")
    check(8, len(kf.get("copy", [])), "fail copies")
    check(5, len(kf.get("bounce_attempt", [])), "fail attempts")
    check(["1024", "2048", "2048", "4096", "512"], sorted(
        e["data"]["requested_bytes"]
        for e in kf.get("bounce_attempt", [])),
        "fail attempt bytes")
    check(True, len(ki.get("map_result", [])) > 0, "traffic maps")
    check(True, len(ki.get("bounce_attempt", [])) > 0,
        "traffic attempts")
    check(True, any(int(e["data"]["bytes"]) > 0
                    for e in ki.get("copy", [])), "traffic copy bytes")
    gens = [e["data"]["wire_generation"]
            for e in ko.get("map_result", [])
            + kf.get("map_result", [])]
    check(True, all(g not in (None, "0") for g in gens),
        "assigned generations")
    if bad:
        print("MISMATCH:\n" + "\n".join(bad)); sys.exit(1)
    print("oracle slices exact: %d + %d + %d events" %
        (len(o), len(f), len(io)))
    EOF

The automated form of the same comparison is the
shipped-record and shipped-bundle laboratory lane below
(`tools/test vm-lifecycle`), which runs these phases and
asserts the same multisets plus report consistency. The
worked example's README records the full agreement table.

## Expected results

- Exit 4 with a profile decision naming the shipped
  reference profile.
- Detail and aggregate quality `complete_for_scope` with
  loss 0; terminal `partial`; correlation `partial`
  wherever copies or syncs lack mapping identity (their
  byte facts persist as global known values).
- Oracle slice: 2 operations (4,096 + 1,024 bytes) with 10
  detail events matching exactly (2 maps, 2 unmaps,
  2 syncs, 2 copies, 2 attempts; pool samples and counter
  snapshots share the window). Fail slice: 5 maps,
  5 unmaps, 8 syncs, 8 copies, 5 attempts; the failed
  outer mapping never appears as an outer map, sync, or
  release, while its inner executed copies survive.
- 208 distinct opaque mapping generations in the worked
  example, 0 unassigned; 35,002 original-to-bounce and
  24,784 bounce-to-original bytes; 208 completed lifetimes.
- `memveil report --format text DIR` and
  `memveil top DIR` replay the finished capture; the final
  live summary of a `memveil top --output DIR` run equals a
  replay of the retained capture.

## Limits

Mappings are observed in global scope and stay
unattributed: the device catalog may list observed names,
but identity stays unresolved, and nothing here
reconstructs one device's DMA from unattributed global
mappings. Pool samples are opportunistic debugfs reads at
start, on a best-effort cadence, and at close; gaps stay
visible and never establish sustained pressure alone.
Conversion and region sources do not exist in ordinary
mode; their rows render unavailable with reasons.

## Evidence

Record the kernel image/config/BTF/format/build-id bytes,
the binary/BPF/bridge/profile hashes, the oracle module
source hash and scenario parameters, the workload, the
command, expected and actual results, losses, cleanup, and
artifact hashes. Distinguish PASS, FAIL, BLOCKED, SKIPPED,
and NOT RUN. Re-run evidence invalidated by a relevant
change; never relabel an older receipt as current.

## Laboratory comparisons and shipped capture gates

The laboratory-only comparisons below (low-rate matrix,
per-direction witness, canonical, and fault rows, plus
the copy and real-I/O lanes) compare decoded laboratory
probe records against independent module facts. They
never run shipping capture and never qualify packaged
collection.

The shipped three-channel record and shipped-bundle rows
are different: they run the packaged or built capture
verbs end to end, and their PASS is the shipping
lifecycle/copy qualification, limited to the exact tested
artifact on the admitted profile - the bundle or built
tree admitted through the shipped reference profile on
the tested kernel, selected in shipped mode (see
[VM gate kernel](#vm-gate-kernel)). A PASS never qualifies
a rebuilt object with different bytes, another kernel,
another profile, or a minted gate profile.

Every row needs `MEMVEIL_VM_LIFECYCLE=1`, the laboratory
lifecycle probes in `build/bpf`, the oracle module source
building against the guest kernel, and the frozen
harness; without all four they skip fast with exit 77,
and a skip is never a pass.

| Lane | What it proves |
|---|---|
| `tools/test vm-lifecycle` | Laboratory low-rate matrix, per-direction witness, canonical, shipped three-channel record, shipped-bundle, and fault comparisons. |
| `tools/test vm-copy` | Scripted request/copy comparisons on laboratory probe records. |
| `tools/test vm-real-io` | Laboratory real-I/O hook exercise in the guest. |

`tools/vm-lifecycle` runs the matrix, copy, real-I/O, and
witness laboratory gates in one invocation.
