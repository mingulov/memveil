<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Running MemVeil alongside other observers

No joint observer pairing or simultaneous MemVeil instances are qualified
for the current candidate. The [support table](support.md#capabilities-by-mode)
keeps these claims separate from attempt collection. Each observer uses its
own programs and output directory, but shared kernel facilities and observer
overhead still require a controlled joint test.

## Historical experiments

Earlier documentation reported MemVeil `84339ac` with KryProbe `7896a5a`
on x86-64 Linux `7.0.0-34-generic`, separate crypto/disk workloads and five
interleaved 60-second rounds. It also reported two MemVeil instances in
separate directories. These statements identify historical source revisions;
they do not bind a later packaged candidate or establish present pairing
support. KryProbe's reported partial completion verdict was not complete
evidence simply because its integrity counters were zero.

Historical p11scope and osslscope experiments reported native PARTIAL
verdicts, also reproduced with the other observer alone. No current pairing
qualification or supported run recipe is earned by those experiments.
Other revisions, kernels and observers remain untested with this candidate.

## Requirements for a supported pairing

Use an isolated environment with exclusive ownership of its test resources,
and separate capture directories. Record exact packaged artifacts and each
observer revision, kernel/config/BTF/profile, workload and aligned measured
windows. Run each observer alone before combined runs and check each against
its own independent oracle; matching outputs from different event domains
are not an oracle. Compare baseline and combined overhead, preserve every
loss/partial channel, and verify cleanup. A missing observer is not tested,
and a partial verdict stays partial.

Publish a pairing recipe only after a candidate-compatible receipt proves
the intended capability. Existing suite locks do not authorize concurrent
privileged gates. The shipping collector's lifecycle and terminal limits
continue to apply during any experiment.
