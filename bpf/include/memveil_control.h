/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil stop-control protocol (staged, not yet wired).
 *
 * Writer inventory for the attempt probe
 * (bpf/programs/swiotlb_attempt.bpf.c, function
 * mv_swiotlb_attempt, the only BPF writer in this profile):
 *
 *   W1  mv_counts[MV_CNT_OBSERVED]       fetch_and_add, step 1
 *   W2  mv_counts[MV_CNT_FLAGS]          sticky OR via mv_raise
 *   W3  mv_counts[MV_CNT_OBSERVED_BYTES] fetch_and_add, step 3
 *   W4  mv_counts[MV_CNT_SUBMIT_FAIL]    checked add via mv_submit_fail
 *   W5  mv_attempts ringbuf              bpf_ringbuf_output, step 6
 *   W6  mv_counts[MV_CNT_EMITTED]        fetch_and_add, step 7
 *   W7  mv_counts[MV_CNT_EMITTED_BYTES]  fetch_and_add, step 7
 *
 * Admission rule today: W1 always counts the firing; step 2
 * refuses emission while any flag bit is set. Quiescence today
 * is consumerside only (collector close-out: settle sleeps,
 * bounded drain, stable-pair counter cut). The control map
 * below stages an explicit kernel-side protocol; wiring it
 * into the probe changes the BPF object and therefore needs a
 * fresh profile qualification before any complete-terminal
 * claim may cite it. Until then the consumer-side stages in
 * src/memveil/capture/stop.mojo carry the proof, and any
 * unproven stage reports partial (exit 4), never complete.
 *
 * Staged map: MV_CTL_LEN u64 cells in a single-entry array.
 *
 *   cell 0  admission epoch: nonzero while writers may begin.
 *           Userspace closes admission by writing 0 with a
 *           full barrier; writers read it before W1 and refuse
 *           (without counting) on 0.
 *   cell 1  active writers: incremented after a successful
 *           epoch read, decremented on every writer exit path
 *           (submit, reject, early return). Quiescence is epoch
 *           0 plus a stable zero here across the settle window.
 *
 * Weak-memory assumptions (x86-64, admitted builds only):
 * atomic read-modify-write ops are the sole cross-CPU
 * channel; no plain-load counter is trusted without a stable
 * pair; the epoch store uses __sync_synchronize before the
 * settle window starts. Other architectures need their own
 * barrier argument before reuse.
 */

#ifndef MEMVEIL_CONTROL_H
#define MEMVEIL_CONTROL_H

/* Staged control-map geometry (see note above). */
#define MV_CTL_LEN 2u
#define MV_CTL_EPOCH 0u
#define MV_CTL_ACTIVE 1u

/* Consumer stop budget: 5000 ms of monotonic time. The budget
 * bounds waiting; a deadline never establishes quiescence. */
#define MV_STOP_BUDGET_MS 5000u

#endif /* MEMVEIL_CONTROL_H */
