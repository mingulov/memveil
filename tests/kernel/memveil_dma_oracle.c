/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil owned-DMA oracle: test-only kernel module.
 *
 * The module drives a scripted sequence of DMA calls (map, sync,
 * unmap) against a synthetic platform device and logs every raw
 * call to the kernel log with an "mv-oracle:" prefix. The VM
 * harness replays the log into the independent oracle ledger and
 * compares it against MemVeil reports over the same window.
 *
 * The module never imports MemVeil code and never applies
 * reducer math: it is ground truth, not a second
 * implementation. It refuses to load without the explicit
 * mv_oracle_arm=1 parameter, binds no real hardware, and
 * performs no DMA to real devices.
 *
 * Scenario 0 runs the standard ops loop (unchanged since
 * 0.3.1); scenarios 1..5 run fixed canonical scripts
 * (nested, noop-sync, clamp, early-return, reuse) with
 * readback witnesses for every executed-copy claim.
 */

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define MV_ORACLE_OPS 4
#define MV_ORACLE_MAX_OPS 8192
#define MV_ORACLE_SIZES { 512, 1024, 2048, 4096 }
#define MV_ORACLE_DRVNAME "memveil-oracle"
/* Upstream limit for the fail-probe op: the inner swiotlb
 * allocator still finds slots (pool is reachable), but the
 * outer dma_capable check rejects the bounce address against
 * the clamped bus limit, so the mapping fails after a real
 * map+bounce+cleanup-unmap. A restrictive DMA mask cannot do
 * this: dma_supported refuses masks below the addressable
 * floor before any mapping is attempted.
 */
#define MV_ORACLE_FAIL_BUS_LIMIT 0x100000ULL

static bool mv_oracle_arm;
module_param(mv_oracle_arm, bool, 0444);
MODULE_PARM_DESC(mv_oracle_arm,
		 "Arm the oracle traffic script (test-only, default off)");

static unsigned int mv_oracle_ops = MV_ORACLE_OPS;
module_param(mv_oracle_ops, uint, 0444);
MODULE_PARM_DESC(mv_oracle_ops,
		 "Scripted map/sync/unmap ops, 1..8192 (default 4)");

static unsigned int mv_oracle_delay_ms;
module_param(mv_oracle_delay_ms, uint, 0444);
MODULE_PARM_DESC(mv_oracle_delay_ms,
		 "Sleep between scripted ops in ms (default 0)");

static int mv_oracle_fail_op = -1;
module_param(mv_oracle_fail_op, int, 0444);
MODULE_PARM_DESC(mv_oracle_fail_op,
		 "Op index to fail via a clamped bus DMA limit (-1 off)");

static bool mv_oracle_witness;
module_param(mv_oracle_witness, bool, 0444);
MODULE_PARM_DESC(mv_oracle_witness,
		 "Verify executed copies via bounce readback (default off)");

static bool mv_oracle_inner_probe;
module_param(mv_oracle_inner_probe, bool, 0444);
MODULE_PARM_DESC(mv_oracle_inner_probe,
		 "Retry the fail op unclamped as inner-health evidence (default off)");

static unsigned int mv_oracle_scenario;
module_param(mv_oracle_scenario, uint, 0444);
MODULE_PARM_DESC(mv_oracle_scenario,
		 "Fixed canonical script 0..5 (default 0: standard ops loop;"
		 " 1 nested, 2 noop-sync, 3 clamp, 4 early-return, 5 reuse)");

static struct platform_device *mv_pdev;
static dma_addr_t mv_handle[MV_ORACLE_MAX_OPS];
static void *mv_cpu[MV_ORACLE_MAX_OPS];
static size_t mv_size[MV_ORACLE_MAX_OPS];
static size_t mv_backing[MV_ORACLE_MAX_OPS];
static u64 mv_map_ts[MV_ORACLE_MAX_OPS];
static bool mv_mapped[MV_ORACLE_MAX_OPS];
static unsigned int mv_nops;

static void mv_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	pr_info("mv-oracle: %pV", &(struct va_format){ fmt, &args });
	va_end(args);
}

/* Executed-copy witness: position-dependent pattern fill plus
 * bounce-slot readback through the direct map. The pattern
 * makes every byte position distinct per op and phase, so a
 * full-buffer match proves the kernel copy executed with the
 * logged length. Reads are guarded by pfn_valid on the first
 * and last page; a NULL return means no witness, never a
 * guessed byte count.
 *
 * Only the seed's low byte shifts the pattern, so every phase
 * base below keeps a distinct low byte (map 0x00, sync 0x40,
 * release 0x80, inner 0xC0): for any op index, a buffer
 * holding one phase's bytes can never verify as another
 * phase. Stale destination content therefore fails instead
 * of passing, and mv_witness_selftest refuses to load when
 * that separation breaks.
 */
static void mv_fill(void *buf, size_t len, unsigned int seed)
{
	size_t j;
	u8 *p = buf;

	for (j = 0; j < len; j++)
		p[j] = (u8)(seed + j * 17u + (j >> 8) * 13u);
}

static void *mv_bounce_ptr(dma_addr_t handle, size_t len)
{
	unsigned long first = __phys_to_pfn(handle);
	unsigned long last = __phys_to_pfn(handle + len - 1);

	if (!pfn_valid(first) || !pfn_valid(last))
		return NULL;
	return phys_to_virt(handle);
}

static size_t mv_verified_bytes(const void *buf, size_t len,
				unsigned int seed)
{
	size_t j;
	const u8 *p = buf;

	for (j = 0; j < len; j++) {
		if (p[j] != (u8)(seed + j * 17u + (j >> 8) * 13u))
			return 0;
	}
	return len;
}

/* Position-true fill/verify for a sub-range: byte k of the
 * region must equal the pattern at absolute position off+k,
 * so a guard region keeps its identity wherever it sits. */
static void mv_fill_at(void *buf, size_t off, size_t len,
		       unsigned int seed)
{
	size_t j;
	u8 *p = (u8 *)buf + off;

	for (j = 0; j < len; j++) {
		size_t k = off + j;

		p[j] = (u8)(seed + k * 17u + (k >> 8) * 13u);
	}
}

static size_t mv_verified_at(const void *buf, size_t off, size_t len,
			     unsigned int seed)
{
	size_t j;
	const u8 *p = (const u8 *)buf + off;

	for (j = 0; j < len; j++) {
		size_t k = off + j;

		if (p[j] != (u8)(seed + k * 17u + (k >> 8) * 13u))
			return 0;
	}
	return len;
}

static int mv_witness_selftest(void)
{
	static const unsigned int bases[] = {
		0xA500, 0xB540, 0xD580, 0xE5C0, 0xF520, 0x9560
	};
	static const unsigned int ops[] = { 0, 1, 255, 256, 8191 };
	static u8 probe[512];
	unsigned int a, b, o;

	/* Self-match proves the check can pass; every cross-phase
	 * mismatch proves a skipped copy cannot pass. */
	for (o = 0; o < ARRAY_SIZE(ops); o++) {
		for (a = 0; a < ARRAY_SIZE(bases); a++) {
			mv_fill(probe, sizeof(probe),
				bases[a] + ops[o]);
			if (mv_verified_bytes(probe, sizeof(probe),
					       bases[a] + ops[o]) !=
			    sizeof(probe))
				return -EIO;
			for (b = 0; b < ARRAY_SIZE(bases); b++) {
				if (b == a)
					continue;
				if (mv_verified_bytes(probe,
						       sizeof(probe),
						       bases[b] + ops[o]) != 0)
					return -EIO;
			}
		}
	}
	return 0;
}

static int mv_map_one(struct device *dev, unsigned int i,
		      enum dma_data_direction dir)
{
	dma_addr_t handle;
	size_t backing = mv_backing[i] ? mv_backing[i] : mv_size[i];

	mv_cpu[i] = kmalloc(backing, GFP_KERNEL);
	if (!mv_cpu[i]) {
		mv_log("op=%u outcome=failure rc=-ENOMEM", i);
		return -ENOMEM;
	}
	if (mv_oracle_witness)
		mv_fill(mv_cpu[i], mv_size[i], 0xA500 + i);
	mv_map_ts[i] = ktime_get_ns();
	handle = dma_map_single(dev, mv_cpu[i], mv_size[i], dir);
	if (dma_mapping_error(dev, handle)) {
		mv_log("op=%u outcome=failure rc=-EIO", i);
		kfree(mv_cpu[i]);
		mv_cpu[i] = NULL;
		return -EIO;
	}
	mv_handle[i] = handle;
	mv_mapped[i] = true;
	mv_log("op=%u outcome=success mapping=%u mapped=%zu", i, i,
	       mv_size[i]);
	if (mv_oracle_witness) {
		void *bounce = mv_bounce_ptr(handle, mv_size[i]);
		size_t verified = bounce ?
			mv_verified_bytes(bounce, mv_size[i],
					  0xA500 + i) : 0;

		mv_log("op=%u mapping=%u witness copy=map copied=%zu verified=%zu",
		       i, i, mv_size[i], verified);
	}
	return 0;
}

static void mv_sync_one(struct device *dev, unsigned int i,
			enum dma_data_direction dir)
{
	if (!mv_mapped[i])
		return;
	if (mv_oracle_witness && dir == DMA_TO_DEVICE)
		mv_fill(mv_cpu[i], mv_size[i], 0xB540 + i);
	dma_sync_single_for_device(dev, mv_handle[i], mv_size[i], dir);
	mv_log("op=%u mapping=%u sync dir=%d len=%zu for=device", i, i,
	       (int)dir, mv_size[i]);
	if (mv_oracle_witness && dir == DMA_TO_DEVICE) {
		void *bounce = mv_bounce_ptr(mv_handle[i],
					      mv_size[i]);
		size_t verified = bounce ?
			mv_verified_bytes(bounce, mv_size[i],
					  0xB540 + i) : 0;

		mv_log("op=%u mapping=%u witness copy=sync copied=%zu verified=%zu",
		       i, i, mv_size[i], verified);
	}
}

static void mv_sync_cpu_one(struct device *dev, unsigned int i,
			    enum dma_data_direction dir)
{
	/* A for-cpu sync on a TO_DEVICE mapping reaches the
	 * inner helper and copies nothing: request-only. */
	if (!mv_mapped[i])
		return;
	dma_sync_single_for_cpu(dev, mv_handle[i], mv_size[i], dir);
	mv_log("op=%u mapping=%u sync dir=%d len=%zu for=cpu", i, i,
	       (int)dir, mv_size[i]);
}

/* Over-sized sync against a smaller mapping: the hook clamps
 * the request to the slot room. The guard region past the
 * expected effective bytes is pre-filled with a pattern
 * that differs from the sync pattern at every position
 * (distinct low bytes), so intact guard bytes prove the
 * copy stopped exactly at the clamp boundary. */
#define MV_CLAMP_REQ 4096u
#define MV_CLAMP_EFF 1024u
#define MV_CLAMP_GUARD 1024u

static void mv_sync_clamp(struct device *dev, unsigned int i,
			  enum dma_data_direction dir)
{
	void *bounce;
	size_t pre = 0, post = 0;

	if (!mv_mapped[i])
		return;
	if (mv_oracle_witness)
		mv_fill(mv_cpu[i], MV_CLAMP_REQ, 0xF520 + i);
	bounce = mv_bounce_ptr(mv_handle[i], MV_CLAMP_EFF + MV_CLAMP_GUARD);
	if (mv_oracle_witness && bounce)
		mv_fill_at(bounce, MV_CLAMP_EFF, MV_CLAMP_GUARD, 0x9560 + i);
	dma_sync_single_for_device(dev, mv_handle[i], MV_CLAMP_REQ, dir);
	mv_log("op=%u mapping=%u sync dir=%d len=%zu for=device", i, i,
	       (int)dir, (size_t)MV_CLAMP_REQ);
	if (mv_oracle_witness && bounce) {
		pre = mv_verified_bytes(bounce, MV_CLAMP_EFF, 0xF520 + i);
		post = mv_verified_at(bounce, MV_CLAMP_EFF,
				      MV_CLAMP_GUARD, 0x9560 + i);
		mv_log("op=%u mapping=%u witness copy=clamped copied=%zu verified=%zu pre=%zu post=%zu",
		       i, i, (size_t)MV_CLAMP_REQ, pre, pre, post);
	}
}

/* Sync on a released handle: the address still resolves to a
 * pool, so the inner helper runs and its hook fires, but the
 * slot holds INVALID_PHYS_ADDR and the copy early-returns.
 * A full stale-pattern readback proves zero bytes moved.
 * The cpu buffer stays freed: the early return happens
 * before any address is touched, so there is nothing to
 * fill, and any copy attempt would fault on the invalid
 * origin instead of passing silently. */
static void mv_sync_stale(struct device *dev, unsigned int i,
			  enum dma_data_direction dir)
{
	void *bounce;
	size_t stale = 0;

	dma_sync_single_for_device(dev, mv_handle[i], mv_size[i], dir);
	mv_log("op=%u mapping=%u sync dir=%d len=%zu for=device stale=1",
	       i, i, (int)dir, mv_size[i]);
	if (mv_oracle_witness) {
		bounce = mv_bounce_ptr(mv_handle[i], mv_size[i]);
		if (bounce)
			stale = mv_verified_bytes(bounce, mv_size[i],
						   0xA500 + i);
		mv_log("op=%u mapping=%u witness copy=early copied=%zu verified=0 stale=%zu",
		       i, i, mv_size[i], stale);
	}
}

static void mv_unmap_one(struct device *dev, unsigned int i,
			 enum dma_data_direction dir)
{
	u64 dur;

	if (!mv_mapped[i])
		return;
	if (mv_oracle_witness && dir == DMA_FROM_DEVICE) {
		void *bounce = mv_bounce_ptr(mv_handle[i],
					      mv_size[i]);

		/* Device-write simulation through the exact
		 * memory a DMA write would land in; the
		 * kernel's own unmap path copies it back. */
		if (bounce)
			mv_fill(bounce, mv_size[i], 0xD580 + i);
		dma_unmap_single(dev, mv_handle[i], mv_size[i], dir);
		mv_log("op=%u mapping=%u witness copy=release copied=%zu verified=%zu",
		       i, i, mv_size[i],
		       bounce ? mv_verified_bytes(mv_cpu[i],
						   mv_size[i],
						   0xD580 + i) : 0);
	} else {
		dma_unmap_single(dev, mv_handle[i], mv_size[i], dir);
	}
	dur = ktime_get_ns() - mv_map_ts[i];
	mv_log("mapping=%u release lifetime_ns=%llu", i, dur);
	mv_mapped[i] = false;
	kfree(mv_cpu[i]);
	mv_cpu[i] = NULL;
}

static void mv_inner_probe(struct device *dev, unsigned int i,
			   enum dma_data_direction dir)
{
	dma_addr_t handle;
	void *cpu;
	size_t verified = 0;

	/* Unclamped retry of the fail op: success shows the
	 * inner allocator serves this request, but retry health
	 * alone does not prove the original failure is outer;
	 * that boundary rests on the probe observations checked
	 * against the failed outer mapping. Dedicated log lines
	 * only; never a second attempt/outcome pair for the op. */
	cpu = kmalloc(mv_size[i], GFP_KERNEL);
	if (!cpu) {
		mv_log("op=%u inner=unknown retry=failed rc=-ENOMEM", i);
		return;
	}
	mv_fill(cpu, mv_size[i], 0xE5C0 + i);
	handle = dma_map_single(dev, cpu, mv_size[i], dir);
	if (dma_mapping_error(dev, handle)) {
		mv_log("op=%u inner=unknown retry=failed rc=-EIO", i);
		kfree(cpu);
		return;
	}
	mv_log("op=%u inner-probe map ok=1 mapped=%zu", i,
	       mv_size[i]);
	if (mv_oracle_witness) {
		void *bounce = mv_bounce_ptr(handle, mv_size[i]);

		if (bounce)
			verified = mv_verified_bytes(bounce,
						      mv_size[i],
						      0xE5C0 + i);
		mv_log("op=%u mapping=%u witness copy=inner-map copied=%zu verified=%zu",
		       i, i, mv_size[i], verified);
	}
	dma_unmap_single(dev, handle, mv_size[i], dir);
	kfree(cpu);
	mv_log("op=%u inner=healthy retry=success", i);
}

/* Scripted traffic: even ops map/unmap cleanly, op 1 syncs
 * twice, the last op stays mapped until exit to model an
 * open mapping at the horizon. Sizes cycle 512/1024/2048/
 * 4096, directions alternate TO/FROM.
 */
static void mv_run_standard(struct device *dev)
{
	unsigned int i;
	int rc;

	for (i = 0; i < mv_nops; i++) {
		enum dma_data_direction dir =
			(i % 2) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;

		if (mv_oracle_delay_ms && i > 0)
			msleep(mv_oracle_delay_ms);
		mv_log("op=%u attempt requested=%zu forced=0", i,
		       mv_size[i]);
		if ((int)i == mv_oracle_fail_op) {
			dev->bus_dma_limit = MV_ORACLE_FAIL_BUS_LIMIT;
			rc = mv_map_one(dev, i, dir);
			mv_log("op=%u fail-probe map rc=%d", i, rc);
			dev->bus_dma_limit = 0;
			if (mv_oracle_inner_probe)
				mv_inner_probe(dev, i, dir);
			continue;
		}
		if (mv_map_one(dev, i, dir))
			continue;
		mv_sync_one(dev, i, dir);
		if (i == 1)
			mv_sync_one(dev, i, dir);
		if (i == mv_nops - 1) {
			mv_log("op=%u mapping=%u held-open", i, i);
			continue;
		}
		mv_unmap_one(dev, i, dir);
	}
}

/* Canonical scenario 1 (nested): two overlapping TO_DEVICE
 * mappings, no syncs. Map-time copies sum to 5120. */
static void mv_run_nested(struct device *dev)
{
	mv_nops = 2;
	mv_size[0] = 4096;
	mv_size[1] = 1024;
	mv_log("op=0 attempt requested=4096 forced=0");
	if (mv_map_one(dev, 0, DMA_TO_DEVICE))
		return;
	if (mv_oracle_delay_ms)
		msleep(mv_oracle_delay_ms);
	mv_log("op=1 attempt requested=1024 forced=0");
	if (mv_map_one(dev, 1, DMA_TO_DEVICE)) {
		mv_unmap_one(dev, 0, DMA_TO_DEVICE);
		return;
	}
	mv_unmap_one(dev, 0, DMA_TO_DEVICE);
	mv_unmap_one(dev, 1, DMA_TO_DEVICE);
}

/* Canonical scenario 2 (noop-sync): a for-cpu sync on a
 * TO_DEVICE mapping fires its hook and copies nothing. */
static void mv_run_noopsync(struct device *dev)
{
	mv_nops = 1;
	mv_size[0] = 2048;
	mv_log("op=0 attempt requested=2048 forced=0");
	if (mv_map_one(dev, 0, DMA_TO_DEVICE))
		return;
	mv_sync_cpu_one(dev, 0, DMA_TO_DEVICE);
	mv_unmap_one(dev, 0, DMA_TO_DEVICE);
}

/* Canonical scenario 3 (clamp): a 1024 mapping over-synced
 * at 4096. The hook clamps to the 1024 slot room. */
static void mv_run_clamp(struct device *dev)
{
	mv_nops = 1;
	mv_size[0] = 1024;
	mv_backing[0] = 4096;
	mv_log("op=0 attempt requested=1024 forced=0");
	if (mv_map_one(dev, 0, DMA_TO_DEVICE))
		return;
	mv_sync_clamp(dev, 0, DMA_TO_DEVICE);
	mv_unmap_one(dev, 0, DMA_TO_DEVICE);
}

/* Canonical scenario 4 (early-return): a sync on a released
 * handle fires its hook and copies nothing. */
static void mv_run_early(struct device *dev)
{
	mv_nops = 1;
	mv_size[0] = 2048;
	mv_log("op=0 attempt requested=2048 forced=0");
	if (mv_map_one(dev, 0, DMA_TO_DEVICE))
		return;
	mv_unmap_one(dev, 0, DMA_TO_DEVICE);
	mv_sync_stale(dev, 0, DMA_TO_DEVICE);
}

/* Canonical scenario 5 (reuse): two sequential mappings of
 * the same size; the product must not conflate them. */
static void mv_run_reuse(struct device *dev)
{
	unsigned int i;

	mv_nops = 2;
	for (i = 0; i < 2; i++) {
		mv_size[i] = 2048;
		if (mv_oracle_delay_ms && i > 0)
			msleep(mv_oracle_delay_ms);
		mv_log("op=%u attempt requested=2048 forced=0", i);
		if (mv_map_one(dev, i, DMA_TO_DEVICE))
			continue;
		mv_unmap_one(dev, i, DMA_TO_DEVICE);
	}
}

static int __init mv_oracle_init(void)
{
	struct device *dev;
	int rc;
	unsigned int i;

	if (!mv_oracle_arm) {
		pr_err("mv-oracle: refusing to load without mv_oracle_arm=1\n");
		return -EPERM;
	}
	if (mv_oracle_scenario > 5) {
		pr_err("mv-oracle: bad mv_oracle_scenario=%u\n",
		       mv_oracle_scenario);
		return -EINVAL;
	}
	if (mv_oracle_scenario > 0 &&
	    (mv_oracle_ops != MV_ORACLE_OPS || mv_oracle_fail_op >= 0 ||
	     mv_oracle_inner_probe)) {
		pr_err("mv-oracle: scenario scripts take no ops/fail/inner options\n");
		return -EINVAL;
	}
	if (mv_oracle_ops < 1 || mv_oracle_ops > MV_ORACLE_MAX_OPS) {
		pr_err("mv-oracle: bad mv_oracle_ops=%u\n", mv_oracle_ops);
		return -EINVAL;
	}
	if (mv_oracle_delay_ms > 60000) {
		pr_err("mv-oracle: bad mv_oracle_delay_ms=%u\n",
		       mv_oracle_delay_ms);
		return -EINVAL;
	}
	if (mv_oracle_fail_op >= (int)mv_oracle_ops) {
		pr_err("mv-oracle: bad mv_oracle_fail_op=%d\n",
		       mv_oracle_fail_op);
		return -EINVAL;
	}
	if (mv_oracle_inner_probe && mv_oracle_fail_op < 0) {
		pr_err("mv-oracle: inner probe needs a fail op\n");
		return -EINVAL;
	}
	if (mv_oracle_witness && mv_witness_selftest()) {
		pr_err("mv-oracle: witness pattern selftest failed\n");
		return -EIO;
	}
	mv_pdev = platform_device_register_simple(MV_ORACLE_DRVNAME, -1,
						  NULL, 0);
	if (IS_ERR(mv_pdev))
		return PTR_ERR(mv_pdev);
	dev = &mv_pdev->dev;
	rc = dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (rc)
		goto out_unregister;
	mv_nops = mv_oracle_ops;
	for (i = 0; i < mv_nops; i++) {
		static const size_t sizes[] = MV_ORACLE_SIZES;

		mv_size[i] = sizes[i % ARRAY_SIZE(sizes)];
	}

	switch (mv_oracle_scenario) {
	case 1:
		mv_run_nested(dev);
		break;
	case 2:
		mv_run_noopsync(dev);
		break;
	case 3:
		mv_run_clamp(dev);
		break;
	case 4:
		mv_run_early(dev);
		break;
	case 5:
		mv_run_reuse(dev);
		break;
	default:
		mv_run_standard(dev);
		break;
	}
	mv_log("script complete ops=%u", mv_nops);
	return 0;

out_unregister:
	platform_device_unregister(mv_pdev);
	mv_pdev = NULL;
	return rc;
}

static void __exit mv_oracle_exit(void)
{
	struct device *dev;
	unsigned int i;

	if (!mv_pdev)
		return;
	dev = &mv_pdev->dev;
	for (i = 0; i < mv_nops; i++) {
		enum dma_data_direction dir =
			(i % 2) ? DMA_FROM_DEVICE : DMA_TO_DEVICE;

		if (mv_mapped[i]) {
			mv_log("op=%u mapping=%u exit-release", i, i);
			mv_unmap_one(dev, i, dir);
		}
	}
	platform_device_unregister(mv_pdev);
	mv_pdev = NULL;
	mv_log("unloaded");
}

module_init(mv_oracle_init);
module_exit(mv_oracle_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MemVeil test fixtures");
MODULE_DESCRIPTION("Test-only owned-DMA oracle traffic generator");
MODULE_VERSION("0.4.0");
