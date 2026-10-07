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
 */

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/init.h>
#include <linux/ktime.h>
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

static struct platform_device *mv_pdev;
static dma_addr_t mv_handle[MV_ORACLE_MAX_OPS];
static void *mv_cpu[MV_ORACLE_MAX_OPS];
static size_t mv_size[MV_ORACLE_MAX_OPS];
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

static int mv_map_one(struct device *dev, unsigned int i,
		      enum dma_data_direction dir)
{
	dma_addr_t handle;

	mv_cpu[i] = kmalloc(mv_size[i], GFP_KERNEL);
	if (!mv_cpu[i]) {
		mv_log("op=%u outcome=failure rc=-ENOMEM", i);
		return -ENOMEM;
	}
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
	return 0;
}

static void mv_sync_one(struct device *dev, unsigned int i,
			enum dma_data_direction dir)
{
	if (!mv_mapped[i])
		return;
	dma_sync_single_for_device(dev, mv_handle[i], mv_size[i], dir);
	mv_log("op=%u mapping=%u sync dir=%d len=%zu", i, i, (int)dir,
	       mv_size[i]);
}

static void mv_unmap_one(struct device *dev, unsigned int i,
			 enum dma_data_direction dir)
{
	u64 dur;

	if (!mv_mapped[i])
		return;
	dma_unmap_single(dev, mv_handle[i], mv_size[i], dir);
	dur = ktime_get_ns() - mv_map_ts[i];
	mv_log("mapping=%u release lifetime_ns=%llu", i, dur);
	mv_mapped[i] = false;
	kfree(mv_cpu[i]);
	mv_cpu[i] = NULL;
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

	/* Scripted traffic: even ops map/unmap cleanly, op 1 syncs
	 * twice, the last op stays mapped until exit to model an
	 * open mapping at the horizon. Sizes cycle 512/1024/2048/
	 * 4096, directions alternate TO/FROM.
	 */
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
MODULE_VERSION("0.2.0");
