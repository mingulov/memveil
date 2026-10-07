/* SPDX-License-Identifier: GPL-2.0-only */

/* MemVeil owned-region oracle: test-only kernel module.
 *
 * The module allocates two of its own contiguous pages, runs one
 * shared->private->shared conversion sequence on them with the
 * native set_memory_decrypted/set_memory_encrypted APIs, and logs
 * every native outcome plus the owned PFN range to the kernel log
 * with an "mv-region-oracle:" prefix. The confidential-guest
 * harness replays that log as the independent ledger and compares
 * it against MemVeil's observed conversion records over the same
 * window.
 *
 * The module never imports MemVeil code and never applies reducer
 * math: it is ground truth, not a second implementation. It
 * refuses to load without the explicit mv_region_oracle_arm=1
 * parameter, converts only its own pages, restores them before
 * freeing, and never touches host memory. On ordinary kernels
 * both calls are no-ops returning 0, which the log records
 * honestly. Disposable test VMs only.
 */

#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/set_memory.h>

#define MV_REGION_ORDER 1
#define MV_REGION_PAGES (1U << MV_REGION_ORDER)

static bool mv_region_oracle_arm;
module_param(mv_region_oracle_arm, bool, 0444);
MODULE_PARM_DESC(mv_region_oracle_arm,
		 "Arm the oracle conversion script (test-only, default off)");

static unsigned long mv_addr;
static unsigned int mv_pages;
static bool mv_decrypted;

static void mv_log(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	pr_info("mv-region-oracle: %pV", &(struct va_format){ fmt, &args });
	va_end(args);
}

static int __init mv_region_oracle_init(void)
{
	unsigned long addr;
	unsigned long pfn;
	u64 start_ns;
	int rc;

	if (!mv_region_oracle_arm) {
		pr_err("mv-region-oracle: refusing to load without mv_region_oracle_arm=1\n");
		return -EPERM;
	}
	addr = __get_free_pages(GFP_KERNEL | __GFP_ZERO, MV_REGION_ORDER);
	if (!addr) {
		mv_log("outcome=failure phase=alloc rc=-ENOMEM");
		return -ENOMEM;
	}
	pfn = page_to_pfn(virt_to_page((void *)addr));
	mv_log("region pages=%u pfn=0x%lx outcome=allocated",
	       MV_REGION_PAGES, pfn);
	start_ns = ktime_get_ns();
	rc = set_memory_decrypted(addr, MV_REGION_PAGES);
	mv_log("region pages=%u pfn=0x%lx target=shared rc=%d elapsed_ns=%llu",
	       MV_REGION_PAGES, pfn, rc, ktime_get_ns() - start_ns);
	if (rc) {
		mv_log("outcome=failure phase=decrypt rc=%d", rc);
		free_pages(addr, MV_REGION_ORDER);
		return rc;
	}
	mv_decrypted = true;
	mv_addr = addr;
	mv_pages = MV_REGION_PAGES;
	start_ns = ktime_get_ns();
	rc = set_memory_encrypted(addr, MV_REGION_PAGES);
	mv_log("region pages=%u pfn=0x%lx target=private rc=%d elapsed_ns=%llu",
	       MV_REGION_PAGES, pfn, rc, ktime_get_ns() - start_ns);
	if (rc) {
		mv_log("outcome=failure phase=encrypt rc=%d", rc);
		mv_log("outcome=restored-after-failure pages=%u", MV_REGION_PAGES);
		free_pages(addr, MV_REGION_ORDER);
		mv_addr = 0;
		mv_pages = 0;
		mv_decrypted = false;
		return rc;
	}
	mv_decrypted = false;
	mv_log("script complete pages=%u", MV_REGION_PAGES);
	return 0;
}

static void __exit mv_region_oracle_exit(void)
{
	int rc;

	if (!mv_addr)
		goto out;
	if (mv_decrypted) {
		rc = set_memory_encrypted(mv_addr, mv_pages);
		mv_log("exit-restore pages=%u rc=%d", mv_pages, rc);
		mv_decrypted = false;
	}
	free_pages(mv_addr, MV_REGION_ORDER);
	mv_addr = 0;
	mv_pages = 0;
out:
	mv_log("unloaded");
}

module_init(mv_region_oracle_init);
module_exit(mv_region_oracle_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("MemVeil test fixtures");
MODULE_DESCRIPTION("Test-only owned-region conversion oracle");
MODULE_VERSION("0.1.0");
