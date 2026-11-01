/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only owned allocation; never load outside an authorized disposable guest. */
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/set_memory.h>
#include <linux/string.h>

#define MV_REGION_MAX_PAGES 256U

static bool mv_region_oracle_arm;
static unsigned int mv_region_oracle_pages = 2;
static unsigned long long mv_region_oracle_epoch;
module_param(mv_region_oracle_arm, bool, 0444);
module_param(mv_region_oracle_pages, uint, 0444);
module_param(mv_region_oracle_epoch, ullong, 0444);
MODULE_PARM_DESC(mv_region_oracle_arm, "Arm owned allocation (disposable guests only)");
MODULE_PARM_DESC(mv_region_oracle_pages, "Owned page count, 1..256");
MODULE_PARM_DESC(mv_region_oracle_epoch, "Nonzero test epoch token, unique per load");

static DEFINE_MUTEX(mv_lock);
static void *mv_owned;
static bool mv_ready;
static bool mv_started;
static bool mv_uncertain;
static unsigned int mv_count;
static int mv_results[2];

/* The caller holds mv_lock; the entire allocation needs a successful restore. */
static int mv_restore(void)
{
	int rc = set_memory_encrypted((unsigned long)mv_owned,
				      mv_region_oracle_pages);

	mv_results[mv_count++] = rc;
	if (!rc) {
		mv_uncertain = false;
		module_put(THIS_MODULE);
	}
	return rc;
}

static int mv_command_set(const char *value, const struct kernel_param *kp)
{
	int rc = -EINVAL;

	(void)kp;
	mutex_lock(&mv_lock);
	if (!mv_ready) {
		rc = -EAGAIN;
		goto out;
	}
	if (sysfs_streq(value, "share") && !mv_started) {
		if (!try_module_get(THIS_MODULE)) {
			rc = -EBUSY;
			goto out;
		}
		mv_started = true;
		mv_uncertain = true;
		rc = set_memory_decrypted((unsigned long)mv_owned,
					  mv_region_oracle_pages);
		mv_results[mv_count++] = rc;
		/* Even a failed decrypt can have changed part of the allocation. */
		if (rc)
			mv_restore();
	} else if (sysfs_streq(value, "restore") && mv_count == 1) {
		rc = mv_restore();
	}
out:
	mutex_unlock(&mv_lock);
	return rc;
}

static int mv_ledger_get(char *buffer, const struct kernel_param *kp)
{
	unsigned int i;
	int used = 0;

	(void)kp;
	mutex_lock(&mv_lock);
	for (i = 0; i < mv_count; i++)
		used += scnprintf(buffer + used, PAGE_SIZE - used,
			"epoch=%llu ordinal=%u direction=%s pages=%u result=%d\n",
			mv_region_oracle_epoch, i + 1,
			i ? "private" : "shared", mv_region_oracle_pages,
			mv_results[i]);
	mutex_unlock(&mv_lock);
	return used;
}

static const struct kernel_param_ops mv_command_ops = { .set = mv_command_set };
static const struct kernel_param_ops mv_ledger_ops = { .get = mv_ledger_get };
module_param_cb(command, &mv_command_ops, NULL, 0200);
module_param_cb(ledger, &mv_ledger_ops, NULL, 0400);

static int __init mv_region_oracle_init(void)
{
	if (!mv_region_oracle_arm)
		return -EPERM;
	if (!mv_region_oracle_epoch || !mv_region_oracle_pages ||
	    mv_region_oracle_pages > MV_REGION_MAX_PAGES)
		return -EINVAL;
	mutex_lock(&mv_lock);
	mv_owned = alloc_pages_exact((size_t)mv_region_oracle_pages * PAGE_SIZE,
				    GFP_KERNEL | __GFP_ZERO);
	if (!mv_owned) {
		mutex_unlock(&mv_lock);
		return -ENOMEM;
	}
	/* No conversion or fallible initialization follows allocation. */
	mv_ready = true;
	mutex_unlock(&mv_lock);
	return 0;
}

static void __exit mv_region_oracle_exit(void)
{
	mutex_lock(&mv_lock);
	mv_ready = false;
	/* The retained module reference prevents normal unload while uncertain. */
	if (mv_owned && !mv_uncertain) {
		free_pages_exact(mv_owned,
				 (size_t)mv_region_oracle_pages * PAGE_SIZE);
		mv_owned = NULL;
	}
	mutex_unlock(&mv_lock);
}

module_init(mv_region_oracle_init);
module_exit(mv_region_oracle_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MemVeil test fixtures");
MODULE_DESCRIPTION("Test-only bounded owned-region native request oracle");
MODULE_VERSION("0.2.0");
