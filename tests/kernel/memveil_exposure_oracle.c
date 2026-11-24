/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only owned allocation with a persistent benign buffer; never load
 * outside an authorized disposable guest. Fixture tokens, page counts and
 * results are recorded in the ledger; the ledger never carries addresses
 * and is never consumed by the collector.
 */
#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/set_memory.h>
#include <linux/string.h>

#define MV_EXPOSURE_MAX_PAGES 256U
#define MV_EXPOSURE_QUEUE_PAGES 2U
/* Worst case: queue+owned decrypt plus both restores after a failed share. */
#define MV_EXPOSURE_MAX_RECORDS 5U

static bool mv_exposure_oracle_arm;
static unsigned int mv_exposure_oracle_pages = 2;
static unsigned long long mv_exposure_oracle_epoch;
module_param(mv_exposure_oracle_arm, bool, 0444);
module_param(mv_exposure_oracle_pages, uint, 0444);
module_param(mv_exposure_oracle_epoch, ullong, 0444);
MODULE_PARM_DESC(mv_exposure_oracle_arm, "Arm owned allocation (disposable guests only)");
MODULE_PARM_DESC(mv_exposure_oracle_pages, "Owned page count, 1..256");
MODULE_PARM_DESC(mv_exposure_oracle_epoch, "Nonzero test epoch token, unique per load");

struct mv_record {
	bool queue;
	bool to_private;
	unsigned int pages;
	int result;
};

static DEFINE_MUTEX(mv_lock);
static void *mv_owned;
static void *mv_queue;
static bool mv_ready;
static bool mv_started;
static bool mv_uncertain;
static bool mv_queue_shared;
static unsigned int mv_count;
static struct mv_record mv_records[MV_EXPOSURE_MAX_RECORDS];

/* The caller holds mv_lock; records are bounded so this cannot overflow. */
static void mv_append(bool queue, bool to_private, unsigned int pages, int result)
{
	if (mv_count < MV_EXPOSURE_MAX_RECORDS) {
		mv_records[mv_count].queue = queue;
		mv_records[mv_count].to_private = to_private;
		mv_records[mv_count].pages = pages;
		mv_records[mv_count].result = result;
		mv_count++;
	}
}

/* The caller holds mv_lock. Restore every touched region in reverse order;
 * even a failed decrypt can have changed part of the region. A region is
 * proved private only by a successful restore. Anything else stays
 * quarantined: the module reference is retained and the pages are never
 * freed.
 */
static int mv_share(void)
{
	int rc;
	int restore;
	bool owned_touched = false;
	bool owned_proved = true;
	bool queue_proved = false;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;
	mv_started = true;
	mv_uncertain = true;
	rc = set_memory_decrypted((unsigned long)mv_queue,
				  MV_EXPOSURE_QUEUE_PAGES);
	mv_append(true, false, MV_EXPOSURE_QUEUE_PAGES, rc);
	if (!rc) {
		mv_queue_shared = true;
		rc = set_memory_decrypted((unsigned long)mv_owned,
					  mv_exposure_oracle_pages);
		mv_append(false, false, mv_exposure_oracle_pages, rc);
		owned_touched = true;
		owned_proved = false;
	}
	if (rc) {
		if (owned_touched) {
			restore = set_memory_encrypted((unsigned long)mv_owned,
						       mv_exposure_oracle_pages);
			mv_append(false, true, mv_exposure_oracle_pages,
				  restore);
			owned_proved = !restore;
		}
		restore = set_memory_encrypted((unsigned long)mv_queue,
					       MV_EXPOSURE_QUEUE_PAGES);
		mv_append(true, true, MV_EXPOSURE_QUEUE_PAGES, restore);
		queue_proved = !restore;
		if (!restore)
			mv_queue_shared = false;
		if (owned_proved && queue_proved) {
			mv_uncertain = false;
			module_put(THIS_MODULE);
		}
	}
	return rc;
}

/* The caller holds mv_lock; the entire owned allocation needs a successful
 * restore. The persistent queue buffer intentionally stays shared: it is
 * restored only at unload, after the owned region is proved private.
 */
static int mv_restore_owned(void)
{
	int rc = set_memory_encrypted((unsigned long)mv_owned,
				      mv_exposure_oracle_pages);

	mv_append(false, true, mv_exposure_oracle_pages, rc);
	if (!rc) {
		mv_uncertain = false;
		module_put(THIS_MODULE);
	} else {
		mv_uncertain = true;
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
		rc = mv_share();
	} else if (sysfs_streq(value, "restore") && mv_count == 2) {
		rc = mv_restore_owned();
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
			"epoch=%llu ordinal=%u object=%s direction=%s pages=%u result=%d\n",
			mv_exposure_oracle_epoch, i + 1,
			mv_records[i].queue ? "queue" : "owned",
			mv_records[i].to_private ? "private" : "shared",
			mv_records[i].pages, mv_records[i].result);
	mutex_unlock(&mv_lock);
	return used;
}

static const struct kernel_param_ops mv_command_ops = { .set = mv_command_set };
static const struct kernel_param_ops mv_ledger_ops = { .get = mv_ledger_get };
module_param_cb(command, &mv_command_ops, NULL, 0200);
module_param_cb(ledger, &mv_ledger_ops, NULL, 0400);

static int __init mv_exposure_oracle_init(void)
{
	if (!mv_exposure_oracle_arm)
		return -EPERM;
	if (!mv_exposure_oracle_epoch || !mv_exposure_oracle_pages ||
	    mv_exposure_oracle_pages > MV_EXPOSURE_MAX_PAGES)
		return -EINVAL;
	mutex_lock(&mv_lock);
	mv_owned = alloc_pages_exact((size_t)mv_exposure_oracle_pages * PAGE_SIZE,
				    GFP_KERNEL | __GFP_ZERO);
	if (!mv_owned) {
		mutex_unlock(&mv_lock);
		return -ENOMEM;
	}
	mv_queue = alloc_pages_exact((size_t)MV_EXPOSURE_QUEUE_PAGES * PAGE_SIZE,
				    GFP_KERNEL | __GFP_ZERO);
	if (!mv_queue) {
		free_pages_exact(mv_owned,
				 (size_t)mv_exposure_oracle_pages * PAGE_SIZE);
		mv_owned = NULL;
		mutex_unlock(&mv_lock);
		return -ENOMEM;
	}
	/* No conversion or fallible initialization follows allocation. */
	mv_ready = true;
	mutex_unlock(&mv_lock);
	return 0;
}

static void __exit mv_exposure_oracle_exit(void)
{
	int rc;

	mutex_lock(&mv_lock);
	mv_ready = false;
	if (!mv_started) {
		/* Never shared: both regions are still private. */
		free_pages_exact(mv_queue,
				 (size_t)MV_EXPOSURE_QUEUE_PAGES * PAGE_SIZE);
		free_pages_exact(mv_owned,
				 (size_t)mv_exposure_oracle_pages * PAGE_SIZE);
		mv_queue = NULL;
		mv_owned = NULL;
	} else if (mv_owned && !mv_uncertain) {
		/* Owned is proved private; restore the persistent buffer
		 * before freeing. A failed restore quarantines both
		 * regions: they stay shared and are never freed, rather
		 * than freeing unproved-private pages.
		 */
		rc = set_memory_encrypted((unsigned long)mv_queue,
					  MV_EXPOSURE_QUEUE_PAGES);
		if (!rc) {
			free_pages_exact(mv_queue,
					 (size_t)MV_EXPOSURE_QUEUE_PAGES * PAGE_SIZE);
			free_pages_exact(mv_owned,
					 (size_t)mv_exposure_oracle_pages * PAGE_SIZE);
			mv_queue = NULL;
			mv_owned = NULL;
		}
	}
	/* Uncertain state retains everything; the held module reference
	 * normally prevents reaching here while uncertain.
	 */
	mutex_unlock(&mv_lock);
}

module_init(mv_exposure_oracle_init);
module_exit(mv_exposure_oracle_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("MemVeil test fixtures");
MODULE_DESCRIPTION("Test-only bounded exposure native request oracle");
MODULE_VERSION("0.2.0");
