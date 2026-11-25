#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile the exposure oracle module against an independent native-operation oracle.

Same stub-harness technique as test_region_oracle.py, extended to the two
test regions (owned buffer plus persistent queue buffer) with an independent
native result per region and direction. This pins the failure orders: a
refused restore after any failed share, quarantine retention while any
region is unproved-private, and no exit-time conversion of a queue buffer
that is already private.
"""
import errno
import os
import resource
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
STUB = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
typedef uint64_t u64;
#define __init
#define __exit
#define GFP_KERNEL 1
#define __GFP_ZERO 2
#define PAGE_SIZE 4096
#define THIS_MODULE NULL
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_VERSION(x)
#define MODULE_PARM_DESC(a,b)
#define module_param(a,b,c)
#define module_param_cb(a,b,c,d)
#define module_init(x)
#define module_exit(x)
#define DEFINE_MUTEX(x) pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER
struct kernel_param { int unused; };
struct kernel_param_ops { int (*set)(const char *, const struct kernel_param *); int (*get)(char *, const struct kernel_param *); };
static int dec_queue_rc, dec_owned_rc, enc_queue_rc, enc_owned_rc;
static int refs, ngets, nputs, alloc_fail_owned, alloc_fail_queue, frees, calls, fail_pin;
static size_t owned_len, queue_len;
static void *owned, *queue;
static int unsafe_owned, unsafe_queue;
static int regions[8], dirs[8], sizes[8], results[8];
static void mutex_lock(pthread_mutex_t *m) { assert(!pthread_mutex_lock(m)); }
static void mutex_unlock(pthread_mutex_t *m) { assert(!pthread_mutex_unlock(m)); }
static int sysfs_streq(const char *a, const char *b) { return !strcmp(a,b); }
#define scnprintf snprintf
static int try_module_get(void *m) { (void)m; if (fail_pin) return 0; ++ngets; ++refs; return 1; }
static void module_put(void *m) { (void)m; ++nputs; --refs; }
static void *alloc_pages_exact(size_t n, int flags) {
    assert(flags & __GFP_ZERO);
    if (!owned && !alloc_fail_owned) {
        owned_len = n; owned = calloc(1,n); assert(owned); return owned;
    }
    if (owned && !queue && !alloc_fail_queue) {
        queue_len = n; queue = calloc(1,n); assert(queue); return queue;
    }
    return NULL;
}
static void free_pages_exact(void *p, size_t n) {
    if (p == owned && owned) {
        assert(!unsafe_owned && "free after unproved restore");
        assert(n == owned_len); ++frees; free(p); owned = NULL;
    } else {
        assert(p == queue && queue);
        assert(!unsafe_queue && "free after unproved restore");
        assert(n == queue_len); ++frees; free(p); queue = NULL;
    }
}
static int native_call(unsigned long p, int pages, int dir, int rc) {
    unsigned char *bytes;
    size_t len;
    int *unsafe, id;
    if ((void *)p == queue) { bytes = queue; len = queue_len; unsafe = &unsafe_queue; id = 0; }
    else { assert((void *)p == owned); bytes = owned; len = owned_len; unsafe = &unsafe_owned; id = 1; }
    assert(bytes && (size_t)pages * PAGE_SIZE == len);
    assert(calls < 8);
    regions[calls] = id; dirs[calls] = dir; sizes[calls] = pages; results[calls++] = rc;
    if (dir == 1) {
        for (size_t i=0; i<len; ++i) assert(bytes[i] == 0);
        *unsafe = 1;
    } else if (!rc) *unsafe = 0;
    return rc;
}
static int set_memory_decrypted(unsigned long p, int n) {
    return native_call(p, n, 1, ((void *)p == queue) ? dec_queue_rc : dec_owned_rc);
}
static int set_memory_encrypted(unsigned long p, int n) {
    return native_call(p, n, 2, ((void *)p == queue) ? enc_queue_rc : enc_owned_rc);
}
'''


def compile_run(body, source=None, sanitize=False):
    source = source or ROOT / 'memveil_exposure_oracle.c'
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / 'linux').mkdir()
        for name in ('gfp', 'init', 'ktime', 'mm', 'module', 'set_memory', 'mutex', 'string', 'kernel'):
            (base / 'linux' / (name + '.h')).write_text('')
        unit = base / 'unit.c'
        unit.write_text(STUB + '\n#include "' + str(source) + '"\n' + body)
        exe = base / 'unit'
        flags = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'] if sanitize else []
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-pthread', '-Wall', '-Wextra',
                        '-Wno-unused-function', '-Wno-unused-variable', *flags,
                        '-I', str(base), str(unit), '-o', str(exe)], check=True)
        return subprocess.run([str(exe)], capture_output=True, text=True,
                              preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))


class FailedShareRestoreOrders(unittest.TestCase):
    def test_failed_queue_share_refuses_restore(self):
        # The queue decrypt fails but its restore succeeds: the owned region
        # was never touched and the module is already unpinned, so restore
        # must refuse without converting anything or dropping a reference.
        # Unload afterwards must free both regions without reconverting.
        for pages in (1, 2, 256):
            with self.subTest(pages=pages):
                result = compile_run('''int main(void) {
                    char ledger[4096];
                    mv_exposure_oracle_arm = true;
                    mv_exposure_oracle_pages = %d;
                    mv_exposure_oracle_epoch = 7;
                    dec_queue_rc = -EIO; enc_queue_rc = 0;
                    assert(!mv_exposure_oracle_init());
                    assert(mv_command_set("share", NULL) == -EIO);
                    assert(calls == 2 && regions[0] == 0 && regions[1] == 0);
                    assert(dirs[0] == 1 && dirs[1] == 2);
                    assert(sizes[0] == 2 && sizes[1] == 2);
                    assert(!unsafe_owned && !unsafe_queue);
                    assert(ngets == 1 && nputs == 1 && refs == 0 && !mv_uncertain);
                    assert(mv_command_set("restore", NULL) == -EINVAL);
                    assert(calls == 2 && ngets == 1 && nputs == 1 && refs == 0);
                    assert(mv_count == 2);
                    assert(mv_ledger_get(ledger, NULL) > 0);
                    printf("%%s", ledger);
                    mv_exposure_oracle_exit();
                    assert(calls == 2 && frees == 2 && !owned && !queue);
                    return 0;
                }''' % pages)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout,
                    f'epoch=7 ordinal=1 object=queue direction=shared pages=2 result={-errno.EIO}\n'
                    f'epoch=7 ordinal=2 object=queue direction=private pages=2 result=0\n')

    def test_failed_queue_share_restore_failure_stays_quarantined(self):
        # Both the queue decrypt and its restore fail: a later restore must
        # refuse and leave the quarantine (held reference, uncertain flag,
        # still-shared queue) untouched. Unload must retain everything.
        result = compile_run('''int main(void) {
            mv_exposure_oracle_arm = true; mv_exposure_oracle_pages = 2;
            mv_exposure_oracle_epoch = 7;
            dec_queue_rc = -EIO; enc_queue_rc = -EIO;
            assert(!mv_exposure_oracle_init());
            assert(mv_command_set("share", NULL) == -EIO);
            assert(calls == 2 && unsafe_queue && !unsafe_owned);
            assert(refs == 1 && mv_uncertain);
            assert(mv_command_set("restore", NULL) == -EINVAL);
            assert(calls == 2 && refs == 1 && mv_uncertain && unsafe_queue);
            assert(mv_count == 2);
            mv_exposure_oracle_exit();
            assert(!frees && owned && queue && refs == 1);
            return 0;
        }''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_failed_owned_share_orders(self):
        # The owned decrypt fails after a successful queue decrypt. When both
        # restores succeed the share is fully recovered and unload must free
        # both regions without converting anything; when any restore fails
        # the module stays quarantined and unload retains everything.
        # Restore is refused in every case: no shared owned region remains.
        for enc_owned, enc_queue in ((0, 0), (-errno.EIO, 0),
                                     (0, -errno.EIO), (-errno.EIO, -errno.EIO)):
            with self.subTest(enc_owned=enc_owned, enc_queue=enc_queue):
                result = compile_run("""int main(void) {
                    mv_exposure_oracle_arm = true; mv_exposure_oracle_pages = 3;
                    mv_exposure_oracle_epoch = 9;
                    dec_owned_rc = -EIO; enc_owned_rc = %d; enc_queue_rc = %d;
                    assert(!mv_exposure_oracle_init());
                    assert(mv_command_set("share", NULL) == -EIO);
                    assert(calls == 4);
                    assert(regions[0] == 0 && regions[1] == 1);
                    assert(regions[2] == 1 && regions[3] == 0);
                    assert(dirs[0] == 1 && dirs[1] == 1);
                    assert(dirs[2] == 2 && dirs[3] == 2);
                    assert(sizes[0] == 2 && sizes[1] == 3);
                    assert(sizes[2] == 3 && sizes[3] == 2);
                    assert(mv_count == 4);
                    assert(mv_command_set("restore", NULL) == -EINVAL);
                    assert(calls == 4);
                    if (!%d && !%d) {
                        assert(refs == 0 && !mv_uncertain);
                        assert(!unsafe_owned && !unsafe_queue);
                        mv_exposure_oracle_exit();
                        assert(calls == 4 && frees == 2 && !owned && !queue);
                    } else {
                        assert(refs == 1 && mv_uncertain);
                        mv_exposure_oracle_exit();
                        assert(!frees && owned && queue && refs == 1);
                    }
                    return 0;
                }""" % (enc_owned, enc_queue, enc_owned, enc_queue))
                self.assertEqual(result.returncode, 0, result.stderr)


class ShareRestoreSuccessOrders(unittest.TestCase):
    def test_share_restore_exit_matrix(self):
        for pages in (1, 256):
            for enc_owned, enc_queue in ((0, 0), (0, -errno.EIO), (-errno.EIO, 0)):
                with self.subTest(pages=pages, enc_owned=enc_owned, enc_queue=enc_queue):
                    result = compile_run("""int main(void) {
                        char ledger[4096];
                        mv_exposure_oracle_arm = true;
                        mv_exposure_oracle_pages = %d;
                        mv_exposure_oracle_epoch = 123;
                        enc_owned_rc = %d; enc_queue_rc = %d;
                        assert(mv_command_set("share", NULL) == -EAGAIN);
                        assert(!mv_exposure_oracle_init());
                        assert(!calls && !refs);
                        assert(mv_command_set("restore", NULL) == -EINVAL);
                        assert(mv_command_set("bogus", NULL) == -EINVAL);
                        assert(!mv_command_set("share", NULL));
                        assert(calls == 2 && refs == 1 && mv_uncertain);
                        assert(unsafe_owned && unsafe_queue);
                        assert(regions[0] == 0 && regions[1] == 1);
                        assert(sizes[0] == 2 && sizes[1] == %d);
                        assert(mv_command_set("share", NULL) == -EINVAL);
                        assert(mv_command_set("restore", NULL) == %d);
                        assert(calls == 3 && regions[2] == 1 && dirs[2] == 2);
                        assert(mv_command_set("restore", NULL) == -EINVAL);
                        assert(mv_command_set("share", NULL) == -EINVAL);
                        assert(mv_ledger_get(ledger, NULL) > 0);
                        printf("%%s", ledger);
                        if (!%d) {
                            assert(refs == 0 && !mv_uncertain && !unsafe_owned);
                            mv_exposure_oracle_exit();
                            assert(calls == 4 && regions[3] == 0 && dirs[3] == 2);
                            assert(sizes[3] == 2 && results[3] == enc_queue_rc);
                            if (!%d) {
                                assert(frees == 2 && !owned && !queue);
                            } else {
                                assert(!frees && owned && queue);
                            }
                        } else {
                            assert(refs == 1 && mv_uncertain);
                            mv_exposure_oracle_exit();
                            assert(calls == 3 && !frees && owned && queue);
                        }
                        return 0;
                    }""" % (pages, enc_owned, enc_queue, pages, enc_owned,
                             enc_owned, enc_queue), sanitize=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout,
                        f'epoch=123 ordinal=1 object=queue direction=shared pages=2 result=0\n'
                        f'epoch=123 ordinal=2 object=owned direction=shared pages={pages} result=0\n'
                        f'epoch=123 ordinal=3 object=owned direction=private pages={pages} result={enc_owned}\n')


class InitAndIdleUnload(unittest.TestCase):
    def test_init_refusals_and_safe_idle_unload(self):
        for setup, expected in [('', '-EPERM'),
                ('mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=0;', '-EINVAL'),
                ('mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1; mv_exposure_oracle_pages=0;', '-EINVAL'),
                ('mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1; mv_exposure_oracle_pages=257;', '-EINVAL'),
                ('mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1; alloc_fail_owned=1;', '-ENOMEM')]:
            result = compile_run('int main(void) {' + setup +
                'assert(mv_exposure_oracle_init() == ' + expected + ');' +
                'assert(!owned && !queue && !calls && !refs && !frees); return 0;}')
            self.assertEqual(result.returncode, 0, result.stderr)
        result = compile_run('''int main(void) {
            mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1;
            alloc_fail_queue=1;
            assert(mv_exposure_oracle_init() == -ENOMEM);
            assert(!owned && !queue && frees == 1 && !refs);
            return 0;
        }''')
        self.assertEqual(result.returncode, 0, result.stderr)
        result = compile_run('''int main(void) {
            mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1;
            assert(!mv_exposure_oracle_init()); fail_pin=1;
            assert(mv_command_set("share", NULL) == -EBUSY);
            assert(!calls && !refs); mv_exposure_oracle_exit();
            assert(frees == 2 && !owned && !queue); return 0;
        }''')
        self.assertEqual(result.returncode, 0, result.stderr)


class ConcurrentShare(unittest.TestCase):
    def test_concurrent_share_runs_one_nonnested_native_sequence(self):
        result = compile_run('''
            static void *share(void *p) {
                *(int *)p = mv_command_set("share", NULL); return NULL;
            }
            int main(void) {
                pthread_t a, b; int x, y;
                mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1;
                assert(!mv_exposure_oracle_init());
                assert(!pthread_create(&a, NULL, share, &x));
                assert(!pthread_create(&b, NULL, share, &y));
                assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
                assert((x == 0 && y == -EINVAL) || (y == 0 && x == -EINVAL));
                assert(calls == 2 && refs == 1);
                assert(!mv_command_set("restore", NULL));
                mv_exposure_oracle_exit();
                assert(calls == 4 && frees == 2);
                return 0;
            }
        ''', sanitize=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class SafetyMutations(unittest.TestCase):
    def test_safety_mutations_are_detected(self):
        source = (ROOT / 'memveil_exposure_oracle.c').read_text()
        quarantine_body = '''int main(void) {
            mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1;
            dec_owned_rc=-EIO; enc_owned_rc=-EIO; enc_queue_rc=0;
            assert(!mv_exposure_oracle_init());
            assert(mv_command_set("share", NULL) == -EIO);
            assert(refs == 1 && calls == 4 && mv_uncertain);
            mv_exposure_oracle_exit(); assert(!frees && owned && queue);
            return 0;
        }'''
        recovered_body = '''int main(void) {
            mv_exposure_oracle_arm=true; mv_exposure_oracle_epoch=1;
            dec_queue_rc=-EIO; enc_queue_rc=0;
            assert(!mv_exposure_oracle_init());
            assert(mv_command_set("share", NULL) == -EIO);
            assert(refs == 0 && calls == 2);
            mv_exposure_oracle_exit(); assert(calls == 2 && frees == 2);
            return 0;
        }'''
        mutations = [('mv_owned && !mv_uncertain', 'mv_owned', quarantine_body),
                     ('if (mv_queue_shared) {', 'if (1) {', recovered_body),
                     ('GFP_KERNEL | __GFP_ZERO', 'GFP_KERNEL', recovered_body)]
        with tempfile.TemporaryDirectory() as tmp:
            for old, new, body in mutations:
                with self.subTest(mutation=old):
                    self.assertIn(old, source)
                    path = Path(tmp) / 'mutant.c'
                    path.write_text(source.replace(old, new, 1))
                    result = compile_run(body, source=path)
                    self.assertNotEqual(result.returncode, 0, old)
                    self.assertIn('Assertion', result.stderr)


class SourceHygiene(unittest.TestCase):
    def test_no_address_logging(self):
        source = (ROOT / 'memveil_exposure_oracle.c').read_text()
        self.assertNotIn('pfn=', source)
        self.assertNotIn('%p', source)


if __name__ == '__main__':
    unittest.main()
