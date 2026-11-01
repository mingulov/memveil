#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compile the actual test module against an independent native operation oracle."""
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
#include <stdarg.h>
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
struct va_format { const char *fmt; va_list *va; };
static int dec_rc, enc_rc, unsafe, refs, alloc_fail, frees, calls, fail_pin;
static size_t allocated;
static void *owned;
static int dirs[4], sizes[4], results[4];
static void mutex_lock(pthread_mutex_t *m) { assert(!pthread_mutex_lock(m)); }
static void mutex_unlock(pthread_mutex_t *m) { assert(!pthread_mutex_unlock(m)); }
static int sysfs_streq(const char *a, const char *b) { return !strcmp(a,b); }
#define scnprintf snprintf
#define pr_info(...) ((void)0)
#define pr_err(...) ((void)0)
static u64 ktime_get_ns(void) { return 1; }
static int try_module_get(void *m) { (void)m; if (fail_pin) return 0; ++refs; return 1; }
static void module_put(void *m) { (void)m; assert(refs > 0); --refs; }
static void *alloc_pages_exact(size_t n, int flags) {
    assert(flags & __GFP_ZERO); assert(!owned);
    if (alloc_fail) return NULL;
    allocated = n; owned = calloc(1,n); assert(owned); return owned;
}
static void free_pages_exact(void *p, size_t n) {
    assert(!unsafe && "free after unproved restore");
    assert(p == owned && n == allocated); ++frees; free(p); owned = NULL;
}
static unsigned long __get_free_pages(int flags, unsigned order) {
    return (unsigned long)alloc_pages_exact(PAGE_SIZE << order, flags);
}
static void free_pages(unsigned long p, unsigned order) { free_pages_exact((void *)p, PAGE_SIZE << order); }
static void *virt_to_page(void *p) { return p; }
static unsigned long page_to_pfn(void *p) { (void)p; return 1; }
static int native_call(unsigned long p, int pages, int dir, int rc) {
    assert((void *)p == owned && (size_t)pages * PAGE_SIZE == allocated);
    assert(calls < 4); dirs[calls] = dir; sizes[calls] = pages; results[calls++] = rc;
    if (dir == 1) {
        for (size_t i=0; i<allocated; ++i) assert(((unsigned char *)owned)[i] == 0);
        unsafe = 1;
    } else if (!rc) unsafe = 0;
    return rc;
}
static int set_memory_decrypted(unsigned long p, int n) { return native_call(p,n,1,dec_rc); }
static int set_memory_encrypted(unsigned long p, int n) { return native_call(p,n,2,enc_rc); }
'''


def compile_run(body, source=None, sanitize=False):
    source = source or ROOT / 'memveil_region_oracle.c'
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


class Safety(unittest.TestCase):
    def test_failed_decryption_never_frees_uncertain_pages(self):
        result = compile_run('''int main(void) {
            mv_region_oracle_arm = true; mv_region_oracle_epoch = 1;
            dec_rc = -EIO; enc_rc = -EIO;
            assert(!mv_region_oracle_init());
            assert(mv_command_set("share", NULL) == -EIO);
            assert(calls == 2 && unsafe && refs == 1);
            mv_region_oracle_exit();
            assert(!frees && owned && refs == 1);
            return 0;
        }''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_serial_owned_epoch_and_native_failures(self):
        scenarios = [(0, 0), (-5, 0), (-5, -5), (0, -5)]
        for pages in (1, 3, 256):
            for decrypt, encrypt in scenarios:
                with self.subTest(pages=pages, decrypt=decrypt, encrypt=encrypt):
                    result = compile_run("""int main(void) {
                        char ledger[4096];
                        mv_region_oracle_arm = true;
                        mv_region_oracle_pages = %d;
                        mv_region_oracle_epoch = 123;
                        dec_rc = %d; enc_rc = %d;
                        assert(mv_command_set("share", NULL) == -EAGAIN);
                        assert(!mv_region_oracle_init());
                        assert(!calls && !refs && !unsafe);
                        assert(mv_command_set("restore", NULL) == -EINVAL);
                        assert(mv_command_set("bogus", NULL) == -EINVAL);
                        assert(mv_command_set("share", NULL) == dec_rc);
                        if (!dec_rc) {
                            assert(calls == 1 && refs == 1 && unsafe);
                            assert(mv_command_set("share", NULL) == -EINVAL);
                            assert(mv_command_set("restore", NULL) == enc_rc);
                        }
                        assert(calls == 2 && dirs[0] == 1 && dirs[1] == 2);
                        assert(sizes[0] == %d && sizes[1] == %d);
                        assert(results[0] == dec_rc && results[1] == enc_rc);
                        assert(mv_command_set("restore", NULL) == -EINVAL);
                        assert(mv_command_set("share", NULL) == -EINVAL);
                        assert(mv_ledger_get(ledger, NULL) > 0);
                        printf("%%s", ledger);
                        assert(refs == (enc_rc != 0));
                        mv_region_oracle_exit();
                        assert(frees == (enc_rc == 0));
                        assert(!!owned == (enc_rc != 0));
                        return 0;
                    }""" % (pages, decrypt, encrypt, pages, pages), sanitize=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout,
                        f'epoch=123 ordinal=1 direction=shared pages={pages} result={decrypt}\n'
                        f'epoch=123 ordinal=2 direction=private pages={pages} result={encrypt}\n')

    def test_init_refusals_and_safe_idle_unload(self):
        for setup, expected in [('', '-EPERM'),
                ('mv_region_oracle_arm=true; mv_region_oracle_epoch=0;', '-EINVAL'),
                ('mv_region_oracle_arm=true; mv_region_oracle_epoch=1; mv_region_oracle_pages=0;', '-EINVAL'),
                ('mv_region_oracle_arm=true; mv_region_oracle_epoch=1; mv_region_oracle_pages=257;', '-EINVAL'),
                ('mv_region_oracle_arm=true; mv_region_oracle_epoch=1; alloc_fail=1;', '-ENOMEM')]:
            result = compile_run('int main(void) {' + setup +
                'assert(mv_region_oracle_init() == ' + expected + ');' +
                'assert(!owned && !calls && !refs && !frees); return 0;}')
            self.assertEqual(result.returncode, 0, result.stderr)
        result = compile_run('''int main(void) {
            mv_region_oracle_arm=true; mv_region_oracle_epoch=1;
            assert(!mv_region_oracle_init()); fail_pin=1;
            assert(mv_command_set("share", NULL) == -EBUSY);
            assert(!calls && !refs); mv_region_oracle_exit();
            assert(frees == 1 && !owned); return 0;
        }''')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_concurrent_share_runs_one_nonnested_native_sequence(self):
        result = compile_run('''
            static void *share(void *p) {
                *(int *)p = mv_command_set("share", NULL); return NULL;
            }
            int main(void) {
                pthread_t a, b; int x, y;
                mv_region_oracle_arm=true; mv_region_oracle_epoch=1;
                assert(!mv_region_oracle_init());
                assert(!pthread_create(&a, NULL, share, &x));
                assert(!pthread_create(&b, NULL, share, &y));
                assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
                assert((x == 0 && y == -EINVAL) || (y == 0 && x == -EINVAL));
                assert(calls == 1 && refs == 1);
                assert(!mv_command_set("restore", NULL));
                mv_region_oracle_exit(); assert(calls == 2 && frees == 1);
                return 0;
            }
        ''', sanitize=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_safety_mutations_are_detected(self):
        source = (ROOT / 'memveil_region_oracle.c').read_text()
        mutations = [('mv_owned && !mv_uncertain', 'mv_owned'),
                     ('if (!rc) {', 'if (1) {'),
                     ('GFP_KERNEL | __GFP_ZERO', 'GFP_KERNEL')]
        body = '''int main(void) {
            mv_region_oracle_arm=true; mv_region_oracle_epoch=1;
            dec_rc=-EIO; enc_rc=-EIO;
            assert(!mv_region_oracle_init());
            assert(mv_command_set("share", NULL) == -EIO);
            assert(refs == 1 && calls == 2);
            mv_region_oracle_exit(); assert(!frees && owned);
            return 0;
        }'''
        with tempfile.TemporaryDirectory() as tmp:
            for old, new in mutations:
                self.assertIn(old, source)
                path = Path(tmp) / 'mutant.c'
                path.write_text(source.replace(old, new, 1))
                result = compile_run(body, source=path)
                self.assertNotEqual(result.returncode, 0, old)
                self.assertIn('Assertion', result.stderr)

    def test_no_address_logging(self):
        source = (ROOT / 'memveil_region_oracle.c').read_text()
        self.assertNotIn('pfn=', source)
        self.assertNotIn('%p', source)


if __name__ == '__main__':
    unittest.main()
