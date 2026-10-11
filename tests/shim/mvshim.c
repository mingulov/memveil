/* SPDX-License-Identifier: GPL-3.0-or-later */

/* LD_PRELOAD fault injector for EventWriter tests.
 *
 * Modes come from MVSHIM as a comma-separated list:
 *   short:N          pwrite call #N (1-based, global) returns a short
 *                    count (success): exercises the retry loop.
 *   enospc_after:N   pwrite calls #N and later fail with ENOSPC.
 *   enospc_events    pwrite on fds resolving to events.ndjson fails ENOSPC.
 *   enospc_tmp       openat/pwrite on *.tmp paths fails ENOSPC.
 *   fsync_dir        fsync on directory fds fails EIO.
 *   fsync_parent:P   fsync on the fd resolving to path P fails EIO.
 *   read_eintr_once  first read on a signalfd fails EINTR once.
 *   fail_rename      renameat2 fails EACCES.
 *   fail_truncate    ftruncate fails EIO.
 *   fstat_fail_events
 *                    fstat on fds resolving to events.ndjson fails EIO.
 *   fstat_fail_dir:P fstat on the fd resolving to path P fails EIO.
 *   fail_unlink_events
 *                    unlinkat of the events.ndjson name (file, not
 *                    dir) fails EACCES, sticking construction unwind.
 *   stderr_decoy:P  open of /dev/stderr opens P instead: simulates
 *                    guests that rebind /dev/stderr away from fd 2
 *                    (diagnostics must follow the fd, not the path).
 *   swapdir:PLANTED:BASE
 *                    one-shot mkdirat interposition: after the first
 *                    successful mkdirat whose created path has
 *                    basename BASE, move the fresh dir aside to
 *                    <path>.displaced and move PLANTED into its
 *                    place. Exercises the mkdir->openat window
 *                    deterministically.
 *   fstat_fail_tmp
 *                    fstat on fds resolving to *.tmp fails EIO.
 *   fstat_fail_tmp_written
 *                    fstat on *.tmp fds fails EIO, but only after
 *                    a pwrite to a *.tmp fd was observed: the
 *                    creation-time pin succeeds while a later
 *                    re-pin of the same file fails.
 *   swap_session:PLANTED
 *                    one-shot openat interposition: before the first
 *                    open of the "session.json" basename without
 *                    O_CREAT, move the published file aside to
 *                    session.json.displaced and move PLANTED into
 *                    its place. Shows whether the session-origin
 *                    comparison ran.
 *   fstat_fail_session
 *                    fstat on fds resolving to a session.json path
 *                    fails EIO (the published session, not the tmp).
 *
 * Torn records arise from composition: short:N with
 * enospc_after:N+1 makes loop iteration N short and the
 * retry fail, leaving done > 0 for ftruncate recovery.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static ssize_t (*real_pwrite)(int, const void *, size_t, off_t);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_open)(const char *, int, ...);
static int (*real_open64)(const char *, int, ...);
static int (*real_fsync)(int);
static int (*real_ftruncate)(int, off_t);
static int (*real_renameat2)(int, const char *, int, const char *, unsigned);
static ssize_t (*real_read)(int, void *, size_t);
static int (*real_fstat)(int, struct stat *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_mkdirat)(int, const char *, mode_t);
static int read_eintr_fired = 0;

static long opt_short_at = 0;
static long opt_enospc_after = 0;
static int opt_enospc_events = 0;
static int opt_enospc_tmp = 0;
static int opt_fsync_dir = 0;
static char opt_fsync_parent[1024];
static int opt_read_eintr_once = 0;
static int opt_fail_rename = 0;
static int opt_fail_truncate = 0;
static int opt_fstat_fail_events = 0;
static char opt_fstat_fail_dir[1024];
static int opt_fail_unlink_events = 0;
static char opt_stderr_decoy[1024];
static char opt_swapdir_planted[1024];
static char opt_swapdir_base[256];
static int swapdir_fired = 0;
static int opt_fstat_fail_tmp = 0;
static int opt_fstat_fail_tmp_written = 0;
static int tmp_written_seen = 0;
static char opt_swap_session[1024];
static int swap_session_fired = 0;
static int opt_fstat_fail_session = 0;
static long pwrite_count = 0;
static int inited = 0;

static int ends_with(const char *s, const char *suffix) {
    size_t sl = strlen(s), xl = strlen(suffix);
    if (sl < xl)
        return 0;
    return strcmp(s + sl - xl, suffix) == 0;
}

static void parse_opts(void) {
    const char *env = getenv("MVSHIM");
    if (!env || !*env)
        return;
    char buf[1024];
    size_t n = strlen(env);
    if (n >= sizeof(buf))
        n = sizeof(buf) - 1;
    memcpy(buf, env, n);
    buf[n] = '\0';
    for (char *tok = strtok(buf, ","); tok; tok = strtok(NULL, ",")) {
        if (strncmp(tok, "short:", 6) == 0)
            opt_short_at = atol(tok + 6);
        else if (strncmp(tok, "enospc_after:", 13) == 0)
            opt_enospc_after = atol(tok + 13);
        else if (strcmp(tok, "enospc_events") == 0)
            opt_enospc_events = 1;
        else if (strcmp(tok, "enospc_tmp") == 0)
            opt_enospc_tmp = 1;
        else if (strcmp(tok, "fsync_dir") == 0)
            opt_fsync_dir = 1;
        else if (strncmp(tok, "fsync_parent:", 13) == 0) {
            size_t pl = strlen(tok + 13);
            if (pl >= sizeof(opt_fsync_parent))
                pl = sizeof(opt_fsync_parent) - 1;
            memcpy(opt_fsync_parent, tok + 13, pl);
            opt_fsync_parent[pl] = '\0';
        }
        else if (strcmp(tok, "read_eintr_once") == 0)
            opt_read_eintr_once = 1;
        else if (strcmp(tok, "fail_rename") == 0)
            opt_fail_rename = 1;
        else if (strcmp(tok, "fail_truncate") == 0)
            opt_fail_truncate = 1;
        else if (strcmp(tok, "fstat_fail_events") == 0)
            opt_fstat_fail_events = 1;
        else if (strcmp(tok, "fail_unlink_events") == 0)
            opt_fail_unlink_events = 1;
        else if (strncmp(tok, "fstat_fail_dir:", 15) == 0) {
            size_t pl = strlen(tok + 15);
            if (pl >= sizeof(opt_fstat_fail_dir))
                pl = sizeof(opt_fstat_fail_dir) - 1;
            memcpy(opt_fstat_fail_dir, tok + 15, pl);
            opt_fstat_fail_dir[pl] = '\0';
        }
        else if (strncmp(tok, "stderr_decoy:", 13) == 0) {
            size_t pl = strlen(tok + 13);
            if (pl >= sizeof(opt_stderr_decoy))
                pl = sizeof(opt_stderr_decoy) - 1;
            memcpy(opt_stderr_decoy, tok + 13, pl);
            opt_stderr_decoy[pl] = '\0';
        }
        else if (strncmp(tok, "swapdir:", 8) == 0) {
            char *sep = strchr(tok + 8, ':');
            if (sep && sep[1]) {
                size_t pl = (size_t)(sep - (tok + 8));
                if (pl >= sizeof(opt_swapdir_planted))
                    pl = sizeof(opt_swapdir_planted) - 1;
                memcpy(opt_swapdir_planted, tok + 8, pl);
                opt_swapdir_planted[pl] = '\0';
                size_t bl = strlen(sep + 1);
                if (bl >= sizeof(opt_swapdir_base))
                    bl = sizeof(opt_swapdir_base) - 1;
                memcpy(opt_swapdir_base, sep + 1, bl);
                opt_swapdir_base[bl] = '\0';
            }
        }
        else if (strcmp(tok, "fstat_fail_tmp") == 0)
            opt_fstat_fail_tmp = 1;
        else if (strcmp(tok, "fstat_fail_tmp_written") == 0)
            opt_fstat_fail_tmp_written = 1;
        else if (strncmp(tok, "swap_session:", 13) == 0) {
            size_t pl = strlen(tok + 13);
            if (pl >= sizeof(opt_swap_session))
                pl = sizeof(opt_swap_session) - 1;
            memcpy(opt_swap_session, tok + 13, pl);
            opt_swap_session[pl] = '\0';
        }
        else if (strcmp(tok, "fstat_fail_session") == 0)
            opt_fstat_fail_session = 1;
    }
}

static void ensure_init(void) {
    if (inited)
        return;
    inited = 1;
    real_pwrite = dlsym(RTLD_NEXT, "pwrite");
    real_openat = dlsym(RTLD_NEXT, "openat");
    real_open = dlsym(RTLD_NEXT, "open");
    real_open64 = dlsym(RTLD_NEXT, "open64");
    real_fsync = dlsym(RTLD_NEXT, "fsync");
    real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
    real_renameat2 = dlsym(RTLD_NEXT, "renameat2");
    real_read = dlsym(RTLD_NEXT, "read");
    real_fstat = dlsym(RTLD_NEXT, "fstat");
    real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
    real_mkdirat = dlsym(RTLD_NEXT, "mkdirat");
    parse_opts();
}

static int fd_path_ends(int fd, const char *suffix) {
    char proc[64], target[1024];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, target, sizeof(target) - 1);
    if (n < 0)
        return 0;
    target[n] = '\0';
    return ends_with(target, suffix);
}

static int resolve_at(int dirfd, const char *path, char *out,
                      size_t outlen) {
    if (path[0] == '/') {
        snprintf(out, outlen, "%s", path);
        return 1;
    }
    if (dirfd == AT_FDCWD) {
        if (outlen < 256 || !getcwd(out, outlen - 256))
            return 0;
        size_t l = strlen(out);
        snprintf(out + l, outlen - l, "/%s", path);
        return 1;
    }
    char proc[64], parent[1024];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", dirfd);
    ssize_t n = readlink(proc, parent, sizeof(parent) - 1);
    if (n < 0)
        return 0;
    parent[n] = '\0';
    snprintf(out, outlen, "%s/%s", parent, path);
    return 1;
}

ssize_t pwrite(int fd, const void *buf, size_t count, off_t off) {
    ensure_init();
    pwrite_count++;
    if (opt_fstat_fail_tmp_written && fd_path_ends(fd, ".tmp"))
        tmp_written_seen = 1;
    if (opt_enospc_events && fd_path_ends(fd, "events.ndjson")) {
        errno = ENOSPC;
        return -1;
    }
    if (opt_enospc_tmp && fd_path_ends(fd, ".tmp")) {
        errno = ENOSPC;
        return -1;
    }
    if (opt_enospc_after > 0 && pwrite_count >= opt_enospc_after) {
        errno = ENOSPC;
        return -1;
    }
    if (opt_short_at > 0 && pwrite_count == opt_short_at && count > 1) {
        size_t half = count / 2;
        if (half == 0)
            half = 1;
        return real_pwrite(fd, buf, half, off);
    }
    return real_pwrite(fd, buf, count, off);
}

int openat(int dirfd, const char *path, int flags, ...) {
    ensure_init();
    if (opt_enospc_tmp && ends_with(path, ".tmp")) {
        errno = ENOSPC;
        return -1;
    }
    if (opt_swap_session[0] && !swap_session_fired &&
        strcmp(path, "session.json") == 0 && !(flags & O_CREAT)) {
        char target[2048], aside[2160];
        if (resolve_at(dirfd, path, target, sizeof(target))) {
            swap_session_fired = 1;
            snprintf(aside, sizeof(aside), "%s.displaced", target);
            if (rename(target, aside) == 0)
                rename(opt_swap_session, target);
        }
    }
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return real_openat(dirfd, path, flags, mode);
}

static int open_redirect(const char *path, int flags, mode_t mode,
                         int (*real)(const char *, int, ...)) {
    if (opt_stderr_decoy[0] && strcmp(path, "/dev/stderr") == 0)
        return real(opt_stderr_decoy, O_WRONLY | O_CREAT | O_APPEND,
                    0600);
    return real(path, flags, mode);
}

int open(const char *path, int flags, ...) {
    ensure_init();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return open_redirect(path, flags, mode, real_open);
}

int open64(const char *path, int flags, ...) {
    ensure_init();
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    return open_redirect(path, flags, mode, real_open64);
}

static int fd_path_is(int fd, const char *want) {
    char proc[64], target[1024];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(proc, target, sizeof(target) - 1);
    if (n < 0)
        return 0;
    target[n] = '\0';
    return strcmp(target, want) == 0;
}

ssize_t read(int fd, void *buf, size_t count) {
    ensure_init();
    if (opt_read_eintr_once && !read_eintr_fired &&
        fd_path_is(fd, "anon_inode:[signalfd]")) {
        read_eintr_fired = 1;
        errno = EINTR;
        return -1;
    }
    return real_read(fd, buf, count);
}

int fsync(int fd) {
    ensure_init();
    if (opt_fsync_dir) {
        struct stat st;
        if (real_fsync && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
            errno = EIO;
            return -1;
        }
    }
    if (opt_fsync_parent[0] && fd_path_is(fd, opt_fsync_parent)) {
        errno = EIO;
        return -1;
    }
    return real_fsync(fd);
}

int fstat(int fd, struct stat *st) {
    ensure_init();
    if (opt_fstat_fail_events && fd_path_ends(fd, "events.ndjson")) {
        errno = EIO;
        return -1;
    }
    if (opt_fstat_fail_dir[0] && fd_path_is(fd, opt_fstat_fail_dir)) {
        errno = EIO;
        return -1;
    }
    if (opt_fstat_fail_tmp && fd_path_ends(fd, ".tmp")) {
        errno = EIO;
        return -1;
    }
    if (opt_fstat_fail_tmp_written && tmp_written_seen &&
        fd_path_ends(fd, ".tmp")) {
        errno = EIO;
        return -1;
    }
    if (opt_fstat_fail_session && fd_path_ends(fd, "/session.json")) {
        errno = EIO;
        return -1;
    }
    return real_fstat(fd, st);
}

int unlinkat(int dirfd, const char *path, int flags) {
    ensure_init();
    if (opt_fail_unlink_events && flags == 0 &&
        strcmp(path, "events.ndjson") == 0) {
        errno = EACCES;
        return -1;
    }
    return real_unlinkat(dirfd, path, flags);
}

int ftruncate(int fd, off_t len) {
    ensure_init();
    if (opt_fail_truncate) {
        errno = EIO;
        return -1;
    }
    return real_ftruncate(fd, len);
}

int renameat2(int a, const char *b, int c, const char *d, unsigned e) {
    ensure_init();
    if (opt_fail_rename) {
        errno = EACCES;
        return -1;
    }
    return real_renameat2(a, b, c, d, e);
}

int mkdirat(int dirfd, const char *path, mode_t mode) {
    ensure_init();
    int r = real_mkdirat(dirfd, path, mode);
    if (r != 0 || !opt_swapdir_planted[0] || swapdir_fired)
        return r;
    char created[2048];
    if (!resolve_at(dirfd, path, created, sizeof(created)))
        return r;
    const char *slash = strrchr(created, '/');
    const char *base = slash ? slash + 1 : created;
    if (strcmp(base, opt_swapdir_base) != 0)
        return r;
    swapdir_fired = 1;
    char aside[2160];
    snprintf(aside, sizeof(aside), "%s.displaced", created);
    if (rename(created, aside) != 0)
        return r;
    if (rename(opt_swapdir_planted, created) != 0) {
        rename(aside, created);
        return r;
    }
    return r;
}

/* MVSHIM_COUNT=path: write the total pwrite call count at
 * exit. The lane asserts the baseline count so every
 * short:N / enospc_after:N mode is anchored to a verified
 * op->call mapping (any runtime pwrite would fail loudly
 * here instead of silently shifting the modes).
 */
static void __attribute__((destructor)) dump_count(void) {
    const char *path = getenv("MVSHIM_COUNT");
    if (!path || !*path)
        return;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%ld\n", pwrite_count);
    if (n <= 0)
        return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    ssize_t w = write(fd, buf, (size_t)n);
    (void)w;
    close(fd);
}
