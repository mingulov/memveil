/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fired, checkpoint_syncs, checkpoint_count;
static void mark(const char *name) {
    const char *path = getenv("MV_FAULT_MARKER");
    if (!path) _exit(92);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || write(fd, name, strlen(name)) != (ssize_t)strlen(name)) _exit(92);
    close(fd);
}
static int selected(const char *name) {
    const char *mode = getenv("MV_CAPTURE_FAULT");
    if (fired || !mode || strcmp(mode, name)) return 0;
    fired = 1;
    mark(name);
    return 1;
}
static int named(int fd, const char *name) {
    char link[64], path[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(link, path, sizeof(path)-1);
    if (n < 0) return 0;
    path[n] = 0;
    char *base = strrchr(path, '/');
    return base && !strcmp(base+1, name);
}
__attribute__((constructor)) static void no_host_bpf(void) {
    if (!getenv("MEMVEIL_TEST_NO_BPF")) return;
    struct sock_filter insns[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_bpf, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_init_module, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_finit_module, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS)
    };
    struct sock_fprog program = {sizeof(insns)/sizeof(insns[0]), insns};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) _exit(94);
}
ssize_t pwrite(int fd, const void *buf, size_t len, off_t off) {
    ssize_t (*real)(int, const void *, size_t, off_t) = dlsym(RTLD_NEXT, "pwrite");
    if (named(fd, "events.ndjson")) {
        if (selected("event-eio")) { errno = EIO; return -1; }
        if (selected("event-full")) { errno = ENOSPC; return -1; }
        if (len > 1 && selected("event-short")) return real(fd, buf, len/2, off);
    }
    return real(fd, buf, len, off);
}
int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    struct stat st;
    if (named(fd, "session.finalizing") && fstat(fd, &st) == 0 && st.st_size > 0 && selected("final-sync")) { errno = EIO; return -1; }
    int result = real(fd);
    if (result == 0 && checkpoint_syncs && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (--checkpoint_syncs == 0) {
            char point[64];
            snprintf(point, sizeof(point), "checkpoint-%d", checkpoint_count);
            if (selected(point)) raise(SIGSTOP);
        }
    }
    return result;
}
int renameat2(int a, const char *b, int c, const char *d, unsigned flags) {
    int (*real)(int, const char *, int, const char *, unsigned) = dlsym(RTLD_NEXT, "renameat2");
    if (!strcmp(d, "session.json") && selected("final-rename")) { errno = EIO; return -1; }
    if (!strcmp(d, "session.json") && selected("final-stop")) raise(SIGSTOP);
    int result = real(a, b, c, d, flags);
    if (result == 0 && !strcmp(d, "checkpoint.json")) {
        checkpoint_count++;
        checkpoint_syncs = 2;
    }
    return result;
}

int openat(int dir, const char *path, int flags, ...) {
    int (*real)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, unsigned);
        va_end(args);
    }
    int fd = real(dir, path, flags, mode);
    const char *target = getenv("MV_FINAL_OPEN_SWAP");
    static int swapped;
    if (fd >= 0 && target && !swapped && !strcmp(path, target)) {
        swapped = 1;
        char saved[4096];
        int n = snprintf(saved, sizeof(saved), "%s.saved", path);
        if (n <= 0 || n >= (int)sizeof(saved) || rename(path, saved) || mkfifo(path, 0600)) _exit(93);
        mark("events-open-swap");
    }
    return fd;
}

FILE *fdopen(int fd, const char *mode) {
    FILE *(*real)(int, const char *) = dlsym(RTLD_NEXT, "fdopen");
    if (getenv("MV_FAIL_FDOPEN_EVENTS") && named(fd, "events.ndjson")) {
        static int marked;
        if (!marked) { marked = 1; mark("events-fdopen-failure"); }
        errno = EMFILE;
        return NULL;
    }
    return real(fd, mode);
}
