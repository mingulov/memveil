/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(struct stat) == 144, "Linux x86-64 stat size");
_Static_assert(offsetof(struct stat, st_dev) == 0, "stat device");
_Static_assert(offsetof(struct stat, st_ino) == 8, "stat inode");
_Static_assert(offsetof(struct stat, st_nlink) == 16, "stat links");
_Static_assert(offsetof(struct stat, st_mode) == 24, "stat mode");
_Static_assert(offsetof(struct stat, st_uid) == 28, "stat owner");
_Static_assert(offsetof(struct stat, st_size) == 48, "stat size");
_Static_assert(offsetof(struct stat, st_blocks) == 64, "stat allocation");

static unsigned call_count;
static int trace_fd = -1;
static int armed;
static unsigned fail_at;
static int after;
static int repeat;
static unsigned checkpoint_renames;

static void init(void) {
    if (armed) return;
    armed = 1;
    const char *path = getenv("MV_IO_TRACE");
    if (path) trace_fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    const char *point = getenv("MV_IO_FAIL");
    if (point) fail_at = (unsigned)strtoul(point, NULL, 10);
    after = getenv("MV_IO_AFTER") != NULL;
    repeat = getenv("MV_IO_REPEAT") != NULL;
}

static int boundary(const char *op, int fd, const char *name, int post) {
    init();
    if (!post) {
        call_count++;
        if (trace_fd >= 0) {
            char target[256] = "";
            if (fd >= 0) {
                char proc[64];
                int n = snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
                if (n > 0 && n < (int)sizeof(proc)) {
                    ssize_t len = readlink(proc, target, sizeof(target) - 1);
                    if (len >= 0) target[len] = 0;
                }
            }
            const char *base = strrchr(target, '/');
            char line[384];
            int n = snprintf(line, sizeof(line), "%u %s %s%s\n", call_count, op,
                             base ? base + 1 : target, name ? name : "");
            if (n > 0 && n < (int)sizeof(line)) (void)write(trace_fd, line, (size_t)n);
        }
    }
    if (fail_at && (call_count == fail_at || (repeat && call_count >= fail_at)) && post == after) {
        if (post) _exit(91);
        errno = EIO;
        return 1;
    }
    return 0;
}

ssize_t pwrite(int fd, const void *buf, size_t len, off_t off) {
    ssize_t (*real)(int, const void *, size_t, off_t) = dlsym(RTLD_NEXT, "pwrite");
    if (getenv("MV_GROUP_FAIL_NEXT")) {
        unsetenv("MV_GROUP_FAIL_NEXT");
        errno = EIO;
        return -1;
    }
    if (boundary("write", fd, NULL, 0)) return -1;
    ssize_t out = real(fd, buf, len, off);
    boundary("write", fd, NULL, 1);
    return out;
}
int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    if (boundary("sync", fd, NULL, 0)) return -1;
    int out = real(fd);
    boundary("sync", fd, NULL, 1);
    return out;
}
int renameat2(int a, const char *b, int c, const char *d, unsigned flags) {
    int (*real)(int, const char *, int, const char *, unsigned) = dlsym(RTLD_NEXT, "renameat2");
    if (!strcmp(d, "checkpoint.json")) {
        checkpoint_renames++;
        if (checkpoint_renames == 2 && getenv("MV_IO_SWAP_CHECKPOINT")) {
            if (real(c, d, c, "checkpoint.displaced", 1) != 0) _exit(93);
            int planted = openat(c, d, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
            if (planted < 0) _exit(93);
            const char marker[] = "foreign checkpoint: preserve exactly";
            if (write(planted, marker, sizeof(marker)-1) != (ssize_t)(sizeof(marker)-1)) _exit(93);
            close(planted);
        }
    }
    if (boundary("rename", -1, d, 0)) return -1;
    int out = real(a, b, c, d, flags);
    if (out == 0 && !strcmp(d, "session.json") && getenv("MV_IO_SWAP_FINAL_FIFO")) {
        if (real(c, d, c, "session.displaced", 1) != 0 || mkfifoat(c, d, 0600) != 0)
            _exit(93);
    }
    boundary("rename", -1, d, 1);
    return out;
}
int ftruncate(int fd, off_t size) {
    int (*real)(int, off_t) = dlsym(RTLD_NEXT, "ftruncate");
    if (boundary("truncate", fd, NULL, 0)) return -1;
    int out = real(fd, size);
    boundary("truncate", fd, NULL, 1);
    return out;
}

int posix_fallocate(int fd, off_t offset, off_t length) {
    int (*real)(int, off_t, off_t) = dlsym(RTLD_NEXT, "posix_fallocate");
    const char *mode = getenv("MV_IO_ALLOCATION");
    if (mode && !strcmp(mode, "unsupported")) return EOPNOTSUPP;
    if (mode && !strcmp(mode, "full")) return ENOSPC;
    if (mode && !strcmp(mode, "sparse")) {
        int (*truncate_real)(int, off_t) = dlsym(RTLD_NEXT, "ftruncate");
        return truncate_real(fd, length) == 0 ? 0 : errno;
    }
    return real(fd, offset, length);
}

ssize_t pread(int fd, void *buffer, size_t count, off_t offset) {
    ssize_t (*real)(int, void *, size_t, off_t) = dlsym(RTLD_NEXT, "pread");
    ssize_t result = real(fd, buffer, count, offset);
    static int swapped;
    const char *target = getenv("MV_IO_SWAP_READ");
    if (!target || swapped || result <= 0) return result;
    char proc[64], path[1024], saved[1024];
    int n = snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    if (n <= 0 || n >= (int)sizeof(proc)) _exit(93);
    ssize_t size = readlink(proc, path, sizeof(path)-1);
    if (size < 0) _exit(93);
    path[size] = 0;
    const char *base = strrchr(path, '/');
    if (!base || strcmp(base+1, "checkpoint.json")) return result;
    swapped = 1;
    n = snprintf(saved, sizeof(saved), "%s.displaced", target);
    if (n <= 0 || n >= (int)sizeof(saved)) _exit(93);
    int (*rename_real)(int, const char *, int, const char *, unsigned) = dlsym(RTLD_NEXT, "renameat2");
    if (rename_real(AT_FDCWD, target, AT_FDCWD, saved, 1) != 0) _exit(93);
    if (getenv("MV_IO_SWAP_DIRECTORY")) {
        if (mkdir(target, 0700) != 0) _exit(93);
    } else {
        int planted = open(target, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        const char marker[] = "foreign evidence";
        if (planted < 0 || write(planted, marker, sizeof(marker)-1) != (ssize_t)(sizeof(marker)-1)) _exit(93);
        close(planted);
    }
    return result;
}
