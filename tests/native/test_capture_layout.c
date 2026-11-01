/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(sizeof(void *) == 8, "Linux x86-64 pointer ABI");
_Static_assert(sizeof(off_t) == 8, "64-bit file offsets");
_Static_assert(sizeof(size_t) == 8 && sizeof(ssize_t) == 8, "64-bit I/O extents");
_Static_assert(sizeof(int) == 4, "32-bit descriptor and status ABI");

static uint64_t word(const unsigned char *raw, size_t offset, size_t width) {
    uint64_t value = 0;
    for (size_t i = 0; i < width; i++) value |= (uint64_t)raw[offset+i] << (8*i);
    return value;
}

int main(void) {
    char path[] = "/tmp/memveil-layout-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(unlink(path) == 0);
    assert(posix_fallocate(fd, 0, 17*1024*1024) == 0);
    assert(fsync(fd) == 0);
    struct stat st;
    assert(fstat(fd, &st) == 0);
    unsigned char raw[144];
    assert(sizeof(st) == sizeof(raw));
    memcpy(raw, &st, sizeof(raw));
    assert(word(raw, 0, 8) == st.st_dev);
    assert(word(raw, 8, 8) == st.st_ino);
    assert(word(raw, 16, 8) == st.st_nlink);
    assert(word(raw, 24, 4) == st.st_mode);
    assert(word(raw, 28, 4) == st.st_uid);
    assert(word(raw, 48, 8) == 17*1024*1024);
    assert(word(raw, 64, 8)*512 >= 17*1024*1024);
    assert(flock(fd, LOCK_EX | LOCK_NB) == 0);
    assert(close(fd) == 0);
    return 0;
}
