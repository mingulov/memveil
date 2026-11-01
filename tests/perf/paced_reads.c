/* SPDX-License-Identifier: GPL-3.0-or-later */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static uint64_t calls, bytes, lines, maximum, started, duration, expected;
static int error, finished, initialized;
static struct stat target;

static uint64_t now(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time)) _exit(95);
    return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}
static uint64_t number(const char *name, uint64_t maximum) {
    const char *value = getenv(name);
    char *end;
    if (!value || !*value) _exit(95);
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (errno || *end || !parsed || parsed > maximum) _exit(95);
    return parsed;
}
static void receipt(void) {
    const char *path = getenv("MEMVEIL_PACED_RECEIPT");
    if (!path) _exit(95);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) _exit(95);
    char data[512];
    int size = snprintf(data, sizeof(data),
        "{\"calls\":%llu,\"bytes\":%llu,\"lines\":%llu,\"max_request_bytes\":%llu,"
        "\"elapsed_ns\":%llu,\"device\":%llu,\"inode\":%llu,\"eof\":true,\"error\":%d}\n",
        (unsigned long long)calls, (unsigned long long)bytes, (unsigned long long)lines,
        (unsigned long long)maximum, (unsigned long long)(now()-started),
        (unsigned long long)target.st_dev, (unsigned long long)target.st_ino, error);
    if (size <= 0 || size >= (int)sizeof(data) || write(fd, data, (size_t)size) != size) _exit(95);
    close(fd);
}
size_t fread(void *buffer, size_t size, size_t count, FILE *stream) {
    size_t (*real)(void *, size_t, size_t, FILE *) = dlsym(RTLD_NEXT, "fread");
    const char *path = getenv("MEMVEIL_PACED_FILE");
    if (!path) return real(buffer, size, count, stream);
    if (!initialized) {
        if (stat(path, &target) || !S_ISREG(target.st_mode)) _exit(95);
        expected = number("MEMVEIL_PACED_LINES", 1000000);
        duration = number("MEMVEIL_PACED_NS", 3600000000000ULL);
        initialized = 1;
    }
    struct stat actual;
    int matches = fstat(fileno(stream), &actual) == 0 && S_ISREG(actual.st_mode) &&
                  actual.st_dev == target.st_dev && actual.st_ino == target.st_ino;
    if (!matches) return real(buffer, size, count, stream);
    if (!calls) started = now();
    if (size && count > UINT64_MAX / size) _exit(95);
    uint64_t request = size * count;
    if (request > maximum) maximum = request;
    if (request > 65536 || finished) _exit(95);
    calls++;
    size_t result = real(buffer, size, count, stream);
    size_t received = result * size;
    bytes += received;
    const unsigned char *data = buffer;
    for (size_t i = 0; i < received; i++) if (data[i] == '\n') lines++;
    if (lines > expected) _exit(95);
    uint64_t deadline = started + (uint64_t)(((__uint128_t)duration * lines) / expected);
    struct timespec until = {(time_t)(deadline / 1000000000), (long)(deadline % 1000000000)};
    int rc;
    do { rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL); } while (rc == EINTR);
    if (rc) error = rc;
    if (!result) {
        error = error ? error : (ferror(stream) ? EIO : 0);
        finished = 1;
        receipt();
    }
    return result;
}
