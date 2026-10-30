/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fake zlib for the C4 ABI guard test: the four symbols memveil
 * binds, with inflate/crc32 lying. inflateInit2_ accepts any
 * stream size, inflate reports STREAM_END while writing nothing
 * and advancing nothing, crc32 always returns 0. A correct ABI
 * guard must refuse this library before trusting any output.
 * Test-only; never linked into the binary. */
#include <stddef.h>

typedef struct {
    unsigned char *next_in;
    unsigned int avail_in;
    unsigned long total_in;
    unsigned char *next_out;
    unsigned int avail_out;
    unsigned long total_out;
    char *msg;
    void *state;
    void *(*zalloc)(void *, unsigned, unsigned);
    void (*zfree)(void *, void *);
    void *opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
} fake_stream;

int inflateInit2_(fake_stream *s, int bits, const char *ver, int size) {
    (void)s;
    (void)bits;
    (void)ver;
    (void)size;
    return 0;
}

int inflate(fake_stream *s, int flush) {
    (void)s;
    (void)flush;
    return 1;
}

int inflateEnd(fake_stream *s) {
    (void)s;
    return 0;
}

unsigned long crc32(unsigned long crc, const unsigned char *buf,
                    unsigned len) {
    (void)crc;
    (void)buf;
    (void)len;
    return 0;
}
