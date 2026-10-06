/* Counter-flow simulator: mirrors the 7 BPF steps (design 1.1)
 * over a scripted firing schedule with injectable
 * probe-read/ring failures. Every shared update follows
 * the same checked-wrap semantics as the BPF program
 * (single-threaded here; the BPF uses atomics).
 *
 * Required schedule: [injected fixed-read failure, normal
 * firing] -> O=2 S=2 E=0 bytes=0 flags=BYTE_COVERAGE with
 * the epoch halted. The close-out matrix injects this
 * exact cut (flowinject); the lane pins the printed cut.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memveil_events.h"

#define CTX_CAP 512u
#define FIXED_FLOOR 41u
#define NAME_MAX_LEN 64u

struct mv_counters {
    uint64_t v[MV_CNT_LEN];
};

struct mv_firing {
    int fixed_fail;
    uint16_t off;
    uint16_t dlen;
    int name_fail;
    char name[NAME_MAX_LEN];
    uint8_t force;
    int ring_fail;
    uint64_t size;
};

static void submit_checked(struct mv_counters *c) {
    uint64_t old = c->v[MV_CNT_SUBMIT_FAIL];
    c->v[MV_CNT_SUBMIT_FAIL] = old + 1;
    if (old == UINT64_MAX)
        c->v[MV_CNT_FLAGS] |= MV_FLAG_SUBMIT_WRAP;
}

/* One firing. Returns emitted seq, or -1 when rejected. */
static int64_t mv_fire(struct mv_counters *c, const struct mv_firing *f) {
    /* Step 1: ordinal fetch. */
    uint64_t o = c->v[MV_CNT_OBSERVED];
    c->v[MV_CNT_OBSERVED] = o + 1;
    if (o == UINT64_MAX) {
        c->v[MV_CNT_FLAGS] |= MV_FLAG_OBSERVED_WRAP;
        submit_checked(c);
        return -1;
    }
    /* Step 2: invalid epoch halts emission. */
    if (c->v[MV_CNT_FLAGS] != 0) {
        submit_checked(c);
        return -1;
    }
    /* Step 3: fixed 41-byte read, then byte fetch. */
    if (f->fixed_fail) {
        c->v[MV_CNT_FLAGS] |= MV_FLAG_BYTE_COVERAGE;
        submit_checked(c);
        return -1;
    }
    {
        uint64_t b = c->v[MV_CNT_OBSERVED_BYTES];
        c->v[MV_CNT_OBSERVED_BYTES] = b + f->size;
        if (b > UINT64_MAX - f->size) {
            c->v[MV_CNT_FLAGS] |= MV_FLAG_OBSERVED_BYTES_WRAP;
            submit_checked(c);
            return -1;
        }
    }
    /* Step 4: dev_loc geometry. */
    if (f->off < FIXED_FLOOR || (uint32_t)f->off + f->dlen > CTX_CAP ||
        f->dlen < 1 || f->dlen > NAME_MAX_LEN) {
        submit_checked(c);
        return -1;
    }
    /* Step 5: name read + NUL + force checks. */
    if (f->name_fail) {
        submit_checked(c);
        return -1;
    }
    if (f->name[f->dlen - 1] != '\0') {
        submit_checked(c);
        return -1;
    }
    for (uint16_t i = 0; i < f->dlen - 1; i++) {
        if (f->name[i] == '\0') {
            submit_checked(c);
            return -1;
        }
    }
    if (f->force != 0 && f->force != 1) {
        submit_checked(c);
        return -1;
    }
    /* Step 6: ring output. */
    if (f->ring_fail) {
        submit_checked(c);
        return -1;
    }
    /* Step 7: emit counts (the event counts even on wrap). */
    {
        uint64_t e = c->v[MV_CNT_EMITTED];
        c->v[MV_CNT_EMITTED] = e + 1;
        if (e == UINT64_MAX)
            c->v[MV_CNT_FLAGS] |= MV_FLAG_EMITTED_WRAP;
    }
    {
        uint64_t b = c->v[MV_CNT_EMITTED_BYTES];
        c->v[MV_CNT_EMITTED_BYTES] = b + f->size;
        if (b > UINT64_MAX - f->size)
            c->v[MV_CNT_FLAGS] |= MV_FLAG_EMITTED_BYTES_WRAP;
    }
    return (int64_t)o;
}

static void normal_firing(struct mv_firing *f, uint64_t size) {
    memset(f, 0, sizeof(*f));
    f->off = 48;
    f->dlen = 4;
    memcpy(f->name, "sda", 4);
    f->force = 0;
    f->size = size;
}

static int fails = 0;

#define WANT_EQ(got, want, label)                                          \
    do {                                                                   \
        if ((uint64_t)(got) != (uint64_t)(want)) {                          \
            printf("flow: FAIL %s: got %" PRIu64 ", want %" PRIu64 "\n",    \
                   label, (uint64_t)(got), (uint64_t)(want));               \
            fails++;                                                       \
        }                                                                  \
    } while (0)

static void check_cut(const char *label, const struct mv_counters *c,
                      uint64_t o, uint64_t ob, uint64_t e, uint64_t eb,
                      uint64_t s, uint64_t fl) {
    WANT_EQ(c->v[MV_CNT_OBSERVED], o, label);
    WANT_EQ(c->v[MV_CNT_OBSERVED_BYTES], ob, label);
    WANT_EQ(c->v[MV_CNT_EMITTED], e, label);
    WANT_EQ(c->v[MV_CNT_EMITTED_BYTES], eb, label);
    WANT_EQ(c->v[MV_CNT_SUBMIT_FAIL], s, label);
    WANT_EQ(c->v[MV_CNT_FLAGS], fl, label);
}

int main(void) {
    struct mv_counters c;
    struct mv_firing f;
    int64_t seq;

    /* Required schedule: injected fail, then a normal firing
     * into the halted epoch. */
    memset(&c, 0, sizeof(c));
    normal_firing(&f, 64);
    f.fixed_fail = 1;
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "fail-then-normal/seq0");
    normal_firing(&f, 64);
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "fail-then-normal/seq1");
    check_cut("fail-then-normal", &c, 2, 0, 0, 0, 2,
              MV_FLAG_BYTE_COVERAGE);
    printf("cut O=%" PRIu64 " OB=%" PRIu64 " E=%" PRIu64
           " EB=%" PRIu64 " S=%" PRIu64 " F=%" PRIu64 "\n",
           c.v[MV_CNT_OBSERVED], c.v[MV_CNT_OBSERVED_BYTES],
           c.v[MV_CNT_EMITTED], c.v[MV_CNT_EMITTED_BYTES],
           c.v[MV_CNT_SUBMIT_FAIL], c.v[MV_CNT_FLAGS]);

    /* Clean emit: seq 0, all counts advance. */
    memset(&c, 0, sizeof(c));
    normal_firing(&f, 64);
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, 0, "clean/seq");
    check_cut("clean", &c, 1, 64, 1, 64, 0, 0);

    /* Ring failure: fetched and sized, never emitted. */
    memset(&c, 0, sizeof(c));
    normal_firing(&f, 64);
    f.ring_fail = 1;
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "ring-fail/seq");
    check_cut("ring-fail", &c, 1, 64, 0, 0, 1, 0);

    /* Bad geometry (off below the fixed floor) rejects
     * after the byte fetch. */
    memset(&c, 0, sizeof(c));
    normal_firing(&f, 64);
    f.off = 40;
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "geometry/seq");
    check_cut("geometry", &c, 1, 64, 0, 0, 1, 0);

    /* Impossible force value rejects. */
    memset(&c, 0, sizeof(c));
    normal_firing(&f, 64);
    f.force = 2;
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "force/seq");
    check_cut("force", &c, 1, 64, 0, 0, 1, 0);

    /* Observed wrap: counter wraps, flag set, submit path. */
    memset(&c, 0, sizeof(c));
    c.v[MV_CNT_OBSERVED] = UINT64_MAX;
    normal_firing(&f, 64);
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "observed-wrap/seq");
    check_cut("observed-wrap", &c, 0, 0, 0, 0, 1,
              MV_FLAG_OBSERVED_WRAP);

    /* Coverage flag halts a later normal firing. */
    memset(&c, 0, sizeof(c));
    c.v[MV_CNT_FLAGS] = MV_FLAG_BYTE_COVERAGE;
    normal_firing(&f, 64);
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, (uint64_t)-1, "halted/seq");
    check_cut("halted", &c, 1, 0, 0, 0, 1, MV_FLAG_BYTE_COVERAGE);

    /* Emit-side byte wrap: event still counts, epoch dead. */
    memset(&c, 0, sizeof(c));
    c.v[MV_CNT_OBSERVED] = 5;
    c.v[MV_CNT_EMITTED_BYTES] = UINT64_MAX;
    normal_firing(&f, 64);
    seq = mv_fire(&c, &f);
    WANT_EQ(seq, 5, "emit-bytes-wrap/seq");
    check_cut("emit-bytes-wrap", &c, 6, 64, 1, 63,
              0, MV_FLAG_EMITTED_BYTES_WRAP);

    if (fails != 0) {
        printf("flow: %d check(s) FAILED\n", fails);
        return 1;
    }
    printf("flow: 8 schedules passed\n");
    return 0;
}
