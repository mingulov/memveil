/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Lifecycle/copy decode test: shared header decoders + effective rule.
 *
 * Reads the corpus (corpus.bin inputs, corpus.txt expectations),
 * runs every vector through the shared mv_decode_lifecycle /
 * mv_decode_copy / mv_effective_bytes from
 * bpf/include/memveil_events.h, asserts each verdict and all
 * decoded fields, and writes a verdict dump. The Mojo decoder
 * writes the same dump format over the same corpus; the
 * native-decode lane diffs the two byte-for-byte.
 *
 * Usage: test_lifecycle_decode corpus.bin corpus.txt out.dump
 * Exit 0 prints "lifecycle-decode: N vectors passed"; any
 * mismatch exits 1.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memveil_events.h"

#define MAX_VECTORS 4096
#define MAX_INPUT 65536
#define MAX_LINE 4096
#define EFF_INPUT_LEN 25

static const char *reason_name(enum mv_reason reason)
{
    switch (reason) {
    case MV_OK:
        return "OK";
    case MV_CTX_SHORT:
        return "CTX_SHORT";
    case MV_CTX_LOC_OOB:
        return "CTX_LOC_OOB";
    case MV_CTX_DLEN_ZERO:
        return "CTX_DLEN_ZERO";
    case MV_CTX_DLEN_BIG:
        return "CTX_DLEN_BIG";
    case MV_CTX_NUL_MISSING:
        return "CTX_NUL_MISSING";
    case MV_CTX_NUL_EARLY:
        return "CTX_NUL_EARLY";
    case MV_CTX_FORCE_BAD:
        return "CTX_FORCE_BAD";
    case MV_PAY_SHORT:
        return "PAY_SHORT";
    case MV_PAY_LONG:
        return "PAY_LONG";
    case MV_PAY_MAGIC:
        return "PAY_MAGIC";
    case MV_PAY_VERSION:
        return "PAY_VERSION";
    case MV_PAY_FLAGS:
        return "PAY_FLAGS";
    case MV_PAY_NAMELEN:
        return "PAY_NAMELEN";
    case MV_PAY_NUL:
        return "PAY_NUL";
    case MV_PAY_PAD:
        return "PAY_PAD";
    case MV_PAY_KIND:
        return "PAY_KIND";
    case MV_PAY_DIR:
        return "PAY_DIR";
    case MV_PAY_REASON:
        return "PAY_REASON";
    }
    return "?";
}

static int fail(const char *message)
{
    fprintf(stderr, "lifecycle-decode: FAIL %s\n", message);
    return 1;
}

struct lc_expectation {
    unsigned idx;
    char verdict[24];
    int has_fields;
    unsigned kind;
    unsigned ok;
    unsigned skip;
    unsigned dir;
    unsigned long long seq;
    unsigned long long ktime;
    unsigned long long size;
};

struct cp_expectation {
    unsigned idx;
    char verdict[24];
    int has_fields;
    unsigned kind;
    unsigned todevice;
    unsigned known;
    unsigned clamped;
    unsigned earlyzero;
    unsigned dir;
    unsigned reason;
    unsigned long long seq;
    unsigned long long ktime;
    unsigned long long requested;
    unsigned long long effective;
};

struct eff_expectation {
    unsigned idx;
    unsigned long long effective;
    unsigned clamped;
    unsigned earlyzero;
};

static uint32_t read_le32_file(FILE *handle, int *ok)
{
    uint8_t buf[4];
    if (fread(buf, 1, 4, handle) != 4) {
        *ok = 0;
        return 0;
    }
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

/* Parse one u64 k=v token strictly: full match or failure. */
static int parse_u64_tok(char *tok, const char *key, unsigned long long *num)
{
    unsigned pos = 0;
    size_t want = strlen(key);

    if (tok == NULL || strncmp(tok, key, want) != 0 || tok[want] == '\0')
        return -1;
    if (sscanf(tok + want, "%llu%n", num, &pos) != 1 ||
        tok[want + pos] != '\0')
        return -1;
    return 0;
}

/* Parse one small-int k=v token strictly: full match or failure. */
static int parse_u_tok(char *tok, const char *key, unsigned *num)
{
    unsigned pos = 0;
    size_t want = strlen(key);

    if (tok == NULL || strncmp(tok, key, want) != 0 || tok[want] == '\0')
        return -1;
    if (sscanf(tok + want, "%u%n", num, &pos) != 1 ||
        tok[want + pos] != '\0')
        return -1;
    return 0;
}

/* Parse one corpus.txt line for a lifecycle vector. */
static int parse_lc_line(char *line, struct lc_expectation *exp)
{
    char kind[16], verdict[24];
    char *save = NULL;
    char *tok;

    tok = strtok_r(line, " \t\r\n", &save);
    if (tok == NULL)
        return -1;
    {
        unsigned pos = 0;
        if (sscanf(tok, "%u%n", &exp->idx, &pos) != 1 ||
            tok[pos] != '\0')
            return -1;
    }
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%15s", kind) != 1 ||
        strcmp(kind, "lifecycle") != 0)
        return -1;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%23s", verdict) != 1)
        return -1;
    strcpy(exp->verdict, verdict);
    if (strcmp(verdict, "OK") != 0) {
        exp->has_fields = 0;
        if (strtok_r(NULL, " \t\r\n", &save) != NULL)
            return -1;
        return 0;
    }
    exp->has_fields = 1;
    /* kind= ok= skip= dir= seq= ktime= size= in fixed order */
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "kind=",
                    &exp->kind) != 0)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "ok=",
                    &exp->ok) != 0 ||
        exp->ok > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "skip=",
                    &exp->skip) != 0 ||
        exp->skip > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "dir=",
                    &exp->dir) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "seq=",
                      &exp->seq) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "ktime=",
                      &exp->ktime) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "size=",
                      &exp->size) != 0)
        return -1;
    if (strtok_r(NULL, " \t\r\n", &save) != NULL)
        return -1;
    return 0;
}

/* Parse one corpus.txt line for a copy vector. */
static int parse_cp_line(char *line, struct cp_expectation *exp)
{
    char kind[16], verdict[24];
    char *save = NULL;
    char *tok;

    tok = strtok_r(line, " \t\r\n", &save);
    if (tok == NULL)
        return -1;
    {
        unsigned pos = 0;
        if (sscanf(tok, "%u%n", &exp->idx, &pos) != 1 ||
            tok[pos] != '\0')
            return -1;
    }
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%15s", kind) != 1 ||
        strcmp(kind, "copy") != 0)
        return -1;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%23s", verdict) != 1)
        return -1;
    strcpy(exp->verdict, verdict);
    if (strcmp(verdict, "OK") != 0) {
        exp->has_fields = 0;
        if (strtok_r(NULL, " \t\r\n", &save) != NULL)
            return -1;
        return 0;
    }
    exp->has_fields = 1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "kind=",
                    &exp->kind) != 0)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "todevice=",
                    &exp->todevice) != 0 ||
        exp->todevice > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "known=",
                    &exp->known) != 0 ||
        exp->known > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "clamped=",
                    &exp->clamped) != 0 ||
        exp->clamped > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "earlyzero=",
                    &exp->earlyzero) != 0 ||
        exp->earlyzero > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "dir=",
                    &exp->dir) != 0)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "reason=",
                    &exp->reason) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "seq=",
                      &exp->seq) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "ktime=",
                      &exp->ktime) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "requested=",
                      &exp->requested) != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "effective=",
                      &exp->effective) != 0)
        return -1;
    if (strtok_r(NULL, " \t\r\n", &save) != NULL)
        return -1;
    return 0;
}

/* Parse one corpus.txt line for an effective-rule vector. */
static int parse_eff_line(char *line, struct eff_expectation *exp)
{
    char kind[16], verdict[24];
    char *save = NULL;
    char *tok;

    tok = strtok_r(line, " \t\r\n", &save);
    if (tok == NULL)
        return -1;
    {
        unsigned pos = 0;
        if (sscanf(tok, "%u%n", &exp->idx, &pos) != 1 ||
            tok[pos] != '\0')
            return -1;
    }
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%15s", kind) != 1 ||
        strcmp(kind, "effective") != 0)
        return -1;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%23s", verdict) != 1 ||
        strcmp(verdict, "OK") != 0)
        return -1;
    if (parse_u64_tok(strtok_r(NULL, " \t\r\n", &save), "effective=",
                      &exp->effective) != 0)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "clamped=",
                    &exp->clamped) != 0 ||
        exp->clamped > 1)
        return -1;
    if (parse_u_tok(strtok_r(NULL, " \t\r\n", &save), "earlyzero=",
                    &exp->earlyzero) != 0 ||
        exp->earlyzero > 1)
        return -1;
    if (strtok_r(NULL, " \t\r\n", &save) != NULL)
        return -1;
    return 0;
}

static void dump_lc_ok(FILE *dump, unsigned idx,
                       const struct mv_lifecycle *got)
{
    fprintf(dump,
            "%u lifecycle OK kind=%u ok=%u skip=%u dir=%u "
            "seq=%llu ktime=%llu size=%llu\n",
            idx, got->kind, got->ok, got->skip_sync, got->dir,
            (unsigned long long)got->seq,
            (unsigned long long)got->ktime,
            (unsigned long long)got->size);
}

static void dump_cp_ok(FILE *dump, unsigned idx,
                       const struct mv_copy *got)
{
    fprintf(dump,
            "%u copy OK kind=%u todevice=%u known=%u clamped=%u "
            "earlyzero=%u dir=%u reason=%u seq=%llu ktime=%llu "
            "requested=%llu effective=%llu\n",
            idx, got->kind, got->to_device, got->known,
            got->clamped, got->early_zero, got->dir, got->reason,
            (unsigned long long)got->seq,
            (unsigned long long)got->ktime,
            (unsigned long long)got->requested,
            (unsigned long long)got->effective);
}

static int check_lc_vector(uint32_t idx, const uint8_t *input,
                           uint32_t len, char *line, FILE *dump)
{
    struct lc_expectation exp;
    struct mv_lifecycle got;
    enum mv_reason reason;

    if (parse_lc_line(line, &exp) != 0)
        return fail("unparseable corpus line");
    if (exp.idx != idx) {
        fprintf(stderr, "lifecycle-decode: corpus desync at %u\n",
                idx);
        return 1;
    }
    reason = mv_decode_lifecycle(input, len, &got);
    if (strcmp(reason_name(reason), exp.verdict) != 0) {
        fprintf(stderr, "lifecycle-decode: lifecycle %u: got %s want %s\n",
                idx, reason_name(reason), exp.verdict);
        return 1;
    }
    if (reason != MV_OK) {
        fprintf(dump, "%u lifecycle %s\n", idx, exp.verdict);
        return 0;
    }
    if (got.kind != exp.kind || got.ok != exp.ok ||
        got.skip_sync != exp.skip || got.dir != exp.dir ||
        (unsigned long long)got.seq != exp.seq ||
        (unsigned long long)got.ktime != exp.ktime ||
        (unsigned long long)got.size != exp.size) {
        fprintf(stderr, "lifecycle-decode: lifecycle %u field mismatch\n",
                idx);
        return 1;
    }
    dump_lc_ok(dump, idx, &got);
    return 0;
}

static int check_cp_vector(uint32_t idx, const uint8_t *input,
                           uint32_t len, char *line, FILE *dump)
{
    struct cp_expectation exp;
    struct mv_copy got;
    enum mv_reason reason;

    if (parse_cp_line(line, &exp) != 0)
        return fail("unparseable corpus line");
    if (exp.idx != idx) {
        fprintf(stderr, "lifecycle-decode: corpus desync at %u\n",
                idx);
        return 1;
    }
    reason = mv_decode_copy(input, len, &got);
    if (strcmp(reason_name(reason), exp.verdict) != 0) {
        fprintf(stderr, "lifecycle-decode: copy %u: got %s want %s\n",
                idx, reason_name(reason), exp.verdict);
        return 1;
    }
    if (reason != MV_OK) {
        fprintf(dump, "%u copy %s\n", idx, exp.verdict);
        return 0;
    }
    if (got.kind != exp.kind || got.to_device != exp.todevice ||
        got.known != exp.known || got.clamped != exp.clamped ||
        got.early_zero != exp.earlyzero || got.dir != exp.dir ||
        got.reason != exp.reason ||
        (unsigned long long)got.seq != exp.seq ||
        (unsigned long long)got.ktime != exp.ktime ||
        (unsigned long long)got.requested != exp.requested ||
        (unsigned long long)got.effective != exp.effective) {
        fprintf(stderr, "lifecycle-decode: copy %u field mismatch\n",
                idx);
        return 1;
    }
    dump_cp_ok(dump, idx, &got);
    return 0;
}

static int check_eff_vector(uint32_t idx, const uint8_t *input,
                            uint32_t len, char *line, FILE *dump)
{
    struct eff_expectation exp;
    struct mv_effective got;
    uint64_t size, alloc;
    int64_t off;
    int valid;

    if (len != EFF_INPUT_LEN)
        return fail("bad effective input length");
    if (parse_eff_line(line, &exp) != 0)
        return fail("unparseable corpus line");
    if (exp.idx != idx) {
        fprintf(stderr, "lifecycle-decode: corpus desync at %u\n",
                idx);
        return 1;
    }
    size = mv_read_le64(input);
    off = (int64_t)mv_read_le64(input + 8);
    alloc = mv_read_le64(input + 16);
    valid = input[24] != 0;
    got = mv_effective_bytes(size, off, alloc, valid);
    if ((unsigned long long)got.effective != exp.effective ||
        got.clamped != exp.clamped ||
        got.early_zero != exp.earlyzero) {
        fprintf(stderr, "lifecycle-decode: effective %u mismatch: "
                "got %llu/%u/%u want %llu/%u/%u\n",
                idx, (unsigned long long)got.effective,
                got.clamped, got.early_zero, exp.effective,
                exp.clamped, exp.earlyzero);
        return 1;
    }
    fprintf(dump, "%u effective OK effective=%llu clamped=%u "
            "earlyzero=%u\n",
            idx, (unsigned long long)got.effective, got.clamped,
            got.early_zero);
    return 0;
}

/* Pin the lifecycle/copy wire vocabulary the Mojo decoder mirrors:
 * record lengths, magics, kinds, flags, reasons, and the map
 * failure sentinel. */
static int check_wire_vocab(void)
{
    if (MV_LC_LEN != 36 || MV_CP_LEN != 48)
        return fail("record length drift");
    if (MV_LC_MAGIC != 0x434C564Du || MV_CP_MAGIC != 0x5043564Du)
        return fail("magic drift");
    if (MV_LC_KIND_MAP != 1 || MV_LC_KIND_UNMAP != 2 ||
        MV_CP_KIND_SYNC != 1 || MV_CP_KIND_COPY != 2)
        return fail("kind drift");
    if (MV_CP_REASON_NOT_COPY != 4 ||
        MV_INVALID_PHYS != 0xFFFFFFFFFFFFFFFFULL)
        return fail("reason/sentinel drift");
    return 0;
}

int main(int argc, char **argv)
{
    FILE *bin, *txt, *dump;
    char line[MAX_LINE];
    uint8_t *input;
    uint32_t count, i;
    int ok = 1;

    if (check_wire_vocab() != 0)
        return 1;
    if (argc != 4) {
        fprintf(stderr, "usage: %s corpus.bin corpus.txt out.dump\n",
                argv[0]);
        return 2;
    }
    bin = fopen(argv[1], "rb");
    txt = fopen(argv[2], "r");
    dump = fopen(argv[3], "w");
    if (bin == NULL || txt == NULL || dump == NULL) {
        fprintf(stderr, "lifecycle-decode: cannot open inputs/output\n");
        return 2;
    }
    input = malloc(MAX_INPUT);
    if (input == NULL)
        return fail("out of memory");
    count = read_le32_file(bin, &ok);
    if (!ok || count > MAX_VECTORS)
        return fail("bad corpus count");
    /* Skip the header comment line. */
    if (fgets(line, sizeof(line), txt) == NULL || line[0] != '#')
        return fail("missing corpus header");
    for (i = 0; i < count; i++) {
        uint32_t kind, len;
        int rc;

        kind = read_le32_file(bin, &ok);
        len = read_le32_file(bin, &ok);
        if (!ok || kind < 1 || kind > 3 || len > MAX_INPUT)
            return fail("bad corpus record");
        if (fread(input, 1, len, bin) != len)
            return fail("truncated corpus record");
        do {
            if (fgets(line, sizeof(line), txt) == NULL)
                return fail("missing corpus line");
        } while (line[0] == '#' || line[0] == '\n');
        if (kind == 1)
            rc = check_lc_vector(i, input, len, line, dump);
        else if (kind == 2)
            rc = check_cp_vector(i, input, len, line, dump);
        else
            rc = check_eff_vector(i, input, len, line, dump);
        if (rc != 0)
            return 1;
    }
    /* Corpus must be fully consumed on both sides. */
    {
        int extra = 0;
        while (fgets(line, sizeof(line), txt) != NULL) {
            if (line[0] != '#' && line[0] != '\n')
                extra = 1;
        }
        if (extra)
            return fail("trailing corpus lines");
        if (fgetc(bin) != EOF)
            return fail("trailing corpus bytes");
    }
    free(input);
    fclose(bin);
    fclose(txt);
    fclose(dump);
    printf("lifecycle-decode: %u vectors passed\n", count);
    return 0;
}
