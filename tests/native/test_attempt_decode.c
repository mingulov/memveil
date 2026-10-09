/* SPDX-License-Identifier: GPL-3.0-or-later */

/* Attempt decode test: C reference extractor + shared decoder.
 *
 * Reads the corpus (corpus.bin inputs, corpus.txt expectations),
 * runs every vector through the reference extractor (ctx records,
 * mirroring the BPF program's context walk) and the shared
 * mv_decode_payload (payload records, plus extractor-produced
 * payloads as a pipeline check), asserts each verdict and all
 * decoded fields, and writes a verdict dump. The Mojo decoder
 * writes the same dump format over the same corpus; the attempts
 * lane diffs the two byte-for-byte.
 *
 * ctx-extracted payloads use seq=<record idx> and
 * ktime=1000000000+idx so dumps stay deterministic; both sides
 * compute these identically (any skew fails the lane diff).
 *
 * Usage: test_attempt_decode corpus.bin corpus.txt out.dump
 * Exit 0 prints "decode: N vectors passed"; any mismatch exits 1.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "memveil_events.h"

#define KTIME_CTX_BASE 1000000000ULL
#define MAX_VECTORS 4096
#define MAX_INPUT 65536
#define MAX_LINE 4096

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
    case MV_PAY_RANGE:
        return "PAY_RANGE";
    }
    return "?";
}

static int fail(const char *message)
{
    fprintf(stderr, "decode: FAIL %s\n", message);
    return 1;
}

/* Reference extractor: mirrors the BPF program's context walk over a
 * byte buffer (memcpy in place of bpf_probe_read_kernel). Shared
 * validation and packing logic is identical by construction. */
static enum mv_reason ref_extract(const uint8_t *ctx, uint32_t ctx_len,
                                  uint64_t seq, uint64_t ktime,
                                  uint8_t out[MV_PAYLOAD_LEN])
{
    uint32_t loc, off, dlen, i;
    uint64_t size;
    uint8_t force;

    if (ctx_len < MV_CTX_FIXED)
        return MV_CTX_SHORT;
    loc = mv_read_le32(ctx + 8);
    off = loc & 0xFFFFu;
    dlen = (loc >> 16) & 0xFFFFu;
    {
        enum mv_reason loc_reason = mv_validate_loc(off, dlen, ctx_len);
        if (loc_reason != MV_OK)
            return loc_reason;
    }
    for (i = 0; i < dlen; i++) {
        uint8_t byte = ctx[off + i];
        if (i + 1 == dlen) {
            if (byte != 0)
                return MV_CTX_NUL_MISSING;
        } else if (byte == 0) {
            return MV_CTX_NUL_EARLY;
        }
    }
    if (ctx[40] != 0 && ctx[40] != 1)
        return MV_CTX_FORCE_BAD;
    force = ctx[40];
    size = mv_read_le64(ctx + 32);
    out[0] = (uint8_t)(MV_MAGIC & 0xFFu);
    out[1] = (uint8_t)((MV_MAGIC >> 8) & 0xFFu);
    out[2] = (uint8_t)((MV_MAGIC >> 16) & 0xFFu);
    out[3] = (uint8_t)((MV_MAGIC >> 24) & 0xFFu);
    out[4] = (uint8_t)(MV_VERSION & 0xFFu);
    out[5] = (uint8_t)((MV_VERSION >> 8) & 0xFFu);
    out[6] = force ? MV_FLAG_FORCE : 0;
    out[7] = 0;
    for (i = 0; i < 8; i++) {
        out[8 + i] = (uint8_t)((seq >> (8 * i)) & 0xFFu);
        out[16 + i] = (uint8_t)((ktime >> (8 * i)) & 0xFFu);
        out[24 + i] = (uint8_t)((size >> (8 * i)) & 0xFFu);
    }
    out[32] = (uint8_t)((dlen - 1) & 0xFFu);
    out[33] = (uint8_t)(((dlen - 1) >> 8) & 0xFFu);
    for (i = 0; i < 64; i++)
        out[34 + i] = 0;
    for (i = 0; i + 1 < dlen; i++)
        out[34 + i] = ctx[off + i];
    return MV_OK;
}

struct expectation {
    unsigned idx;
    unsigned kind; /* 1 = ctx, 2 = payload */
    char verdict[24];
    int has_fields;
    unsigned long long size;
    unsigned force;
    unsigned long long seq;
    unsigned long long ktime;
    unsigned namelen;
    char name[129];
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

/* Parse one corpus.txt line strictly: full match or failure. */
static int parse_line(char *line, struct expectation *exp)
{
    char kind[16], verdict[24];
    char *save = NULL;
    char *tok;
    unsigned long long num;
    unsigned pos = 0;

    /* idx */
    tok = strtok_r(line, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%u%n", &exp->idx, &pos) != 1 ||
        tok[pos] != '\0')
        return -1;
    /* kind */
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "%15s", kind) != 1)
        return -1;
    if (strcmp(kind, "ctx") == 0)
        exp->kind = 1;
    else if (strcmp(kind, "payload") == 0)
        exp->kind = 2;
    else
        return -1;
    /* verdict */
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
    /* size= force= seq= ktime= namelen= name= in fixed order */
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "size=%llu%n", &num, &pos) != 1 ||
        tok[pos] != '\0')
        return -1;
    exp->size = num;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "force=%u%n", &exp->force, &pos) != 1 ||
        tok[pos] != '\0' || exp->force > 1)
        return -1;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL)
        return -1;
    if (strcmp(tok, "seq=-") == 0) {
        exp->seq = 0;
    } else if (sscanf(tok, "seq=%llu%n", &num, &pos) != 1 ||
               tok[pos] != '\0') {
        return -1;
    } else {
        exp->seq = num;
    }
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL)
        return -1;
    if (strcmp(tok, "ktime=-") == 0) {
        exp->ktime = 0;
    } else if (sscanf(tok, "ktime=%llu%n", &num, &pos) != 1 ||
               tok[pos] != '\0') {
        return -1;
    } else {
        exp->ktime = num;
    }
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || sscanf(tok, "namelen=%u%n", &exp->namelen, &pos) != 1 ||
        tok[pos] != '\0' || exp->namelen > 63)
        return -1;
    tok = strtok_r(NULL, " \t\r\n", &save);
    if (tok == NULL || strncmp(tok, "name=", 5) != 0)
        return -1;
    if (strlen(tok + 5) != 2 * exp->namelen)
        return -1;
    strcpy(exp->name, tok + 5);
    if (strtok_r(NULL, " \t\r\n", &save) != NULL)
        return -1;
    return 0;
}

static void dump_ok(FILE *dump, unsigned idx, unsigned kind,
                    const struct mv_attempt *got)
{
    unsigned i;
    fprintf(dump, "%u %s OK size=%llu force=%u seq=%llu ktime=%llu "
            "namelen=%u name=",
            idx, kind == 1 ? "ctx" : "payload",
            (unsigned long long)got->size, got->force,
            (unsigned long long)got->seq,
            (unsigned long long)got->ktime, got->name_len);
    for (i = 0; i < got->name_len; i++)
        fprintf(dump, "%02x", got->name[i]);
    fprintf(dump, "\n");
}

/* Pin the shared counter vocabulary: six entries, six distinct
 * single-bit flags. The collector matrix seeds these words and
 * asserts policy; this pins the header they mirror. */
static int check_counter_vocab(void)
{
    unsigned long long bits[6];
    unsigned i, j;

    if (MV_CNT_LEN != 6 || MV_CNT_FLAGS != 5)
        return fail("counter geometry drift");
    bits[0] = MV_FLAG_OBSERVED_WRAP;
    bits[1] = MV_FLAG_OBSERVED_BYTES_WRAP;
    bits[2] = MV_FLAG_EMITTED_WRAP;
    bits[3] = MV_FLAG_EMITTED_BYTES_WRAP;
    bits[4] = MV_FLAG_SUBMIT_WRAP;
    bits[5] = MV_FLAG_BYTE_COVERAGE;
    for (i = 0; i < 6; i++) {
        if (bits[i] == 0 || (bits[i] & (bits[i] - 1)) != 0)
            return fail("flag bit not a power of two");
        for (j = 0; j < i; j++) {
            if (bits[i] == bits[j])
                return fail("flag bits collide");
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *bin, *txt, *dump;
    char line[MAX_LINE];
    uint8_t *input;
    uint32_t count, i;
    int ok = 1;

    if (check_counter_vocab() != 0)
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
        fprintf(stderr, "decode: cannot open inputs/output\n");
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
        struct expectation exp;
        uint32_t kind, len;
        kind = read_le32_file(bin, &ok);
        len = read_le32_file(bin, &ok);
        if (!ok || (kind != 1 && kind != 2) || len > MAX_INPUT)
            return fail("bad corpus record");
        if (fread(input, 1, len, bin) != len)
            return fail("truncated corpus record");
        do {
            if (fgets(line, sizeof(line), txt) == NULL)
                return fail("missing corpus line");
        } while (line[0] == '#' || line[0] == '\n');
        if (parse_line(line, &exp) != 0)
            return fail("unparseable corpus line");
        if (exp.idx != i || exp.kind != kind) {
            fprintf(stderr, "decode: corpus desync at %u\n", i);
            return 1;
        }
        if (kind == 1) {
            enum mv_reason reason;
            uint8_t produced[MV_PAYLOAD_LEN];
            reason = ref_extract(input, len, (uint64_t)i,
                                 KTIME_CTX_BASE + (uint64_t)i, produced);
            if (strcmp(reason_name(reason), exp.verdict) != 0) {
                fprintf(stderr, "decode: ctx %u: got %s want %s\n",
                        i, reason_name(reason), exp.verdict);
                return 1;
            }
            if (reason != MV_OK) {
                fprintf(dump, "%u ctx %s\n", i, exp.verdict);
                continue;
            }
            /* Pipeline check: extractor output must decode. */
            {
                struct mv_attempt got;
                reason = mv_decode_payload(produced, MV_PAYLOAD_LEN,
                                           &got);
                if (reason != MV_OK) {
                    fprintf(stderr, "decode: ctx %u pipeline: %s\n",
                            i, reason_name(reason));
                    return 1;
                }
                if ((unsigned long long)got.size != exp.size ||
                    got.force != exp.force ||
                    (unsigned long long)got.seq != (unsigned long long)i ||
                    (unsigned long long)got.ktime != KTIME_CTX_BASE + (unsigned long long)i ||
                    got.name_len != exp.namelen) {
                    fprintf(stderr, "decode: ctx %u field mismatch\n", i);
                    return 1;
                }
                {
                    char hex[129];
                    unsigned j;
                    for (j = 0; j < got.name_len; j++)
                        sprintf(hex + 2 * j, "%02x", got.name[j]);
                    hex[2 * got.name_len] = '\0';
                    if (strcmp(hex, exp.name) != 0) {
                        fprintf(stderr, "decode: ctx %u name mismatch\n", i);
                        return 1;
                    }
                }
                dump_ok(dump, i, kind, &got);
            }
        } else {
            struct mv_attempt got;
            enum mv_reason reason =
                mv_decode_payload(input, len, &got);
            if (strcmp(reason_name(reason), exp.verdict) != 0) {
                fprintf(stderr, "decode: payload %u: got %s want %s\n",
                        i, reason_name(reason), exp.verdict);
                return 1;
            }
            if (reason != MV_OK) {
                fprintf(dump, "%u payload %s\n", i, exp.verdict);
                continue;
            }
            if ((unsigned long long)got.size != exp.size ||
                got.force != exp.force ||
                (unsigned long long)got.seq != exp.seq ||
                (unsigned long long)got.ktime != exp.ktime ||
                got.name_len != exp.namelen) {
                fprintf(stderr, "decode: payload %u field mismatch\n", i);
                return 1;
            }
            {
                char hex[129];
                unsigned j;
                for (j = 0; j < got.name_len; j++)
                    sprintf(hex + 2 * j, "%02x", got.name[j]);
                hex[2 * got.name_len] = '\0';
                if (strcmp(hex, exp.name) != 0) {
                    fprintf(stderr, "decode: payload %u name mismatch\n", i);
                    return 1;
                }
            }
            dump_ok(dump, i, kind, &got);
        }
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
    fclose(bin);
    fclose(txt);
    fclose(dump);
    free(input);
    printf("decode: %u vectors passed\n", count);
    return 0;
}
