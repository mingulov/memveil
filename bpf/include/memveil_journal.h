/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MEMVEIL_JOURNAL_H
#define MEMVEIL_JOURNAL_H

#include "memveil_events.h"
#define MV_JR_MAGIC 0x524A564Du
#define MV_JR_VERSION 1u
#define MV_JR_LEN 72u
#define MV_JR_KIND_RESULT 1u
#define MV_JR_FLAG_MATCHED 1u
#define MV_JR_OPERATION_CAPACITY 4096u
#define MV_JR_NESTING_CAPACITY 8u
#define MV_JR_CALLER_FRAME_CAPACITY 16u
#define MV_JR_RING_BYTES 8388608u
#define MV_JR_TOKEN_MAX 0xFFFFFFFFFFFFFFFEULL
#define MV_JR_OFF_MAGIC 0u
#define MV_JR_OFF_VERSION 4u
#define MV_JR_OFF_KIND 6u
#define MV_JR_OFF_FLAGS 8u
#define MV_JR_OFF_DIRECTION 10u
#define MV_JR_OFF_CPU 12u
#define MV_JR_OFF_SEQUENCE 16u
#define MV_JR_OFF_EXIT_NS 24u
#define MV_JR_OFF_EPOCH 32u
#define MV_JR_OFF_TOKEN 40u
#define MV_JR_OFF_ENTRY_NS 48u
#define MV_JR_OFF_PAGES 56u
#define MV_JR_OFF_RESULT 60u
#define MV_JR_OFF_CALLER_STATUS 64u
#define MV_JR_OFF_CALLER_CLASS 66u
#define MV_JR_OFF_CALLER_LABEL 68u
#define MV_JR_OFF_RESERVED 70u

/* Internal map key only; the task pointer and birth time never enter the wire. */
struct mv_journal_key {
    __u64 current_task_pointer;
    __u64 start_boottime;
    __u64 epoch;
    __u32 depth;
    __u32 reserved;
};
_Static_assert(sizeof(struct mv_journal_key) == 32, "journal key size");
_Static_assert(__builtin_offsetof(struct mv_journal_key, epoch) == 16, "journal key epoch");
_Static_assert(__builtin_offsetof(struct mv_journal_key, depth) == 24, "journal key depth");

/* Host representation only; never cast wire bytes to this struct. */
struct mv_journal {
    __u16 direction;
    __u32 cpu;
    __u64 sequence, exit_ns, epoch, token, entry_ns;
    __s32 pages, native_result;
    __u16 caller_status, caller_class, caller_label;
    __u8 matched;
};

static __inline __u16 mv_journal_label_class(__u16 label)
{
    if (label >= 1 && label <= 2) return 1;
    if (label >= 3 && label <= 6) return 2;
    if (label >= 7 && label <= 10) return 3;
    return 0;
}

/* Signed native values are distinct from requested unsigned measurements. */
static __inline __s32 mv_journal_read_s32(const __u8 *buf)
{
    __u32 value = mv_read_le32(buf);
    __s64 signed_value = value;
    if (value >= 0x80000000u) signed_value -= 0x100000000LL;
    return (__s32)signed_value;
}

static __inline enum mv_reason mv_decode_journal(const __u8 *buf,
                                                __u32 len,
                                                struct mv_journal *out)
{
    __u16 flags, direction, status, cls, label;
    __u64 epoch, token, entry, end;
    __u32 cpu;
    if (len < MV_JR_LEN) return MV_PAY_SHORT;
    if (len > MV_JR_LEN) return MV_PAY_LONG;
    if (mv_read_le32(buf) != MV_JR_MAGIC) return MV_PAY_MAGIC;
    if (mv_read_le16(buf + 4) != MV_JR_VERSION) return MV_PAY_VERSION;
    if (mv_read_le16(buf + 6) != MV_JR_KIND_RESULT) return MV_PAY_KIND;
    flags = mv_read_le16(buf + 8);
    direction = mv_read_le16(buf + 10);
    cpu = mv_read_le32(buf + 12);
    if (flags > MV_JR_FLAG_MATCHED || mv_read_le16(buf + 70)) return MV_PAY_FLAGS;
    if (direction < 1 || direction > 2) return MV_PAY_DIR;
    if (cpu > 1048575) return MV_PAY_RANGE;
    status = mv_read_le16(buf + 64);
    cls = mv_read_le16(buf + 66);
    label = mv_read_le16(buf + 68);
    if (status > 4) return MV_PAY_REASON;
    if (status == 1) {
        if (!cls || mv_journal_label_class(label) != cls) return MV_PAY_REASON;
    } else if (cls || label) return MV_PAY_REASON;
    epoch = mv_read_le64(buf + 32);
    token = mv_read_le64(buf + 40);
    entry = mv_read_le64(buf + 48);
    end = mv_read_le64(buf + 24);
    if (!epoch || token > MV_JR_TOKEN_MAX) return MV_PAY_RANGE;
    if (flags == MV_JR_FLAG_MATCHED) {
        if (!token || entry > end) return MV_PAY_RANGE;
    } else if (token || entry) return MV_PAY_RANGE;
    out->direction = direction;
    out->cpu = cpu;
    out->sequence = mv_read_le64(buf + 16);
    out->exit_ns = end;
    out->epoch = epoch;
    out->token = token;
    out->entry_ns = entry;
    out->pages = mv_journal_read_s32(buf + 56);
    out->native_result = mv_journal_read_s32(buf + 60);
    out->caller_status = status;
    out->caller_class = cls;
    out->caller_label = label;
    out->matched = flags == MV_JR_FLAG_MATCHED;
    return MV_OK;
}

_Static_assert(MV_JR_OFF_RESERVED + 2 == MV_JR_LEN, "journal fixed layout");
_Static_assert(MV_JR_OPERATION_CAPACITY == 4096, "journal operation cap");
_Static_assert(MV_JR_NESTING_CAPACITY == 8, "journal nesting cap");
#endif
