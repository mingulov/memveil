/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef MEMVEIL_JOURNAL_CONTROL_H
#define MEMVEIL_JOURNAL_CONTROL_H
#include "memveil_journal.h"
enum mv_jr_counter {
    MV_JR_ENTRIES, MV_JR_EXITS, MV_JR_MATCHED, MV_JR_UNMATCHED,
    MV_JR_CENSORED, MV_JR_RING_DROPS, MV_JR_OPERATION_EXHAUSTION,
    MV_JR_NESTING_EXHAUSTION, MV_JR_TOKEN_EXHAUSTION,
    MV_JR_IDENTITY_FAILURE, MV_JR_POISONED, MV_JR_OVERFLOW,
    MV_JR_ACTIVE, MV_JR_NEXT_TOKEN, MV_JR_EMITTED, MV_JR_COUNT_KEYS
};
struct mv_jr_control {
    __u64 epoch, start_ns, end_ns;
    __u64 open, observe, callers;
};
struct mv_jr_symbol { __u64 start, end, ambiguous; };
_Static_assert(sizeof(struct mv_jr_control) == 48, "journal control layout");
_Static_assert(sizeof(struct mv_jr_symbol) == 24, "journal symbol layout");
#endif
