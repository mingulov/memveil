// LD_PRELOAD shim: report a foreign owner so capture-open tests reach
// the not-owned-by-reader refusals unprivileged.
//
// Only the geteuid() library call is faked; every syscall still runs
// under the real credentials, so file access itself is unaffected and
// exactly the ownership checks observe the foreign id.
#include <sys/types.h>
#include <unistd.h>

uid_t geteuid(void) {
    return 424242;
}
