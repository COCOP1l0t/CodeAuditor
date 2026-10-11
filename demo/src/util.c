#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "minisvc.h"

/*
 * Bounded copy helper. This is the pattern the handlers are supposed to use;
 * it clamps the length to the destination size and is not a vulnerability.
 */
int util_copy_bounded(char *dst, size_t cap, const char *src)
{
    size_t n;

    if (cap == 0) {
        return -1;
    }
    n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return (int)n;
}

/*
 * Benign: the command string is a compile-time constant, so no attacker input
 * reaches the shell. Not a command-injection sink.
 */
int util_show_time(char *resp, size_t resp_cap)
{
    int rc = system("/bin/date >/dev/null 2>&1");
    (void)rc;
    return snprintf(resp, resp_cap, "TIME\n");
}
