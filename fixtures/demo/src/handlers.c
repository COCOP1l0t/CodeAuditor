#include <stdio.h>
#include <string.h>

#include "minisvc.h"

int handle_echo(const char *arg, char *resp, size_t resp_cap)
{
    char line[128];

    /*
     * The client-supplied argument is copied into a fixed 128-byte stack
     * buffer with no length check. The protocol reader accepts lines up to
     * ~4 KB, so an over-long ECHO argument overflows `line`.
     */
    strcpy(line, arg);

    return snprintf(resp, resp_cap, "ECHO %s\n", line);
}

int handle_file(const char *arg, char *resp, size_t resp_cap)
{
    char path[512];
    FILE *fp;
    size_t n;

    /*
     * The client controls the path tail. It is concatenated under "public/"
     * but never canonicalized and the result is never checked to be inside
     * that directory, so "../" escapes the document root.
     */
    snprintf(path, sizeof(path), "public/%s", arg);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return snprintf(resp, resp_cap, "ERR 404\n");
    }

    n = fread(resp, 1, resp_cap - 1, fp);
    resp[n] = '\0';
    fclose(fp);
    return (int)n;
}

int handle_exec(const char *arg, char *resp, size_t resp_cap)
{
    char cmd[256];
    FILE *p;
    size_t n;

    /*
     * The client-supplied host is interpolated into a shell command line with
     * no validation or quoting, so shell metacharacters run as extra commands.
     */
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", arg);

    p = popen(cmd, "r");
    if (p == NULL) {
        return snprintf(resp, resp_cap, "ERR 500\n");
    }

    n = fread(resp, 1, resp_cap - 1, p);
    resp[n] = '\0';
    pclose(p);
    return (int)n;
}

int handle_hello(const char *arg, char *resp, size_t resp_cap)
{
    char name[64];

    /* Correct: the copy is clamped to the destination size. */
    util_copy_bounded(name, sizeof(name), arg);

    return snprintf(resp, resp_cap, "HELLO %s\n", name);
}
