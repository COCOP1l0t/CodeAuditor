#ifndef MINISVC_H
#define MINISVC_H

#include <stddef.h>

/* src/server.c */
int server_run(int port);

/* src/handlers.c */
int handle_echo(const char *arg, char *resp, size_t resp_cap);
int handle_file(const char *arg, char *resp, size_t resp_cap);
int handle_exec(const char *arg, char *resp, size_t resp_cap);
int handle_hello(const char *arg, char *resp, size_t resp_cap);

/* src/util.c */
int util_copy_bounded(char *dst, size_t cap, const char *src);
int util_show_time(char *resp, size_t resp_cap);

#endif /* MINISVC_H */
