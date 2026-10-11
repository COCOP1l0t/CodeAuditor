#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "minisvc.h"

#define LINE_MAX 4096
#define RESP_MAX 8192

static void dispatch(const char *line, char *resp, size_t resp_cap)
{
    char cmd[32];
    const char *sp = strchr(line, ' ');
    const char *arg = sp ? sp + 1 : "";
    size_t n = sp ? (size_t)(sp - line) : strlen(line);

    if (n >= sizeof(cmd)) {
        n = sizeof(cmd) - 1;
    }
    memcpy(cmd, line, n);
    cmd[n] = '\0';

    if (strcmp(cmd, "ECHO") == 0) {
        handle_echo(arg, resp, resp_cap);
    } else if (strcmp(cmd, "GET") == 0) {
        handle_file(arg, resp, resp_cap);
    } else if (strcmp(cmd, "PING") == 0) {
        handle_exec(arg, resp, resp_cap);
    } else if (strcmp(cmd, "HELLO") == 0) {
        handle_hello(arg, resp, resp_cap);
    } else {
        snprintf(resp, resp_cap, "ERR unknown command\n");
    }
}

int server_run(int port)
{
    int srv;
    int one = 1;
    struct sockaddr_in addr;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return -1;
    }
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv);
        return -1;
    }
    if (listen(srv, 16) < 0) {
        perror("listen");
        close(srv);
        return -1;
    }

    printf("minisvc listening on 127.0.0.1:%d\n", port);
    fflush(stdout);

    for (;;) {
        int cli;
        FILE *fp;
        char line[LINE_MAX];

        cli = accept(srv, NULL, NULL);
        if (cli < 0) {
            perror("accept");
            continue;
        }
        fp = fdopen(cli, "r+");
        if (fp == NULL) {
            close(cli);
            continue;
        }
        setvbuf(fp, NULL, _IONBF, 0);

        while (fgets(line, sizeof(line), fp) != NULL) {
            char resp[RESP_MAX];
            size_t len = strlen(line);

            if (len > 0 && line[len - 1] == '\n') {
                line[--len] = '\0';
            }
            if (len > 0 && line[len - 1] == '\r') {
                line[--len] = '\0';
            }

            resp[0] = '\0';
            dispatch(line, resp, sizeof(resp));
            if (resp[0] != '\0') {
                fputs(resp, fp);
            }
        }
        fclose(fp);
    }
}
