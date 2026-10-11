#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "minisvc.h"

int main(int argc, char **argv)
{
    int port;

    if (argc < 2 || strcmp(argv[1], "serve") != 0) {
        fprintf(stderr, "usage: %s serve [port]\n", argv[0]);
        return 2;
    }

    port = (argc >= 3) ? atoi(argv[2]) : 8080;
    return server_run(port) == 0 ? 0 : 1;
}
