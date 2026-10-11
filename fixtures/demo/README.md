# minisvc

`minisvc` is a small toy network service used as the target for security-audit
exercises. It speaks a line-based text protocol over TCP.

> **Intentionally vulnerable.** This project exists only to exercise a code
> auditing pipeline. Run it on an isolated host, never in production, and never
> expose it to an untrusted network.

## Build

```bash
make            # build/minisvc       (default flags)
make asan       # build/minisvc-asan  (ASan + UBSan)
```

## Run

```bash
# TCP service on 127.0.0.1:8080 (binds loopback only)
./build/minisvc serve 8080
```

## Protocol

One command per line, newline terminated. Responses are plain text lines.

| Command       | Effect                                            |
|---------------|---------------------------------------------------|
| `ECHO <text>` | Echo the text back.                               |
| `GET <path>`  | Read a file below `public/`.                      |
| `PING <host>` | Run a reachability check against the host.        |
| `HELLO <name>`| Greet the name.                                   |

## Layout

```
include/minisvc.h   declared interfaces
src/main.c          CLI entry point (serve)
src/server.c        accept loop and command dispatch
src/handlers.c      one handler per command
src/util.c          small helpers
public/             document root served by GET
```
