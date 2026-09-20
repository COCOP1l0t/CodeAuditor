#!/usr/bin/env python3
"""Reset a local CodeAuditor Web account password.

This is the documented out-of-band recovery path: the Web API has no password
change endpoint (only first-run setup, admin-only registration, login, and
logout), so a forgotten password can only be repaired by writing the SQLite
``users`` row directly.

Usage (interactive, password is not echoed)::

    python3 scripts/reset_password.py            # defaults to the admin account
    python3 scripts/reset_password.py --list
    python3 scripts/reset_password.py --username alice

Or non-interactively, reading the new password from stdin::

    printf '%s' "$NEW_PASSWORD" | python3 scripts/reset_password.py --stdin

Every existing session of the account is revoked, so a stale cookie cannot
survive a reset.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from code_auditor.db import DEFAULT_DB_PATH  # noqa: E402
from code_auditor.web.auth import (  # noqa: E402
    hash_password,
    normalize_username,
    verify_password,
)

MIN_PASSWORD_LENGTH = 12


def _list_users(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username, role, is_active, last_login_at FROM users ORDER BY id"
    ).fetchall()


def _read_new_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.read().strip()
        if len(password) < MIN_PASSWORD_LENGTH:
            raise SystemExit(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            )
        return password
    while True:
        password = getpass.getpass(
            f"New password (at least {MIN_PASSWORD_LENGTH} characters): "
        )
        if len(password) < MIN_PASSWORD_LENGTH:
            print("  Too short, try again.")
            continue
        if password != getpass.getpass("Repeat the new password: "):
            print("  The two entries differ, try again.")
            continue
        return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--username", default="admin", help="account to reset")
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="audit database path")
    parser.add_argument(
        "--list", action="store_true", help="only list accounts, change nothing"
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read the new password from stdin instead of prompting",
    )
    args = parser.parse_args(argv)

    db_path = os.path.realpath(os.path.expanduser(args.db))
    if not os.path.isfile(db_path):
        raise SystemExit(f"No database at {db_path}")

    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        accounts = _list_users(conn)
        if not accounts:
            raise SystemExit("No accounts exist yet; open the Web UI to run setup.")
        print(f"Accounts in {db_path}:")
        for row in accounts:
            print(
                f"  id={row['id']}  username={row['username']}  role={row['role']}"
                f"  active={row['is_active']}"
            )
        if args.list:
            return 0

        username = normalize_username(args.username)
        target = conn.execute(
            "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
        if target is None:
            raise SystemExit(f"No account named {args.username!r}.")

        password = _read_new_password(args.stdin)
        encoded = hash_password(password)
        if not verify_password(password, encoded) or verify_password(
            password + " ", encoded
        ):
            raise SystemExit("Hash self-test failed; nothing was written.")

        with conn:
            conn.execute(
                "UPDATE users SET password_hash = ?, is_active = 1 WHERE id = ?",
                (encoded, target["id"]),
            )
            revoked = conn.execute(
                "DELETE FROM sessions WHERE user_id = ?", (target["id"],)
            ).rowcount
    finally:
        conn.close()

    check = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        stored = check.execute(
            "SELECT password_hash FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()[0]
    finally:
        check.close()
    if not verify_password(password, stored):
        raise SystemExit("Written hash did not verify; investigate before signing in.")

    print(
        f"\nPassword updated for {target['username']} (id={target['id']}); "
        f"revoked {revoked} active session(s). Sign in with the new password."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
