"""Password and browser-session primitives for the Web API.

The Web UI runs as a local service, but its audit and terminal endpoints can
still mutate or expose sensitive project data.  Passwords are therefore stored
with the stdlib scrypt implementation and session cookies contain only a
random bearer token whose digest is persisted in SQLite.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

PASSWORD_SCHEME = "scrypt"
PASSWORD_N = 2**14
PASSWORD_R = 8
PASSWORD_P = 1
PASSWORD_DKLEN = 64
SESSION_TOKEN_BYTES = 32
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60
SESSION_COOKIE_NAME = "codeauditor_session"


def normalize_username(username: str) -> str:
    """Normalize a login name while retaining its user-visible spelling rules."""
    return username.strip().casefold()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=PASSWORD_N,
        r=PASSWORD_R,
        p=PASSWORD_P,
        dklen=PASSWORD_DKLEN,
    )
    encode = base64.urlsafe_b64encode
    return "$".join(
        (
            PASSWORD_SCHEME,
            str(PASSWORD_N),
            str(PASSWORD_R),
            str(PASSWORD_P),
            encode(salt).decode("ascii"),
            encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n_text, r_text, p_text, salt_text, digest_text = encoded.split("$", 5)
        if scheme != PASSWORD_SCHEME:
            return False
        n = int(n_text)
        r = int(r_text)
        p = int(p_text)
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
        )
    except (TypeError, ValueError, UnicodeError):
        return False
    return hmac.compare_digest(actual, expected)


def new_session_token() -> str:
    return secrets.token_urlsafe(SESSION_TOKEN_BYTES)


def session_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
