"""Encryption at rest for provider API keys kept in the audit database.

The Web UI stores a custom model provider's endpoint and API key in SQLite
(see ``AuditStore.save_provider_settings``). The key is encrypted with Fernet
(AES-128-CBC + HMAC) so the database file alone never discloses it. The
encryption key lives next to the database in a ``0600`` file, or is supplied
through ``CODE_AUDITOR_SECRET_KEY`` (a Fernet key) for externally managed
deployments.
"""
from __future__ import annotations

import hashlib
import os
import stat

from cryptography.fernet import Fernet, InvalidToken

ENCRYPTED_PREFIX = "enc:v1:"
SECRET_KEY_ENV = "CODE_AUDITOR_SECRET_KEY"


class SecretCipherError(ValueError):
    """Raised when a stored secret cannot be decrypted or the key is unusable."""


class SecretCipher:
    """Encrypts and decrypts provider secrets with a host-owned Fernet key."""

    def __init__(self, key_path: str) -> None:
        self._key_path = key_path
        self._fernet: Fernet | None = None
        #: True once this process generated the key file (used to prompt the
        #: operator to back it up before the encrypted secret depends on it).
        self.created = False

    @property
    def key_path(self) -> str:
        return self._key_path

    @property
    def uses_env_key(self) -> bool:
        """Whether the key comes from CODE_AUDITOR_SECRET_KEY (externally managed)."""
        return bool(os.environ.get(SECRET_KEY_ENV))

    def key_file_exists(self) -> bool:
        """Whether a managed key file is present (env-managed keys have none)."""
        if self.uses_env_key:
            return False
        try:
            info = os.lstat(self._key_path)
        except OSError:
            return False
        return stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)

    @property
    def fernet(self) -> Fernet:
        if self._fernet is None:
            key = self._load_key()
            try:
                self._fernet = Fernet(key)
            except (TypeError, ValueError) as exc:
                raise SecretCipherError(
                    f"invalid secret key for {self._key_path}: {exc}"
                ) from exc
        return self._fernet

    def _load_key(self) -> bytes:
        override = os.environ.get(SECRET_KEY_ENV)
        if override:
            return override.strip().encode("ascii", "ignore")
        path = self._key_path
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return self._create_key(path)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SecretCipherError(
                f"secret key path is not a regular file: {path}"
            )
        try:
            with open(path, "rb") as stream:
                key = stream.read().strip()
        except OSError as exc:
            raise SecretCipherError(f"cannot read secret key {path}: {exc}") from exc
        if not key:
            raise SecretCipherError(f"secret key file is empty: {path}")
        return key

    def _create_key(self, path: str) -> bytes:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        key = Fernet.generate_key()
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # Another process created it first; reuse that key.
            with open(path, "rb") as stream:
                return stream.read().strip()
        except OSError as exc:
            raise SecretCipherError(f"cannot create secret key {path}: {exc}") from exc
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
        self.created = True
        return key

    def read_key_text(self) -> str | None:
        """Return the managed key file contents, or None when not downloadable."""
        if not self.key_file_exists():
            return None
        try:
            with open(self._key_path, encoding="ascii") as stream:
                return stream.read().strip()
        except (OSError, UnicodeError):
            return None

    def key_fingerprint(self) -> str | None:
        """Stable digest of the active key, used to invalidate a stale ack."""
        text = self.read_key_text()
        if text is None:
            return None
        return hashlib.sha256(text.encode("ascii", "ignore")).hexdigest()

    def _ack_path(self) -> str:
        return f"{self._key_path}.ack"

    def backup_acknowledged(self) -> bool:
        """Whether the operator confirmed storing the current key file."""
        fingerprint = self.key_fingerprint()
        if fingerprint is None:
            # Env-managed keys are backed up outside CodeAuditor.
            return True
        try:
            with open(self._ack_path(), encoding="ascii") as stream:
                return stream.read().strip() == fingerprint
        except (OSError, UnicodeError):
            return False

    def acknowledge_backup(self) -> bool:
        """Record that the current key file has been stored by the operator."""
        fingerprint = self.key_fingerprint()
        if fingerprint is None:
            return False
        ack_path = self._ack_path()
        directory = os.path.dirname(ack_path)
        if directory:
            os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            fd = os.open(
                ack_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
        except OSError as exc:
            raise SecretCipherError(f"cannot write {ack_path}: {exc}") from exc
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(fingerprint + "\n")
        return True

    def is_encrypted(self, value: str) -> bool:
        return value.startswith(ENCRYPTED_PREFIX)

    def encrypt(self, plaintext: str) -> str:
        """Return an encrypted, prefixed token; empty input stays empty."""
        if not plaintext:
            return ""
        if self.is_encrypted(plaintext):
            return plaintext
        token = self.fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return ENCRYPTED_PREFIX + token

    def decrypt(self, stored: str) -> str:
        """Return the plaintext; a legacy unprefixed value is returned as-is."""
        if not stored:
            return ""
        if not self.is_encrypted(stored):
            # Value written before encryption was introduced.
            return stored
        token = stored[len(ENCRYPTED_PREFIX) :].encode("ascii", "ignore")
        try:
            return self.fernet.decrypt(token).decode("utf-8")
        except InvalidToken as exc:
            raise SecretCipherError(
                "stored API key could not be decrypted with the current secret key"
            ) from exc
