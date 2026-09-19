from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from code_auditor.db import AuditStore
from code_auditor.secret_cipher import (
    ENCRYPTED_PREFIX,
    SECRET_KEY_ENV,
    SecretCipher,
    SecretCipherError,
)


def test_secret_cipher_round_trip_and_key_file_permissions(tmp_path: Path) -> None:
    key_path = tmp_path / "state" / "provider.key"
    cipher = SecretCipher(str(key_path))

    token = cipher.encrypt("super-secret")

    assert token.startswith(ENCRYPTED_PREFIX)
    assert "super-secret" not in token
    assert cipher.decrypt(token) == "super-secret"
    assert cipher.encrypt("") == ""
    assert cipher.decrypt("") == ""
    assert os.stat(key_path).st_mode & 0o777 == 0o600


def test_secret_cipher_rejects_a_symlinked_key_path(tmp_path: Path) -> None:
    real_key = tmp_path / "real.key"
    SecretCipher(str(real_key)).encrypt("x")
    link = tmp_path / "linked.key"
    link.symlink_to(real_key)

    with pytest.raises(SecretCipherError, match="regular file"):
        SecretCipher(str(link)).encrypt("x")


def test_secret_cipher_cannot_decrypt_with_another_key(tmp_path: Path) -> None:
    first = SecretCipher(str(tmp_path / "a.key"))
    second = SecretCipher(str(tmp_path / "b.key"))

    with pytest.raises(SecretCipherError, match="could not be decrypted"):
        second.decrypt(first.encrypt("super-secret"))


def test_provider_api_key_is_encrypted_in_the_database(tmp_path: Path) -> None:
    db_path = tmp_path / "audits.db"
    store = AuditStore(str(db_path))
    store.save_provider_settings(
        "codex",
        mode="custom",
        base_url="https://models.example.test/v1",
        api_key="secret-token",
        model="secure-coder",
    )

    with sqlite3.connect(db_path) as conn:
        raw = conn.execute(
            "SELECT api_key FROM provider_settings WHERE backend = 'codex'"
        ).fetchone()[0]
    assert raw.startswith(ENCRYPTED_PREFIX)
    assert "secret-token" not in raw

    loaded = store.get_provider_settings()["codex"]
    assert loaded["api_key"] == "secret-token"
    assert loaded["mode"] == "custom"


def test_legacy_plaintext_api_key_is_migrated_to_ciphertext(tmp_path: Path) -> None:
    db_path = tmp_path / "audits.db"
    store = AuditStore(str(db_path))
    with store._connect() as conn:
        conn.execute(
            """
            INSERT INTO provider_settings (backend, mode, base_url, api_key, model)
            VALUES ('claude', 'custom', 'https://legacy.test/v1', 'legacy-key', 'm')
            """
        )

    loaded = store.get_provider_settings()["claude"]
    assert loaded["api_key"] == "legacy-key"

    with sqlite3.connect(db_path) as conn:
        raw = conn.execute(
            "SELECT api_key FROM provider_settings WHERE backend = 'claude'"
        ).fetchone()[0]
    assert raw.startswith(ENCRYPTED_PREFIX)
    assert "legacy-key" not in raw


def test_unreadable_api_key_is_blanked_instead_of_crashing(tmp_path: Path) -> None:
    db_path = tmp_path / "audits.db"
    AuditStore(str(db_path), secret_key_path=str(tmp_path / "first.key")).save_provider_settings(
        "codex",
        mode="custom",
        base_url="https://models.example.test/v1",
        api_key="secret-token",
        model="secure-coder",
    )

    # A rotated/lost key must not prevent the Web app from starting.
    other = AuditStore(
        str(db_path), secret_key_path=str(tmp_path / "second.key")
    )
    loaded = other.get_provider_settings()["codex"]
    assert loaded["api_key"] == ""
    assert loaded["mode"] == "custom"


def test_secret_key_env_override_avoids_a_key_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    override = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv(SECRET_KEY_ENV, override)
    key_path = tmp_path / "override.key"

    store = AuditStore(str(tmp_path / "audits.db"), secret_key_path=str(key_path))
    store.save_provider_settings(
        "claude",
        mode="custom",
        base_url="https://models.example.test/v1",
        api_key="env-secret",
        model="m",
    )

    assert not key_path.exists()
    assert store.get_provider_settings()["claude"]["api_key"] == "env-secret"


def test_created_flag_and_backup_acknowledgement(tmp_path: Path) -> None:
    key_path = tmp_path / "provider.key"
    cipher = SecretCipher(str(key_path))

    assert cipher.created is False
    cipher.encrypt("first")
    assert cipher.created is True
    assert cipher.key_file_exists() is True
    assert cipher.backup_acknowledged() is False

    assert cipher.acknowledge_backup() is True
    assert cipher.backup_acknowledged() is True
    # Reusing the same key keeps the acknowledgement valid.
    SecretCipher(str(key_path)).encrypt("second")
    assert SecretCipher(str(key_path)).backup_acknowledged() is True


def test_replacing_the_key_invalidates_the_backup_acknowledgement(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "provider.key"
    cipher = SecretCipher(str(key_path))
    cipher.encrypt("first")
    cipher.acknowledge_backup()
    assert cipher.backup_acknowledged() is True

    # Rotate the key behind CodeAuditor's back.
    key_path.write_bytes(Fernet.generate_key())
    rotated = SecretCipher(str(key_path))
    assert rotated.backup_acknowledged() is False


def test_save_provider_settings_reports_key_creation(tmp_path: Path) -> None:
    store = AuditStore(str(tmp_path / "audits.db"))
    first = store.save_provider_settings(
        "claude",
        mode="custom",
        base_url="https://models.example.test/v1",
        api_key="one",
        model="m",
    )
    second = store.save_provider_settings(
        "claude",
        mode="custom",
        base_url="https://models.example.test/v1",
        api_key="two",
        model="m",
    )
    assert first is True
    assert second is False
    assert store.secret_key_info()["prompt_required"] is True
    assert store.acknowledge_secret_key_backup() is True
    assert store.secret_key_info()["prompt_required"] is False

