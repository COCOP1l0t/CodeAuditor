"""Persistent, server-side settings for the CodeAuditor web UI."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DEFAULT_BACKEND

DEFAULT_STATE_DIR = os.path.join("~", ".code_auditor")
DEFAULT_SETTINGS_PATH = os.path.join(DEFAULT_STATE_DIR, "settings.json")
LEGACY_WEB_CONFIG_FILENAME = "web-config.json"
_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR"}
_CONFIG_KEYS = {
    "backend",
    "log_level",
    "max_concurrent_jobs",
    "max_parallel",
    "repos_dir",
    "results_dir",
    "reproductions_dir",
}


class WebSettingsError(ValueError):
    """Raised when the persistent web settings file is invalid."""


@dataclass(frozen=True)
class WebSettings:
    config_path: str
    state_dir: str
    backend: str
    log_level: str
    max_parallel: int
    max_concurrent_jobs: int
    repos_dir: str
    results_dir: str
    reproductions_dir: str

    @classmethod
    def for_state_dir(
        cls,
        state_dir: str,
        *,
        backend: str = DEFAULT_BACKEND,
        log_level: str = "DEBUG",
        max_parallel: int = 1,
        max_concurrent_jobs: int = 4,
    ) -> "WebSettings":
        """Build validated settings for an isolated state directory."""
        root = os.path.realpath(os.path.expanduser(state_dir))
        return _validate_settings(
            os.path.join(root, "settings.json"),
            {
                "backend": backend,
                "log_level": log_level,
                "max_concurrent_jobs": max_concurrent_jobs,
                "max_parallel": max_parallel,
                "repos_dir": os.path.join(root, "repo"),
                "results_dir": os.path.join(root, "results"),
                "reproductions_dir": os.path.join(root, "reproductions"),
            },
        )

    def serialized(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "log_level": self.log_level,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "max_parallel": self.max_parallel,
            "repos_dir": self.repos_dir,
            "results_dir": self.results_dir,
            "reproductions_dir": self.reproductions_dir,
        }

    @property
    def wikis_dir(self) -> str:
        """Fixed local Wiki root; intentionally absent from settings.json."""
        return os.path.join(self.state_dir, "wiki")


def load_web_settings(path: str = DEFAULT_SETTINGS_PATH) -> WebSettings:
    """Load settings, migrating the old web-config.json name when needed."""
    config_path = os.path.realpath(os.path.expanduser(path))
    state_dir = os.path.dirname(config_path)
    state_dir_existed = os.path.isdir(state_dir)
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    default_state_dir = os.path.realpath(os.path.expanduser(DEFAULT_STATE_DIR))
    if not state_dir_existed or state_dir == default_state_dir:
        os.chmod(state_dir, 0o700)
    defaults = WebSettings.for_state_dir(state_dir).serialized()
    config_file = Path(config_path)
    legacy_file = config_file.with_name(LEGACY_WEB_CONFIG_FILENAME)
    migrated_legacy_file = False
    if (
        not config_file.exists()
        and config_file.name == "settings.json"
        and legacy_file.is_file()
    ):
        try:
            raw = json.loads(legacy_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WebSettingsError(
                f"Cannot migrate web settings {legacy_file}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise WebSettingsError("Web settings must be a JSON object.")
        raw.pop("wiki_path", None)
        raw.pop("discovered_path", None)
        raw.pop("model", None)
        unknown = sorted(set(raw) - _CONFIG_KEYS)
        if unknown:
            raise WebSettingsError(f"Unknown web settings: {', '.join(unknown)}")
        validated = _validate_settings(config_path, {**defaults, **raw})
        _write_settings_file(config_path, validated.serialized())
        try:
            legacy_file.unlink()
        except OSError as exc:
            try:
                config_file.unlink()
            except OSError:
                pass
            raise WebSettingsError(
                f"Cannot finish settings migration from {legacy_file}: {exc}"
            ) from exc
        migrated_legacy_file = True
    if not config_file.exists():
        _write_settings_file(config_path, defaults)
        return _validate_settings(config_path, defaults)
    try:
        raw = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise WebSettingsError(f"Cannot read web settings {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise WebSettingsError("Web settings must be a JSON object.")
    # One-time migration from paths that are now owned by the Web database or
    # discovered from fixed state-directory locations.
    removed_legacy_paths = any(
        key in raw for key in ("wiki_path", "discovered_path")
    )
    raw.pop("wiki_path", None)
    raw.pop("discovered_path", None)
    # model is now resolved from ~/.claude/settings.json at agent call time.
    removed_model = raw.pop("model", None) is not None
    unknown = sorted(set(raw) - _CONFIG_KEYS)
    if unknown:
        raise WebSettingsError(
            f"Unknown web settings: {', '.join(unknown)}"
        )
    if (removed_legacy_paths or removed_model) and not migrated_legacy_file:
        _write_settings_file(config_path, {**defaults, **raw})
    os.chmod(config_path, 0o600)
    return _validate_settings(config_path, {**defaults, **raw})


def _validate_settings(config_path: str, raw: dict[str, Any]) -> WebSettings:
    state_dir = os.path.dirname(os.path.realpath(config_path))
    backend = raw.get("backend")
    if backend not in {"claude", "codex"}:
        raise WebSettingsError("backend must be 'claude' or 'codex'.")
    log_level = raw.get("log_level")
    if not isinstance(log_level, str) or log_level.upper() not in _LOG_LEVELS:
        raise WebSettingsError("log_level must be DEBUG, INFO, WARNING, or ERROR.")
    max_parallel = raw.get("max_parallel")
    if not isinstance(max_parallel, int) or isinstance(max_parallel, bool):
        raise WebSettingsError("max_parallel must be an integer.")
    if not 1 <= max_parallel <= 16:
        raise WebSettingsError("max_parallel must be between 1 and 16.")
    max_concurrent_jobs = raw.get("max_concurrent_jobs")
    if not isinstance(max_concurrent_jobs, int) or isinstance(
        max_concurrent_jobs, bool
    ):
        raise WebSettingsError("max_concurrent_jobs must be an integer.")
    if not 1 <= max_concurrent_jobs <= 16:
        raise WebSettingsError("max_concurrent_jobs must be between 1 and 16.")

    managed_paths = {}
    for key in (
        "repos_dir",
        "results_dir",
        "reproductions_dir",
    ):
        managed_paths[key] = _managed_path(raw.get(key), key, state_dir)

    return WebSettings(
        config_path=os.path.realpath(config_path),
        state_dir=state_dir,
        backend=backend,
        log_level=log_level.upper(),
        max_parallel=max_parallel,
        max_concurrent_jobs=max_concurrent_jobs,
        repos_dir=managed_paths["repos_dir"],
        results_dir=managed_paths["results_dir"],
        reproductions_dir=managed_paths["reproductions_dir"],
    )


def _managed_path(value: Any, key: str, state_dir: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise WebSettingsError(f"{key} must be a non-empty path string.")
    resolved = os.path.realpath(os.path.expanduser(value))
    if resolved != state_dir and not resolved.startswith(state_dir + os.sep):
        raise WebSettingsError(f"{key} must stay under {state_dir}.")
    return resolved


def _write_settings_file(path: str, settings: dict[str, Any]) -> None:
    directory = os.path.dirname(path)
    fd, temporary = tempfile.mkstemp(
        prefix=".settings-", suffix=".tmp", dir=directory, text=True
    )
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(settings, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
