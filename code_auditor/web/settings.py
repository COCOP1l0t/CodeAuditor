"""Persistent, server-side settings for the CodeAuditor web UI."""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from ..config import DEFAULT_BACKEND, DEFAULT_SANDBOX_MODE, SandboxMode

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
    "sandbox_mode",
    "providers",
}
_PROVIDER_KEYS = {"mode", "base_url", "api_key", "model"}
_BACKENDS = ("claude", "codex")
ProviderMode = Literal["local", "custom"]


class WebSettingsError(ValueError):
    """Raised when the persistent web settings file is invalid."""


@dataclass(frozen=True)
class ModelProviderSettings:
    """One backend's local-config or explicitly configured provider."""

    mode: ProviderMode = "local"
    base_url: str = ""
    api_key: str = field(default="", repr=False)
    model: str = ""

    def serialized(self) -> dict[str, str]:
        return {
            "mode": self.mode,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
        }

    def public(self) -> dict[str, str | bool]:
        """Return browser-safe settings without exposing the stored API key."""
        return {
            "mode": self.mode,
            "base_url": self.base_url,
            "model": self.model,
            "api_key_configured": bool(self.api_key),
        }


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
    sandbox_mode: SandboxMode = DEFAULT_SANDBOX_MODE
    claude_provider: ModelProviderSettings = field(
        default_factory=ModelProviderSettings, repr=False
    )
    codex_provider: ModelProviderSettings = field(
        default_factory=ModelProviderSettings, repr=False
    )

    @classmethod
    def for_state_dir(
        cls,
        state_dir: str,
        *,
        backend: str = DEFAULT_BACKEND,
        log_level: str = "DEBUG",
        max_parallel: int = 1,
        max_concurrent_jobs: int = 4,
        sandbox_mode: SandboxMode = DEFAULT_SANDBOX_MODE,
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
                "sandbox_mode": sandbox_mode,
                "providers": {"claude": {}, "codex": {}},
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
            "sandbox_mode": self.sandbox_mode,
            "providers": {
                "claude": self.claude_provider.serialized(),
                "codex": self.codex_provider.serialized(),
            },
        }

    def provider(self, backend: str | None = None) -> ModelProviderSettings:
        selected = backend or self.backend
        if selected == "claude":
            return self.claude_provider
        if selected == "codex":
            return self.codex_provider
        raise WebSettingsError(f"Unsupported backend: {selected}")

    def public_agent_settings(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "sandbox_mode": self.sandbox_mode,
            "providers": {
                "claude": self.claude_provider.public(),
                "codex": self.codex_provider.public(),
            },
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
    added_providers = "providers" not in raw
    added_sandbox_mode = "sandbox_mode" not in raw
    unknown = sorted(set(raw) - _CONFIG_KEYS)
    if unknown:
        raise WebSettingsError(
            f"Unknown web settings: {', '.join(unknown)}"
        )
    if (
        removed_legacy_paths or removed_model or added_providers or added_sandbox_mode
    ) and not migrated_legacy_file:
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
    sandbox_mode = raw.get("sandbox_mode")
    if sandbox_mode not in {
        "docker-networked",
        "docker-isolated",
        "local-worktree",
    }:
        raise WebSettingsError(
            "sandbox_mode must be 'docker-networked', 'docker-isolated', "
            "or 'local-worktree'."
        )

    managed_paths = {}
    for key in (
        "repos_dir",
        "results_dir",
        "reproductions_dir",
    ):
        managed_paths[key] = _managed_path(raw.get(key), key, state_dir)

    providers = raw.get("providers")
    if not isinstance(providers, dict):
        raise WebSettingsError("providers must be a JSON object.")
    unknown_providers = sorted(set(providers) - set(_BACKENDS))
    if unknown_providers:
        raise WebSettingsError(
            f"Unknown model providers: {', '.join(unknown_providers)}"
        )
    validated_providers = {
        name: _validate_provider(name, providers.get(name, {}))
        for name in _BACKENDS
    }

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
        sandbox_mode=sandbox_mode,
        claude_provider=validated_providers["claude"],
        codex_provider=validated_providers["codex"],
    )


def update_agent_settings(
    settings: WebSettings,
    *,
    backend: str,
    mode: str,
    base_url: str,
    model: str,
    sandbox_mode: str | None = None,
    api_key: str | None = None,
    clear_api_key: bool = False,
) -> WebSettings:
    """Validate and atomically persist the selected backend and provider."""
    if backend not in _BACKENDS:
        raise WebSettingsError("backend must be 'claude' or 'codex'.")
    current = settings.provider(backend)
    key = "" if clear_api_key else current.api_key
    if api_key is not None:
        key = api_key
    provider = _validate_provider(
        backend,
        {"mode": mode, "base_url": base_url, "api_key": key, "model": model},
    )
    selected_sandbox_mode = settings.sandbox_mode
    if sandbox_mode is not None:
        if sandbox_mode not in {
            "docker-networked",
            "docker-isolated",
            "local-worktree",
        }:
            raise WebSettingsError(
                "sandbox_mode must be 'docker-networked', 'docker-isolated', "
                "or 'local-worktree'."
            )
        selected_sandbox_mode = sandbox_mode
    updated = replace(
        settings,
        backend=backend,
        sandbox_mode=selected_sandbox_mode,
        **{f"{backend}_provider": provider},
    )
    _write_settings_file(updated.config_path, updated.serialized())
    os.chmod(updated.config_path, 0o600)
    return updated


def _validate_provider(name: str, raw: Any) -> ModelProviderSettings:
    if not isinstance(raw, dict):
        raise WebSettingsError(f"providers.{name} must be a JSON object.")
    unknown = sorted(set(raw) - _PROVIDER_KEYS)
    if unknown:
        raise WebSettingsError(
            f"Unknown providers.{name} settings: {', '.join(unknown)}"
        )
    mode = raw.get("mode", "local")
    if mode not in {"local", "custom"}:
        raise WebSettingsError(f"providers.{name}.mode must be 'local' or 'custom'.")
    values: dict[str, str] = {}
    limits = {"base_url": 2048, "api_key": 8192, "model": 256}
    for key, limit in limits.items():
        value = raw.get(key, "")
        if not isinstance(value, str):
            raise WebSettingsError(f"providers.{name}.{key} must be a string.")
        value = value.strip()
        if len(value) > limit or any(ord(char) < 32 for char in value):
            raise WebSettingsError(f"providers.{name}.{key} is invalid.")
        values[key] = value
    if values["base_url"]:
        parsed = urlsplit(values["base_url"])
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise WebSettingsError(
                f"providers.{name}.base_url must be an HTTP(S) URL without "
                "credentials or a fragment."
            )
    if mode == "custom":
        missing = [key for key in ("base_url", "api_key", "model") if not values[key]]
        if missing:
            raise WebSettingsError(
                f"Custom {name} provider requires: {', '.join(missing)}."
            )
    return ModelProviderSettings(mode=mode, **values)  # type: ignore[arg-type]


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
