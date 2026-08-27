from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from code_auditor.web.settings import (
    WebSettings,
    WebSettingsError,
    load_web_settings,
    update_agent_settings,
)


def test_load_web_settings_creates_secure_debug_defaults(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    config_path = state_dir / "settings.json"

    settings = load_web_settings(str(config_path))

    assert config_path.is_file()
    assert settings.backend == "claude"
    assert settings.sandbox_mode == "docker-networked"
    assert settings.log_level == "DEBUG"
    assert settings.repos_dir == str(state_dir / "repo")
    assert settings.results_dir == str(state_dir / "results")
    assert settings.reproductions_dir == str(state_dir / "reproductions")
    assert settings.wikis_dir == str(state_dir / "wiki")
    assert settings.claude_provider.mode == "local"
    assert settings.codex_provider.mode == "local"
    assert os.stat(state_dir).st_mode & 0o777 == 0o700
    assert os.stat(config_path).st_mode & 0o777 == 0o600


def test_load_web_settings_reads_valid_server_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    configured = WebSettings.for_state_dir(
        str(tmp_path),
        backend="codex",
        max_parallel=4,
    )
    config_path.write_text(
        json.dumps(configured.serialized()), encoding="utf-8"
    )
    config_path.chmod(0o644)

    settings = load_web_settings(str(config_path))

    assert settings.backend == "codex"
    assert settings.log_level == "DEBUG"
    assert settings.max_parallel == 4
    assert os.stat(config_path).st_mode & 0o777 == 0o600


def test_load_web_settings_removes_legacy_managed_paths(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    raw = WebSettings.for_state_dir(str(tmp_path)).serialized()
    raw["wiki_path"] = "/tmp/legacy-wiki"
    raw["discovered_path"] = "/tmp/legacy-disclosure-index"
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    settings = load_web_settings(str(config_path))

    assert settings.wikis_dir == str(tmp_path / "wiki")
    stored = json.loads(config_path.read_text(encoding="utf-8"))
    assert "wiki_path" not in stored
    assert "discovered_path" not in stored


def test_load_web_settings_adds_default_sandbox_mode(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    raw = WebSettings.for_state_dir(str(tmp_path)).serialized()
    raw.pop("sandbox_mode")
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    settings = load_web_settings(str(config_path))

    assert settings.sandbox_mode == "docker-networked"
    stored = json.loads(config_path.read_text(encoding="utf-8"))
    assert stored["sandbox_mode"] == "docker-networked"


@pytest.mark.parametrize(
    "override",
    [
        {"backend": "shell"},
        {"log_level": "TRACE"},
        {"max_parallel": 0},
        {"results_dir": "/tmp/outside-managed-state"},
        {"sandbox_mode": "host"},
        {"unknown_key": "value"},
    ],
)
def test_load_web_settings_rejects_invalid_values(
    tmp_path: Path, override: dict
) -> None:
    config_path = tmp_path / "settings.json"
    raw = WebSettings.for_state_dir(str(tmp_path)).serialized()
    raw.update(override)
    config_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(WebSettingsError):
        load_web_settings(str(config_path))


def test_load_web_settings_renames_legacy_web_config(tmp_path: Path) -> None:
    legacy_path = tmp_path / "web-config.json"
    settings_path = tmp_path / "settings.json"
    raw = WebSettings.for_state_dir(str(tmp_path), backend="codex").serialized()
    legacy_path.write_text(json.dumps(raw), encoding="utf-8")

    settings = load_web_settings(str(settings_path))

    assert settings.backend == "codex"
    assert settings.config_path == str(settings_path)
    assert settings_path.is_file()
    assert not legacy_path.exists()
    assert os.stat(settings_path).st_mode & 0o777 == 0o600


def test_update_agent_settings_persists_custom_provider_without_public_key(
    tmp_path: Path,
) -> None:
    settings = load_web_settings(str(tmp_path / "settings.json"))

    updated = update_agent_settings(
        settings,
        backend="codex",
        mode="custom",
        base_url="https://models.example.test/v1",
        model="secure-coder",
        sandbox_mode="local-worktree",
        api_key="secret-token",
    )

    assert updated.backend == "codex"
    assert updated.sandbox_mode == "local-worktree"
    assert updated.codex_provider.api_key == "secret-token"
    assert updated.public_agent_settings()["providers"]["codex"] == {
        "mode": "custom",
        "base_url": "https://models.example.test/v1",
        "model": "secure-coder",
        "api_key_configured": True,
    }
    assert "secret-token" not in json.dumps(updated.public_agent_settings())
    stored = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert stored["providers"]["codex"]["api_key"] == "secret-token"
    assert os.stat(tmp_path / "settings.json").st_mode & 0o777 == 0o600

    preserved = update_agent_settings(
        updated,
        backend="codex",
        mode="custom",
        base_url="https://models.example.test/v1",
        model="secure-coder-v2",
    )
    assert preserved.codex_provider.api_key == "secret-token"


@pytest.mark.parametrize(
    "base_url",
    [
        "file:///tmp/provider",
        "https://user:password@example.test/v1",
        "https://example.test/v1#fragment",
        "https://example.test/\nheader",
    ],
)
def test_update_agent_settings_rejects_unsafe_provider_urls(
    tmp_path: Path, base_url: str
) -> None:
    settings = load_web_settings(str(tmp_path / "settings.json"))

    with pytest.raises(WebSettingsError):
        update_agent_settings(
            settings,
            backend="claude",
            mode="custom",
            base_url=base_url,
            model="model",
            api_key="key",
        )
