from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from code_auditor.web.settings import (
    WebSettings,
    WebSettingsError,
    load_web_settings,
)


def test_load_web_settings_creates_secure_debug_defaults(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    config_path = state_dir / "settings.json"

    settings = load_web_settings(str(config_path))

    assert config_path.is_file()
    assert settings.backend == "claude"
    assert settings.model is None
    assert settings.log_level == "DEBUG"
    assert settings.repos_dir == str(state_dir / "repo")
    assert settings.results_dir == str(state_dir / "results")
    assert settings.reproductions_dir == str(state_dir / "reproductions")
    assert settings.wikis_dir == str(state_dir / "wiki")
    assert os.stat(state_dir).st_mode & 0o777 == 0o700
    assert os.stat(config_path).st_mode & 0o777 == 0o600


def test_load_web_settings_reads_valid_server_configuration(tmp_path: Path) -> None:
    config_path = tmp_path / "settings.json"
    configured = WebSettings.for_state_dir(
        str(tmp_path),
        backend="codex",
        model="gpt-5.5",
        max_parallel=4,
    )
    config_path.write_text(
        json.dumps(configured.serialized()), encoding="utf-8"
    )
    config_path.chmod(0o644)

    settings = load_web_settings(str(config_path))

    assert settings.backend == "codex"
    assert settings.model == "gpt-5.5"
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


@pytest.mark.parametrize(
    "override",
    [
        {"backend": "shell"},
        {"model": "model; rm -rf"},
        {"log_level": "TRACE"},
        {"max_parallel": 0},
        {"results_dir": "/tmp/outside-managed-state"},
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
