from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from code_auditor.sandbox import (
    DOCKER_CWD_ENV,
    DOCKER_SPEC_ENV,
    DockerSandboxError,
    DockerScratch,
    _locate_codex_vendor,
    _require_tmp_root,
    docker_cli_command,
    inspect_docker_sandbox_environment,
)
from code_auditor.config import AuditConfig


def _option_value(command: list[str], option: str) -> str:
    return command[command.index(option) + 1]


def test_sandbox_root_must_be_a_dedicated_tmp_directory() -> None:
    assert _require_tmp_root("/tmp/code-auditor") == Path("/tmp/code-auditor")
    with pytest.raises(DockerSandboxError, match="dedicated directory"):
        _require_tmp_root("/tmp")
    with pytest.raises(DockerSandboxError, match="under /tmp"):
        _require_tmp_root("/var/tmp/code-auditor")


def test_sandbox_capability_checks_runtime_storage_and_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from code_auditor import sandbox as sandbox_module

    monkeypatch.setattr(DockerScratch, "_verify_runtime", lambda _self: None)
    monkeypatch.setattr(sandbox_module, "_locate_claude_cli", lambda: Path("/cli"))
    monkeypatch.setattr(
        sandbox_module.shutil,
        "disk_usage",
        lambda _path: type("Usage", (), {"free": 0})(),
    )

    capability = inspect_docker_sandbox_environment("claude")

    assert capability.available is False
    assert "at least" in capability.reason


def test_sandbox_capability_reports_ready_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from code_auditor import sandbox as sandbox_module

    free_bytes = 16 * 1024 * 1024 * 1024
    monkeypatch.setattr(DockerScratch, "_verify_runtime", lambda _self: None)
    monkeypatch.setattr(sandbox_module, "_locate_codex_vendor", lambda: Path("/vendor"))
    monkeypatch.setattr(
        sandbox_module.shutil,
        "disk_usage",
        lambda _path: type("Usage", (), {"free": free_bytes})(),
    )

    capability = inspect_docker_sandbox_environment("codex")

    assert capability.available is True
    assert capability.free_bytes == free_bytes
    assert capability.public()["image"] == "code-auditor-sandbox:latest"


def test_sandbox_capability_reports_invalid_config_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CODE_AUDITOR_SANDBOX_ROOT", "/var/tmp/code-auditor")

    capability = inspect_docker_sandbox_environment("claude")

    assert capability.available is False
    assert "under /tmp" in capability.reason


def test_codex_vendor_follows_codex_selected_from_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "new-codex"
    launcher = package_root / "bin" / "codex.js"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    launcher.chmod(0o755)
    vendor = (
        package_root
        / "node_modules"
        / "@openai"
        / "codex-linux-x64"
        / "vendor"
        / "x86_64-unknown-linux-musl"
    )
    binary = vendor / "bin" / "codex"
    binary.parent.mkdir(parents=True)
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o755)
    legacy_root = tmp_path / "old-codex"

    from code_auditor import sandbox as sandbox_module

    monkeypatch.delenv("CODE_AUDITOR_CODEX_BIN", raising=False)
    monkeypatch.delenv("CODE_AUDITOR_CODEX_VENDOR", raising=False)
    monkeypatch.setattr(sandbox_module.shutil, "which", lambda _name: str(launcher))
    monkeypatch.setattr(sandbox_module, "_LEGACY_CODEX_PACKAGE_ROOT", legacy_root)

    assert _locate_codex_vendor() == vendor.resolve()


@pytest.mark.parametrize("tool", ["claude", "codex"])
def test_docker_wrapper_builds_a_confined_command(
    tmp_path: Path,
    tool: str,
) -> None:
    scratch = tmp_path / "scratch"
    cwd = scratch / "source"
    home = scratch / "home"
    readonly = tmp_path / "git-objects"
    for directory in (cwd, home, readonly):
        directory.mkdir(parents=True)
    claude_cli = tmp_path / "claude"
    claude_cli.write_text("binary", encoding="utf-8")
    codex_vendor = tmp_path / "codex-vendor"
    (codex_vendor / "bin").mkdir(parents=True)
    (codex_vendor / "bin" / "codex").write_text("binary", encoding="utf-8")
    spec = {
        "schema_version": 1,
        "docker_bin": "docker",
        "image": "code-auditor-sandbox:test",
        "scratch_root": str(scratch),
        "scratch_id": "abc123",
        "home": str(home),
        "uid": os.getuid(),
        "gid": os.getgid(),
        "network_enabled": False,
        "pids_limit": 128,
        "memory": "2g",
        "cpus": "1.5",
        "claude_cli": str(claude_cli),
        "codex_vendor": str(codex_vendor),
        "readonly_mounts": [str(readonly)],
    }
    spec_path = tmp_path / "docker-spec.json"
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    environ = {
        DOCKER_SPEC_ENV: str(spec_path),
        DOCKER_CWD_ENV: str(cwd),
        "CODE_AUDITOR_AGENT_RUN_ID": "run-marker",
        "OPENAI_API_KEY": "secret",
        "PATH": "/should/not/be/forwarded",
    }

    command = docker_cli_command(tool, ["--version"], environ)

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in command
    assert "--cap-drop=ALL" in command
    assert "--security-opt=no-new-privileges" in command
    assert "--network" in command
    assert _option_value(command, "--network") == "none"
    assert _option_value(command, "--workdir") == str(cwd)
    assert f"type=bind,src={scratch},dst={scratch}" in command
    assert f"type=bind,src={readonly},dst={readonly},readonly" in command
    assert "OPENAI_API_KEY" in command
    assert "PATH" not in command
    assert DOCKER_SPEC_ENV not in command
    assert DOCKER_CWD_ENV not in command
    assert command[-1] == "--version"


def test_docker_wrapper_rejects_cwd_outside_scratch(tmp_path: Path) -> None:
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    spec_path = tmp_path / "docker-spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scratch_root": str(scratch),
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(DockerSandboxError, match="escapes scratch root"):
        docker_cli_command(
            "codex",
            [],
            {
                DOCKER_SPEC_ENV: str(spec_path),
                DOCKER_CWD_ENV: str(tmp_path / "outside"),
            },
        )


def test_scratch_control_files_are_outside_agent_writable_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "source.c").write_text("int main(void) { return 0; }\n")
    vendor = tmp_path / "codex-vendor"
    (vendor / "bin").mkdir(parents=True)
    binary = vendor / "bin" / "codex"
    binary.write_text("binary", encoding="utf-8")
    binary.chmod(0o700)
    config = AuditConfig(
        target=str(target),
        output_dir=str(tmp_path / "output"),
        backend="codex",
        sandbox_root=str(tmp_path / "scratch-root"),
        sandbox_min_free_bytes=0,
    )
    from code_auditor import sandbox as sandbox_module

    monkeypatch.setattr(sandbox_module, "_locate_codex_vendor", lambda: vendor)
    monkeypatch.setattr(sandbox_module.DockerScratch, "_verify_runtime", lambda _self: None)
    monkeypatch.setattr(sandbox_module.DockerScratch, "_remove_containers", lambda _self: None)
    scratch = sandbox_module.DockerScratch(config, "stage5-H-01")

    asyncio.run(scratch.prepare(str(target), ""))
    root = scratch.root
    control = scratch.control_dir
    assert root is not None
    assert control is not None
    assert root.parent == control.parent
    assert control.parent == Path(config.sandbox_root)
    assert control != root
    assert scratch.spec_path is not None
    assert scratch.spec_path.parent == control
    assert Path(scratch.wrapper_path("codex")).parent == control
    assert (scratch.source_dir / "source.c").is_file()  # type: ignore[operator]

    asyncio.run(scratch.close())

    assert not root.exists()
    assert not control.exists()
