from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import signal
import sys
import threading
import types
from collections.abc import AsyncIterator
from enum import Enum
from pathlib import Path

import pytest

from code_auditor import __main__ as main_module
from code_auditor import agent
from code_auditor import config as config_module
from code_auditor import logger as logger_module
from code_auditor import tui as tui_module
from code_auditor.__main__ import _build_parser
from code_auditor.config import (
    DEFAULT_AGENT_TIMEOUT_SECONDS,
    DEFAULT_BACKEND,
    DEFAULT_CLAUDE_POC_MODEL,
    DEFAULT_CODEX_POC_MODEL,
    AgentBackend,
    AuditConfig,
    select_poc_model,
)
from code_auditor.sandbox import DockerScratch
from code_auditor.tui import TUIManager, TUIState, _TUILogHandler, _make_config_table, _visible_log_lines


@pytest.fixture(autouse=True)
def _stub_history_persistence(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    """Prevent main() tests from writing to the real history database."""
    calls: list[dict] = []

    def fake_persist(db_path, config, status, error, started_at):  # type: ignore[no-untyped-def]
        calls.append({
            "db_path": db_path,
            "config": config,
            "status": status,
            "error": error,
            "started_at": started_at,
        })

    monkeypatch.setattr(main_module, "_persist_run_safely", fake_persist)
    return calls


def test_cli_backend_defaults_to_claude() -> None:
    args = _build_parser().parse_args(["--target", "."])

    assert args.backend == DEFAULT_BACKEND == "claude"
    assert args.model is None


def test_cli_accepts_codex_backend_and_model_override() -> None:
    args = _build_parser().parse_args([
        "--target",
        ".",
        "--backend",
        "codex",
        "--model",
        "gpt-5.4",
    ])

    assert args.backend == "codex"
    assert args.model == "gpt-5.4"



def test_cli_accepts_wiki_path() -> None:
    args = _build_parser().parse_args([
        "--target",
        ".",
        "--wiki",
        "/tmp/wiki",
    ])

    assert args.wiki == "/tmp/wiki"


def test_cli_rejects_removed_discovered_option() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(
            ["--target", ".", "--discovered", "/tmp/bugs.html"]
        )


def test_cli_accepts_tui_flag() -> None:
    args = _build_parser().parse_args(["--target", ".", "--tui"])

    assert args.tui is True


def test_cli_accepts_retention_migration_dry_run_root() -> None:
    args = _build_parser().parse_args(
        ["--retention-migration-dry-run", "/tmp/results"]
    )

    assert args.retention_migration_dry_run == "/tmp/results"


def test_cli_accepts_retention_manifest_apply_root() -> None:
    args = _build_parser().parse_args(
        ["--retention-manifest-apply", "/tmp/results"]
    )

    assert args.retention_manifest_apply == "/tmp/results"


def test_cli_rejects_both_retention_migration_modes() -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(
            [
                "--retention-migration-dry-run",
                "/tmp/results",
                "--retention-manifest-apply",
                "/tmp/results",
            ]
        )


@pytest.mark.parametrize(
    ("flag", "attribute"),
    [
        (
            "--retention-entrypoint-repair-dry-run",
            "retention_entrypoint_repair_dry_run",
        ),
        (
            "--retention-entrypoint-repair-apply",
            "retention_entrypoint_repair_apply",
        ),
        ("--reviewed-cleanup-dry-run", "reviewed_cleanup_dry_run"),
        ("--reviewed-cleanup-apply", "reviewed_cleanup_apply"),
    ],
)
def test_cli_accepts_reviewed_cleanup_modes(flag: str, attribute: str) -> None:
    args = _build_parser().parse_args([flag, "/tmp/results"])

    assert getattr(args, attribute) == "/tmp/results"


def test_main_prints_retention_migration_without_starting_audit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    results = tmp_path / "results"
    results.mkdir()

    async def unexpected_audit(_config: AuditConfig) -> None:
        raise AssertionError("dry-run migration must not start an audit")

    monkeypatch.setattr(main_module, "run_audit", unexpected_audit)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "code-auditor",
            "--retention-migration-dry-run",
            str(results),
            "--db",
            str(tmp_path / "missing.db"),
        ],
    )

    main_module.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload["mode"] == "dry-run"
    assert payload["mutations"] == []


@pytest.mark.parametrize("removed_flag", ["--enable-timeout", "--disable-stale-log-kill"])
def test_cli_rejects_removed_timeout_flags(removed_flag: str) -> None:
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["--target", ".", removed_flag])


def test_main_maps_wiki_path_to_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}
    target = tmp_path / "target"
    wiki = tmp_path / "wiki"
    target.mkdir()
    wiki.mkdir()

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(wiki),
    ])

    main_module.main()

    assert captured["config"].wiki_path == str(wiki.resolve())


def test_main_rejects_missing_wiki_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    missing_wiki = tmp_path / "missing-wiki"
    target.mkdir()

    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(missing_wiki),
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1
    assert f"Error: Wiki directory not found: {missing_wiki.resolve()}" in capsys.readouterr().err


def test_main_rejects_wiki_file_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    wiki_file = tmp_path / "wiki.md"
    target.mkdir()
    wiki_file.write_text("# Not a directory\n")

    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--wiki",
        str(wiki_file),
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1
    assert f"Error: Wiki path is not a directory: {wiki_file.resolve()}" in capsys.readouterr().err


def test_additional_directories_includes_existing_wiki_path(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    output = tmp_path / "output"
    wiki = tmp_path / "wiki"
    target.mkdir()
    output.mkdir()
    wiki.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output),
        wiki_path=str(wiki),
    )

    assert agent._additional_directories(config, str(target)) == [
        str(output.resolve()),
        str(wiki.resolve()),
    ]


def test_additional_directories_skips_wiki_when_it_is_cwd(tmp_path) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    output = tmp_path / "output"
    target.mkdir()
    output.mkdir()
    config = AuditConfig(
        target=str(target),
        output_dir=str(output),
        wiki_path=str(target),
    )

    assert agent._additional_directories(config, str(target)) == [str(output.resolve())]


def test_main_enables_default_agent_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
    ])

    main_module.main()

    assert captured["config"].agent_timeout_seconds == DEFAULT_AGENT_TIMEOUT_SECONDS


def test_main_defaults_output_dir_to_results_dir_with_commit_stamp(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}

    class FakeDateTime:
        @classmethod
        def now(cls):  # type: ignore[no-untyped-def]
            return cls()

        def strftime(self, _format: str) -> str:
            return "20300102"

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    # tmp_path is not a git repo, so the stamp falls back to the date.
    monkeypatch.setattr("code_auditor.repos.datetime", FakeDateTime)
    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
    ])

    main_module.main()

    import os

    expected = os.path.expanduser(
        f"~/.code_auditor/results/{tmp_path.name}/audit-output-20300102"
    )
    assert captured["config"].output_dir == expected


def test_main_keeps_explicit_output_dir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}
    explicit_output = tmp_path / "custom-output"

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
        "--output-dir",
        str(explicit_output),
    ])

    main_module.main()

    assert captured["config"].output_dir == str(explicit_output)


def test_main_records_run_in_history_db(
    _stub_history_persistence: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    async def fake_run_audit(config: AuditConfig) -> None:
        pass

    db_path = str(tmp_path / "history.db")
    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
        "--db",
        db_path,
    ])

    main_module.main()

    assert len(_stub_history_persistence) == 1
    call = _stub_history_persistence[0]
    assert call["db_path"] == db_path
    assert call["status"] == "done"
    assert call["error"] == ""
    assert call["config"].target == str(tmp_path)


def test_main_records_failed_run_in_history_db(
    _stub_history_persistence: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    async def fake_run_audit(config: AuditConfig) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
        "--db",
        str(tmp_path / "history.db"),
    ])

    with pytest.raises(SystemExit):
        main_module.main()

    assert len(_stub_history_persistence) == 1
    assert _stub_history_persistence[0]["status"] == "failed"
    assert _stub_history_persistence[0]["error"] == "boom"


def test_cli_accepts_repo_url() -> None:
    args = _build_parser().parse_args(["--repo-url", "https://github.com/u/r.git"])

    assert args.repo_url == "https://github.com/u/r.git"


def test_main_with_repo_url_clones_and_audits(
    _stub_history_persistence: list[dict],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(
        main_module, "ensure_repo_sync", lambda url: str(tmp_path)
    )
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--repo-url",
        "https://github.com/u/r.git",
        "--db",
        str(tmp_path / "history.db"),
    ])

    main_module.main()

    assert captured["config"].target == str(tmp_path)
    assert _stub_history_persistence[0]["status"] == "done"


def test_main_exits_130_on_keyboard_interrupt(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main_module._exit_after_keyboard_interrupt()

    assert exc.value.code == 130
    assert "Interrupted by user." in capsys.readouterr().err


def test_tui_mode_exits_nonzero_after_audit_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    target.mkdir()

    class FakeTUIManager:
        def configure(self, **_kwargs) -> None:  # type: ignore[no-untyped-def]
            pass

        def run_audit(self, audit_coro_factory) -> tuple[bool, bool]:  # type: ignore[no-untyped-def]
            try:
                asyncio.run(audit_coro_factory())
            except Exception:
                return True, False
            return False, False

    async def failing_run_audit(*_args, **_kwargs) -> None:  # type: ignore[no-untyped-def]
        raise RuntimeError("audit failed")

    monkeypatch.setattr(main_module, "TUIManager", FakeTUIManager)
    monkeypatch.setattr(main_module, "run_audit", failing_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--tui",
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1


def test_tui_mode_runs_audit_through_textual_manager(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    target = tmp_path / "target"
    target.mkdir()
    captured: dict[str, object] = {}

    class FakeTUIManager:
        def configure(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
            captured["configured"] = kwargs

        def run_audit(self, audit_coro_factory) -> tuple[bool, bool]:  # type: ignore[no-untyped-def]
            captured["run_audit_called"] = True
            asyncio.run(audit_coro_factory())
            return False, False

    async def fake_run_audit(config: AuditConfig, tui: FakeTUIManager | None = None) -> None:
        captured["config"] = config
        captured["tui"] = tui

    monkeypatch.setattr(main_module, "TUIManager", FakeTUIManager)
    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--tui",
    ])

    main_module.main()

    assert captured["run_audit_called"] is True
    assert isinstance(captured["config"], AuditConfig)
    assert isinstance(captured["tui"], FakeTUIManager)


def test_textual_tui_runs_audit_outside_app_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    audit_started = threading.Event()
    audit_continue = threading.Event()
    app_entered = threading.Event()

    class FakeCodeAuditorApp:
        def __init__(self, *_args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            self._exit_callback = kwargs.get("exit_callback")

        def run(self) -> None:
            app_entered.set()
            assert audit_started.wait(timeout=1.0), "audit did not start while Textual app was running"
            audit_continue.set()
            if self._exit_callback:
                self._exit_callback()

        def exit(self) -> None:
            pass

    async def blocking_audit() -> None:
        audit_started.set()
        assert app_entered.is_set()
        assert audit_continue.wait(timeout=1.0)

    monkeypatch.setattr(tui_module, "CodeAuditorApp", FakeCodeAuditorApp)

    manager = TUIManager()
    failed, interrupted = manager.run_audit(blocking_audit)

    assert failed is False
    assert interrupted is False


@pytest.mark.parametrize(
    ("backend", "config_model", "expected_model"),
    [
        ("claude", None, DEFAULT_CLAUDE_POC_MODEL),
        ("codex", None, DEFAULT_CODEX_POC_MODEL),
        ("claude", "custom-global-model", "custom-global-model"),
        ("codex", "custom-global-model", "custom-global-model"),
    ],
)
def test_select_poc_model_prefers_global_model_override(
    backend: AgentBackend,
    config_model: str | None,
    expected_model: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Isolate from the developer's real ~/.claude/settings.json.
    monkeypatch.setattr(config_module, "local_claude_model", lambda **_: None)
    monkeypatch.setattr(config_module, "local_codex_model", lambda **_: None)
    monkeypatch.setattr(config_module, "local_codex_model", lambda **_: None)
    config = AuditConfig(
        target="/tmp/project",
        output_dir="/tmp/output",
        backend=backend,
        model=config_model,
    )

    assert select_poc_model(config) == expected_model


def test_select_poc_model_prefers_local_claude_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        config_module, "local_claude_model", lambda **_: "fresh-local-model"
    )
    config = AuditConfig(
        target="/tmp/project",
        output_dir="/tmp/output",
        backend="claude",
        model="stale-stored-model",
    )

    assert select_poc_model(config) == "fresh-local-model"


def test_local_claude_model_reads_env_keys(tmp_path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        '{"env": {"ANTHROPIC_MODEL": "main-model", '
        '"ANTHROPIC_DEFAULT_OPUS_MODEL": "opus-model"}}',
        encoding="utf-8",
    )

    assert config_module.local_claude_model(str(settings)) == "main-model"
    assert (
        config_module.local_claude_model(
            str(settings), keys=("ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_MODEL")
        )
        == "opus-model"
    )


def test_local_codex_model_reads_active_profile(tmp_path: Path) -> None:
    settings = tmp_path / "config.toml"
    settings.write_text(
        'model = "top-level-model"\n'
        'profile = "review"\n'
        '[profiles.review]\n'
        'model = "profile-model"\n',
        encoding="utf-8",
    )

    assert config_module.local_codex_model(str(settings)) == "profile-model"


def test_local_codex_model_ignores_invalid_toml(tmp_path: Path) -> None:
    settings = tmp_path / "config.toml"
    settings.write_text("model = [", encoding="utf-8")

    assert config_module.local_codex_model(str(settings)) is None


def test_local_claude_model_handles_missing_or_invalid_file(tmp_path) -> None:
    assert config_module.local_claude_model(str(tmp_path / "nope.json")) is None
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    assert config_module.local_claude_model(str(bad)) is None


def test_resolve_codex_bin_prefers_path_over_legacy_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    old_codex_bin = tmp_path / "old-codex"
    old_codex_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    old_codex_bin.chmod(0o755)
    codex_bin = tmp_path / "codex"
    codex_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    codex_bin.chmod(0o755)
    monkeypatch.delenv(agent.CODEX_BIN_ENV, raising=False)
    monkeypatch.setattr(agent, "DEFAULT_CODEX_BIN", str(old_codex_bin))
    monkeypatch.setattr(agent.shutil, "which", lambda _name: str(codex_bin))

    assert agent._resolve_codex_bin() == str(codex_bin)


def test_resolve_codex_bin_honors_explicit_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    codex_bin = tmp_path / "custom-codex"
    codex_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    codex_bin.chmod(0o755)
    monkeypatch.setenv(agent.CODEX_BIN_ENV, str(codex_bin))
    monkeypatch.setattr(
        agent.shutil,
        "which",
        lambda _name: (_ for _ in ()).throw(AssertionError("PATH must not be read")),
    )

    assert agent._resolve_codex_bin() == str(codex_bin)


def test_resolve_codex_bin_falls_back_to_legacy_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    codex_bin = tmp_path / "codex"
    codex_bin.write_text("#!/bin/sh\n", encoding="utf-8")
    codex_bin.chmod(0o755)
    monkeypatch.delenv(agent.CODEX_BIN_ENV, raising=False)
    monkeypatch.setattr(agent, "DEFAULT_CODEX_BIN", str(codex_bin))
    monkeypatch.setattr(agent.shutil, "which", lambda _name: None)

    assert agent._resolve_codex_bin() == str(codex_bin)


def test_resolve_codex_bin_rejects_missing_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-codex"
    monkeypatch.delenv(agent.CODEX_BIN_ENV, raising=False)
    monkeypatch.setattr(agent, "DEFAULT_CODEX_BIN", str(missing))
    monkeypatch.setattr(agent.shutil, "which", lambda _name: None)

    with pytest.raises(RuntimeError, match="Codex CLI binary not found"):
        agent._resolve_codex_bin()


def test_run_agent_dispatches_to_codex_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        async def fake_codex_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            return "codex-result"

        async def fake_claude_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            raise AssertionError("Claude backend should not be called")

        monkeypatch.setattr(agent, "_run_codex_agent", fake_codex_agent)
        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="codex")

        assert await agent.run_agent("prompt", config, cwd="/tmp/project") == "codex-result"

    asyncio.run(run_case())


def test_run_agent_hot_switch_keeps_inflight_snapshot_and_switches_next_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_case() -> None:
        codex_started = asyncio.Event()
        release_codex = asyncio.Event()
        calls: list[tuple[str, str, str | None, str | None]] = []

        async def fake_codex_agent(_prompt, invocation, *_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            calls.append(
                (
                    invocation.backend,
                    invocation.provider_mode,
                    invocation.provider_base_url,
                    invocation.model,
                )
            )
            codex_started.set()
            await release_codex.wait()
            # The owning config changes while this call is blocked, but the
            # invocation must retain a coherent Codex provider snapshot.
            assert invocation.backend == "codex"
            assert invocation.provider_base_url == "https://codex.example.test/v1"
            assert invocation.model == "codex-model"
            return "codex-result"

        async def fake_claude_agent(_prompt, invocation, *_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            calls.append(
                (
                    invocation.backend,
                    invocation.provider_mode,
                    invocation.provider_base_url,
                    invocation.model,
                )
            )
            return "claude-result"

        monkeypatch.setattr(agent, "_run_codex_agent", fake_codex_agent)
        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)

        owner = AuditConfig(
            target="/tmp/project",
            output_dir="/tmp/output",
            backend="codex",
            model="codex-model",
            provider_mode="custom",
            provider_base_url="https://codex.example.test/v1",
            provider_api_key="codex-secret",
        )
        # Mirrors a Docker scratch config: filesystem paths are private while
        # agent settings follow the owning Web job.
        derived = AuditConfig(
            target="/tmp/scratch/source",
            output_dir="/tmp/scratch/output",
            agent_settings_source=owner,
        )

        first = asyncio.create_task(
            agent.run_agent("first", derived, cwd=derived.target)
        )
        await codex_started.wait()
        owner.backend = "claude"
        owner.model = "claude-model"
        owner.provider_mode = "custom"
        owner.provider_base_url = "https://claude.example.test/v1"
        owner.provider_api_key = "claude-secret"
        release_codex.set()

        assert await first == "codex-result"
        assert await agent.run_agent("second", derived, cwd=derived.target) == "claude-result"
        owner.backend = "codex"
        owner.model = "codex-model"
        owner.provider_base_url = "https://codex.example.test/v1"
        owner.provider_api_key = "codex-secret"
        assert await agent.run_agent("third", derived, cwd=derived.target) == "codex-result"
        assert calls == [
            ("codex", "custom", "https://codex.example.test/v1", "codex-model"),
            ("claude", "custom", "https://claude.example.test/v1", "claude-model"),
            ("codex", "custom", "https://codex.example.test/v1", "codex-model"),
        ]
        assert owner.backends_used == []
        assert derived.backends_used == ["codex", "claude"]
        assert owner.models_used == []
        assert derived.models_used == ["codex-model", "claude-model"]

    asyncio.run(run_case())


def test_sandbox_config_follows_owner_agent_settings(tmp_path: Path) -> None:
    history_changes: list[str] = []
    owner = AuditConfig(
        target="/tmp/project",
        output_dir="/tmp/output",
        backend="codex",
        agent_history_changed=lambda: history_changes.append("changed"),
    )
    scratch = object.__new__(DockerScratch)
    scratch.source_dir = tmp_path / "source"
    scratch.artifact_dir = tmp_path / "artifacts"

    derived = scratch.audit_config(owner)

    assert derived.target == str(scratch.source_dir)
    assert derived.output_dir == str(scratch.artifact_dir)
    assert derived.agent_settings_source is owner
    assert derived.agent_history_changed is owner.agent_history_changed
    assert derived.backends_used is owner.backends_used
    assert derived.models_used is owner.models_used


def test_sandbox_ensure_backend_rebuilds_metadata_and_rolls_back_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch = object.__new__(DockerScratch)
    scratch.backend = "codex"
    rebuilt: list[str] = []

    def fake_rebuild() -> None:
        rebuilt.append(scratch.backend)

    monkeypatch.setattr(scratch, "_write_spec_and_wrappers", fake_rebuild)
    scratch.ensure_backend("claude")
    assert scratch.backend == "claude"
    assert rebuilt == ["claude"]

    def fail_rebuild() -> None:
        raise RuntimeError("missing backend runtime")

    monkeypatch.setattr(scratch, "_write_spec_and_wrappers", fail_rebuild)
    with pytest.raises(RuntimeError, match="missing backend runtime"):
        scratch.ensure_backend("codex")
    assert scratch.backend == "claude"


@pytest.mark.skipif(not os.path.isdir("/proc"), reason="requires Linux procfs")
def test_run_agent_cleans_detached_descendant_after_completion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def run_case() -> None:
        child_pid: int | None = None
        child_marker: str | None = None

        async def fake_claude_agent(
            *_args,
            run_control=None,
            **_kwargs,
        ) -> str:  # type: ignore[no-untyped-def]
            nonlocal child_pid, child_marker
            assert run_control is not None
            child_code = "import time; time.sleep(60)"
            wrapper_code = (
                "import subprocess, sys; "
                "child = subprocess.Popen("
                "[sys.executable, '-c', sys.argv[1]], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
                "stderr=subprocess.DEVNULL, start_new_session=True); "
                "print(child.pid, flush=True)"
            )
            env = dict(os.environ)
            env.update(run_control.subprocess_env())
            wrapper = await asyncio.create_subprocess_exec(
                sys.executable,
                "-c",
                wrapper_code,
                child_code,
                stdout=asyncio.subprocess.PIPE,
                env=env,
            )
            output, _ = await wrapper.communicate()
            assert wrapper.returncode == 0
            child_pid = int(output)
            child_marker = run_control.process_marker
            assert agent._process_has_agent_marker(child_pid, child_marker)
            return "complete"

        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)
        config = AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path),
            backend="claude",
        )

        try:
            result = await agent.run_agent("prompt", config, cwd=str(tmp_path))
            assert result == "complete"
            assert child_pid is not None
            assert child_marker is not None
            assert not agent._process_has_agent_marker(child_pid, child_marker)
            try:
                state = Path(f"/proc/{child_pid}/stat").read_text().split()[2]
            except FileNotFoundError:
                pass
            else:
                assert state == "Z"
        finally:
            if (
                child_pid is not None
                and child_marker is not None
                and agent._process_has_agent_marker(child_pid, child_marker)
            ):
                os.kill(child_pid, signal.SIGKILL)


def test_run_agent_kills_backend_when_semantic_checker_says_finished(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def run_case() -> None:
        log_file = tmp_path / "agent.log"

        class FakeProcess:
            killed = False
            pid = 1234

            def kill(self) -> None:
                self.killed = True

        process = FakeProcess()

        async def fake_claude_agent(
            *_args,
            log_file: str | None = None,
            run_control=None,
            **_kwargs,
        ) -> str:  # type: ignore[no-untyped-def]
            assert run_control is not None
            run_control.register_process(process)
            assert log_file is not None
            Path(log_file).write_text("final analysis is already complete\n", encoding="utf-8")
            while True:
                await asyncio.sleep(1)

        async def fake_status_check(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            return agent._AgentCompletionDecision(finished=True, reason="agent already wrote a final answer")

        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)
        monkeypatch.setattr(agent, "_check_agent_log_semantically", fake_status_check)

        config = AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path),
            backend="claude",
            agent_timeout_seconds=0.01,
        )

        result = await asyncio.wait_for(
            agent.run_agent("prompt", config, cwd=str(tmp_path), log_file=str(log_file)),
            timeout=1,
        )

        assert process.killed is True
        assert result == "final analysis is already complete\n"

    asyncio.run(run_case())


def test_run_agent_runs_process_cleanup_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def run_case() -> None:
        started = asyncio.Event()
        cleaned_markers: list[str] = []

        async def fake_claude_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
            started.set()
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        async def fake_cleanup(run_control) -> None:  # type: ignore[no-untyped-def]
            cleaned_markers.append(run_control.process_marker)

        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)
        monkeypatch.setattr(agent._AgentRunControl, "cleanup_processes", fake_cleanup)
        config = AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path),
            backend="claude",
        )
        task = asyncio.create_task(
            agent.run_agent("prompt", config, cwd=str(tmp_path))
        )
        await started.wait()

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert len(cleaned_markers) == 1

    asyncio.run(run_case())


def test_run_agent_repeats_semantic_check_until_checker_says_finished(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def run_case() -> None:
        log_file = tmp_path / "agent.log"

        class FakeProcess:
            killed = False
            pid = 5678

            def kill(self) -> None:
                self.killed = True

        process = FakeProcess()
        decisions: list[str] = []

        async def fake_claude_agent(
            *_args,
            log_file: str | None = None,
            run_control=None,
            **_kwargs,
        ) -> str:  # type: ignore[no-untyped-def]
            assert run_control is not None
            run_control.register_process(process)
            assert log_file is not None
            Path(log_file).write_text("analysis still running\n", encoding="utf-8")
            while True:
                await asyncio.sleep(1)

        async def fake_status_check(*_args, **_kwargs):  # type: ignore[no-untyped-def]
            decisions.append(Path(log_file).read_text(encoding="utf-8"))
            return agent._AgentCompletionDecision(
                finished=len(decisions) == 2,
                reason="finished on second semantic check",
            )

        monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)
        monkeypatch.setattr(agent, "_check_agent_log_semantically", fake_status_check)

        config = AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path),
            backend="claude",
            agent_timeout_seconds=0.01,
        )

        await asyncio.wait_for(
            agent.run_agent("prompt", config, cwd=str(tmp_path), log_file=str(log_file)),
            timeout=1,
        )

        assert len(decisions) == 2
        assert process.killed is True

    asyncio.run(run_case())


def test_codex_backend_uses_current_openai_codex_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        captured: dict[str, object] = {}
        fake_openai_codex = types.ModuleType("openai_codex")
        fake_openai_codex_client = types.ModuleType("openai_codex.client")
        fake_openai_codex_types = types.ModuleType("openai_codex.types")

        class FakeApprovalMode(Enum):
            deny_all = "deny_all"
            auto_review = "auto_review"

        class FakeSandboxPolicy:
            @classmethod
            def model_validate(cls, value: dict[str, str]) -> dict[str, str]:
                return value

        class FakeReasoningEffort:
            def __init__(self, value: str) -> None:
                self.value = value

        class FakeAppServerConfig:
            def __init__(
                self,
                *,
                codex_bin: str,
                cwd: str,
                config_overrides: tuple[str, ...] = (),
                env: dict[str, str] | None = None,
            ) -> None:
                captured["codex_bin"] = codex_bin
                captured["cwd"] = cwd
                captured["config_overrides"] = config_overrides
                captured["env"] = env

        class FakeAppServerClient:
            pass

        class FakeDeltaPayload:
            delta = "codex-result"
            turn_id = "turn-1"

        class FakeCompletedTurn:
            id = "turn-1"
            status = types.SimpleNamespace(value="completed")
            error = None

        class FakeCompletedPayload:
            turn = FakeCompletedTurn()

        class FakeNotification:
            def __init__(self, method: str, payload: object) -> None:
                self.method = method
                self.payload = payload

        class FakeTurnHandle:
            id = "turn-1"

            async def stream(self) -> AsyncIterator[FakeNotification]:
                yield FakeNotification("item/agentMessage/delta", FakeDeltaPayload())
                yield FakeNotification("turn/completed", FakeCompletedPayload())

        class FakeThread:
            async def turn(self, prompt: str, **kwargs: object) -> FakeTurnHandle:
                captured["prompt"] = prompt
                captured["run_kwargs"] = kwargs
                captured["run_approval_mode"] = kwargs.get("approval_mode")
                captured["run_sandbox_policy"] = kwargs.get("sandbox_policy")
                return FakeTurnHandle()

        class FakeAsyncCodex:
            def __init__(self, *, config: FakeAppServerConfig) -> None:
                captured["app_server_config"] = config
                self._client = types.SimpleNamespace(_sync=types.SimpleNamespace(_proc=None))

            async def __aenter__(self) -> "FakeAsyncCodex":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def thread_start(self, **kwargs: object) -> FakeThread:
                captured["thread_start_kwargs"] = kwargs
                captured["thread_start_approval_mode"] = kwargs.get("approval_mode")
                return FakeThread()

        fake_openai_codex.AppServerConfig = FakeAppServerConfig
        fake_openai_codex.ApprovalMode = FakeApprovalMode
        fake_openai_codex.AsyncCodex = FakeAsyncCodex
        fake_openai_codex_client.AppServerClient = FakeAppServerClient
        fake_openai_codex_types.ReasoningEffort = FakeReasoningEffort
        fake_openai_codex_types.SandboxPolicy = FakeSandboxPolicy
        monkeypatch.setitem(sys.modules, "openai_codex", fake_openai_codex)
        monkeypatch.setitem(sys.modules, "openai_codex.client", fake_openai_codex_client)
        monkeypatch.setitem(sys.modules, "openai_codex.types", fake_openai_codex_types)
        monkeypatch.setattr(agent, "_resolve_codex_bin", lambda: "/tmp/codex")

        config = AuditConfig(
            target="/tmp/project",
            output_dir="/tmp/output",
            backend="codex",
            model="custom-coder",
            provider_mode="custom",
            provider_base_url="https://provider.example.test/v1",
            provider_api_key="secret-key",
        )

        assert await agent._run_codex_agent("prompt", config, cwd="/tmp/project") == "codex-result"
        overrides = captured["config_overrides"]
        assert isinstance(overrides, tuple)
        assert 'model_provider="codeauditor"' in overrides
        assert (
            'model_providers.codeauditor.base_url="https://provider.example.test/v1"'
            in overrides
        )
        assert 'model_providers.codeauditor.wire_api="responses"' in overrides
        assert "secret-key" not in "\n".join(overrides)
        codex_env = captured["env"]
        assert isinstance(codex_env, dict)
        assert codex_env["CODEAUDITOR_PROVIDER_API_KEY"] == "secret-key"
        assert agent.AGENT_PROCESS_MARKER_ENV in codex_env
        assert captured["thread_start_kwargs"]["model"] == "custom-coder"
        assert captured["thread_start_approval_mode"] is FakeApprovalMode.deny_all
        assert captured["thread_start_kwargs"]["service_tier"] == "flex"
        assert captured["run_approval_mode"] is FakeApprovalMode.deny_all
        assert captured["run_sandbox_policy"] == {"type": "dangerFullAccess"}
        assert "service_tier" not in captured["run_kwargs"]

    asyncio.run(run_case())


def test_codex_backend_requests_flex_legacy_service_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        captured: dict[str, object] = {}
        fake_codex_app_server = types.ModuleType("codex_app_server")

        class FakeTextInput:
            def __init__(self, text: str) -> None:
                self.text = text

        class FakeAskForApproval:
            @classmethod
            def model_validate(cls, value: str) -> str:
                return value

        class FakeSandboxPolicy:
            @classmethod
            def model_validate(cls, value: dict[str, str]) -> dict[str, str]:
                return value

        class FakeReasoningEffort:
            def __init__(self, value: str) -> None:
                self.value = value

        class FakeAppServerConfig:
            def __init__(
                self,
                *,
                codex_bin: str,
                cwd: str,
                config_overrides: tuple[str, ...] = (),
                env: dict[str, str] | None = None,
            ) -> None:
                captured["codex_bin"] = codex_bin
                captured["cwd"] = cwd
                captured["config_overrides"] = config_overrides
                captured["env"] = env

        class FakeAppServerClient:
            def _request_raw(self, _method: str, _params: dict[str, object] | None = None) -> dict[str, object]:
                return {}

        class FakeDeltaPayload:
            delta = "codex-result"
            turn_id = "turn-1"

        class FakeCompletedTurn:
            id = "turn-1"
            status = types.SimpleNamespace(value="completed")
            error = None

        class FakeCompletedPayload:
            turn = FakeCompletedTurn()

        class FakeNotification:
            def __init__(self, method: str, payload: object) -> None:
                self.method = method
                self.payload = payload

        class FakeTurnHandle:
            id = "turn-1"

            async def stream(self) -> AsyncIterator[FakeNotification]:
                yield FakeNotification("item/agentMessage/delta", FakeDeltaPayload())
                yield FakeNotification("turn/completed", FakeCompletedPayload())

        class FakeThread:
            async def turn(self, prompt: object, **kwargs: object) -> FakeTurnHandle:
                if isinstance(prompt, str):
                    raise TypeError(f"unsupported input item: {type(prompt)!r}")
                captured["prompt"] = prompt
                captured["run_kwargs"] = kwargs
                return FakeTurnHandle()

        class FakeAsyncCodex:
            def __init__(self, *, config: FakeAppServerConfig) -> None:
                captured["app_server_config"] = config
                self._client = types.SimpleNamespace(_sync=types.SimpleNamespace(_proc=None))

            async def __aenter__(self) -> "FakeAsyncCodex":
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def thread_start(self, **kwargs: object) -> FakeThread:
                captured["thread_start_kwargs"] = kwargs
                captured["thread_start_approval_policy"] = kwargs.get("approval_policy")
                return FakeThread()

        fake_codex_app_server.AskForApproval = FakeAskForApproval
        fake_codex_app_server.AppServerConfig = FakeAppServerConfig
        fake_codex_app_server.AppServerClient = FakeAppServerClient
        fake_codex_app_server.AsyncCodex = FakeAsyncCodex
        fake_codex_app_server.ReasoningEffort = FakeReasoningEffort
        fake_codex_app_server.SandboxPolicy = FakeSandboxPolicy
        fake_codex_app_server.TextInput = FakeTextInput
        monkeypatch.setitem(sys.modules, "openai_codex", None)
        monkeypatch.setitem(sys.modules, "openai_codex.client", None)
        monkeypatch.setitem(sys.modules, "openai_codex.types", None)
        monkeypatch.setitem(sys.modules, "codex_app_server", fake_codex_app_server)
        monkeypatch.setattr(agent, "_resolve_codex_bin", lambda: "/tmp/codex")
        monkeypatch.setattr(agent, "AGENT_MAX_RETRIES", 1)

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="codex")

        assert await agent._run_codex_agent("prompt", config, cwd="/tmp/project") == "codex-result"
        prompt = captured["prompt"]
        assert isinstance(prompt, FakeTextInput)
        assert prompt.text == "prompt"
        assert captured["config_overrides"] == ()
        assert agent.AGENT_PROCESS_MARKER_ENV in captured["env"]
        assert captured["thread_start_approval_policy"] == "never"
        assert captured["thread_start_kwargs"]["service_tier"] == "flex"
        assert "service_tier" not in captured["run_kwargs"]

    asyncio.run(run_case())


def test_codex_sdk_patch_normalizes_unsupported_service_tier_responses() -> None:
    class FakeClient:
        def _request_raw(self, _method: str, _params: dict[str, object] | None = None) -> dict[str, object]:
            return {
                "serviceTier": "priority",
                "nested": {
                    "service_tier": "default",
                    "unchanged": "priority",
                },
            }

        def request(self, method: str, params: dict[str, object] | None, *, response_model):  # type: ignore[no-untyped-def]
            return response_model.model_validate(self._request_raw(method, params))

    class FakeResponseModel:
        @classmethod
        def model_validate(cls, payload: dict[str, object]) -> dict[str, object]:
            assert payload["serviceTier"] == "flex"
            nested = payload["nested"]
            assert isinstance(nested, dict)
            assert nested["service_tier"] == "flex"
            assert nested["unchanged"] == "priority"
            return payload

    agent._patch_codex_sdk_service_tier_compat(FakeClient)

    result = FakeClient().request("thread/start", None, response_model=FakeResponseModel)

    assert result["serviceTier"] == "flex"


def test_claude_backend_keeps_claude_code_settings_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        captured: dict[str, dict[str, str | None]] = {}

        class FakeClaudeCodeOptions:
            extra_args: dict[str, str | None]

            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                self.__dict__.update(kwargs)

        async def fake_query(*, prompt: str, options: FakeClaudeCodeOptions):  # type: ignore[no-untyped-def]
            captured["extra_args"] = options.extra_args
            captured["setting_sources"] = options.setting_sources
            captured["env"] = options.env
            if False:
                yield None

        monkeypatch.setattr(agent, "_load_claude_sdk", lambda: (FakeClaudeCodeOptions, fake_query))

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="claude")

        await agent.run_agent("prompt", config, cwd="/tmp/project")

        assert "setting-sources" not in captured["extra_args"]
        assert captured["setting_sources"] == ["user", "project", "local"]
        assert agent.AGENT_PROCESS_MARKER_ENV in captured["env"]

    asyncio.run(run_case())


def test_claude_backend_injects_custom_provider_via_agent_sdk_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def run_case() -> None:
        captured: dict[str, object] = {}

        class FakeClaudeAgentOptions:
            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                captured.update(kwargs)

        async def fake_query(*, prompt: str, options: FakeClaudeAgentOptions):  # type: ignore[no-untyped-def]
            if False:
                yield prompt, options

        monkeypatch.setattr(
            agent,
            "_load_claude_sdk",
            lambda: (FakeClaudeAgentOptions, fake_query),
        )
        config = AuditConfig(
            target="/tmp/project",
            output_dir="/tmp/output",
            backend="claude",
            model="claude-compatible-model",
            provider_mode="custom",
            provider_base_url="https://claude.example.test",
            provider_api_key="secret-key",
        )

        await agent.run_agent("prompt", config, cwd="/tmp/project")

        assert captured["model"] == "claude-compatible-model"
        assert captured["setting_sources"] == []
        claude_env = captured["env"]
        assert isinstance(claude_env, dict)
        assert claude_env["ANTHROPIC_BASE_URL"] == "https://claude.example.test"
        assert claude_env["ANTHROPIC_AUTH_TOKEN"] == "secret-key"
        assert agent.AGENT_PROCESS_MARKER_ENV in claude_env

    asyncio.run(run_case())


def test_claude_backend_streams_bounded_tool_activity_to_logs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def run_case() -> None:
        class FakeClaudeCodeOptions:
            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                self.__dict__.update(kwargs)

        class SystemMessage:
            subtype = "init"

        class ToolUseBlock:
            id = "tool-1"
            name = "Edit"
            input = {
                "file_path": "/tmp/project/src/a.c",
                "new_string": "secret file contents must not be logged",
            }

        class ToolResultBlock:
            tool_use_id = "tool-1"
            is_error = False

        class TextBlock:
            text = "Finished reviewing the affected path."

        class AssistantMessage:
            def __init__(self, content: list[object]) -> None:
                self.content = content

        class UserMessage:
            def __init__(self, content: list[object]) -> None:
                self.content = content

        class ResultMessage:
            num_turns = 3
            duration_ms = 2500
            is_error = False

        async def fake_query(*, prompt: str, options: FakeClaudeCodeOptions):  # type: ignore[no-untyped-def]
            yield SystemMessage()
            yield AssistantMessage([ToolUseBlock()])
            yield UserMessage([ToolResultBlock()])
            yield AssistantMessage([TextBlock()])
            yield ResultMessage()

        monkeypatch.setattr(
            agent,
            "_load_claude_sdk",
            lambda: (FakeClaudeCodeOptions, fake_query),
        )
        config = AuditConfig(
            target="/tmp/project",
            output_dir=str(tmp_path),
            backend="claude",
        )
        log_file = tmp_path / "agent.log"

        with caplog.at_level(logging.DEBUG, logger="code_auditor.agent"):
            result = await agent._run_claude_agent(
                "prompt",
                config,
                cwd="/tmp/project",
                log_file=str(log_file),
            )

        assert result == "Finished reviewing the affected path."
        persisted = log_file.read_text(encoding="utf-8")
        assert "[activity] Session event: init" in persisted
        assert "Started Edit: file_path=/tmp/project/src/a.c" in persisted
        assert "Edit completed" in persisted
        assert "Finished reviewing the affected path." in persisted
        assert "secret file contents" not in persisted
        web_messages = "\n".join(record.getMessage() for record in caplog.records)
        assert "Agent: Started Edit" in web_messages
        assert "Agent: Edit completed" in web_messages
        assert "Agent: Response: Finished reviewing" in web_messages
        assert "Agent result complete turns=3 duration=2.5s" in web_messages
        # Agent activity is DEBUG-only: INFO stays at stage-level milestones.
        assert all(record.levelno < logging.INFO for record in caplog.records)

    asyncio.run(run_case())


def test_claude_backend_records_result_usage_stats(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def run_case() -> None:
        class FakeClaudeCodeOptions:
            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                self.__dict__.update(kwargs)

        class TextBlock:
            text = "done"

        class AssistantMessage:
            content = [TextBlock()]

        class ResultMessage:
            num_turns = 1
            duration_ms = 100
            is_error = False
            usage = {
                "input_tokens": 1200,
                "output_tokens": 300,
                "cache_read_input_tokens": 5000,
            }
            total_cost_usd = 0.042

        async def fake_query(*, prompt: str, options: FakeClaudeCodeOptions):  # type: ignore[no-untyped-def]
            yield AssistantMessage()
            yield ResultMessage()

        monkeypatch.setattr(
            agent,
            "_load_claude_sdk",
            lambda: (FakeClaudeCodeOptions, fake_query),
        )
        config = AuditConfig(
            target="/tmp/project",
            output_dir=str(tmp_path),
            backend="claude",
        )

        result = await agent._run_claude_agent("prompt", config, cwd="/tmp/project")

        assert result == "done"
        assert config.usage_stats == {
            "agent_calls": 1,
            "input_tokens": 1200,
            "output_tokens": 300,
            "cache_read_input_tokens": 5000,
            "cost_usd": 0.042,
        }

    asyncio.run(run_case())


def test_claude_backend_rate_limits_thinking_token_events(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def run_case() -> None:
        class FakeClaudeCodeOptions:
            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                self.__dict__.update(kwargs)

        class SystemMessage:
            subtype = "thinking_tokens"

        class TextBlock:
            text = "Analysis complete."

        class AssistantMessage:
            content = [TextBlock()]

        class ResultMessage:
            num_turns = 1
            duration_ms = 100
            is_error = False

        async def fake_query(*, prompt: str, options: FakeClaudeCodeOptions):  # type: ignore[no-untyped-def]
            for _ in range(20_000):
                yield SystemMessage()
            yield AssistantMessage()
            yield ResultMessage()

        monkeypatch.setattr(
            agent,
            "_load_claude_sdk",
            lambda: (FakeClaudeCodeOptions, fake_query),
        )
        config = AuditConfig(
            target="/tmp/project",
            output_dir=str(tmp_path),
            backend="claude",
        )
        log_file = tmp_path / "agent.log"

        with caplog.at_level(logging.DEBUG, logger="code_auditor.agent"):
            result = await agent._run_claude_agent(
                "prompt",
                config,
                cwd="/tmp/project",
                log_file=str(log_file),
            )

        assert result == "Analysis complete."
        persisted = log_file.read_text(encoding="utf-8")
        assert persisted.count("Reasoning in progress") == 1
        assert "thinking_tokens" not in persisted
        web_messages = "\n".join(record.getMessage() for record in caplog.records)
        assert web_messages.count("Agent: Reasoning in progress") == 1

    asyncio.run(run_case())


def test_codex_activity_summary_tracks_command_lifecycle() -> None:
    payload = types.SimpleNamespace(
        item=types.SimpleNamespace(type="commandExecution", command="rg -n sink src")
    )

    assert agent._codex_item_activity("item/started", payload) == (
        "Started command: rg -n sink src"
    )
    assert agent._codex_item_activity("item/completed", payload) == (
        "Completed command: rg -n sink src"
    )
    assert agent._codex_item_activity("item/agentMessage/delta", payload) is None


def test_project_declares_textual_tui_dependencies() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert '"textual>=0.50"' in pyproject
    assert '"rich>=13.0"' in pyproject


def test_tui_backend_is_textual_app() -> None:
    from textual.app import App

    assert tui_module.TUI_BACKEND == "textual"
    assert issubclass(tui_module.CodeAuditorApp, App)


def test_tui_configure_does_not_display_discovered_path() -> None:
    manager = TUIManager()

    manager.configure(
        target="/tmp/project",
        output_dir="/tmp/output",
        wiki_path=None,
        backend="claude",
        model=None,
        max_parallel=1,
    )

    console = logger_module.Console(record=True, force_terminal=False, color_system=None, width=120)
    console.print(_make_config_table(manager._state))
    rendered = console.export_text(styles=False)

    assert "Discovered" not in rendered
    assert "reproduced-bugs" not in rendered


def _render_stage_panel(state: TUIState, *, width: int = 100) -> str:
    console = logger_module.Console(
        record=True,
        file=io.StringIO(),
        force_terminal=False,
        color_system=None,
        width=width,
    )
    console.print(tui_module._make_stage_panel(state))
    return console.export_text(styles=False)


def test_tui_progress_bars_stay_aligned_for_short_counts() -> None:
    state = TUIState(stages={
        2: tui_module._StageState(status="done", items_done=24, items_total=24),
        3: tui_module._StageState(status="running", items_done=8, items_total=18),
    })

    rendered = _render_stage_panel(state)
    complete_line = next(line for line in rendered.splitlines() if "24/24" in line)
    partial_line = next(line for line in rendered.splitlines() if "8/18" in line)

    complete_bar_start = min(index for index, char in enumerate(complete_line) if char in "█░")
    partial_bar_start = min(index for index, char in enumerate(partial_line) if char in "█░")
    assert partial_bar_start == complete_bar_start


def test_tui_progress_column_expands_for_wide_counts() -> None:
    state = TUIState(stages={
        2: tui_module._StageState(status="done", items_done=100, items_total=100),
        3: tui_module._StageState(status="running", items_done=8, items_total=100),
    })

    rendered = _render_stage_panel(state)

    assert any("████████ 100/100" in line for line in rendered.splitlines())
    assert any("░░░░░░░░   8/100" in line for line in rendered.splitlines())


def test_tui_log_handler_splits_multiline_records_into_scrollable_rows() -> None:
    state = TUIState(max_log_lines=2, max_log_history=10)
    handler = _TUILogHandler(state)

    handler.emit(logging.LogRecord(
        name="code_auditor.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=0,
        msg="first row\nsecond row\nthird row",
        args=(),
        exc_info=None,
    ))

    assert len(state.log_lines) == 3
    assert "first row" in state.log_lines[0].plain
    assert state.log_lines[1].plain == "second row"
    assert state.log_lines[2].plain == "third row"
    assert [line.plain for line in _visible_log_lines(state)] == ["second row", "third row"]


def test_tui_start_replaces_normal_console_log_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    root_logger = logging.getLogger("code_auditor")
    root_logger.handlers.clear()
    logger_module.configure_logging("INFO")
    manager = TUIManager()

    monkeypatch.setattr(manager, "_start_live", lambda: None)
    monkeypatch.setattr(manager, "_start_keyboard_listener", lambda: None)

    try:
        manager.start()

        assert any(isinstance(handler, _TUILogHandler) for handler in root_logger.handlers)
        assert not any(isinstance(handler, logger_module._ConsoleLogHandler) for handler in root_logger.handlers)
    finally:
        manager.stop()


def test_tui_wait_for_exit_returns_without_keyboard_listener() -> None:
    manager = TUIManager()
    worker = threading.Thread(target=manager.wait_for_exit)

    worker.start()
    worker.join(timeout=0.2)
    try:
        assert not worker.is_alive()
    finally:
        manager._stop_keyboard.set()
        worker.join(timeout=1.0)


def test_tui_exit_key_requests_exit() -> None:
    manager = TUIManager()

    prefix = manager._handle_keyboard_char("q", prefix=False)

    assert prefix is False
    assert manager._exit_requested is True
    assert manager._stop_keyboard.is_set()


def test_tui_ctrl_c_interrupts_main_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = TUIManager()
    interrupted = False

    def fake_interrupt_main() -> None:
        nonlocal interrupted
        interrupted = True

    monkeypatch.setattr(manager, "_interrupt_main", fake_interrupt_main)

    manager._handle_keyboard_char("\x03", prefix=False)

    assert interrupted is True
