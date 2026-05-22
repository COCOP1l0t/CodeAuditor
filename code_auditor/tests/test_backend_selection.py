from __future__ import annotations

import asyncio
import logging
import sys
import threading
from pathlib import Path

import pytest

from code_auditor import __main__ as main_module
from code_auditor import agent
from code_auditor import logger as logger_module
from code_auditor import tui as tui_module
from code_auditor.__main__ import _build_parser
from code_auditor.config import DEFAULT_BACKEND, AuditConfig
from code_auditor.tui import TUIManager, TUIState, _TUILogHandler, _visible_log_lines


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


def test_cli_accepts_tui_flag() -> None:
    args = _build_parser().parse_args(["--target", ".", "--tui"])

    assert args.tui is True


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
    assert captured["configured"] == {
        "target": str(target.resolve()),
        "output_dir": str((target / "audit-output").resolve()),
        "backend": "claude",
        "model": None,
        "max_parallel": 1,
    }


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


def test_project_declares_textual_tui_dependencies() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert '"textual>=0.50"' in pyproject
    assert '"rich>=13.0"' in pyproject
    assert '"click>=8.1"' not in pyproject


def test_tui_backend_is_textual_app() -> None:
    from textual.app import App

    assert tui_module.TUI_BACKEND == "textual"
    assert issubclass(tui_module.CodeAuditorApp, App)


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


def test_resolve_codex_bin_uses_default_path(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    codex_bin = tmp_path / "codex"
    codex_bin.write_text("#!/bin/sh\n")
    codex_bin.chmod(0o755)
    monkeypatch.setattr(agent, "DEFAULT_CODEX_BIN", str(codex_bin))

    assert agent._resolve_codex_bin() == str(codex_bin)


def test_resolve_codex_bin_rejects_missing_default(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    missing = tmp_path / "missing-codex"
    monkeypatch.setattr(agent, "DEFAULT_CODEX_BIN", str(missing))

    with pytest.raises(RuntimeError, match="Codex CLI binary not found"):
        agent._resolve_codex_bin()


async def test_run_agent_dispatches_to_codex_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake_codex_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
        return "codex-result"

    async def fake_claude_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
        raise AssertionError("Claude backend should not be called")

    monkeypatch.setattr(agent, "_run_codex_agent", fake_codex_agent)
    monkeypatch.setattr(agent, "_run_claude_agent", fake_claude_agent)

    config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="codex")

    assert await agent.run_agent("prompt", config, cwd="/tmp/project") == "codex-result"
