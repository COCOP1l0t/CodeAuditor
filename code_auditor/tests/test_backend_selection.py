from __future__ import annotations

import asyncio
import logging
import sys
import threading
import types
from enum import Enum
from pathlib import Path

import pytest

from code_auditor import __main__ as main_module
from code_auditor import agent
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
from code_auditor.tui import TUIManager, TUIState, _TUILogHandler, _make_config_table, _visible_log_lines


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


def test_cli_accepts_discovered_path() -> None:
    args = _build_parser().parse_args([
        "--target",
        ".",
        "--discovered",
        "/tmp/bugs.html",
    ])

    assert args.discovered == "/tmp/bugs.html"


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


def test_main_maps_omitted_discovered_to_target_reproduced_bugs_html(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}
    target = tmp_path / "target"
    target.mkdir()

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
    ])

    main_module.main()

    assert captured["config"].discovered_path == str((target / "reproduced-bugs.html").resolve())


def test_main_maps_explicit_discovered_to_resolved_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}
    target = tmp_path / "target"
    discovered = tmp_path / "missing-parent" / "bugs.html"
    target.mkdir()

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--discovered",
        str(discovered),
    ])

    main_module.main()

    assert captured["config"].discovered_path == str(discovered.resolve())


def test_main_rejects_existing_directory_as_discovered_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = tmp_path / "target"
    discovered = tmp_path / "discovered-dir"
    target.mkdir()
    discovered.mkdir()

    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(target),
        "--discovered",
        str(discovered),
    ])

    with pytest.raises(SystemExit) as exc:
        main_module.main()

    assert exc.value.code == 1
    assert capsys.readouterr().err == f"Error: Discovered path is a directory: {discovered.resolve()}\n"


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


def test_main_disables_timeout_by_default(
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

    assert captured["config"].agent_timeout_seconds is None


def test_main_defaults_output_dir_to_local_dated_audit_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, AuditConfig] = {}

    class FakeDate:
        @classmethod
        def today(cls):  # type: ignore[no-untyped-def]
            return cls()

        def strftime(self, _format: str) -> str:
            return "20300102"

    async def fake_run_audit(config: AuditConfig) -> None:
        captured["config"] = config

    monkeypatch.setattr(main_module, "date", FakeDate, raising=False)
    monkeypatch.setattr(main_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(sys, "argv", [
        "code-auditor",
        "--target",
        str(tmp_path),
    ])

    main_module.main()

    assert captured["config"].output_dir == str(tmp_path / "audit-output-20300102")


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


def test_main_maps_enable_timeout_to_config(
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
        "--enable-timeout",
    ])

    main_module.main()

    assert captured["config"].agent_timeout_seconds == DEFAULT_AGENT_TIMEOUT_SECONDS


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
) -> None:
    config = AuditConfig(
        target="/tmp/project",
        output_dir="/tmp/output",
        backend=backend,
        model=config_model,
    )

    assert select_poc_model(config) == expected_model


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
            ) -> None:
                captured["codex_bin"] = codex_bin
                captured["cwd"] = cwd
                captured["config_overrides"] = config_overrides

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
                captured["run_approval_mode"] = kwargs.get("approval_mode")
                captured["run_sandbox_policy"] = kwargs.get("sandbox_policy")
                captured["run_service_tier"] = kwargs.get("service_tier")
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
                captured["thread_start_approval_mode"] = kwargs.get("approval_mode")
                captured["thread_start_service_tier"] = kwargs.get("service_tier")
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

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="codex")

        assert await agent._run_codex_agent("prompt", config, cwd="/tmp/project") == "codex-result"
        assert captured["config_overrides"] == ('service_tier="fast"',)
        assert captured["thread_start_approval_mode"] is FakeApprovalMode.deny_all
        assert captured["thread_start_service_tier"] == "fast"
        assert captured["run_approval_mode"] is FakeApprovalMode.deny_all
        assert captured["run_sandbox_policy"] == {"type": "dangerFullAccess"}
        assert captured["run_service_tier"] == "fast"

    asyncio.run(run_case())


def test_codex_backend_forces_supported_legacy_service_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        captured: dict[str, object] = {}
        fake_codex_app_server = types.ModuleType("codex_app_server")

        class FakeServiceTier(Enum):
            fast = "fast"
            flex = "flex"

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
            ) -> None:
                captured["codex_bin"] = codex_bin
                captured["cwd"] = cwd
                captured["config_overrides"] = config_overrides

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
            async def turn(self, prompt: str, **kwargs: object) -> FakeTurnHandle:
                captured["prompt"] = prompt
                captured["run_service_tier"] = kwargs.get("service_tier")
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
                captured["thread_start_approval_policy"] = kwargs.get("approval_policy")
                captured["thread_start_service_tier"] = kwargs.get("service_tier")
                return FakeThread()

        fake_codex_app_server.AskForApproval = FakeAskForApproval
        fake_codex_app_server.AppServerConfig = FakeAppServerConfig
        fake_codex_app_server.AppServerClient = FakeAppServerClient
        fake_codex_app_server.AsyncCodex = FakeAsyncCodex
        fake_codex_app_server.ReasoningEffort = FakeReasoningEffort
        fake_codex_app_server.SandboxPolicy = FakeSandboxPolicy
        fake_codex_app_server.ServiceTier = FakeServiceTier
        monkeypatch.setitem(sys.modules, "openai_codex", None)
        monkeypatch.setitem(sys.modules, "openai_codex.client", None)
        monkeypatch.setitem(sys.modules, "openai_codex.types", None)
        monkeypatch.setitem(sys.modules, "codex_app_server", fake_codex_app_server)
        monkeypatch.setattr(agent, "_resolve_codex_bin", lambda: "/tmp/codex")

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="codex")

        assert await agent._run_codex_agent("prompt", config, cwd="/tmp/project") == "codex-result"
        assert captured["config_overrides"] == ('service_tier="fast"',)
        assert captured["thread_start_approval_policy"] == "never"
        assert captured["thread_start_service_tier"] is FakeServiceTier.fast
        assert captured["run_service_tier"] is FakeServiceTier.fast

    asyncio.run(run_case())


def test_codex_sdk_patch_normalizes_priority_service_tier_responses() -> None:
    class FakeClient:
        def _request_raw(self, _method: str, _params: dict[str, object] | None = None) -> dict[str, object]:
            return {
                "serviceTier": "priority",
                "nested": {
                    "service_tier": "priority",
                    "unchanged": "priority",
                },
            }

        def request(self, method: str, params: dict[str, object] | None, *, response_model):  # type: ignore[no-untyped-def]
            return response_model.model_validate(self._request_raw(method, params))

    class FakeResponseModel:
        @classmethod
        def model_validate(cls, payload: dict[str, object]) -> dict[str, object]:
            assert payload["serviceTier"] == "fast"
            nested = payload["nested"]
            assert isinstance(nested, dict)
            assert nested["service_tier"] == "fast"
            assert nested["unchanged"] == "priority"
            return payload

    agent._patch_codex_sdk_service_tier_compat(FakeClient)

    result = FakeClient().request("thread/start", None, response_model=FakeResponseModel)

    assert result["serviceTier"] == "fast"


def test_claude_backend_keeps_claude_code_settings_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    async def run_case() -> None:
        captured: dict[str, dict[str, str | None]] = {}

        class FakeClaudeCodeOptions:
            extra_args: dict[str, str | None]

            def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
                self.__dict__.update(kwargs)

        async def fake_query(*, prompt: str, options: FakeClaudeCodeOptions):  # type: ignore[no-untyped-def]
            captured["extra_args"] = options.extra_args
            if False:
                yield None

        monkeypatch.setattr(agent, "_load_claude_sdk", lambda: (FakeClaudeCodeOptions, fake_query))

        config = AuditConfig(target="/tmp/project", output_dir="/tmp/output", backend="claude")

        await agent.run_agent("prompt", config, cwd="/tmp/project")

        assert "setting-sources" not in captured["extra_args"]

    asyncio.run(run_case())


def test_project_declares_textual_tui_dependencies() -> None:
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

    assert '"textual>=0.50"' in pyproject
    assert '"rich>=13.0"' in pyproject


def test_tui_backend_is_textual_app() -> None:
    from textual.app import App

    assert tui_module.TUI_BACKEND == "textual"
    assert issubclass(tui_module.CodeAuditorApp, App)


def test_tui_configure_displays_discovered_path() -> None:
    manager = TUIManager()
    discovered_path = "/tmp/project/reproduced-bugs.html"

    manager.configure(
        target="/tmp/project",
        output_dir="/tmp/output",
        discovered_path=discovered_path,
        wiki_path=None,
        backend="claude",
        model=None,
        max_parallel=1,
    )

    console = logger_module.Console(record=True, force_terminal=False, color_system=None, width=120)
    console.print(_make_config_table(manager._state))
    rendered = console.export_text(styles=False)

    assert "Discovered" in rendered
    assert discovered_path in rendered


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
