from __future__ import annotations

import pytest

from code_auditor import agent
from code_auditor.__main__ import _build_parser
from code_auditor.config import DEFAULT_BACKEND, AuditConfig


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
