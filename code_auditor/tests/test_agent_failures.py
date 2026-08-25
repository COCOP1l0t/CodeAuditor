from __future__ import annotations

import asyncio
import json

from code_auditor.agent import _codex_usage_dict, _is_non_retryable_agent_error
from code_auditor.checkpoint import CheckpointManager
from code_auditor.config import AuditConfig
from code_auditor.stages import stage5
from code_auditor.utils import (
    record_agent_usage,
    sanitize_task_error_text,
    summarize_task_errors,
)


def test_quota_exhaustion_is_non_retryable() -> None:
    exc = RuntimeError(
        "API Error: Request rejected (429) · you have no left credit for step plan"
    )
    assert _is_non_retryable_agent_error(exc)


def test_auth_error_is_non_retryable() -> None:
    assert _is_non_retryable_agent_error(RuntimeError("HTTP 401: invalid API key"))


def test_transient_error_is_retryable() -> None:
    assert not _is_non_retryable_agent_error(
        RuntimeError("Connection reset by peer")
    )


def test_unknown_model_error_is_non_retryable() -> None:
    exc = RuntimeError(
        "API Error: 400 The supported API model names are deepseek-v4-pro or "
        "deepseek-v4-flash, but you passed step-3.7-flash."
    )
    assert _is_non_retryable_agent_error(exc)


def test_sanitize_task_error_text_strips_sdk_debug_lines() -> None:
    raw = (
        "Command failed with exit code 1 (exit code: 1)\n"
        "Error output: Check stderr output for details — stderr:\n"
        "2026-08-08T13:48:08.035Z [DEBUG] MDM settings load completed in 0ms\n"
        "2026-08-08T13:48:08.066Z [DEBUG] more debug noise\n"
        "API Error: 400 The supported API model names are deepseek-v4-pro"
    )
    cleaned = sanitize_task_error_text(raw)
    assert "MDM settings" not in cleaned
    assert "debug noise" not in cleaned
    assert "API Error: 400" in cleaned


def test_stage5_agent_failure_is_recorded_and_not_checkpointed(
    tmp_path, monkeypatch
) -> None:
    out = tmp_path / "out"
    vulns = out / "stage4-vulnerabilities"
    vulns.mkdir(parents=True)
    vuln_file = vulns / "H-03.json"
    vuln_file.write_text(
        json.dumps({"id": "H-03", "title": "Some vuln"}), encoding="utf-8"
    )

    async def boom(*args, **kwargs):
        raise RuntimeError("API Error: no left credit")

    monkeypatch.setattr(stage5, "run_agent", boom)
    config = AuditConfig(
        target=str(tmp_path),
        output_dir=str(out),
        sandbox_enabled=False,
    )
    checkpoint = CheckpointManager(str(out), resume=True)

    reports = asyncio.run(stage5.run_stage5([str(vuln_file)], config, checkpoint))

    assert reports == []
    assert len(config.task_errors) == 1
    assert config.task_errors[0].startswith("stage5:H-03:")
    # No marker: a resumed run must retry the failed PoC task.
    assert not checkpoint.is_complete("stage5:H-03")


def test_summarize_task_errors() -> None:
    assert summarize_task_errors([]) == ""
    summary = summarize_task_errors(
        ["stage5:H-03: API Error: 429", "stage6:C-02: API Error: 429"]
    )
    assert summary.startswith("2 agent task(s) failed: stage5:H-03, stage6:C-02")
    assert "First error: stage5:H-03:" in summary


def test_record_agent_usage_accumulates_claude_style() -> None:
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/out")

    record_agent_usage(
        config,
        {
            "input_tokens": 1000,
            "output_tokens": 200,
            "cache_creation_input_tokens": 300,
            "cache_read_input_tokens": 4000,
            "service_tier": "standard",
        },
        0.5,
    )
    record_agent_usage(config, {"input_tokens": 500, "output_tokens": 50}, 0.25)

    assert config.usage_stats == {
        "agent_calls": 2,
        "input_tokens": 1500,
        "output_tokens": 250,
        "cache_creation_input_tokens": 300,
        "cache_read_input_tokens": 4000,
        "cost_usd": 0.75,
    }


def test_record_agent_usage_accepts_codex_camel_case() -> None:
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/out")

    record_agent_usage(
        config,
        {"inputTokens": 800, "outputTokens": 100, "cachedInputTokens": 6000},
        None,
    )

    assert config.usage_stats["input_tokens"] == 800
    assert config.usage_stats["output_tokens"] == 100
    assert config.usage_stats["cache_read_input_tokens"] == 6000
    assert "cost_usd" not in config.usage_stats


def test_record_agent_usage_tolerates_missing_usage() -> None:
    config = AuditConfig(target="/tmp/project", output_dir="/tmp/out")

    record_agent_usage(config, None, None)

    assert config.usage_stats == {"agent_calls": 1}


def test_codex_usage_dict_unwraps_total_breakdown() -> None:
    payload = {
        "tokenUsage": {
            "last": {"inputTokens": 1, "outputTokens": 2},
            "total": {"inputTokens": 10, "outputTokens": 20},
        }
    }
    assert _codex_usage_dict(payload) == {"inputTokens": 10, "outputTokens": 20}


def test_codex_usage_dict_reads_object_attributes() -> None:
    class Breakdown:
        inputTokens = 7
        outputTokens = 3
        cachedInputTokens = 9
        totalTokens = None
        reasoningOutputTokens = None

    assert _codex_usage_dict(Breakdown()) == {
        "inputTokens": 7,
        "outputTokens": 3,
        "cachedInputTokens": 9,
    }
    assert _codex_usage_dict(None) is None
