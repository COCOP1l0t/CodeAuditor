from __future__ import annotations

import os
from enum import Enum
from types import SimpleNamespace

import pytest

from code_auditor.agent import _get_backend
from code_auditor.agent_backends.codex import (
    CodexTurnFailedError,
    _is_retryable_codex_error,
    _sandbox_policy_payload,
    _turn_completed_state,
)
from code_auditor.config import AuditConfig


def test_unknown_agent_backend_rejected():
    config = AuditConfig(
        target="/tmp/target",
        output_dir="/tmp/output",
        agent_backend="unknown",
    )

    with pytest.raises(ValueError, match="Unsupported agent backend"):
        _get_backend(config)


def test_codex_workspace_write_policy_includes_target_output_and_extra_roots():
    config = AuditConfig(
        target="/tmp/target",
        output_dir="/tmp/output",
        agent_backend="codex",
        codex_extra_writable_roots=["/tmp/output", "/tmp/extra"],
    )

    policy = _sandbox_policy_payload(config, "/tmp/target")

    assert policy["type"] == "workspaceWrite"
    assert policy["networkAccess"] is False
    assert policy["writableRoots"] == [
        os.path.realpath("/tmp/target"),
        os.path.realpath("/tmp/output"),
        os.path.realpath("/tmp/extra"),
    ]


def test_codex_danger_full_access_policy():
    config = AuditConfig(
        target="/tmp/target",
        output_dir="/tmp/output",
        agent_backend="codex",
        codex_sandbox="danger-full-access",
    )

    assert _sandbox_policy_payload(config, "/tmp/target") == {"type": "dangerFullAccess"}


def test_codex_turn_completed_state_reads_success_status():
    class Status(Enum):
        completed = "completed"

    event = SimpleNamespace(
        method="turn/completed",
        payload=SimpleNamespace(turn=SimpleNamespace(status=Status.completed, error=None)),
    )

    assert _turn_completed_state(event) == ("completed", None)


def test_codex_turn_completed_state_reads_failed_error():
    event = SimpleNamespace(
        method="turn/completed",
        payload=SimpleNamespace(
            turn=SimpleNamespace(
                status="failed",
                error=SimpleNamespace(message="stream disconnected before completion"),
            ),
        ),
    )

    status, error = _turn_completed_state(event)

    assert status == "failed"
    assert "stream disconnected" in error


def test_codex_network_turn_failure_is_retryable():
    exc = CodexTurnFailedError(
        "Codex turn ended with status failed: stream disconnected before completion: "
        "error sending request for url"
    )

    assert _is_retryable_codex_error(exc)
