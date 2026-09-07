from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest

from code_auditor import agent, sandbox
from code_auditor.config import AuditConfig
from code_auditor.sandbox_records import (
    create_execution_directory, list_sandbox_executions,
    read_execution_records, write_execution_record,
)

IMAGE_ID = "sha256:" + "a" * 64


@pytest.mark.parametrize("requested,default,expected", [
    ("docker-default", "runsc", "runsc"),
    ("runc", "runsc", "runc"),
    ("runsc", "runc", "runsc"),
])
def test_runtime_is_resolved_and_image_is_pinned(monkeypatch, requested, default, expected):
    scratch = sandbox.DockerScratch(AuditConfig(".", ".", sandbox_runtime=requested), "test")

    def checked(command, **_kwargs):
        if command[1] == "info":
            return json.dumps({"DefaultRuntime": default, "Runtimes": {"runc": {}, "runsc": {}},
                               "ServerVersion": "test-version"})
        assert command[1:3] == ["image", "inspect"]
        return json.dumps([{"Id": IMAGE_ID}])

    monkeypatch.setattr(sandbox, "_run_checked", checked)
    scratch._verify_runtime()
    assert scratch.runtime == expected
    assert scratch.image_id == IMAGE_ID
    assert scratch.server_version == "test-version"


def test_missing_runtime_fails_without_falling_back(monkeypatch):
    scratch = sandbox.DockerScratch(AuditConfig(".", ".", sandbox_runtime="runsc"), "test")
    calls = []

    def checked(command, **_kwargs):
        calls.append(command)
        return json.dumps({"DefaultRuntime": "runc", "Runtimes": {"runc": {}}})

    monkeypatch.setattr(sandbox, "_run_checked", checked)
    with pytest.raises(sandbox.DockerSandboxError, match="not registered"):
        scratch._verify_runtime()
    assert len(calls) == 1


def _spec(tmp_path):
    root = tmp_path / "scratch"
    root.mkdir()
    source = root / "source"
    source.mkdir()
    directory = create_execution_directory(str(tmp_path / "output"), uuid4().hex)
    spec = {
        "schema_version": 2, "docker_bin": "docker", "image": "image:mutable",
        "image_id": IMAGE_ID, "scratch_root": str(root), "scratch_id": directory.name,
        "home": str(root / "home"), "uid": os.getuid(), "gid": os.getgid(),
        "network_enabled": False, "pids_limit": 64, "memory": "256m", "cpus": "1",
        "claude_cli": "/test-cli", "codex_vendor": "/test-vendor", "readonly_mounts": [],
        "requested_runtime": "runsc", "runtime": "runsc", "task_name": "stage5-test",
        "execution_dir": str(directory), "source_commit": "b" * 40,
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    environ = {sandbox.DOCKER_SPEC_ENV: str(spec_path), sandbox.DOCKER_CWD_ENV: str(source),
               "CODE_AUDITOR_AGENT_RUN_ID": "main"}
    return spec, environ


@pytest.mark.parametrize("mismatch", [None, "runtime", "image"])
def test_supervisor_verifies_before_start_and_records_exit(tmp_path, monkeypatch, mismatch):
    spec, environ = _spec(tmp_path)
    monkeypatch.setenv("CODE_AUDITOR_AGENT_RUN_ID", "main")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-recorded")
    command = sandbox.docker_cli_command("claude", ["--version"], environ)
    assert command[command.index("--runtime") + 1] == "runsc"
    assert IMAGE_ID in command and "image:mutable" not in command
    events = []

    def checked(args, **_kwargs):
        events.append(args[1])
        if args[1] == "create":
            assert "--rm" not in args
            return "c" * 64
        assert args[1] == "inspect"
        return json.dumps([{
            "HostConfig": {"Runtime": "runc" if mismatch == "runtime" else "runsc"},
            "Image": "other" if mismatch == "image" else IMAGE_ID,
            "Config": {"Env": ["OPENAI_API_KEY=must-not-be-recorded"]},
            "State": {"Status": "exited", "ExitCode": 7, "OOMKilled": False},
        }])

    class Attached:
        def __init__(self, args):
            assert args[1:4] == ["start", "--attach", "--interactive"]
            events.append("start")

        def wait(self):
            return 7

        def poll(self):
            return 7

    monkeypatch.setattr(sandbox, "_run_checked", checked)
    monkeypatch.setattr(sandbox.subprocess, "Popen", Attached)
    monkeypatch.setattr(sandbox, "_remove_named_container", lambda *args: events.append("cleanup"))
    code = sandbox._supervise_container(command, spec, "claude")
    assert code == (125 if mismatch else 7)
    if mismatch:
        assert "start" not in events
    else:
        assert events == ["create", "inspect", "start", "inspect", "cleanup"]
    records = read_execution_records(Path(spec["execution_dir"]))
    assert len(records) == 1
    assert records[0]["state"] == ("failed" if mismatch else "exited")
    assert records[0]["exit_code"] == (None if mismatch else 7)
    assert records[0]["cleanup"] == "verified"
    assert "must-not-be-recorded" not in json.dumps(records)


def test_invocation_cleanup_keeps_other_invocations(tmp_path, monkeypatch):
    spec, _ = _spec(tmp_path)
    scratch = sandbox.DockerScratch(AuditConfig(".", "."), "test")
    scratch.execution_dir = Path(spec["execution_dir"])
    for marker in ("main", "checker"):
        write_execution_record(scratch.execution_dir, {
            "schema_version": 1, "execution_id": uuid4().hex, "agent_run_id": marker,
            "state": "starting", "exit_code": None,
        })
    calls = []

    def checked(command, **kwargs):
        calls.append(command)
        if command[1] == "ps":
            assert f"label=code_auditor.scratch_id={scratch.scratch_id}" in command
            assert "label=code_auditor.agent_run_id=main" in command
            return "container-id" if len(calls) == 1 else ""
        assert command == ["docker", "rm", "-f", "container-id"]
        return ""

    monkeypatch.setattr(sandbox, "_run_checked", checked)
    monkeypatch.setattr(sandbox.time, "sleep", lambda *_: None)
    asyncio.run(scratch.cleanup_invocation("main", "cancelled"))
    records = {row["agent_run_id"]: row for row in read_execution_records(scratch.execution_dir)}
    assert records["main"]["cleanup"] == "verified"
    assert records["main"]["state"] == "interrupted"
    assert records["main"]["exit_code"] is None
    assert records["checker"]["state"] == "starting"
    assert "cleanup" not in records["checker"]
    assert len(calls) == 3  # scan, remove, verify absence


@pytest.mark.parametrize("outcome", ["completed", "cancelled", "cleanup_failed"])
def test_agent_uses_protected_log_and_always_cleans_container(tmp_path, monkeypatch, outcome):
    spec, _ = _spec(tmp_path)
    config = AuditConfig(str(tmp_path / "scratch"), str(tmp_path / "output"), backend="codex")
    scratch = sandbox.DockerScratch(config, "test")
    scratch.execution_dir = Path(spec["execution_dir"])
    logical_log = tmp_path / "scratch" / "agent.log"
    cleaned = []

    async def run(*args, **kwargs):
        actual_log = Path(kwargs["log_file"])
        assert actual_log.parent == scratch.execution_dir
        with agent._open_agent_log(str(actual_log)) as stream:
            stream.write("host-owned-log\n")
        if outcome == "cancelled":
            raise asyncio.CancelledError
        return "ok"

    async def cleanup(marker, status):
        cleaned.append((marker, status))
        if outcome == "cleanup_failed":
            raise sandbox.DockerSandboxError("cleanup could not be verified")

    monkeypatch.setattr(agent, "_run_codex_agent", run)
    monkeypatch.setattr(scratch, "cleanup_invocation", cleanup)
    call = agent.run_agent("test", config, config.target, log_file=str(logical_log), sandbox=scratch)
    if outcome == "cancelled":
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(call)
    elif outcome == "cleanup_failed":
        with pytest.raises(sandbox.DockerSandboxError, match="verified"):
            asyncio.run(call)
    else:
        assert asyncio.run(call) == "ok"
    assert len(cleaned) == 1
    assert not logical_log.exists()
    assert len(list(scratch.execution_dir.glob("agent-*.log"))) == 1


def test_records_survive_cleanup_and_reject_symlink_directories(tmp_path):
    root = tmp_path / "output"
    assert list_sandbox_executions(str(root)) == []
    directory = create_execution_directory(str(root), uuid4().hex)
    record = {"schema_version": 1, "execution_id": uuid4().hex, "started_at": 1,
              "runtime": "runc"}
    write_execution_record(directory, record)
    assert list_sandbox_executions(str(root)) == [record]
    (directory.parent / uuid4().hex).symlink_to(directory, target_is_directory=True)
    assert list_sandbox_executions(str(root)) == [record]
    other = create_execution_directory(str(root), uuid4().hex)
    newer = {**record, "execution_id": uuid4().hex, "started_at": 2, "runtime": "runsc"}
    write_execution_record(other, newer)
    assert list_sandbox_executions(str(root)) == [newer, record]


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_log_open_rejects_indirection_and_special_files(tmp_path, kind):
    original = tmp_path / "original"
    original.write_text("unchanged\n")
    log = tmp_path / "agent.log"
    if kind == "symlink":
        log.symlink_to(original)
    elif kind == "hardlink":
        os.link(original, log)
    else:
        os.mkfifo(log)
    with pytest.raises((OSError, RuntimeError)):
        agent._open_agent_log(str(log))
    assert original.read_text() == "unchanged\n"


async def test_repeated_cancellation_cannot_skip_container_cleanup(tmp_path, monkeypatch):
    config = AuditConfig(str(tmp_path), str(tmp_path), backend="codex")
    scratch = sandbox.DockerScratch(config, "cancel-test")
    host_started = asyncio.Event()
    host_release = asyncio.Event()
    container_started = asyncio.Event()
    container_release = asyncio.Event()
    cleaned = []

    async def run(*args, **kwargs):
        raise asyncio.CancelledError

    async def host_cleanup(self):
        host_started.set()
        await host_release.wait()

    async def container_cleanup(marker, status):
        container_started.set()
        await container_release.wait()
        cleaned.append(status)

    monkeypatch.setattr(agent, "_run_codex_agent", run)
    monkeypatch.setattr(agent._AgentRunControl, "cleanup_processes", host_cleanup)
    monkeypatch.setattr(scratch, "cleanup_invocation", container_cleanup)
    task = asyncio.create_task(agent.run_agent("test", config, config.target, sandbox=scratch))
    try:
        await asyncio.wait_for(host_started.wait(), timeout=1)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        host_release.set()
        await asyncio.wait_for(container_started.wait(), timeout=1)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        host_release.set()
        container_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert cleaned == ["cancelled"]
