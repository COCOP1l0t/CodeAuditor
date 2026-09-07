"""Opt-in, benign container checks; no model requests or target PoCs.

CODE_AUDITOR_RUN_SANDBOX_TESTS=1 pytest -q -rs code_auditor/tests/test_sandbox_integration.py
The existing image is used as-is. These tests never install a runtime, pull an
image, change daemon configuration, or restart Docker.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time

import pytest

from code_auditor import sandbox
from code_auditor.config import AuditConfig
from code_auditor.sandbox_records import read_execution_records

pytestmark = pytest.mark.skipif(
    os.environ.get("CODE_AUDITOR_RUN_SANDBOX_TESTS") != "1",
    reason="set CODE_AUDITOR_RUN_SANDBOX_TESTS=1 to run container checks",
)


@pytest.fixture(params=["runc", "runsc"])
def scratch(request, tmp_path, monkeypatch):
    runtime = request.param
    docker_bin = os.environ.get("CODE_AUDITOR_DOCKER_BIN", "docker")
    try:
        info = json.loads(subprocess.check_output(
            [docker_bin, "info", "--format", "{{json .Runtimes}}"], stderr=subprocess.PIPE,
            timeout=15, text=True,
        ))
    except (OSError, subprocess.SubprocessError):
        pytest.skip("Docker daemon unavailable")
    if runtime not in info:
        pytest.skip(f"Docker runtime {runtime} is not registered")
    target = tmp_path / "source"
    target.mkdir()
    cli = tmp_path / "benign-cli"
    cli.write_text("""#!/bin/sh
set -eu
if [ "${1:-}" = wait ]; then
  touch "$CODE_AUDITOR_SCRATCH_ROOT/ready"
  exec sleep 120
fi
test -z "${OPENAI_API_KEY:-}"
test -z "${ANTHROPIC_AUTH_TOKEN:-}"
test -z "${CODEAUDITOR_PROVIDER_API_KEY:-}"
test ! -e "$2"
test ! -e "$3"
test "$(id -u)" = "$4"
if touch /etc/code-auditor-smoke-test 2>/dev/null; then exit 80; fi
printf 'sandbox-ok\n' > "$CODE_AUDITOR_SCRATCH_ROOT/benign-output"
exit 7
""")
    cli.chmod(0o700)
    monkeypatch.setattr(sandbox, "_locate_claude_cli", lambda: cli)
    monkeypatch.setattr(sandbox.DockerScratch, "_prepare_minimal_home", lambda _: None)
    config = AuditConfig(
        str(target), str(tmp_path / "output"), backend="claude", sandbox_runtime=runtime,
        sandbox_root=str(tmp_path / "sandboxes"), sandbox_network_enabled=False,
        sandbox_min_free_bytes=0, sandbox_memory="256m", sandbox_cpus="1", sandbox_pids_limit=128,
        sandbox_run_id=42, sandbox_job_key="integration-job",
    )
    instance = sandbox.DockerScratch(config, "integration")
    try:
        asyncio.run(instance.prepare(str(target), ""))
    except sandbox.DockerSandboxError as exc:
        if "is missing" in str(exc):
            pytest.skip("sandbox image is not installed")
        raise
    try:
        yield instance
    finally:
        asyncio.run(instance.close())


def _env(scratch, marker):
    # Do not inherit provider keys, proxy credentials or user configuration.
    return {
        "PATH": os.environ["PATH"], "HOME": os.environ["HOME"],
        **scratch.wrapper_env(str(scratch.source_dir)),
        "CODE_AUDITOR_AGENT_RUN_ID": marker,
    }


def test_runtime_write_boundary_and_durable_record(scratch):
    secret = scratch.execution_dir / "host-only-sentinel"
    secret.write_text("host-only\n")
    assert scratch.control_dir is not None
    completed = subprocess.run(
        [scratch.wrapper_path("claude"), "check", str(secret), str(scratch.control_dir), str(os.getuid())],
        env=_env(scratch, "integration-exit"), capture_output=True, text=True, timeout=45,
    )
    assert completed.returncode == 7, completed.stderr
    assert (scratch.root / "benign-output").read_text() == "sandbox-ok\n"
    records = read_execution_records(scratch.execution_dir)
    assert len(records) == 1
    assert records[0]["runtime"] == scratch.requested_runtime
    assert records[0]["audit_run_id"] == 42
    assert records[0]["job_key"] == "integration-job"
    assert records[0]["image_id"] == scratch.image_id
    assert records[0]["network"] == "none"
    assert records[0]["effective_network"] == "none"
    assert records[0]["effective_limits"] == {
        "memory_bytes": 256 * 1024 * 1024, "nano_cpus": 1_000_000_000, "pids": 128,
    }
    assert records[0]["security"]["read_only_rootfs"] is True
    assert records[0]["security"]["user"] == f"{os.getuid()}:{os.getgid()}"
    assert records[0]["exit_code"] == 7
    assert records[0]["cleanup"] == "verified"
    directory = scratch.execution_dir
    asyncio.run(scratch.close())
    assert read_execution_records(directory) == records


def test_killed_supervisor_is_cleaned_by_invocation_label(scratch):
    process = subprocess.Popen(
        [scratch.wrapper_path("claude"), "wait"], env=_env(scratch, "integration-kill"),
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30
        while not (scratch.root / "ready").exists():
            if process.poll() is not None:
                pytest.fail(process.stderr.read().decode(errors="replace"))
            if time.monotonic() >= deadline:
                pytest.fail("container did not become ready")
            time.sleep(0.1)
        process.kill()
        process.wait(timeout=10)
        asyncio.run(scratch.cleanup_invocation("integration-kill", "cancelled"))
        records = read_execution_records(scratch.execution_dir)
        assert records[0]["state"] == "interrupted"
        assert records[0]["exit_code"] is None
        assert records[0]["cleanup"] == "verified"
        assert not subprocess.check_output([
            scratch.docker_bin, "ps", "-aq", "--filter", f"label=code_auditor.scratch_id={scratch.scratch_id}",
        ], timeout=10).strip()
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        if process.stderr:
            process.stderr.close()
