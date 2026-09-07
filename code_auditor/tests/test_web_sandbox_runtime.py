from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from code_auditor.config import AuditConfig
from code_auditor.sandbox_records import create_execution_directory, write_execution_record
from code_auditor.web import server
from code_auditor.web import job as job_module
from code_auditor.web.job import AuditJob, AuditJobManager, AuditStartParams
from code_auditor.web.settings import WebSettings


@pytest.mark.parametrize("preliminary", [False, True])
def test_job_builders_preserve_selected_runtime(tmp_path, preliminary):
    job = AuditJob(AuditJobManager(), "audit")
    params = AuditStartParams(target=str(tmp_path), results_dir=str(tmp_path / "results"),
                              sandbox_runtime="runsc", sandbox_mode="docker-networked")
    builder = job._build_preliminary_config if preliminary else job._build_config
    config = builder(params, str(tmp_path), None)
    assert config.sandbox_runtime == "runsc"
    assert config.sandbox_network_enabled


def _app(tmp_path):
    settings = WebSettings.for_state_dir(str(tmp_path), sandbox_mode="local-worktree")
    return server.create_app(db_path=str(tmp_path / "db.sqlite"), web_settings=settings)


@pytest.mark.parametrize("clone", [False, True])
async def test_execution_owner_reaches_audit_after_config_rebuild(tmp_path, monkeypatch, clone):
    app = _app(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    captured = []

    async def ensure_repo(*args, **kwargs):
        return str(target)

    async def run_audit(config, reporter=None):
        captured.append(config)

    monkeypatch.setattr(job_module, "ensure_repo", ensure_repo)
    monkeypatch.setattr(job_module, "run_audit", run_audit)
    params = AuditStartParams(
        target=None if clone else str(target),
        git_url="https://example.test/project.git" if clone else None,
        repos_dir=str(tmp_path / "repos"), results_dir=str(tmp_path / "results"),
        sandbox_runtime="runsc",
    )
    job = await app.state.manager.start(params)
    await job.task
    assert job.state == "done"
    assert job.run_id is not None
    assert len(captured) == 1
    assert captured[0].sandbox_run_id == job.run_id
    assert captured[0].sandbox_job_key == job.job_key
    assert captured[0].sandbox_runtime == "runsc"


def test_api_runtime_selection_and_launch_preflight(tmp_path, monkeypatch):
    app = _app(tmp_path)
    client = TestClient(app)
    checks = []
    ready = False

    def capability(backend, runtime):
        checks.append((backend, runtime))
        return SimpleNamespace(available=ready, reason="runsc not registered",
                               public=lambda: {"available": ready, "requested_runtime": runtime})

    monkeypatch.setattr(server, "inspect_docker_sandbox_environment", capability)
    response = client.get("/api/sandbox/capability?backend=claude&runtime=runsc")
    assert response.json()["docker"]["requested_runtime"] == "runsc"
    request = {"backend": "claude", "mode": "local", "sandbox_mode": "docker-networked",
               "sandbox_runtime": "runsc"}
    assert client.put("/api/settings", json=request).status_code == 400
    assert client.get("/api/settings").json()["sandbox_runtime"] == "docker-default"
    ready = True
    assert client.put("/api/settings", json=request).status_code == 200
    captured = []

    async def start(params):
        captured.append(params)
        return SimpleNamespace(status=lambda: {"state": "running"})

    monkeypatch.setattr(app.state.manager, "start", start)
    response = client.post("/api/audit", json={"git_url": "https://example.test/project.git"})
    assert response.status_code == 202
    assert captured[0].sandbox_runtime == "runsc"
    assert checks[-1] == ("claude", "runsc")
    ready = False
    assert client.post("/api/audit", json={"git_url": "https://example.test/project.git"}).status_code == 400
    assert len(captured) == 1
    assert client.put("/api/settings", json={**request, "sandbox_runtime": "arbitrary"}).status_code == 422


def test_history_keeps_per_launch_environments_and_protected_logs(tmp_path, monkeypatch):
    app = _app(tmp_path)
    client = TestClient(app)
    output = tmp_path / "results" / "run"
    output.mkdir(parents=True)
    run_id = app.state.store.create_run(AuditConfig(str(tmp_path), str(output)))
    endpoint = f"/api/history/{run_id}/sandbox-executions"
    assert client.get(endpoint).json()["executions"] == []
    for index, runtime in enumerate(("runc", "runsc")):
        directory = create_execution_directory(str(output), uuid4().hex)
        write_execution_record(directory, {
            "schema_version": 1, "execution_id": uuid4().hex, "runtime": runtime, "audit_run_id": run_id,
            "started_at": index, "state": "exited", "exit_code": 0, "cleanup": "verified",
        })
    (directory / "agent-test.log").write_text("protected log\n")
    response = client.get(endpoint + "?limit=1")
    assert response.json()["total"] == 2
    assert response.json()["executions"][0]["runtime"] == "runsc"
    assert client.get(endpoint + "?offset=1&limit=1").json()["executions"][0]["runtime"] == "runc"
    log = client.get(f"/api/history/{run_id}/agent-log")
    assert log.text == "protected log\n"
    assert log.headers["X-CodeAuditor-Log-Path"].startswith(".sandbox-executions/")
    captured = []

    async def resume(run_id, **kwargs):
        captured.append(kwargs)
        return SimpleNamespace(status=lambda: {"state": "restoring"})

    monkeypatch.setattr(app.state.manager, "resume_cancelled", resume)
    assert client.put("/api/settings", json={"backend": "claude", "mode": "local",
                                           "sandbox_runtime": "runsc"}).status_code == 200
    assert client.post(f"/api/history/{run_id}/resume").status_code == 202
    assert captured[0]["sandbox_runtime"] == "runsc"
    assert client.get(endpoint).json()["total"] == 2
    other_run = app.state.store.create_run(AuditConfig(str(tmp_path), str(output)))
    assert client.get(f"/api/history/{other_run}/sandbox-executions").json()["executions"] == []
    assert client.get("/api/history/99999/sandbox-executions").status_code == 404
