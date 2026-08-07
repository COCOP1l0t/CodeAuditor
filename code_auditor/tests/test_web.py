from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from code_auditor.config import AuditConfig
from code_auditor.db import RUN_CANCELLED, compute_target_key
from code_auditor.web import create_app
from code_auditor.web import job as job_module
from code_auditor.web.job import (
    STATE_CANCELLED,
    STATE_DONE,
    STATE_FAILED,
    STATE_RESTORING,
    STATE_RUNNING,
    AuditJobManager,
    AuditStartParams,
    JobConflictError,
    JobValidationError,
    ReproductionStartParams,
)
from code_auditor.web.progress import EventBus, WebLogHandler, WebProgressReporter
from code_auditor.web.settings import WebSettings


# ── WebProgressReporter / EventBus ───────────────────────────────────────────


def test_progress_reporter_publishes_stage_events() -> None:
    bus = EventBus()
    reporter = WebProgressReporter(bus)

    reporter.begin_stage(1, "Researching security context")
    reporter.stage_progress(1, items_done=3, items_total=10, detail="3/10 done")
    reporter.end_stage(1)

    events = bus.backlog()
    assert [e["type"] for e in events] == ["stage", "progress", "stage"]
    assert events[0]["status"] == "running"
    assert events[1]["items_done"] == 3
    assert events[1]["items_total"] == 10
    assert events[2]["status"] == "done"

    snapshot = reporter.snapshot()
    assert snapshot[0]["stage"] == 1
    assert snapshot[0]["status"] == "done"
    assert snapshot[0]["items_done"] == 3


def test_web_log_handler_publishes_log_events() -> None:
    bus = EventBus()
    handler = WebLogHandler(bus)
    record = logging.LogRecord(
        name="code_auditor.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    handler.emit(record)

    events = bus.backlog()
    assert len(events) == 1
    assert events[0]["type"] == "log"
    assert events[0]["level"] == "INFO"
    assert "hello world" in events[0]["message"]


def test_web_log_handler_bounds_oversized_backend_output() -> None:
    bus = EventBus()
    handler = WebLogHandler(bus)
    record = logging.LogRecord(
        name="code_auditor.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="x" * 50_000,
        args=(),
        exc_info=None,
    )

    handler.emit(record)

    message = bus.backlog()[0]["message"]
    assert len(message) < 21_000
    assert "Web log event truncated" in message


async def test_event_bus_subscribe_receives_published_events() -> None:
    bus = EventBus()
    queue = bus.subscribe()
    bus.publish({"type": "job", "status": "running"})
    event = await asyncio.wait_for(queue.get(), timeout=1)
    assert event["status"] == "running"
    bus.unsubscribe(queue)


async def test_event_bus_bounds_twenty_thousand_slow_client_events() -> None:
    bus = EventBus(max_buffer=40, max_subscriber_events=50)
    queue = bus.subscribe()
    for index in range(20_000):
        bus.publish(
            {
                "type": "log",
                "level": "INFO",
                "message": f"verbose event {index}",
            }
        )
    bus.publish({"type": "log", "level": "ERROR", "message": "keep error"})
    bus.publish({"type": "stage", "stage": 3, "status": "done"})
    for index in range(100):
        bus.publish(
            {"type": "log", "level": "INFO", "message": f"tail {index}"}
        )
    await asyncio.sleep(0)

    assert queue.qsize() <= 50
    queued = [await queue.get() for _ in range(queue.qsize())]
    assert any(event.get("message") == "keep error" for event in queued)
    assert any(event.get("type") == "stage" for event in queued)
    assert len(bus.backlog()) == 40
    bus.unsubscribe(queue)


# ── AuditJobManager ──────────────────────────────────────────────────────────


async def test_start_with_invalid_target_raises(tmp_path) -> None:
    manager = AuditJobManager()
    with pytest.raises(JobValidationError):
        await manager.start(AuditStartParams(target=str(tmp_path / "missing")))


async def test_start_conflict_while_running(tmp_path, monkeypatch) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def fake_run_audit(config, tui=None):
        started.set()
        await release.wait()

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    await manager.start(AuditStartParams(target=str(tmp_path)))
    await asyncio.wait_for(started.wait(), timeout=1)

    with pytest.raises(JobConflictError):
        await manager.start(AuditStartParams(target=str(tmp_path)))

    release.set()
    await manager._task
    assert manager.state == STATE_DONE


async def test_stop_cancels_running_job(tmp_path, monkeypatch) -> None:
    started = asyncio.Event()

    async def fake_run_audit(config, tui=None):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    await manager.start(AuditStartParams(target=str(tmp_path)))
    await asyncio.wait_for(started.wait(), timeout=1)

    assert manager.stop() is True
    await manager._task
    assert manager.state == STATE_CANCELLED
    assert manager.stop() is False


async def test_resume_cancelled_job_reuses_run_and_pinned_output(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "repo" / "example.com" / "team" / "project"
    output = tmp_path / "results" / "project" / "audit-output-deadbeef"
    (target / ".git").mkdir(parents=True)
    output.mkdir(parents=True)
    identity = {
        "repo_name": "project",
        "repo_url": "https://example.com/team/project.git",
        "branch": "main",
        "commit": "a" * 40,
        "dirty": False,
        "submodules": [],
    }
    run = {
        "id": 17,
        "status": RUN_CANCELLED,
        "target": str(target),
        "output_dir": str(output),
        "wiki_path": None,
        "backend": "claude",
        "model": "test-model",
        "max_parallel": 2,
        "target_au_count": -1,
        "log_level": "DEBUG",
        "dirty": 0,
        "branch": identity["branch"],
        "commit": identity["commit"],
        "target_key": compute_target_key(identity),
    }

    class FakeStore:
        def __init__(self):
            self.resumed = []
            self.finished = []

        def get_run(self, run_id):
            return run if run_id == 17 else None

        def disclosure_dedupe_index(self):
            return []

        def resume_cancelled_run(self, run_id):
            self.resumed.append(run_id)
            run["status"] = "running"
            return True

        def seed_analysis_units(self, target_key, output_dir):
            return 0

        def finish_run(self, run_id, status, error, ended_at):
            self.finished.append((run_id, status, error, ended_at))

    audited = []
    checkouts = []
    checkout_started = asyncio.Event()
    checkout_release = asyncio.Event()

    async def fake_run_audit(config, tui=None):
        audited.append(config)

    async def fake_checkout(target_path, commit, branch):
        checkouts.append((target_path, commit, branch))
        checkout_started.set()
        await checkout_release.wait()

    store = FakeStore()
    monkeypatch.setattr(job_module, "capture_repo_identity", lambda _path: identity)
    monkeypatch.setattr(job_module, "_checkout_recorded_revision", fake_checkout)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager(store=store)

    await manager.resume_cancelled(
        17,
        repos_dir=str(tmp_path / "repo"),
        results_dir=str(tmp_path / "results"),
        wikis_dir=str(tmp_path / "wiki"),
    )
    assert manager.state == STATE_RESTORING
    await asyncio.wait_for(checkout_started.wait(), timeout=1)
    with pytest.raises(JobConflictError):
        await manager.resume_cancelled(
            17,
            repos_dir=str(tmp_path / "repo"),
            results_dir=str(tmp_path / "results"),
            wikis_dir=str(tmp_path / "wiki"),
        )
    checkout_release.set()
    await manager._task

    assert store.resumed == [17]
    assert checkouts == [(str(target), "a" * 40, "main")]
    assert manager.state == STATE_DONE
    assert manager.status()["run_id"] == 17
    assert len(audited) == 1
    assert audited[0].target == str(target)
    assert audited[0].output_dir == str(output)
    assert audited[0].resume is True
    assert audited[0].update_repo is False
    assert store.finished[0][0:3] == (17, STATE_DONE, "")


async def test_resume_cancelled_job_keeps_run_cancelled_when_checkout_fails(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "repo" / "project"
    output = tmp_path / "results" / "project" / "audit-output-old"
    (target / ".git").mkdir(parents=True)
    output.mkdir(parents=True)
    recorded = {
        "repo_name": "project",
        "commit": "a" * 40,
        "submodules": [],
    }

    class FakeStore:
        def __init__(self):
            self.resumed = []

        def get_run(self, _run_id):
            return {
                "status": RUN_CANCELLED,
                "target": str(target),
                "output_dir": str(output),
                "dirty": 0,
                "backend": "claude",
                "model": None,
                "max_parallel": 1,
                "target_au_count": -1,
                "log_level": "DEBUG",
                "commit": recorded["commit"],
                "target_key": compute_target_key(recorded),
            }

        def disclosure_dedupe_index(self):
            return []

        def resume_cancelled_run(self, run_id):
            self.resumed.append(run_id)
            return True

    monkeypatch.setattr(
        job_module,
        "capture_repo_identity",
        lambda _path: {
            **recorded,
            "commit": "b" * 40,
            "dirty": False,
        },
    )

    async def fail_checkout(_target, _commit, _branch):
        raise JobValidationError("Cannot restore recorded checkout")

    monkeypatch.setattr(job_module, "_checkout_recorded_revision", fail_checkout)
    store = FakeStore()
    manager = AuditJobManager(store=store)

    await manager.resume_cancelled(
        9,
        repos_dir=str(tmp_path / "repo"),
        results_dir=str(tmp_path / "results"),
        wikis_dir=str(tmp_path / "wiki"),
    )
    assert manager.state == STATE_RESTORING
    await manager._task

    assert manager.state == STATE_FAILED
    assert manager.error == "Cannot restore recorded checkout"
    assert store.resumed == []


async def test_checkout_recorded_revision_restores_commit_and_branch(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    git("init", "-b", "main")
    git("config", "user.email", "test@example.com")
    git("config", "user.name", "CodeAuditor Test")
    (repo / "source.c").write_text("first\n", encoding="utf-8")
    git("add", "source.c")
    git("commit", "-m", "first")
    first_commit = git("rev-parse", "HEAD")
    (repo / "source.c").write_text("second\n", encoding="utf-8")
    git("commit", "-am", "second")
    second_commit = git("rev-parse", "HEAD")

    await job_module._checkout_recorded_revision(
        str(repo), first_commit, "main"
    )
    assert git("rev-parse", "HEAD") == first_commit
    assert git("rev-parse", "--abbrev-ref", "HEAD") == "HEAD"
    assert (repo / "source.c").read_text(encoding="utf-8") == "first\n"

    await job_module._checkout_recorded_revision(
        str(repo), second_commit, "main"
    )
    assert git("rev-parse", "HEAD") == second_commit
    assert git("rev-parse", "--abbrev-ref", "HEAD") == "main"


async def test_checkout_recorded_revision_does_not_initialize_submodules(
    tmp_path,
) -> None:
    sub = tmp_path / "sub"
    sub.mkdir()
    subprocess.run(["git", "init", "-q", str(sub)], check=True)
    subprocess.run(
        ["git", "-C", str(sub), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(sub), "config", "user.name", "CodeAuditor Test"],
        check=True,
    )
    (sub / "README").write_text("sub\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(sub), "add", "README"], check=True)
    subprocess.run(["git", "-C", str(sub), "commit", "-qm", "sub"], check=True)

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "config", "user.name", "CodeAuditor Test"],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(sub),
            "deps/sub",
        ],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "add submodule"], check=True
    )
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "submodule", "deinit", "-f", "--all"],
        check=True,
        capture_output=True,
    )

    await job_module._checkout_recorded_revision(str(repo), commit, "main")

    status = subprocess.run(
        ["git", "-C", str(repo), "submodule", "status"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert status.startswith("-")


async def test_resume_git_command_times_out_and_kills_process_group(tmp_path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)

    with pytest.raises(JobValidationError, match="Timed out"):
        await job_module._run_resume_git_command(
            str(repo),
            "-c",
            "alias.wait=!sleep 60",
            "wait",
            timeout_seconds=0.05,
        )


async def test_failed_job_records_error(tmp_path, monkeypatch) -> None:
    async def fake_run_audit(config, tui=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    await manager.start(AuditStartParams(target=str(tmp_path)))
    await manager._task

    assert manager.state == STATE_FAILED
    assert manager.error == "boom"
    status = manager.status()
    assert status["state"] == STATE_FAILED
    assert status["error"] == "boom"


async def test_start_with_invalid_wiki_raises(tmp_path) -> None:
    manager = AuditJobManager()
    with pytest.raises(JobValidationError):
        await manager.start(
            AuditStartParams(target=str(tmp_path), wiki=str(tmp_path / "no-wiki"))
        )


async def test_standalone_reproduction_runs_only_stage5_in_isolated_tree(
    tmp_path, monkeypatch
) -> None:
    wiki = tmp_path / "wikis" / "qemu-security"
    wiki.mkdir(parents=True)
    (wiki / "index.md").write_text("# Wiki\n", encoding="utf-8")

    class FakeStore:
        def get_reproduction_candidate(self, run_id, vuln_id):
            assert (run_id, vuln_id) == (7, "H-03")
            return {
                "run_id": 7,
                "vuln_id": "H-03",
                "title": "Retest me",
                "repo_name": "qemu",
                "commit": "a" * 40,
                "target": str(tmp_path),
                "severity": "high",
                "cvss_score": 8.1,
                "wiki_path": str(wiki),
                "raw_json": json.dumps({"id": "H-03", "title": "Retest me"}),
            }

    async def fake_create_worktree(repo, commit, destination):
        assert repo == str(tmp_path)
        assert commit == "a" * 40
        Path(destination).mkdir(parents=True)

    async def fake_run_stage5(vulnerabilities, config, checkpoint):
        assert len(vulnerabilities) == 1
        assert config.resume is False
        assert config.wiki_path == str(wiki)
        report = Path(config.output_dir) / "stage5-pocs" / "H-03" / "report.md"
        report.parent.mkdir(parents=True)
        report.write_text(
            "# PoC\n\nReproduction Status: reproduced\n", encoding="utf-8"
        )
        return [str(report)]

    monkeypatch.setattr(job_module, "_create_detached_worktree", fake_create_worktree)
    monkeypatch.setattr(job_module, "run_stage5", fake_run_stage5)
    manager = AuditJobManager(store=FakeStore())
    reproduction_root = tmp_path / "reproduction"

    await manager.start_reproduction(
        ReproductionStartParams(
            run_id=7,
            vuln_id="H-03",
            backend="codex",
            output_dir=str(reproduction_root),
            wikis_dir=str(tmp_path / "wikis"),
        )
    )
    await manager._task

    assert manager.state == STATE_DONE
    assert manager.kind == "reproduction"
    assert manager.config is not None
    assert manager.config.target == str(reproduction_root / "source")
    assert manager.config.output_dir == str(reproduction_root / "output")
    assert manager.reproduction_candidate["vuln_id"] == "H-03"
    assert len(manager.reproduction_reports) == 1


# ── HTTP API ─────────────────────────────────────────────────────────────────


def _make_app(tmp_path, defaults: dict | None = None):
    """create_app with an isolated history database."""
    return create_app(
        defaults,
        db_path=str(tmp_path / "history.db"),
        web_settings=WebSettings.for_state_dir(str(tmp_path)),
    )


def _make_managed_repo(base, name: str = "github.com/user/repo") -> str:
    repo = base / "repo" / Path(name)
    (repo / ".git").mkdir(parents=True)
    return str(repo)


def _make_managed_wiki(base, name: str = "qemu-security") -> str:
    wiki = base / "wiki" / Path(name)
    wiki.mkdir(parents=True)
    (wiki / "index.md").write_text("# Wiki\n", encoding="utf-8")
    return str(wiki)


def _make_output_dir(base) -> str:
    """Synthetic stage 3-5 output layout for history tests."""
    out = base / "results" / "test-project" / "audit-output-20260101"
    vulns = out / "stage4-vulnerabilities"
    vulns.mkdir(parents=True)
    (vulns / "H-01.json").write_text(
        json.dumps(
            {
                "id": "H-01",
                "title": "Test vuln",
                "location": "src/a.c:f (lines 1-2)",
                "trigger": "crafted input",
                "data_flow_trace": {"entry_point": "main", "sink": "memcpy"},
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer-overflow"],
                "cvss_score": "8.1",
                "severity": "High",
            }
        ),
        encoding="utf-8",
    )
    poc = out / "stage5-pocs" / "H-01"
    poc.mkdir(parents=True)
    (poc / "report.md").write_text(
        "# PoC\n\nReproduction Status: reproduced\n", encoding="utf-8"
    )
    disclosure = out / "stage6-disclosures" / "H-01" / "disclosure"
    disclosure.mkdir(parents=True)
    (disclosure / "report.md").write_text(
        "# Local vulnerability report\n", encoding="utf-8"
    )
    (disclosure / "email.txt").write_text(
        "Subject: Local vulnerability\n", encoding="utf-8"
    )
    (disclosure / "disclosure.zip").write_bytes(b"PK\x05\x06")
    return str(out)


def _write_web_stage5_evidence(output_dir: str) -> None:
    poc = Path(output_dir) / "stage5-pocs" / "H-01"
    graph = {
        "schema_version": 1,
        "finding_id": "H-01",
        "title": "Test vuln",
        "trigger": "crafted input",
        "evidence_basis": "ASan run and debugger backtrace from the real target",
        "nodes": [
            {
                "id": "source",
                "function": "main",
                "location": "src/a.c:1",
                "role": "source",
                "description": "Receives the crafted input",
                "evidence": "Debugger breakpoint",
                "key_parameters": [
                    {
                        "name": "size",
                        "value": "4096",
                        "origin": "packet",
                        "security_role": "attacker-controlled length",
                        "description": "Passed to the copy",
                    }
                ],
            },
            {
                "id": "sink",
                "function": "memcpy",
                "location": "src/a.c:2",
                "role": "sink",
                "description": "Writes beyond the destination",
                "evidence": "ASan faulting frame",
                "key_parameters": [],
            },
        ],
        "edges": [
            {
                "from": "source",
                "to": "sink",
                "label": "calls",
                "condition": "size exceeds destination capacity",
                "attacker_controlled": True,
            }
        ],
    }
    (poc / "trigger-graph.json").write_text(
        json.dumps(graph), encoding="utf-8"
    )
    (poc / "asan-report.txt").write_text(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 memcpy\n",
        encoding="utf-8",
    )


def _wait_for_state(app, state: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = app.state.manager.status()
        if status["state"] == state:
            return status
        time.sleep(0.05)
    raise AssertionError(f"job did not reach state {state}: {status}")


def test_api_config_returns_defaults(tmp_path) -> None:
    app = _make_app(tmp_path, {"git_url": "https://github.com/user/repo.git"})
    client = TestClient(app)
    res = client.get("/api/config")
    assert res.status_code == 200
    body = res.json()
    assert body["defaults"]["git_url"] == "https://github.com/user/repo.git"
    assert body["defaults"]["max_parallel"] == 1
    assert body["config_path"].endswith("settings.json")
    assert "discovered_path" not in body
    assert body["wikis_dir"] == str(tmp_path / "wiki")
    assert body["terminal_enabled"] is True
    assert len(body["terminal_token"]) >= 32
    assert "backends" not in body
    assert "default_models" not in body


def test_api_index_serves_html(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers["cache-control"] == "no-store"
    assert "CodeAuditor" in res.text
    assert '<link rel="icon" href="/static/icon.svg" type="image/svg+xml" />' in res.text
    assert '<img class="logo-mark" src="/static/icon.svg"' in res.text
    assert 'id="r-target-select"' in res.text
    assert 'id="r-commit-select"' in res.text
    assert 'id="r-bug-select"' in res.text
    assert 'id="f-repo-select"' in res.text
    assert 'id="f-git-url"' in res.text
    assert 'id="f-wiki-select"' in res.text
    assert 'data-route="cves"' in res.text
    assert 'data-route="trash"' in res.text
    assert 'id="btn-cve-import"' in res.text
    assert 'id="cve-import-dialog"' in res.text
    assert 'id="disclosure-edit-dialog"' in res.text
    assert 'id="disclosure-edit-cves"' in res.text
    assert 'id="trigger-graph-dialog"' in res.text
    assert 'id="trigger-graph-svg"' in res.text
    assert 'id="trigger-graph-details"' in res.text
    assert 'id="asan-report-dialog"' in res.text
    assert 'id="asan-report-content"' in res.text
    assert res.text.count('class="sort-button"') == 13
    assert 'id="terminal-dock"' in res.text
    assert 'id="workspace"' in res.text
    assert 'id="content-pane"' in res.text
    assert 'id="terminal-splitter"' in res.text
    assert 'id="terminal-tabs"' in res.text
    assert 'id="terminal-panels"' in res.text
    assert 'id="disclosure-search"' in res.text
    assert 'id="history-message"' in res.text
    assert 'id="btn-run-resume"' in res.text
    assert 'id="notification-center"' in res.text
    assert 'id="btn-full-agent-log"' in res.text
    assert 'id="results-agent-logs"' in res.text
    assert res.text.count('class="table-shell"') == 3
    assert 'id="trash-table"' in res.text
    assert 'class="col-disclosure-title"' in res.text
    assert 'class="col-cve-local"' in res.text
    assert "⚡" not in res.text
    assert "⏳" not in res.text
    for removed_id in (
        "f-target",
        "f-discovered",
        "f-backend",
        "f-model",
        "f-log-level",
        "r-backend",
        "r-model",
        "r-log-level",
    ):
        assert f'id="{removed_id}"' not in res.text

    script = client.get("/static/app.js")
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-cache"
    assert "Current reproduction status" in script.text
    assert "populateReproductionCommits" in script.text
    assert "openPocTerminal" in script.text
    assert "disclosureTerminalButtonHtml" in script.text
    assert "activatePocTerminal" in script.text
    assert "setupTerminalSplitter" in script.text
    assert "showTerminalDock" in script.text
    assert "terminalSessions" in script.text
    assert "wireSortableTable" in script.text
    assert "openDisclosureEditDialog" in script.text
    assert "disclosureCvesReady" in script.text
    assert "moveDisclosureToTrash" in script.text
    assert 'if (e.review_status === "slop")' not in script.text
    assert "restoreDisclosure" in script.text
    assert "refreshTrashCount" in script.text
    assert "openCveDialog" in script.text
    assert "appendEvidenceActionButtons" in script.text
    assert "renderTriggerGraph" in script.text
    assert "openAsanReport" in script.text
    assert "pollAuditHeartbeat" in script.text
    assert "resumeCancelledAudit" in script.text
    assert "BUSY_JOB_STATES" in script.text
    assert "isJobBusy" in script.text
    assert "/resume`" in script.text
    assert "notifyStageCompleted" in script.text
    assert "MAX_LOG_PANE_ENTRIES" in script.text
    assert "LOG_RENDER_INTERVAL_MS" in script.text
    assert "pane.textContent +=" not in script.text
    assert "pollActiveAgentLog" in script.text
    assert 'fetch("/api/results/agent-log")' in script.text
    assert "is active — Stage" in script.text
    assert "older Web logs trimmed" in script.text
    assert '"fixed"' not in script.text
    assert 'id="btn-disclosures-sync"' not in res.text

    icon = client.get("/static/icon.svg")
    assert icon.status_code == 200
    assert icon.headers["content-type"].startswith("image/svg+xml")
    assert "CodeAuditor" in icon.text


def test_api_cves_imports_only_selected_local_disclosures(tmp_path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    app.state.store.import_output_dir(_make_output_dir(tmp_path))
    disclosure = app.state.store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    assert app.state.store.set_disclosed_status(
        disclosure["project"], key, "confirmed"
    )

    res = client.get("/api/cves")
    assert res.status_code == 200
    assert res.json()["total"] == 0
    candidates = client.get("/api/cves/candidates").json()
    assert candidates["total"] == 1
    assert candidates["entries"][0]["dedupe_key"] == key

    imported = client.post(
        "/api/cves",
        json={
            "cve_id": "cve-2026-12345",
            "dedupe_keys": [key],
            "cvss_score": 7.5,
            "severity": "high",
            "cve_url": "",
            "project_url": "https://example.com/test-project",
            "reference_label": "Upstream advisory",
            "reference_url": "https://example.com/advisory/12345",
        },
    )
    assert imported.status_code == 201
    entry = imported.json()["entry"]
    assert entry["cve_id"] == "CVE-2026-12345"
    assert entry["project"] == "test-project"
    assert entry["local_disclosures"][0]["title"] == "Local vulnerability"
    assert entry["references"] == [
        {"label": "Upstream advisory", "url": "https://example.com/advisory/12345"}
    ]
    assert client.get("/api/cves").json()["total"] == 1
    assert client.get(
        "/api/cves", params={"project": "test-project"}
    ).json()["total"] == 1

    updated = client.put(
        "/api/cves/CVE-2026-12345",
        json={
            "cve_id": "CVE-2026-12345",
            "dedupe_keys": [key],
            "cvss_score": 9.4,
            "severity": "critical",
            "cve_url": "https://example.com/cve/CVE-2026-12345",
            "project_url": "https://example.com/test-project/security",
            "references": [
                {
                    "label": "Updated advisory",
                    "url": "https://example.com/advisory/updated",
                },
                {
                    "label": "Vendor issue",
                    "url": "https://example.com/issues/12345",
                },
            ],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["entry"]["cvss_score"] == 9.4
    assert updated.json()["entry"]["severity"] == "critical"
    assert updated.json()["entry"]["references"] == [
        {"label": "Updated advisory", "url": "https://example.com/advisory/updated"},
        {"label": "Vendor issue", "url": "https://example.com/issues/12345"},
    ]

    mismatched = client.put(
        "/api/cves/CVE-2026-12345",
        json={"cve_id": "CVE-2026-54321", "dedupe_keys": [key]},
    )
    assert mismatched.status_code == 400

    missing = client.put(
        "/api/cves/CVE-2026-99999",
        json={"cve_id": "CVE-2026-99999", "dedupe_keys": [key]},
    )
    assert missing.status_code == 404

    second = client.post(
        "/api/cves",
        json={"cve_id": "CVE-2026-54321", "dedupe_keys": [key]},
    )
    assert second.status_code == 201
    disclosure_entry = client.get("/api/disclosures").json()["entries"][0]
    editable_fields = (
        "title",
        "location",
        "cwe",
        "vulnerability_class",
        "trigger",
        "summary",
        "repo_url",
        "audited_commit",
        "audit_finished_date",
        "model_backend",
    )
    reassignment = {
        "project": disclosure_entry["project"],
        "dedupe_key": key,
        "cve_ids": ["cve-2026-54321"],
        **{field: disclosure_entry.get(field) or "" for field in editable_fields},
    }
    reassigned = client.put("/api/disclosures", json=reassignment)
    assert reassigned.status_code == 200
    assert [cve["cve_id"] for cve in reassigned.json()["entry"]["cves"]] == [
        "CVE-2026-54321"
    ]
    assert [cve["cve_id"] for cve in client.get("/api/cves").json()["entries"]] == [
        "CVE-2026-54321"
    ]
    assert [
        cve["cve_id"]
        for cve in client.get("/api/disclosures").json()["entries"][0]["cves"]
    ] == ["CVE-2026-54321"]

    assert app.state.store.set_disclosed_status(
        disclosure_entry["project"], key, "reported"
    )
    assert client.get("/api/cves").json()["total"] == 0
    assert client.get("/api/disclosures").json()["entries"][0]["cves"] == []
    assert client.get("/api/cves/candidates").json()["total"] == 0
    forbidden = client.put("/api/disclosures", json=reassignment)
    assert forbidden.status_code == 400
    assert "confirmed" in forbidden.json()["detail"]

    rejected = client.post(
        "/api/cves",
        json={
            "cve_id": "CVE-2026-99999",
            "dedupe_keys": ["sha256:" + "b" * 64],
        },
    )
    assert rejected.status_code == 400


def test_poc_terminal_websocket_starts_in_managed_stage5_directory(tmp_path) -> None:
    app = _make_app(tmp_path)
    out = _make_output_dir(tmp_path)
    run_id = app.state.store.import_output_dir(out)
    client = TestClient(app)
    token = client.get("/api/config").json()["terminal_token"]
    output = bytearray()

    with client.websocket_connect(
        f"/ws/terminal/{run_id}/H-01?token={token}"
    ) as websocket:
        ready = websocket.receive_json()
        assert ready["type"] == "ready"
        assert ready["cwd"] == str(Path(out) / "stage5-pocs" / "H-01")
        websocket.send_json(
            {"type": "input", "data": "printf '__POC_TERMINAL_OK__\\n'; exit\n"}
        )
        for _ in range(30):
            message = websocket.receive()
            if message.get("bytes"):
                output.extend(message["bytes"])
            if b"__POC_TERMINAL_OK__" in output:
                break

    assert b"__POC_TERMINAL_OK__" in output


def test_slop_disclosure_terminal_starts_from_registered_stage5_artifact(
    tmp_path,
) -> None:
    from urllib.parse import urlencode

    app = _make_app(tmp_path)
    out = Path(_make_output_dir(tmp_path))
    app.state.store.import_output_dir(str(out))
    entry = app.state.store.list_disclosed()[0]
    assert app.state.store.set_disclosed_status(
        entry["project"], entry["dedupe_key"], "slop"
    )
    entry = app.state.store.list_disclosed(status="slop")[0]
    assert entry["terminal"]["vuln_id"] == "H-01"

    client = TestClient(app)
    token = client.get("/api/config").json()["terminal_token"]
    params = urlencode(
        {
            "project": entry["project"],
            "dedupe_key": entry["dedupe_key"],
            "token": token,
        }
    )
    output = bytearray()
    with client.websocket_connect(f"/ws/disclosure-terminal?{params}") as websocket:
        ready = websocket.receive_json()
        assert ready["type"] == "ready"
        assert ready["vuln_id"] == "H-01"
        assert ready["cwd"] == str(out / "stage5-pocs" / "H-01")
        websocket.send_json(
            {"type": "input", "data": "printf '__SLOP_TERMINAL_OK__\\n'; exit\n"}
        )
        for _ in range(30):
            message = websocket.receive()
            if message.get("bytes"):
                output.extend(message["bytes"])
            if b"__SLOP_TERMINAL_OK__" in output:
                break

    assert b"__SLOP_TERMINAL_OK__" in output

    bad_token_params = urlencode(
        {
            "project": entry["project"],
            "dedupe_key": entry["dedupe_key"],
            "token": "wrong",
        }
    )
    with pytest.raises(WebSocketDisconnect) as bad_token:
        with client.websocket_connect(
            f"/ws/disclosure-terminal?{bad_token_params}"
        ):
            pass
    assert bad_token.value.code == 1008

    missing_params = urlencode(
        {
            "project": entry["project"],
            "dedupe_key": "sha256:" + "0" * 64,
            "token": token,
        }
    )
    with pytest.raises(WebSocketDisconnect) as missing_target:
        with client.websocket_connect(f"/ws/disclosure-terminal?{missing_params}"):
            pass
    assert missing_target.value.code == 1008


def test_poc_terminal_websocket_rejects_bad_token_and_origin(tmp_path) -> None:
    app = _make_app(tmp_path)
    out = _make_output_dir(tmp_path)
    run_id = app.state.store.import_output_dir(out)
    client = TestClient(app)
    token = client.get("/api/config").json()["terminal_token"]

    with pytest.raises(WebSocketDisconnect) as bad_token:
        with client.websocket_connect(f"/ws/terminal/{run_id}/H-01?token=wrong"):
            pass
    assert bad_token.value.code == 1008

    with pytest.raises(WebSocketDisconnect) as bad_origin:
        with client.websocket_connect(
            f"/ws/terminal/{run_id}/H-01?token={token}",
            headers={"origin": "https://attacker.example"},
        ):
            pass
    assert bad_origin.value.code == 1008


def test_api_status_idle_before_any_job(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.get("/api/audit/status")
    assert res.status_code == 200
    assert res.json()["state"] == "idle"


def test_api_rejects_custom_target_and_unknown_repository(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/audit", json={"target": "/definitely/not/here"})
    assert res.status_code == 422

    res = client.post("/api/audit", json={"repository": "github.com/no/such"})
    assert res.status_code == 400
    assert "managed repository" in res.json()["detail"].lower()


def test_api_results_before_any_job_returns_404(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.get("/api/results").status_code == 404
    assert client.get("/api/results/file", params={"path": "x.json"}).status_code == 404
    assert client.get("/api/results/agent-log").status_code == 404


def test_api_serves_and_downloads_latest_agent_log(tmp_path) -> None:
    app = _make_app(tmp_path)
    output = Path(_make_output_dir(tmp_path))
    older = output / "stage1-security-context" / "agent.log"
    older.parent.mkdir(parents=True)
    older.write_text("older log\n", encoding="utf-8")
    latest = output / "stage3-findings" / "logs" / "AU-9.log"
    latest.parent.mkdir(parents=True)
    latest.write_text("latest complete Agent log\n", encoding="utf-8")
    older.touch()
    latest.touch()
    app.state.manager.config = AuditConfig(
        target=str(tmp_path), output_dir=str(output)
    )
    client = TestClient(app)

    response = client.get("/api/results/agent-log")
    assert response.status_code == 200
    assert response.text == "latest complete Agent log\n"
    assert response.headers["x-codeauditor-log-path"] == (
        "stage3-findings/logs/AU-9.log"
    )

    download = client.get("/api/results/agent-log", params={"download": "true"})
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]
    assert download.content == latest.read_bytes()


def test_api_stop_without_running_job_returns_409(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.post("/api/audit/stop").status_code == 409


def test_api_full_job_lifecycle_and_results(tmp_path, monkeypatch) -> None:
    async def fake_run_audit(config, tui=None):
        # Simulate stage output artifacts.
        findings_dir = tmp_path / "out" / "stage3-findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "AU-1-F-1.json").write_text("{}", encoding="utf-8")
        if tui:
            tui.begin_stage(0, "setup")
            tui.end_stage(0)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(
        job_module,
        "default_audit_output_dir",
        lambda target, results_dir=None: str(tmp_path / "out"),
    )

    app = _make_app(tmp_path)
    client = TestClient(app)
    _make_managed_repo(tmp_path)
    wiki = _make_managed_wiki(tmp_path)

    res = client.post(
        "/api/audit",
        json={"repository": "github.com/user/repo", "wiki": "qemu-security"},
    )
    assert res.status_code == 202

    status = _wait_for_state(app, "done")
    assert status["stages"][0]["status"] == "done"

    res = client.get("/api/results")
    assert res.status_code == 200
    assert "findings" not in res.json()

    res = client.get(
        "/api/results/file", params={"path": "stage3-findings/AU-1-F-1.json"}
    )
    assert res.status_code == 200
    assert res.text == "{}"

    res = client.get("/api/results/file", params={"path": "../../etc/passwd"})
    assert res.status_code == 400

    res = client.get("/api/results/file", params={"path": "nope.json"})
    assert res.status_code == 404

    # The completed job was recorded in the history database.
    runs, total = app.state.store.list_runs()
    assert total == 1
    assert runs[0]["status"] == "done"
    assert runs[0]["findings_count"] == 1
    assert app.state.manager.config is not None
    assert app.state.manager.config.backend == "claude"
    assert app.state.manager.config.model is None
    assert app.state.manager.config.log_level == "DEBUG"
    assert app.state.manager.config.wiki_path == wiki
    assert not hasattr(app.state.manager.config, "discovered_path")


# ── History API ──────────────────────────────────────────────────────────────


def test_api_history_empty(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.get("/api/history")
    assert res.status_code == 200
    body = res.json()
    assert body["runs"] == []
    assert body["total"] == 0
    assert body["db_path"].endswith("history.db")


def test_api_resumes_cancelled_history_run_in_place(tmp_path, monkeypatch) -> None:
    app = _make_app(tmp_path)
    target = _make_managed_repo(tmp_path)
    output = _make_output_dir(tmp_path)
    identity = {
        "repo_name": "repo",
        "repo_url": "https://github.com/user/repo.git",
        "branch": "main",
        "commit": "c" * 40,
        "dirty": False,
        "submodules": [],
    }
    run_id = app.state.store.create_run(
        AuditConfig(target=target, output_dir=output),
        status=RUN_CANCELLED,
        started_at=100.0,
    )
    app.state.store.set_run_identity(run_id, identity)
    audited = []

    async def fake_run_audit(config, tui=None):
        audited.append(config)

    monkeypatch.setattr(job_module, "capture_repo_identity", lambda _path: identity)

    async def fake_checkout(_target, commit, branch):
        assert commit == identity["commit"]
        assert branch == identity["branch"]

    monkeypatch.setattr(job_module, "_checkout_recorded_revision", fake_checkout)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    with TestClient(app) as client:
        response = client.post(f"/api/history/{run_id}/resume")
        assert response.status_code == 202
        assert response.json()["run_id"] == run_id
        assert response.json()["state"] == STATE_RESTORING
        _wait_for_state(app, STATE_DONE)

        detail = client.get(f"/api/history/{run_id}").json()
        assert detail["status"] == STATE_DONE
        assert detail["started_at"] == 100.0
        assert client.get("/api/history").json()["total"] == 1
        assert client.post(f"/api/history/{run_id}/resume").status_code == 400

    assert len(audited) == 1
    assert audited[0].output_dir == output
    assert audited[0].resume is True
    assert audited[0].update_repo is False


def test_api_resume_missing_history_run_returns_404(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.post("/api/history/999/resume").status_code == 404


def test_api_history_import_and_detail(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    client = TestClient(_make_app(tmp_path))

    res = client.post("/api/history/import", json={"output_dir": out})
    assert res.status_code == 201
    body = res.json()
    assert body["imported"] == 1
    run = body["runs"][0]
    assert run["status"] == "imported"
    assert run["vulns_count"] == 1

    run_id = run["id"]
    res = client.get(f"/api/history/{run_id}")
    assert res.status_code == 200
    detail = res.json()
    assert detail["vulnerabilities"][0]["vuln_id"] == "H-01"
    assert detail["vulnerabilities"][0]["cvss_score"] == 8.1
    assert detail["vulnerabilities"][0]["poc_status"] == "reproduced"

    res = client.get("/api/history")
    assert res.json()["total"] == 1

    res = client.get(
        f"/api/history/{run_id}/file",
        params={"path": "stage4-vulnerabilities/H-01.json"},
    )
    assert res.status_code == 200
    assert "Test vuln" in res.text

    res = client.get("/api/reproduction/candidates")
    assert res.status_code == 200
    candidates = res.json()["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["run_id"] == run_id
    assert candidates[0]["vuln_id"] == "H-01"
    assert candidates[0]["target"] == str(tmp_path / "results" / "test-project")
    assert candidates[0]["poc_status"] == "reproduced"
    assert "commit" in candidates[0]


def test_api_history_import_invalid_dir_returns_400(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.post(
        "/api/history/import", json={"output_dir": str(tmp_path / "missing")}
    )
    assert res.status_code == 400


def test_api_history_import_rejects_paths_outside_managed_results(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    client = TestClient(_make_app(tmp_path))

    res = client.post(
        "/api/history/import", json={"output_dir": str(outside)}
    )
    assert res.status_code == 400
    assert "managed results" in res.json()["detail"].lower()

    res = client.post(
        "/api/history/import",
        json={"output_dir": str(tmp_path / "results"), "target": "/tmp/repo"},
    )
    assert res.status_code == 422


def test_api_history_import_rejects_symlink_escape(tmp_path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    results = tmp_path / "results"
    results.mkdir()
    (results / "escape").symlink_to(outside, target_is_directory=True)
    client = TestClient(_make_app(tmp_path))

    res = client.post(
        "/api/history/import", json={"output_dir": str(results / "escape")}
    )
    assert res.status_code == 400
    assert "managed results" in res.json()["detail"].lower()


def test_api_history_run_not_found_returns_404(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.get("/api/history/999").status_code == 404
    assert (
        client.get("/api/history/999/file", params={"path": "x"}).status_code == 404
    )


def test_api_history_file_path_traversal_returns_400(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    client = TestClient(_make_app(tmp_path))
    run = client.post("/api/history/import", json={"output_dir": out}).json()["runs"][0]

    res = client.get(
        f"/api/history/{run['id']}/file", params={"path": "../../etc/passwd"}
    )
    assert res.status_code == 400


# ── git_url support ──────────────────────────────────────────────────────────


async def test_start_requires_target_or_git_url(tmp_path) -> None:
    manager = AuditJobManager()
    with pytest.raises(JobValidationError):
        await manager.start(AuditStartParams())


async def test_start_with_git_url_clones_then_audits(tmp_path, monkeypatch) -> None:
    cloned = tmp_path / "repos" / "github.com" / "user" / "repo"
    cloned.mkdir(parents=True)

    async def fake_ensure_repo(url, repos_dir):
        assert url == "https://github.com/user/repo.git"
        return str(cloned)

    seen: dict[str, str] = {}

    async def fake_run_audit(config, tui=None):
        seen["target"] = config.target

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    manager = AuditJobManager()
    await manager.start(
        AuditStartParams(
            git_url="https://github.com/user/repo.git",
            repos_dir=str(tmp_path / "repos"),
        )
    )
    await manager._task

    assert manager.state == STATE_DONE
    assert seen["target"] == str(cloned)
    assert manager.config is not None
    assert manager.config.target == str(cloned)


async def test_start_with_git_url_clone_failure_marks_failed(
    tmp_path, monkeypatch
) -> None:
    from code_auditor.repos import RepoError

    async def fake_ensure_repo(url, repos_dir):
        raise RepoError("git clone failed: repository not found")

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)

    manager = AuditJobManager()
    await manager.start(AuditStartParams(git_url="https://example.com/x/y.git"))
    await manager._task

    assert manager.state == STATE_FAILED
    assert "clone failed" in manager.error


def test_api_start_requires_target_or_git_url(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/audit", json={})
    assert res.status_code == 400


def test_api_audit_rejects_conflicting_or_hidden_configuration(tmp_path) -> None:
    repository = "github.com/user/repo"
    _make_managed_repo(tmp_path, repository)
    client = TestClient(_make_app(tmp_path))

    res = client.post(
        "/api/audit",
        json={
            "repository": repository,
            "git_url": "https://github.com/user/repo.git",
        },
    )
    assert res.status_code == 400

    for hidden_field, value in (
        ("target", "/tmp/project"),
        ("backend", "codex"),
        ("model", "gpt-5.5"),
        ("log_level", "INFO"),
        ("discovered", "/tmp/bugs.html"),
        ("output_dir", "/tmp/output"),
    ):
        res = client.post(
            "/api/audit",
            json={"repository": repository, hidden_field: value},
        )
        assert res.status_code == 422

    res = client.post(
        "/api/audit",
        json={"repository": repository, "wiki": "no-such-wiki"},
    )
    assert res.status_code == 400
    assert "managed local wiki" in res.json()["detail"].lower()


@pytest.mark.parametrize(
    "url",
    [
        "file:///tmp/repo",
        "http://github.com/user/repo.git",
        "https://127.0.0.1/user/repo.git",
        "https://user:password@github.com/user/repo.git",
        "ext::sh -c evil",
    ],
)
def test_api_audit_rejects_unsafe_clone_urls(tmp_path, url) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/audit", json={"git_url": url})
    assert res.status_code == 400


def test_api_reproduction_rejects_frontend_configuration_fields(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    for hidden_field, value in (
        ("backend", "codex"),
        ("model", "gpt-5.5"),
        ("log_level", "INFO"),
        ("output_dir", "/tmp/output"),
    ):
        res = client.post(
            "/api/reproduction",
            json={"run_id": 1, "vuln_id": "H-01", hidden_field: value},
        )
        assert res.status_code == 422


@pytest.mark.parametrize(
    "payload",
    [
        {"run_id": 0, "vuln_id": "H-01"},
        {"run_id": 1, "vuln_id": "../H-01"},
        {"run_id": 1, "vuln_id": "H 01"},
        {"run_id": 1, "vuln_id": "H-01;touch-pwned"},
    ],
)
def test_api_reproduction_rejects_invalid_candidate_ids(tmp_path, payload) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.post("/api/reproduction", json=payload).status_code == 422


def test_api_start_with_git_url(tmp_path, monkeypatch) -> None:
    cloned = tmp_path / "repo"
    cloned.mkdir()

    async def fake_ensure_repo(url, repos_dir):
        return str(cloned)

    async def fake_run_audit(config, tui=None):
        pass

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    app = _make_app(tmp_path)
    client = TestClient(app)
    res = client.post(
        "/api/audit", json={"git_url": "https://github.com/user/repo.git"}
    )
    assert res.status_code == 202
    _wait_for_state(app, "done")
    assert app.state.manager.config is not None
    assert app.state.manager.config.target == str(cloned)


# ── Repos & history target filter API ────────────────────────────────────────


def test_api_repos_lists_cloned_repos(tmp_path, monkeypatch) -> None:
    from code_auditor.web import server as server_module

    monkeypatch.setattr(
        server_module,
        "list_cloned_repos",
        lambda repos_dir=None: [
            {"name": "github.com/u/r", "path": "/repos/github.com/u/r"}
        ],
    )
    client = TestClient(_make_app(tmp_path))

    res = client.get("/api/repos")
    assert res.status_code == 200
    body = res.json()
    assert body["repos"] == [{"name": "github.com/u/r"}]
    assert body["repos_dir"]


def test_api_wikis_lists_only_opaque_local_names(tmp_path) -> None:
    _make_managed_wiki(tmp_path, "group/qemu-security")
    client = TestClient(_make_app(tmp_path))

    res = client.get("/api/wikis")

    assert res.status_code == 200
    assert res.json() == {
        "wikis_dir": str(tmp_path / "wiki"),
        "wikis": [{"name": "group/qemu-security"}],
    }


def test_api_history_filter_by_managed_repository(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    app = _make_app(tmp_path)
    repository = "github.com/user/repo"
    target = _make_managed_repo(tmp_path, repository)
    app.state.store.import_output_dir(out, target=target)
    client = TestClient(app)

    res = client.get("/api/history", params={"repository": repository})
    assert res.status_code == 200
    assert res.json()["total"] == 1

    res = client.get("/api/history", params={"repository": "github.com/no/such"})
    assert res.status_code == 400

    res = client.get("/api/history", params={"repository": "../../etc"})
    assert res.status_code == 400


# ── Results-tree batch import ────────────────────────────────────────────────


def _make_results_tree(base) -> str:
    """results/{qemu,other}/audit-output-YYYYMMDD layout with one vuln each."""
    root = base / "results"
    for project, day in (("qemu", "20260102"), ("other", "20260304")):
        vulns = root / project / f"audit-output-{day}" / "stage4-vulnerabilities"
        vulns.mkdir(parents=True)
        (vulns / "H-01.json").write_text(
            json.dumps(
                {
                    "id": "H-01",
                    "title": f"{project} vuln",
                    "location": "src/a.c:f (lines 1-2)",
                    "trigger": "crafted input",
                    "data_flow_trace": {"entry_point": "main", "sink": "memcpy"},
                    "cwe_id": ["CWE-120"],
                    "vulnerability_class": ["buffer-overflow"],
                    "cvss_score": 7.5,
                    "severity": "High",
                }
            ),
            encoding="utf-8",
        )
    return str(root)


def test_api_history_import_results_tree(tmp_path, monkeypatch) -> None:
    import code_auditor.db as db_module

    root = _make_results_tree(tmp_path)
    # A cloned repo named like the project gets linked as the run target.
    monkeypatch.setattr(
        db_module,
        "list_cloned_repos",
        lambda repos_dir=None: [{"name": "qemu", "path": "/repos/qemu"}],
    )

    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/history/import", json={"output_dir": root})
    assert res.status_code == 201
    body = res.json()
    assert body["imported"] == 2

    by_project = {r["output_dir"].split("/")[-2]: r for r in body["runs"]}
    assert by_project["qemu"]["target"] == "/repos/qemu"
    assert by_project["qemu"]["started_at"] is not None  # parsed from dir date
    assert by_project["other"]["target"].endswith("/other")


def test_api_history_import_tree_without_outputs_returns_400(tmp_path) -> None:
    empty = tmp_path / "results" / "empty"
    empty.mkdir(parents=True)
    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/history/import", json={"output_dir": str(empty)})
    assert res.status_code == 400


# ── Disclosures API ──────────────────────────────────────────────────────────


def test_api_disclosures_list_search_and_status(tmp_path) -> None:
    app = _make_app(tmp_path)
    app.state.store.import_output_dir(_make_output_dir(tmp_path))
    client = TestClient(app)

    res = client.get("/api/disclosures")
    data = res.json()
    assert len(data["entries"]) == 1
    assert data["matches"] == 1
    assert data["projects"] == ["test-project"]
    entry = data["entries"][0]

    res = client.get("/api/disclosures", params={"status": "unreviewed"})
    assert len(res.json()["entries"]) == 1
    res = client.get("/api/disclosures", params={"status": "confirmed"})
    assert res.json()["entries"] == []
    res = client.get("/api/disclosures", params={"q": "LOCAL CWE-120"})
    assert res.json()["matches"] == 1
    res = client.get("/api/disclosures", params={"q": "not-present"})
    assert res.json()["entries"] == []
    assert client.get("/api/disclosures", params={"q": "x" * 257}).status_code == 422

    for status in ("triage", "bug", "slop", "confirmed"):
        res = client.post(
            "/api/disclosures/status",
            json={
                "project": entry["project"],
                "dedupe_key": entry["dedupe_key"],
                "status": status,
            },
        )
        assert res.status_code == 200
        assert res.json()["counts"] == {status: 1}

    updated = client.put(
        "/api/disclosures",
        json={
            "project": entry["project"],
            "dedupe_key": entry["dedupe_key"],
            "title": "Reviewed vulnerability",
            "location": "src/reviewed.c:42",
            "cwe": "CWE-787",
            "vulnerability_class": "out-of-bounds-write",
            "trigger": "Crafted reviewed input",
            "summary": "Reviewed summary",
            "repo_url": "https://example.com/test-project",
            "audited_commit": "deadbeef",
            "audit_finished_date": "2026-08-04",
            "model_backend": "manual-review",
        },
    )
    assert updated.status_code == 200
    updated_entry = updated.json()["entry"]
    assert updated_entry["title"] == "Reviewed vulnerability"
    assert updated_entry["location"] == "src/reviewed.c:42"
    assert updated_entry["review_status"] == "confirmed"

    missing_update = client.put(
        "/api/disclosures",
        json={
            "project": entry["project"],
            "dedupe_key": "sha256:" + "0" * 64,
            "title": "Missing",
        },
    )
    assert missing_update.status_code == 404

    res = client.post(
        "/api/disclosures/status",
        json={
            "project": entry["project"],
            "dedupe_key": "sha256:" + "0" * 64,
            "status": "confirmed",
        },
    )
    assert res.status_code == 404

    res = client.post(
        "/api/disclosures/status",
        json={
            "project": entry["project"],
            "dedupe_key": entry["dedupe_key"],
            "status": "fixed",
        },
    )
    assert res.status_code == 422  # pydantic Literal validation


@pytest.mark.parametrize(
    "review_status",
    [
        "unreviewed",
        "reported",
        "confirmed",
        "rejected",
        "duplicated",
        "triage",
        "bug",
        "slop",
    ],
)
def test_api_any_disclosure_moves_to_trash_and_restores(
    tmp_path, review_status: str
) -> None:
    app = _make_app(tmp_path)
    app.state.store.import_output_dir(_make_output_dir(tmp_path))
    client = TestClient(app)
    entry = client.get("/api/disclosures").json()["entries"][0]
    identity = {
        "project": entry["project"],
        "dedupe_key": entry["dedupe_key"],
    }

    assert client.post(
        "/api/disclosures/status", json={**identity, "status": review_status}
    ).status_code == 200
    moved = client.post("/api/disclosures/trash", json=identity)
    assert moved.status_code == 200
    assert moved.json()["retention_days"] == 30
    assert client.get("/api/disclosures").json()["entries"] == []

    trash = client.get("/api/disclosures/trash").json()
    assert trash["total"] == 1
    assert trash["matches"] == 1
    assert trash["projects"] == ["test-project"]
    assert trash["entries"][0]["review_status"] == review_status
    assert trash["entries"][0]["purge_at"] > trash["entries"][0]["deleted_at"]
    assert client.get(
        "/api/disclosures/artifact",
        params={**identity, "artifact": 0},
    ).status_code == 404
    assert client.post(
        "/api/disclosures/status", json={**identity, "status": "reported"}
    ).status_code == 404

    restored = client.post("/api/disclosures/restore", json=identity)
    assert restored.status_code == 200
    active = client.get("/api/disclosures").json()["entries"]
    assert len(active) == 1
    assert active[0]["review_status"] == review_status
    assert client.get("/api/disclosures/trash").json()["total"] == 0


def test_api_disclosure_artifact_uses_database_registered_path(tmp_path) -> None:
    app = _make_app(tmp_path)
    app.state.store.import_output_dir(_make_output_dir(tmp_path))
    client = TestClient(app)

    disclosure = client.get("/api/disclosures").json()["entries"][0]
    report_artifact = next(
        artifact
        for artifact in disclosure["artifacts"]
        if artifact["label"] == "Stage 6 Report"
    )

    response = client.get(
        "/api/disclosures/artifact",
        params={
            "project": disclosure["project"],
            "dedupe_key": disclosure["dedupe_key"],
            "artifact": report_artifact["index"],
        },
    )
    assert response.status_code == 200
    assert response.content == b"# Local vulnerability report\n"
    assert client.get(
        "/api/disclosures/artifact",
        params={
            "project": disclosure["project"],
            "dedupe_key": disclosure["dedupe_key"],
            "artifact": 32,
        },
    ).status_code == 404


def test_api_serves_registered_graph_and_asan_to_disclosure_and_cve(tmp_path) -> None:
    app = _make_app(tmp_path)
    output_dir = _make_output_dir(tmp_path)
    _write_web_stage5_evidence(output_dir)
    app.state.store.import_output_dir(output_dir)
    client = TestClient(app)

    disclosure = client.get("/api/disclosures").json()["entries"][0]
    artifacts = {item["label"]: item for item in disclosure["artifacts"]}
    assert "Stage 5 Trigger Graph" in artifacts
    assert "Stage 5 ASan Report" in artifacts

    identity = {
        "project": disclosure["project"],
        "dedupe_key": disclosure["dedupe_key"],
    }
    graph_response = client.get(
        "/api/disclosures/artifact",
        params={**identity, "artifact": artifacts["Stage 5 Trigger Graph"]["index"]},
    )
    assert graph_response.status_code == 200
    assert graph_response.json()["nodes"][1]["role"] == "sink"
    asan_response = client.get(
        "/api/disclosures/artifact",
        params={**identity, "artifact": artifacts["Stage 5 ASan Report"]["index"]},
    )
    assert asan_response.status_code == 200
    assert "AddressSanitizer: heap-buffer-overflow" in asan_response.text

    assert app.state.store.set_disclosed_status(
        disclosure["project"], disclosure["dedupe_key"], "confirmed"
    )
    imported = client.post(
        "/api/cves",
        json={
            "cve_id": "CVE-2026-12345",
            "dedupe_keys": [disclosure["dedupe_key"]],
        },
    )
    assert imported.status_code == 201
    cve_artifacts = {
        item["label"]
        for item in imported.json()["entry"]["local_disclosures"][0]["artifacts"]
    }
    assert cve_artifacts >= {"Stage 5 Trigger Graph", "Stage 5 ASan Report"}


def test_api_target_merged(tmp_path, monkeypatch) -> None:
    out = _make_output_dir(tmp_path)
    app = _make_app(tmp_path)
    client = TestClient(app)
    run_id = app.state.store.import_output_dir(out)
    run = app.state.store.get_run(run_id)
    assert run is not None
    target_key = "sha256:" + "1" * 64

    # Imported non-git target has no target_key; simulate one.
    with app.state.store._connect() as conn:
        conn.execute(
            "UPDATE runs SET target_key = ?, repo_name = 'qemu' WHERE id = ?",
            (target_key, run["id"]),
        )

    res = client.get(f"/api/target/{target_key}")
    assert res.status_code == 200
    body = res.json()
    assert len(body["runs"]) == 1
    assert body["vulnerabilities"][0]["vuln_id"] == "H-01"

    assert client.get("/api/target/sha256:nope").status_code == 400
    assert (
        client.get("/api/target/" + "sha256:" + "2" * 64).status_code == 404
    )
