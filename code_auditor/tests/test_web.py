from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from code_auditor import agent as agent_module
from code_auditor.config import AuditConfig
from code_auditor.db import (
    RUN_CANCELLED,
    RUN_DONE,
    RUN_FAILED,
    RUN_KIND_MAINTENANCE,
    RUN_SUPERSEDED,
    AuditStore,
    compute_target_key,
)
from code_auditor.process_tree import CURRENT_AUDIT_PROCESS_MARKER
from code_auditor.web import create_app
from code_auditor.web import job as job_module
from code_auditor.web import server as server_module
from code_auditor.web.job import (
    STATE_CANCELLED,
    STATE_DONE,
    STATE_FAILED,
    STATE_RESTORING,
    STATE_RUNNING,
    AuditJob,
    AuditJobManager,
    AuditStartParams,
    JobConflictError,
    JobValidationError,
    ReproductionStartParams,
)
from code_auditor.web.progress import (
    CURRENT_JOB_KEY,
    EventBus,
    WebLogHandler,
    WebProgressReporter,
)
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


def _log_record(msg: str, args: tuple = (), level: int = logging.INFO):
    return logging.LogRecord(
        name="code_auditor.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


def test_web_log_handler_publishes_log_events() -> None:
    bus = EventBus()
    handler = WebLogHandler(lambda key: bus if key == "job-1" else None)
    token = CURRENT_JOB_KEY.set("job-1")
    try:
        handler.emit(_log_record("hello %s", ("world",)))
    finally:
        CURRENT_JOB_KEY.reset(token)

    events = bus.backlog()
    assert len(events) == 1
    assert events[0]["type"] == "log"
    assert events[0]["level"] == "INFO"
    assert "hello world" in events[0]["message"]


def test_web_log_handler_routes_records_to_the_owning_job() -> None:
    bus_a = EventBus()
    bus_b = EventBus()
    buses = {"job-a": bus_a, "job-b": bus_b}
    handler = WebLogHandler(buses.get)

    token = CURRENT_JOB_KEY.set("job-b")
    try:
        handler.emit(_log_record("for job b"))
    finally:
        CURRENT_JOB_KEY.reset(token)
    # Records logged outside any job task are dropped from the web stream.
    handler.emit(_log_record("no job context"))
    token = CURRENT_JOB_KEY.set("job-a")
    try:
        handler.emit(_log_record("for job a"))
    finally:
        CURRENT_JOB_KEY.reset(token)

    assert len(bus_a.backlog()) == 1
    assert "for job a" in bus_a.backlog()[0]["message"]
    assert len(bus_b.backlog()) == 1
    assert "for job b" in bus_b.backlog()[0]["message"]


def test_web_log_handler_bounds_oversized_backend_output() -> None:
    bus = EventBus()
    handler = WebLogHandler(lambda key: bus)
    token = CURRENT_JOB_KEY.set("job-1")
    try:
        handler.emit(_log_record("x" * 50_000, level=logging.ERROR))
    finally:
        CURRENT_JOB_KEY.reset(token)

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


async def test_start_maps_local_worktree_mode_to_runtime_flags(
    tmp_path, monkeypatch
) -> None:
    captured = []

    async def fake_run_audit(config, reporter=None):
        captured.append(config)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()

    job = await manager.start(
        AuditStartParams(
            target=str(tmp_path),
            results_dir=str(tmp_path / "results"),
            sandbox_mode="local-worktree",
        )
    )
    await job.task

    assert captured[0].sandbox_enabled is False
    assert captured[0].sandbox_network_enabled is False
    assert job.status()["sandbox_mode"] == "local-worktree"


async def test_start_conflict_while_running(tmp_path, monkeypatch) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
        started.set()
        await release.wait()

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    await asyncio.wait_for(started.wait(), timeout=1)

    # A second job on the same repository is rejected…
    with pytest.raises(JobConflictError):
        await manager.start(AuditStartParams(target=str(tmp_path)))

    release.set()
    await job.task
    assert job.state == STATE_DONE


async def test_start_preparation_does_not_block_event_loop(
    tmp_path, monkeypatch
) -> None:
    release = threading.Event()

    def blocking_seed(self, config):  # type: ignore[no-untyped-def]
        assert release.wait(timeout=1), "event loop was blocked by run preparation"

    async def fake_run_audit(config, reporter=None):
        return None

    monkeypatch.setattr(AuditJob, "_seed_analysis_units", blocking_seed)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    asyncio.get_running_loop().call_later(0.01, release.set)

    await job.task

    assert release.is_set()
    assert job.state == STATE_DONE


async def test_manager_hot_switches_active_run_config_params_and_history(
    tmp_path, monkeypatch
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
        started.set()
        await release.wait()

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    target = tmp_path / "target"
    target.mkdir()
    store = AuditStore(str(tmp_path / "history.db"))
    manager = AuditJobManager(store=store)
    params = AuditStartParams(
        target=str(target),
        results_dir=str(tmp_path / "results"),
        backend="codex",
        model="old-model",
        provider_mode="custom",
        provider_base_url="https://old.example.test/v1",
        provider_api_key="old-secret",
    )
    job = await manager.start(params)
    await asyncio.wait_for(started.wait(), timeout=1)

    switched = manager.hot_switch_agent_settings(
        backend="claude",
        model="new-model",
        provider_mode="custom",
        provider_base_url="https://new.example.test/v1",
        provider_api_key="new-secret",
    )

    assert switched == [job.job_key]
    assert job.status()["backend"] == "claude"
    assert job.status()["model"] == "new-model"
    assert job.status()["provider_mode"] == "custom"
    assert job.config is not None
    assert job.config.provider_base_url == "https://new.example.test/v1"
    assert job.config.provider_api_key == "new-secret"
    assert params.backend == "claude"
    assert params.model == "new-model"
    assert params.provider_base_url == "https://new.example.test/v1"
    assert params.provider_api_key == "new-secret"
    assert job.run_id is not None
    history = store.get_run(job.run_id)
    assert history is not None
    assert history["backend"] == "claude"
    assert history["model"] == "new-model"
    assert any(
        event.get("type") == "log" and "subsequent calls" in event.get("message", "")
        for event in job.bus.backlog()
    )
    assert manager.hot_switch_agent_settings(
        backend="claude",
        model="new-model",
        provider_mode="custom",
        provider_base_url="https://new.example.test/v1",
        provider_api_key="new-secret",
    ) == []

    release.set()
    await job.task
    assert job.state == STATE_DONE


async def test_manager_hot_switch_appends_actual_backend_after_prior_and_persists(
    tmp_path, monkeypatch
) -> None:
    codex_started = asyncio.Event()
    release_codex = asyncio.Event()
    claude_started = asyncio.Event()
    release_claude = asyncio.Event()

    async def fake_codex_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
        codex_started.set()
        await release_codex.wait()
        return "codex-result"

    async def fake_claude_agent(*_args, **_kwargs) -> str:  # type: ignore[no-untyped-def]
        claude_started.set()
        await release_claude.wait()
        return "claude-result"

    async def fake_run_audit(config, reporter=None):
        assert (
            await agent_module.run_agent("first", config, cwd=config.target)
            == "codex-result"
        )
        assert (
            await agent_module.run_agent("second", config, cwd=config.target)
            == "claude-result"
        )

    monkeypatch.setattr(agent_module, "_run_codex_agent", fake_codex_agent)
    monkeypatch.setattr(agent_module, "_run_claude_agent", fake_claude_agent)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    target = tmp_path / "target"
    target.mkdir()
    store = AuditStore(str(tmp_path / "history.db"))
    manager = AuditJobManager(store=store)
    job = await manager.start(
        AuditStartParams(
            target=str(target),
            results_dir=str(tmp_path / "results"),
            backend="codex",
            model="codex-model",
            provider_mode="custom",
            provider_base_url="https://codex.example.test/v1",
            provider_api_key="codex-secret",
        )
    )
    await asyncio.wait_for(codex_started.wait(), timeout=1)

    assert manager.hot_switch_agent_settings(
        backend="claude",
        model="claude-model",
        provider_mode="custom",
        provider_base_url="https://claude.example.test/v1",
        provider_api_key="claude-secret",
    ) == [job.job_key]
    assert job.status()["backends_used"] == ["codex"]
    release_codex.set()
    await asyncio.wait_for(claude_started.wait(), timeout=1)

    assert job.state == STATE_RUNNING
    assert job.status()["backends_used"] == ["codex", "claude"]
    live_history_events = [
        event
        for event in job.bus.backlog()
        if event.get("type") == "job" and event.get("agent_history_updated")
    ]
    assert [event["backends_used"] for event in live_history_events] == [
        ["codex"],
        ["codex", "claude"],
    ]
    assert job.run_id is not None
    running_history = store.get_run(job.run_id)
    assert running_history is not None
    assert json.loads(running_history["backends_used"]) == ["codex", "claude"]
    assert json.loads(running_history["models_used"]) == [
        "codex-model",
        "claude-model",
    ]

    release_claude.set()
    await job.task

    assert job.state == STATE_DONE
    assert job.status()["backends_used"] == ["codex", "claude"]
    history = store.get_run(job.run_id)
    assert history is not None
    assert json.loads(history["backends_used"]) == ["codex", "claude"]
    assert json.loads(history["models_used"]) == ["codex-model", "claude-model"]


async def test_concurrent_jobs_on_different_targets(tmp_path, monkeypatch) -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    running = 0

    async def fake_run_audit(config, reporter=None):
        nonlocal running
        running += 1
        if running == 2:
            started.set()
        await release.wait()

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    target_a = tmp_path / "a"
    target_b = tmp_path / "b"
    target_a.mkdir()
    target_b.mkdir()
    manager = AuditJobManager()
    job_a = await manager.start(AuditStartParams(target=str(target_a)))
    job_b = await manager.start(AuditStartParams(target=str(target_b)))
    await asyncio.wait_for(started.wait(), timeout=1)

    # Both jobs run concurrently, each with its own event bus.
    assert job_a.job_key != job_b.job_key
    assert job_a.bus is not job_b.bus
    assert {j.job_key for j in manager._active_jobs()} == {
        job_a.job_key,
        job_b.job_key,
    }
    assert {j["job_key"] for j in manager.list_jobs()} == {
        job_a.job_key,
        job_b.job_key,
    }

    release.set()
    await asyncio.gather(job_a.task, job_b.task)
    assert job_a.state == STATE_DONE
    assert job_b.state == STATE_DONE
    # Each job bus carried its own lifecycle events, tagged with its run key.
    for job in (job_a, job_b):
        job_events = [e for e in job.bus.backlog() if e["type"] == "job"]
        assert job_events
        assert all(e["job_key"] == job.job_key for e in job_events)
    # The manager-level bus saw both jobs' lifecycle events.
    global_keys = {
        e["job_key"] for e in manager.bus.backlog() if e["type"] == "job"
    }
    assert global_keys == {job_a.job_key, job_b.job_key}


async def test_job_launch_sets_run_process_marker(tmp_path, monkeypatch) -> None:
    observed_markers: list[str | None] = []

    async def fake_run_audit(config, reporter=None):
        observed_markers.append(CURRENT_AUDIT_PROCESS_MARKER.get())

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    await job.task

    assert observed_markers == [job.process_marker]


async def test_concurrent_job_limit_is_enforced(tmp_path, monkeypatch) -> None:
    release = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
        await release.wait()

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    target_a = tmp_path / "a"
    target_b = tmp_path / "b"
    target_a.mkdir()
    target_b.mkdir()
    manager = AuditJobManager(max_concurrent_jobs=1)
    first = await manager.start(AuditStartParams(target=str(target_a)))

    with pytest.raises(JobConflictError, match="limit"):
        await manager.start(AuditStartParams(target=str(target_b)))

    release.set()
    await first.task
    # Once the first job finished, the slot is free again.
    second = await manager.start(AuditStartParams(target=str(target_b)))
    await second.task
    assert second.state == STATE_DONE


async def test_stop_cancels_running_job(tmp_path, monkeypatch) -> None:
    started = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    await asyncio.wait_for(started.wait(), timeout=1)

    assert manager.stop(job.job_key) is job
    await job.task
    assert job.state == STATE_CANCELLED
    assert manager.stop(job.job_key) is None


async def test_start_rejects_low_history_database_free_space(
    tmp_path, monkeypatch
) -> None:
    store = AuditStore(str(tmp_path / "history.db"))
    manager = AuditJobManager(store=store)
    monkeypatch.setattr(
        job_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(
            free=job_module.MIN_HISTORY_WRITE_FREE_BYTES - 1
        ),
    )

    with pytest.raises(JobValidationError, match="preserve terminal state"):
        await manager.start(
            AuditStartParams(
                target=str(tmp_path),
                output_dir=str(tmp_path / "output"),
            )
        )

    runs, total = store.list_runs()
    assert runs == []
    assert total == 0


async def test_resume_rejects_low_history_database_free_space(
    tmp_path, monkeypatch
) -> None:
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(
        AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path / "output"),
        )
    )
    store.finish_run(run_id, RUN_CANCELLED, "stopped")
    manager = AuditJobManager(store=store)
    monkeypatch.setattr(
        job_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=0),
    )

    with pytest.raises(JobValidationError, match="preserve terminal state"):
        await manager.resume_cancelled(run_id)

    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_CANCELLED


async def test_terminal_history_write_retries_after_disk_full(
    tmp_path, monkeypatch
) -> None:
    async def fake_run_audit(config, reporter=None):
        config.task_errors.append("stage6: disk full")

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    store = AuditStore(str(tmp_path / "history.db"))
    real_finish_run = store.finish_run
    attempts = 0

    def flaky_finish_run(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise sqlite3.OperationalError("database or disk is full")
        return real_finish_run(*args, **kwargs)

    monkeypatch.setattr(store, "finish_run", flaky_finish_run)
    manager = AuditJobManager(store=store)
    job = await manager.start(
        AuditStartParams(
            target=str(tmp_path),
            output_dir=str(tmp_path / "output"),
        )
    )
    await job.task

    assert job.state == STATE_FAILED
    assert job.history_persist_pending is True
    assert store.get_run(job.run_id)["status"] == STATE_RUNNING

    job._next_history_retry_at = 0.0
    statuses = manager.list_jobs()

    assert statuses[0]["history_persist_pending"] is False
    run = store.get_run(job.run_id)
    assert run is not None
    assert run["status"] == RUN_FAILED
    assert run["ended_at"] is not None


async def test_shutdown_cancels_and_persists_running_audit(
    tmp_path, monkeypatch
) -> None:
    started = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
        started.set()
        await asyncio.sleep(3600)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    store = job_module.AuditStore(str(tmp_path / "history.db"))
    manager = AuditJobManager(store=store)
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    await asyncio.wait_for(started.wait(), timeout=1)
    run_id = job.status()["run_id"]

    await manager.shutdown()

    assert job.state == STATE_CANCELLED
    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_CANCELLED
    assert "Web worker exited" in run["error"]
    assert run["ended_at"] is not None


async def test_status_releases_busy_state_without_a_live_task(tmp_path) -> None:
    store = job_module.AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(
        AuditConfig(target=str(tmp_path), output_dir=str(tmp_path / "output"))
    )
    manager = AuditJobManager(store=store)
    job = AuditJob(manager, "audit")
    job.state = STATE_RUNNING
    job.run_id = run_id
    job.job_key = str(run_id)
    manager._jobs[job.job_key] = job

    status = job.status()

    assert status["state"] == STATE_CANCELLED
    assert store.get_run(run_id)["status"] == RUN_CANCELLED


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
        "backends_used": '["claude"]',
        "models_used": '["old-model"]',
        "usage_stats": '{"agent_calls": 5, "input_tokens": 900, "cost_usd": 0.5}',
        "duration_seconds": 75.0,
        "duration_known": 0,
    }

    class FakeStore:
        def __init__(self):
            self.resumed = []
            self.finished = []

        def get_run(self, run_id):
            return run if run_id == 17 else None

        def disclosure_dedupe_index(self):
            return []

        def resume_cancelled_run(
            self, run_id, *, resumed_at=None, backend=None, model=None
        ):
            self.resumed.append((run_id, resumed_at, backend, model))
            run["status"] = "running"
            return True

        def seed_analysis_units(self, target_key, output_dir):
            return 0

        def finish_run(
            self,
            run_id,
            status,
            error,
            ended_at,
            backends_used=None,
            models_used=None,
            usage_stats=None,
        ):
            self.finished.append(
                (
                    run_id,
                    status,
                    error,
                    ended_at,
                    backends_used,
                    models_used,
                    usage_stats,
                )
            )

    audited = []
    checkouts = []
    checkout_started = asyncio.Event()
    checkout_release = asyncio.Event()

    async def fake_run_audit(config, reporter=None):
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

    job = await manager.resume_cancelled(
        17,
        repos_dir=str(tmp_path / "repo"),
        results_dir=str(tmp_path / "results"),
        wikis_dir=str(tmp_path / "wiki"),
        backend="codex",
        provider_mode="custom",
        provider_base_url="https://codex.example.test/v1",
        provider_api_key="secret-key",
        model="fresh-codex-model",
    )
    assert job.state == STATE_RESTORING
    restoring_status = job.status()
    assert restoring_status["duration_seconds"] == 75.0
    assert restoring_status["active_started_at"] == job.started_at
    assert restoring_status["duration_known"] is False
    await asyncio.wait_for(checkout_started.wait(), timeout=1)
    with pytest.raises(JobConflictError):
        await manager.resume_cancelled(
            17,
            repos_dir=str(tmp_path / "repo"),
            results_dir=str(tmp_path / "results"),
            wikis_dir=str(tmp_path / "wiki"),
        )
    checkout_release.set()
    await job.task

    assert len(store.resumed) == 1
    assert store.resumed[0][0] == 17
    assert store.resumed[0][1:] == (job.started_at, "codex", "fresh-codex-model")
    assert checkouts == [(str(target), "a" * 40, "main")]
    assert job.state == STATE_DONE
    assert job.status()["run_id"] == 17
    assert job.status()["duration_seconds"] >= 75.0
    assert job.status()["active_started_at"] == 0.0
    assert job.status()["duration_known"] is False
    assert len(audited) == 1
    assert audited[0].target == str(target)
    assert audited[0].output_dir == str(output)
    assert audited[0].resume is True
    assert audited[0].update_repo is False
    assert audited[0].backend == "codex"
    assert audited[0].sandbox_enabled is True
    assert audited[0].sandbox_network_enabled is True
    assert audited[0].provider_mode == "custom"
    assert audited[0].provider_base_url == "https://codex.example.test/v1"
    assert audited[0].provider_api_key == "secret-key"
    assert audited[0].model == "fresh-codex-model"
    # Accounting from the original session is carried into the resumed run so
    # the finish update extends it instead of overwriting it.
    assert audited[0].backends_used == ["claude"]
    assert audited[0].models_used == ["old-model"]
    assert audited[0].usage_stats == {
        "agent_calls": 5.0,
        "input_tokens": 900.0,
        "cost_usd": 0.5,
    }
    assert store.finished[0][0:3] == (17, STATE_DONE, "")
    assert store.finished[0][4] == ["claude"]


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

        def resume_cancelled_run(
            self, run_id, *, resumed_at=None, backend=None, model=None
        ):
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

    job = await manager.resume_cancelled(
        9,
        repos_dir=str(tmp_path / "repo"),
        results_dir=str(tmp_path / "results"),
        wikis_dir=str(tmp_path / "wiki"),
    )
    assert job.state == STATE_RESTORING
    await job.task

    assert job.state == STATE_FAILED
    assert job.error == "Cannot restore recorded checkout"
    assert store.resumed == []


async def test_resume_cancelled_job_auto_stashes_dirty_checkout(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "repo" / "example.com" / "team" / "project"
    output = tmp_path / "results" / "project" / "audit-output-deadbeef"
    target.mkdir(parents=True)
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
        "id": 21,
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
        "branch": "main",
        "commit": "a" * 40,
        "target_key": compute_target_key(identity),
    }

    class FakeStore:
        def get_run(self, run_id):
            return run if run_id == 21 else None

        def disclosure_dedupe_index(self):
            return []

        def resume_cancelled_run(
            self, run_id, *, resumed_at=None, backend=None, model=None
        ):
            run["status"] = "running"
            return True

        def seed_analysis_units(self, target_key, output_dir):
            return 0

        def finish_run(self, *args):
            pass

    state = {"dirty": True}
    git_calls = []

    async def fake_git(_target, *args, timeout_seconds=60.0):
        git_calls.append(args)
        if args[:2] == ("stash", "push"):
            state["dirty"] = False
        return ""

    async def fake_checkout(*args):
        pass

    async def fake_run_audit(config, reporter=None):
        pass

    monkeypatch.setattr(
        job_module,
        "capture_repo_identity",
        lambda _path: dict(identity, dirty=state["dirty"]),
    )
    monkeypatch.setattr(job_module, "_run_resume_git_command", fake_git)
    monkeypatch.setattr(job_module, "_checkout_recorded_revision", fake_checkout)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager(store=FakeStore())

    job = await manager.resume_cancelled(
        21,
        repos_dir=str(tmp_path / "repo"),
        results_dir=str(tmp_path / "results"),
        wikis_dir=str(tmp_path / "wiki"),
    )
    await job.task

    assert git_calls and git_calls[0][:3] == (
        "stash",
        "push",
        "--include-untracked",
    )
    assert job.state == STATE_DONE


async def test_stash_resume_leftovers_includes_untracked_files(tmp_path) -> None:
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
    git("config", "user.name", "Test User")
    tracked = repo / "tracked.txt"
    tracked.write_text("original\n", encoding="utf-8")
    git("add", "tracked.txt")
    git("commit", "-m", "initial")

    tracked.write_text("modified\n", encoding="utf-8")
    untracked = repo / ".audit_tmp_au8" / "modeling_probe.py"
    untracked.parent.mkdir()
    untracked.write_text("probe = True\n", encoding="utf-8")

    await job_module._stash_resume_leftovers(str(repo), 23)

    assert git("status", "--porcelain") == ""
    assert git("stash", "list", "--format=%s").splitlines()[0] == (
        "On main: code-auditor auto-stash before resuming run #23"
    )
    assert set(
        git("stash", "show", "--include-untracked", "--name-only").splitlines()
    ) == {"tracked.txt", ".audit_tmp_au8/modeling_probe.py"}


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
    async def fake_run_audit(config, reporter=None):
        raise RuntimeError("boom")

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    manager = AuditJobManager()
    job = await manager.start(AuditStartParams(target=str(tmp_path)))
    await job.task

    assert job.state == STATE_FAILED
    assert job.error == "boom"
    status = job.status()
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
        assert config.sandbox_enabled is True
        assert config.sandbox_network_enabled is False
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

    job = await manager.start_reproduction(
        ReproductionStartParams(
            run_id=7,
            vuln_id="H-03",
            backend="codex",
            output_dir=str(reproduction_root),
            wikis_dir=str(tmp_path / "wikis"),
            sandbox_mode="docker-isolated",
        )
    )
    await job.task

    assert job.state == STATE_DONE
    assert job.kind == "reproduction"
    assert job.job_key.startswith("repro-")
    assert job.config is not None
    assert job.config.target == str(reproduction_root / "source")
    assert job.config.output_dir == str(reproduction_root / "output")
    assert job.reproduction_candidate["vuln_id"] == "H-03"
    assert len(job.reproduction_reports) == 1


# ── HTTP API ─────────────────────────────────────────────────────────────────


def _make_app(tmp_path):
    """create_app with an isolated history database."""
    return create_app(
        db_path=str(tmp_path / "history.db"),
        web_settings=WebSettings.for_state_dir(
            str(tmp_path), sandbox_mode="local-worktree"
        ),
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


def _write_web_stage6_retention(output_dir: str) -> Path:
    disclosure = (
        Path(output_dir) / "stage6-disclosures" / "H-01" / "disclosure"
    )
    reproduce = disclosure / "reproduce.sh"
    reproduce.write_text("#!/bin/sh\nprintf 'reproduced\\n'\n", encoding="utf-8")
    reproduce.chmod(0o700)
    manifest = disclosure / "retain-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "entrypoint": "reproduce.sh",
                "files": [
                    {"path": "report.md", "role": "report"},
                    {"path": "reproduce.sh", "role": "entrypoint"},
                ],
            }
        ),
        encoding="utf-8",
    )
    manifest.chmod(0o600)
    return disclosure


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
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in memcpy src/a.c:2\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow src/a.c:2 in memcpy\n",
        encoding="utf-8",
    )


def _wait_for_state(app, state: str, timeout: float = 5.0) -> dict:
    deadline = time.time() + timeout
    status: dict | None = None
    while time.time() < deadline:
        for status in app.state.manager.list_jobs():
            if status["state"] == state:
                return status
        time.sleep(0.05)
    raise AssertionError(f"no job reached state {state}: {status}")


def test_api_config_returns_defaults(tmp_path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    res = client.get("/api/config")
    assert res.status_code == 200
    body = res.json()
    assert body["defaults"]["max_parallel"] == 1
    assert body["config_path"].endswith("settings.json")
    assert "discovered_path" not in body
    assert body["wikis_dir"] == str(tmp_path / "wiki")
    assert body["terminal_enabled"] is True
    assert len(body["terminal_token"]) >= 32
    assert body["capabilities"]["dashboard_summary"] is True
    assert "backends" not in body
    assert "default_models" not in body


def test_api_dashboard_returns_compact_operational_summary(tmp_path) -> None:
    app = _make_app(tmp_path)
    output_dir = _make_output_dir(tmp_path)
    run_id = app.state.store.import_output_dir(output_dir)
    _make_managed_repo(tmp_path, "github.com/user/dashboard-repo")

    response = TestClient(app).get("/api/dashboard")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    body = response.json()
    assert body["runs"] == {
        "total": 1,
        "counts": {"imported": 1},
        "reproduced": 1,
    }
    assert body["recent_runs"][0]["id"] == run_id
    assert body["recent_runs"][0]["reproduced_vulns_count"] == 1
    assert body["disclosures"]["total"] == 1
    assert body["cves"]["total"] == 0
    assert body["trash"]["total"] == 0
    assert body["repositories"]["total"] == 1
    assert body["jobs"] == []
    assert body["runtime"] == {
        "backend": "claude",
        "sandbox_mode": "local-worktree",
    }


def test_api_sandbox_capability_reports_server_check(tmp_path, monkeypatch) -> None:
    capability = SimpleNamespace(
        available=True,
        reason="runtime ready",
        public=lambda: {
            "available": True,
            "reason": "runtime ready",
            "image": "sandbox:test",
            "free_bytes": 12_345,
            "minimum_free_bytes": 100,
        },
    )
    monkeypatch.setattr(
        server_module,
        "inspect_docker_sandbox_environment",
        lambda backend: capability if backend == "codex" else None,
    )

    response = TestClient(_make_app(tmp_path)).get(
        "/api/sandbox/capability?backend=codex"
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["docker"] == capability.public()
    assert response.json()["local_worktree"]["available"] is True


def test_api_rejects_unavailable_docker_sandbox_setting(tmp_path, monkeypatch) -> None:
    capability = SimpleNamespace(available=False, reason="sandbox image missing")
    monkeypatch.setattr(
        server_module,
        "inspect_docker_sandbox_environment",
        lambda _backend: capability,
    )
    client = TestClient(_make_app(tmp_path))

    response = client.put(
        "/api/settings",
        json={
            "backend": "claude",
            "mode": "local",
            "base_url": "",
            "model": "",
            "sandbox_mode": "docker-isolated",
        },
    )

    assert response.status_code == 400
    assert "sandbox image missing" in response.json()["detail"]
    assert client.get("/api/settings").json()["sandbox_mode"] == "local-worktree"


def test_api_revalidates_docker_sandbox_before_start(tmp_path, monkeypatch) -> None:
    repository = "github.com/user/repo"
    _make_managed_repo(tmp_path, repository)
    settings = WebSettings.for_state_dir(str(tmp_path))
    app = create_app(db_path=str(tmp_path / "history.db"), web_settings=settings)
    capability = SimpleNamespace(available=False, reason="Docker daemon stopped")
    monkeypatch.setattr(
        server_module,
        "inspect_docker_sandbox_environment",
        lambda _backend: capability,
    )

    response = TestClient(app).post("/api/audit", json={"repository": repository})

    assert response.status_code == 400
    assert "Docker daemon stopped" in response.json()["detail"]


def test_api_settings_persists_provider_without_returning_api_key(tmp_path) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)

    initial = client.get("/api/settings")
    assert initial.status_code == 200
    assert initial.headers["cache-control"] == "no-store"
    assert initial.json()["backend"] == "claude"
    assert initial.json()["sandbox_mode"] == "local-worktree"
    assert initial.json()["providers"]["codex"]["mode"] == "local"

    saved = client.put(
        "/api/settings",
        json={
            "backend": "codex",
            "mode": "custom",
            "base_url": "https://models.example.test/v1",
            "api_key": "secret-key",
            "model": "coder-model",
            "sandbox_mode": "local-worktree",
        },
    )

    assert saved.status_code == 200
    assert saved.headers["cache-control"] == "no-store"
    body = saved.json()
    assert body["backend"] == "codex"
    assert body["sandbox_mode"] == "local-worktree"
    assert body["providers"]["codex"]["api_key_configured"] is True
    assert body["active_jobs_updated"] == 0
    assert "secret-key" not in saved.text
    stored = json.loads((tmp_path / "settings.json").read_text(encoding="utf-8"))
    assert stored["providers"]["codex"]["api_key"] == "secret-key"

    preserved = client.put(
        "/api/settings",
        json={
            "backend": "codex",
            "mode": "custom",
            "base_url": "https://models.example.test/v1",
            "model": "coder-model-v2",
        },
    )
    assert preserved.status_code == 200
    assert app.state.web_settings.codex_provider.api_key == "secret-key"


def test_api_settings_hot_switches_active_jobs(tmp_path, monkeypatch) -> None:
    app = _make_app(tmp_path)
    captured = {}

    def fake_hot_switch(**kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return ["7", "repro-abc123def456"]

    monkeypatch.setattr(
        app.state.manager, "hot_switch_agent_settings", fake_hot_switch
    )
    response = TestClient(app).put(
        "/api/settings",
        json={
            "backend": "codex",
            "mode": "custom",
            "base_url": "https://codex.example.test/v1",
            "api_key": "secret-key",
            "model": "codex-model",
        },
    )

    assert response.status_code == 200
    assert response.json()["active_jobs_updated"] == 2
    assert captured == {
        "backend": "codex",
        "model": "codex-model",
        "provider_mode": "custom",
        "provider_base_url": "https://codex.example.test/v1",
        "provider_api_key": "secret-key",
    }


def test_api_audit_snapshots_selected_provider_settings(tmp_path, monkeypatch) -> None:
    repository = "github.com/user/repo"
    _make_managed_repo(tmp_path, repository)
    app = _make_app(tmp_path)
    captured = {}

    class FakeJob:
        @staticmethod
        def status() -> dict:
            return {"state": "running", "job_key": "1"}

    async def fake_start(params):
        captured["params"] = params
        return FakeJob()

    monkeypatch.setattr(app.state.manager, "start", fake_start)
    client = TestClient(app)
    assert client.put(
        "/api/settings",
        json={
            "backend": "claude",
            "mode": "custom",
            "base_url": "https://claude.example.test",
            "api_key": "secret-key",
            "model": "claude-compatible-model",
        },
    ).status_code == 200

    response = client.post("/api/audit", json={"repository": repository})

    assert response.status_code == 202
    params = captured["params"]
    assert params.backend == "claude"
    assert params.provider_mode == "custom"
    assert params.provider_base_url == "https://claude.example.test"
    assert params.provider_api_key == "secret-key"
    assert params.model == "claude-compatible-model"
    assert params.sandbox_mode == "local-worktree"


def test_api_index_serves_html(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.get("/")
    assert res.status_code == 200
    assert res.headers["cache-control"] == "no-store"
    assert "CodeAuditor" in res.text
    assert '<link rel="icon" href="/static/icon.svg" type="image/svg+xml" />' in res.text
    assert '<img class="logo-mark" src="/static/icon.svg"' in res.text
    assert 'data-route="dashboard"' in res.text
    assert 'id="view-dashboard"' in res.text
    assert 'src="/static/code-auditor-8bit.png"' in res.text
    assert 'id="r-target-select"' in res.text
    assert 'id="r-commit-select"' in res.text
    assert 'id="r-bug-select"' in res.text
    assert 'id="f-repo-select"' in res.text
    assert 'id="f-git-url"' in res.text
    assert 'id="f-local-directory-path"' in res.text
    assert 'id="btn-choose-local-directory"' in res.text
    assert 'id="f-wiki-select"' in res.text
    assert res.text.count('name="sandbox-mode"') == 3
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
    assert 'id="process-tree-panel"' in res.text
    assert 'id="process-tree"' in res.text
    assert 'id="process-command-panel"' in res.text
    assert 'id="process-command"' in res.text
    assert 'id="results-agent-logs"' in res.text
    assert 'id="btn-settings"' in res.text
    assert 'id="settings-dialog"' in res.text
    assert 'id="auth-gate"' in res.text
    assert 'id="auth-setup-form"' in res.text
    assert 'id="auth-login-form"' in res.text
    assert 'id="auth-register-form"' in res.text
    assert 'id="btn-logout"' in res.text
    assert 'id="s-backend"' in res.text
    assert 'id="s-mode"' in res.text
    assert "Active jobs switch on their next agent call" in res.text
    assert res.text.count('class="table-shell') == 4
    assert 'class="table-shell history-table-shell"' in res.text
    assert 'id="history-search"' in res.text
    assert 'id="history-status"' in res.text
    assert 'id="history-kind"' not in res.text
    assert 'id="history-page-size"' in res.text
    assert 'id="history-prev"' in res.text
    assert 'id="history-next"' in res.text
    assert 'data-route="reproduction"' not in res.text
    assert 'href="#/reproduction"' not in res.text
    assert 'id="trash-table"' in res.text
    assert 'class="col-disclosure-title"' in res.text
    assert 'class="col-cve-local"' in res.text
    assert "⚡" not in res.text
    assert "⏳" not in res.text
    html_ids = re.findall(r'\bid="([^"]+)"', res.text)
    assert len(html_ids) == len(set(html_ids))
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
    assert "duration_known" in script.text
    assert "durationKnownByRun" in script.text
    assert 'return "N/A"' in script.text
    assert 'btnStart.textContent = "Starting…"' in script.text
    assert "openCveDialog" in script.text
    assert "appendEvidenceActionButtons" in script.text
    assert "disclosureUnavailableReasons" in script.text
    assert "bootstrapAuthentication" in script.text
    assert "auth-setup" in script.text
    assert "No validated retained Stage 5/6 reproducer is registered." in script.text
    assert "No validated runtime trigger-graph.json is registered." in script.text
    assert "ASan may not apply or may have produced no report." in script.text
    assert "Unavailable actions:" in script.text
    assert "renderTriggerGraph" in script.text
    assert "openAsanReport" in script.text
    assert "pollDetailHeartbeat" in script.text
    assert "pollAuditProcessTree" in script.text
    assert "renderAuditProcessTree" in script.text
    assert "/processes`" in script.text
    assert "resumeCancelledAudit" in script.text
    assert "BUSY_JOB_STATES" in script.text
    assert "busyJobForRun" in script.text
    assert "connectGlobalJobEvents" in script.text
    assert "connectDetailEvents" in script.text
    assert "active_jobs_updated" in script.text
    assert "backend_switched" in script.text
    assert "agent_history_updated" in script.text
    assert "backendsUsedDisplay" in script.text
    assert "updateRunAgentHistoryMeta" in script.text
    assert "Backends used" in res.text
    assert "historyServerFiltering" in script.text
    assert "externalMaintenanceJob" in script.text
    assert "refreshJobSnapshot" in script.text
    assert "/api/jobs/events" in script.text
    assert "/resume`" in script.text
    assert "notifyStageCompleted" in script.text
    assert "MAX_LOG_PANE_ENTRIES" in script.text
    assert "LOG_RENDER_INTERVAL_MS" in script.text
    assert "pane.textContent +=" not in script.text
    assert "pollActiveAgentLog" in script.text
    assert "/agent-log" in script.text
    assert "/api/results" not in script.text
    assert "is active — Stage" in script.text
    assert "older Web logs trimmed" in script.text
    assert '"fixed"' not in script.text
    assert 'id="btn-disclosures-sync"' not in res.text

    icon = client.get("/static/icon.svg")
    assert icon.status_code == 200
    dashboard_icon = client.get("/static/code-auditor-8bit.png")
    assert dashboard_icon.status_code == 200
    assert dashboard_icon.headers["content-type"] == "image/png"
    assert dashboard_icon.content.startswith(b"\x89PNG\r\n\x1a\n")
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


def test_poc_terminal_uses_retained_stage6_after_stage5_cleanup(tmp_path) -> None:
    app = _make_app(tmp_path)
    out = _make_output_dir(tmp_path)
    disclosure = _write_web_stage6_retention(out)
    run_id = app.state.store.import_output_dir(out)
    shutil.rmtree(Path(out) / "stage5-pocs" / "H-01")
    client = TestClient(app)
    token = client.get("/api/config").json()["terminal_token"]

    with client.websocket_connect(
        f"/ws/terminal/{run_id}/H-01?token={token}"
    ) as websocket:
        ready = websocket.receive_json()
        assert ready["type"] == "ready"
        assert ready["cwd"] == str(disclosure)
        websocket.send_json({"type": "input", "data": "exit\n"})


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
    res = client.get("/api/jobs")
    assert res.status_code == 200
    assert res.json()["jobs"] == []


def test_api_rejects_custom_target_and_unknown_repository(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.post("/api/audit", json={"target": "/definitely/not/here"})
    assert res.status_code == 422

    res = client.post("/api/audit", json={"repository": "github.com/no/such"})
    assert res.status_code == 400
    assert "managed repository" in res.json()["detail"].lower()


def test_api_selects_and_starts_audit_for_local_directory(
    tmp_path, monkeypatch
) -> None:
    target = tmp_path / "local-project"
    target.mkdir()
    app = _make_app(tmp_path)
    captured = {}

    monkeypatch.setattr(
        server_module, "choose_local_directory", lambda: str(target)
    )

    class FakeJob:
        @staticmethod
        def status():
            return {"state": "starting", "run_id": 7}

    async def fake_start(params):
        captured["params"] = params
        return FakeJob()

    monkeypatch.setattr(app.state.manager, "start", fake_start)
    client = TestClient(app)
    picker_headers = {"X-CodeAuditor-Token": app.state.terminal_token}

    selection = client.post("/api/local-directories/select", headers=picker_headers)
    assert selection.status_code == 200
    assert selection.json()["path"] == str(target.resolve())
    token = selection.json()["token"]

    response = client.post("/api/audit", json={"local_directory": token})
    assert response.status_code == 202
    assert captured["params"].target == str(target.resolve())
    assert captured["params"].git_url is None
    assert captured["params"].update_repo is False

    reused = client.post("/api/audit", json={"local_directory": token})
    assert reused.status_code == 400
    assert "missing or expired" in reused.json()["detail"]


def test_api_local_directory_picker_handles_cancel_and_rejects_root(
    tmp_path, monkeypatch
) -> None:
    app = _make_app(tmp_path)
    client = TestClient(app)
    picker_headers = {"X-CodeAuditor-Token": app.state.terminal_token}

    unauthorized = client.post("/api/local-directories/select")
    assert unauthorized.status_code == 403

    monkeypatch.setattr(server_module, "choose_local_directory", lambda: None)
    cancelled = client.post(
        "/api/local-directories/select", headers=picker_headers
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {"cancelled": True}

    monkeypatch.setattr(server_module, "choose_local_directory", lambda: os.sep)
    rejected = client.post("/api/local-directories/select", headers=picker_headers)
    assert rejected.status_code == 400
    assert "filesystem root" in rejected.json()["detail"]


def test_api_job_endpoints_404_for_unknown_run(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.get("/api/audit/1/status").status_code == 404
    assert client.post("/api/audit/1/stop").status_code == 404
    assert client.get("/api/audit/1/processes").status_code == 404
    assert client.get("/api/audit/1/events").status_code == 404
    assert client.get("/api/history/1/agent-log").status_code == 404


def test_api_process_tree_is_available_only_while_running(
    tmp_path,
    monkeypatch,
) -> None:
    app = _make_app(tmp_path)
    manager = app.state.manager
    job = AuditJob(manager, "audit")
    job.job_key = "7"
    job.run_id = 7
    job.state = STATE_RUNNING

    class RunningTask:
        @staticmethod
        def done() -> bool:
            return False

    job.task = RunningTask()
    manager._jobs[job.job_key] = job
    expected = {
        "sampled_at": 123.0,
        "total": 1,
        "roots": [
            {
                "pid": 10,
                "ppid": 1,
                "name": "agent",
                "state": "S",
                "command": "agent --run",
                "children": [],
            }
        ],
    }
    monkeypatch.setattr(
        job_module,
        "snapshot_process_tree",
        lambda marker: expected if marker == job.process_marker else None,
    )
    client = TestClient(app)

    response = client.get("/api/audit/7/processes")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == expected

    job.state = STATE_RESTORING
    response = client.get("/api/audit/7/processes")
    assert response.status_code == 409
    assert "only while the audit is running" in response.json()["detail"]

    job.state = STATE_DONE
    assert client.get("/api/audit/7/processes").status_code == 409


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
    run_id = app.state.store.import_output_dir(str(output))
    client = TestClient(app)

    response = client.get(f"/api/history/{run_id}/agent-log")
    assert response.status_code == 200
    assert response.text == "latest complete Agent log\n"
    assert response.headers["x-codeauditor-log-path"] == (
        "stage3-findings/logs/AU-9.log"
    )

    download = client.get(
        f"/api/history/{run_id}/agent-log", params={"download": "true"}
    )
    assert download.status_code == 200
    assert "attachment" in download.headers["content-disposition"]
    assert download.content == latest.read_bytes()


def test_api_full_job_lifecycle_and_results(tmp_path, monkeypatch) -> None:
    async def fake_run_audit(config, reporter=None):
        # Simulate stage output artifacts.
        findings_dir = tmp_path / "out" / "stage3-findings"
        findings_dir.mkdir(parents=True, exist_ok=True)
        (findings_dir / "AU-1-F-1.json").write_text("{}", encoding="utf-8")
        if reporter:
            reporter.begin_stage(0, "setup")
            reporter.end_stage(0)

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)
    monkeypatch.setattr(
        job_module,
        "default_audit_output_dir",
        lambda target, results_dir=None: str(tmp_path / "out"),
    )
    monkeypatch.setattr(job_module, "local_claude_model", lambda *a, **kw: None)

    app = _make_app(tmp_path)
    _make_managed_repo(tmp_path)
    wiki = _make_managed_wiki(tmp_path)

    # Keep one ASGI portal alive while the background audit task runs, as a
    # real Uvicorn worker does between requests.
    with TestClient(app) as client:
        res = client.post(
            "/api/audit",
            json={"repository": "github.com/user/repo", "wiki": "qemu-security"},
        )
        assert res.status_code == 202
        run_id = res.json()["run_id"]

        status = _wait_for_state(app, "done")
        assert status["stages"][0]["status"] == "done"

        # Live job endpoints stay available for the finished job's retention
        # window; results are served from the run-scoped history endpoints.
        res = client.get(f"/api/audit/{run_id}/status")
        assert res.status_code == 200
        assert res.json()["state"] == "done"

        res = client.get(f"/api/history/{run_id}/results")
        assert res.status_code == 200
        assert "findings" not in res.json()

        res = client.get(
            f"/api/history/{run_id}/file",
            params={"path": "stage3-findings/AU-1-F-1.json"},
        )
        assert res.status_code == 200
        assert res.text == "{}"

        res = client.get(
            f"/api/history/{run_id}/file", params={"path": "../../etc/passwd"}
        )
        assert res.status_code == 400

        res = client.get(
            f"/api/history/{run_id}/file", params={"path": "nope.json"}
        )
        assert res.status_code == 404

    # The completed job was recorded in the history database.
    runs, total = app.state.store.list_runs()
    assert total == 1
    assert runs[0]["status"] == "done"
    assert runs[0]["findings_count"] == 1
    job = app.state.manager.get_job(str(run_id))
    assert job is not None
    assert job.config is not None
    assert job.config.backend == "claude"
    assert job.config.model is None
    assert job.config.log_level == "DEBUG"
    assert job.config.wiki_path == wiki
    assert not hasattr(job.config, "discovered_path")


# ── History API ──────────────────────────────────────────────────────────────


def test_api_history_empty(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    res = client.get("/api/history")
    assert res.status_code == 200
    body = res.json()
    assert body["runs"] == []
    assert body["total"] == 0
    assert body["capabilities"]["server_filtering"] is True
    assert body["db_path"].endswith("history.db")


def test_api_history_filters_and_paginates(tmp_path) -> None:
    app = _make_app(tmp_path)
    audit_id = app.state.store.create_run(
        AuditConfig(
            target=str(tmp_path / "AuditTarget"),
            output_dir=str(tmp_path / "audit-output-audit"),
        ),
        status=RUN_DONE,
    )
    maintenance_id = app.state.store.create_run(
        AuditConfig(
            target=str(tmp_path / "MaintenanceTarget"),
            output_dir=str(tmp_path / "audit-output-maintenance"),
        ),
        status=RUN_FAILED,
        run_kind=RUN_KIND_MAINTENANCE,
    )
    client = TestClient(app)

    page = client.get("/api/history", params={"limit": 1, "offset": 1}).json()
    assert page["total"] == 2
    assert page["limit"] == 1
    assert page["offset"] == 1
    assert len(page["runs"]) == 1

    filtered = client.get(
        "/api/history",
        params={"status": RUN_FAILED, "run_kind": "maintenance", "q": "target"},
    ).json()
    assert filtered["total"] == 1
    assert filtered["runs"][0]["id"] == maintenance_id
    assert filtered["filters"] == {
        "status": RUN_FAILED,
        "run_kind": "maintenance",
        "q": "target",
    }

    searched = client.get("/api/history", params={"q": "audittarget"}).json()
    assert searched["total"] == 1
    assert searched["runs"][0]["id"] == audit_id
    assert client.get("/api/history", params={"status": "unknown"}).status_code == 422


def test_api_history_accepts_superseded_maintenance_status(tmp_path) -> None:
    app = _make_app(tmp_path)
    run_id = app.state.store.create_run(
        AuditConfig(
            target=str(tmp_path / "target"),
            output_dir=str(tmp_path / "audit-output-maintenance"),
        ),
        status=RUN_SUPERSEDED,
        run_kind=RUN_KIND_MAINTENANCE,
    )
    client = TestClient(app)

    response = client.get(
        "/api/history",
        params={"status": RUN_SUPERSEDED, "run_kind": RUN_KIND_MAINTENANCE},
    )

    assert response.status_code == 200
    assert response.json()["runs"][0]["id"] == run_id


def test_app_startup_recovers_interrupted_running_history(tmp_path) -> None:
    app = _make_app(tmp_path)
    run_id = app.state.store.create_run(
        AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path / "audit-output-interrupted"),
        ),
        started_at=100.0,
    )
    maintenance_id = app.state.store.create_run(
        AuditConfig(
            target=str(tmp_path),
            output_dir=str(tmp_path / "audit-output-maintenance"),
        ),
        started_at=200.0,
        run_kind=RUN_KIND_MAINTENANCE,
    )

    with TestClient(app) as client:
        detail = client.get(f"/api/history/{run_id}").json()
        maintenance = client.get(f"/api/history/{maintenance_id}").json()
        jobs = client.get("/api/jobs").json()

    assert detail["status"] == RUN_CANCELLED
    assert "Web worker exited" in detail["error"]
    assert detail["ended_at"] is not None
    assert maintenance["status"] == "running"
    assert maintenance["run_kind"] == "maintenance"
    assert jobs["external_maintenance_supported"] is True
    assert len(jobs["jobs"]) == 1
    assert jobs["jobs"][0]["run_id"] == maintenance_id
    assert jobs["jobs"][0]["kind"] == "maintenance"
    assert jobs["jobs"][0]["controllable"] is False


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
        AuditConfig(
            target=target,
            output_dir=output,
            backend="codex",
            model="old-codex-model",
            backends_used=["codex"],
        ),
        status=RUN_CANCELLED,
        started_at=100.0,
    )
    app.state.store.set_run_identity(run_id, identity)
    audited = []

    async def fake_run_audit(config, reporter=None):
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
        assert detail["backend"] == "claude"
        assert json.loads(detail["backends_used"]) == ["codex"]
        assert detail["started_at"] == 100.0
        assert 0 <= detail["duration_seconds"] < 60
        assert detail["active_started_at"] is None
        assert client.get("/api/history").json()["total"] == 1
        assert client.post(f"/api/history/{run_id}/resume").status_code == 400

    assert len(audited) == 1
    assert audited[0].output_dir == output
    assert audited[0].resume is True
    assert audited[0].update_repo is False
    assert audited[0].backend == "claude"


def test_api_resume_missing_history_run_returns_404(tmp_path) -> None:
    client = TestClient(_make_app(tmp_path))
    assert client.post("/api/history/999/resume").status_code == 404


def test_api_resumes_done_history_run_with_task_errors(tmp_path, monkeypatch) -> None:
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
        started_at=100.0,
    )
    app.state.store.set_run_identity(run_id, identity)
    app.state.store.finish_run(
        run_id, RUN_DONE, "2 agent task(s) failed: stage5:H-03", ended_at=200.0
    )
    audited = []

    async def fake_run_audit(config, reporter=None):
        audited.append(config)

    monkeypatch.setattr(job_module, "capture_repo_identity", lambda _path: identity)

    async def fake_checkout(_target, commit, branch):
        assert commit == identity["commit"]

    monkeypatch.setattr(job_module, "_checkout_recorded_revision", fake_checkout)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    with TestClient(app) as client:
        response = client.post(f"/api/history/{run_id}/resume")
        assert response.status_code == 202
        _wait_for_state(app, STATE_DONE)

        detail = client.get(f"/api/history/{run_id}").json()
        assert detail["status"] == STATE_DONE

    assert len(audited) == 1
    assert audited[0].output_dir == output
    assert audited[0].resume is True


def test_api_rejects_resume_of_clean_done_history_run(tmp_path) -> None:
    app = _make_app(tmp_path)
    target = _make_managed_repo(tmp_path)
    output = _make_output_dir(tmp_path)
    run_id = app.state.store.create_run(
        AuditConfig(target=target, output_dir=output),
        started_at=100.0,
    )
    app.state.store.finish_run(run_id, RUN_DONE, "", ended_at=200.0)

    client = TestClient(app)
    assert client.post(f"/api/history/{run_id}/resume").status_code == 400


async def test_audit_with_failed_tasks_finishes_as_failed(tmp_path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    params = AuditStartParams(target=str(target))
    manager = AuditJobManager(store=None)
    job = AuditJob(manager, "audit")
    config = job._build_config(params, str(target), None)
    job.config = config
    job.state = STATE_RUNNING
    job.job_key = "audit-test"

    async def fake_run_audit(cfg, reporter=None):
        cfg.backends_used.extend(["claude", "codex"])
        cfg.models_used.append("model-x")
        cfg.usage_stats.update({"agent_calls": 2, "input_tokens": 900, "cost_usd": 0.03})
        cfg.task_errors.append("stage5:H-03: Agent ended with an error result: API Error: 400")

    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    await job._run(config, params, None)

    assert job.state == STATE_FAILED
    assert "stage5:H-03" in job.error
    assert job.status()["backends_used"] == ["claude", "codex"]
    assert job.status()["models_used"] == ["model-x"]
    assert job.status()["usage_stats"] == {
        "agent_calls": 2,
        "input_tokens": 900,
        "cost_usd": 0.03,
    }


def test_run_stage_summary_uses_checkpoint_markers(tmp_path) -> None:
    from code_auditor.web.server import _run_stage_summary

    out = tmp_path / "audit-output-x"
    markers = out / ".markers"
    markers.mkdir(parents=True)
    for name in ("stage2", "stage3-AU-1", "stage3-AU-2"):
        (markers / name).touch()
    run = {
        "output_dir": str(out),
        "status": "done",
        "analysis_units": [{"au_id": "AU-1"}, {"au_id": "AU-2"}],
        "vulnerabilities": [],
        "poc_issues": [],
        "reproduced_vulns_count": 0,
    }

    stages = {s["stage"]: s for s in _run_stage_summary(run)}

    assert stages[0]["status"] == "done"
    assert stages[1]["status"] == "pending"
    assert stages[2]["status"] == "done"
    assert stages[3]["status"] == "done"
    assert stages[3]["items_done"] == 2
    assert stages[3]["items_total"] == 2
    # No fallback to artifact presence once markers exist.
    assert stages[5]["status"] == "pending"


def test_run_stage_summary_marks_partial_failed_run(tmp_path) -> None:
    from code_auditor.web.server import _run_stage_summary

    out = tmp_path / "audit-output-y"
    markers = out / ".markers"
    markers.mkdir(parents=True)
    (markers / "stage3-AU-1").touch()
    run = {
        "output_dir": str(out),
        "status": "failed",
        "analysis_units": [{"au_id": "AU-1"}, {"au_id": "AU-2"}],
        "vulnerabilities": [],
        "poc_issues": [],
        "reproduced_vulns_count": 0,
    }

    stages = {s["stage"]: s for s in _run_stage_summary(run)}

    assert stages[3]["status"] == "failed"
    assert stages[3]["items_done"] == 1
    assert stages[3]["items_total"] == 2
    assert stages[4]["status"] == "pending"


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

    # No checkpoint markers: stage summary falls back to artifact presence.
    stages = {s["stage"]: s for s in detail["stages"]}
    assert stages[0]["status"] == "done"
    assert stages[1]["status"] == "pending"
    assert stages[2]["status"] == "pending"
    assert stages[4]["status"] == "done"
    assert stages[5]["status"] == "done"
    assert stages[6]["status"] == "done"

    res = client.get(f"/api/history/{run_id}/results")
    assert res.status_code == 200
    results = res.json()
    assert results["vulnerabilities"] == ["stage4-vulnerabilities/H-01.json"]
    assert results["poc_reports"] == ["stage5-pocs/H-01/report.md"]
    assert results["disclosures"]

    res = client.get("/api/history/9999/results")
    assert res.status_code == 404

    res = client.get("/api/history")
    assert res.json()["total"] == 1

    res = client.get(
        f"/api/history/{run_id}/file",
        params={"path": "stage4-vulnerabilities/H-01.json"},
    )
    assert res.status_code == 200
    assert "Test vuln" in res.text

    res = client.get(
        f"/api/history/{run_id}/file",
        params={"path": "stage4-vulnerabilities/H-01.json", "download": "true"},
    )
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    assert 'filename="H-01.json"' in res.headers["content-disposition"]

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

    async def fake_run_audit(config, reporter=None):
        seen["target"] = config.target

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    manager = AuditJobManager()
    job = await manager.start(
        AuditStartParams(
            git_url="https://github.com/user/repo.git",
            repos_dir=str(tmp_path / "repos"),
        )
    )
    await job.task

    assert job.state == STATE_DONE
    assert seen["target"] == str(cloned)
    assert job.config is not None
    assert job.config.target == str(cloned)


async def test_start_with_git_url_clone_failure_marks_failed(
    tmp_path, monkeypatch
) -> None:
    from code_auditor.repos import RepoError

    async def fake_ensure_repo(url, repos_dir):
        raise RepoError("git clone failed: repository not found")

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)

    manager = AuditJobManager()
    job = await manager.start(
        AuditStartParams(git_url="https://example.com/x/y.git")
    )
    await job.task

    assert job.state == STATE_FAILED
    assert "clone failed" in job.error


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

    res = client.post(
        "/api/audit",
        json={"repository": repository, "local_directory": "a" * 32},
    )
    assert res.status_code == 400

    for hidden_field, value in (
        ("target", "/tmp/project"),
        ("backend", "codex"),
        ("model", "gpt-5.5"),
        ("sandbox_mode", "local-worktree"),
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
        ("sandbox_mode", "local-worktree"),
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

    async def fake_run_audit(config, reporter=None):
        pass

    monkeypatch.setattr(job_module, "ensure_repo", fake_ensure_repo)
    monkeypatch.setattr(job_module, "run_audit", fake_run_audit)

    app = _make_app(tmp_path)
    with TestClient(app) as client:
        res = client.post(
            "/api/audit", json={"git_url": "https://github.com/user/repo.git"}
        )
        assert res.status_code == 202
        run_id = res.json()["run_id"]
        _wait_for_state(app, "done")
        job = app.state.manager.get_job(str(run_id))
        assert job is not None
        assert job.config is not None
        assert job.config.target == str(cloned)


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


def test_api_purge_disclosure_trash(tmp_path) -> None:
    app = _make_app(tmp_path)
    app.state.store.import_output_dir(_make_output_dir(tmp_path))
    client = TestClient(app)
    entry = client.get("/api/disclosures").json()["entries"][0]
    identity = {
        "project": entry["project"],
        "dedupe_key": entry["dedupe_key"],
    }

    empty = client.post("/api/disclosures/trash/purge")
    assert empty.status_code == 200
    assert empty.json()["removed"] == 0

    assert client.post("/api/disclosures/trash", json=identity).status_code == 200
    assert client.get("/api/disclosures/trash").json()["total"] == 1

    purged = client.post("/api/disclosures/trash/purge")
    assert purged.status_code == 200
    assert purged.json()["removed"] == 1
    assert client.get("/api/disclosures/trash").json()["total"] == 0
    assert client.get("/api/disclosures").json()["entries"] == []


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
