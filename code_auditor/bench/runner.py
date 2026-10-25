"""Sequential benchmark runner: open task -> agent -> grade -> close.

The runner is deliberately adapter-agnostic. It owns only the parts every
benchmark needs:

* one isolated output directory and agent log per instance;
* a bounded prompt suffix that makes the submitted flag extractable;
* exact flag extraction with an explicit ``ANSWER:`` marker as the primary
  channel;
* guaranteed ``close()`` on every path (including agent/grade failures);
* result persistence that never stores the submitted or expected flag;
* best-effort scrubbing of the flag from the agent log (and trajectories when
  capture is enabled).

It runs instances sequentially. CTF task servers commonly use fixed container
names, ports and Docker network aliases, so parallel execution needs adapter
support and is intentionally left to the caller.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from contextlib import suppress
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Iterable, Mapping, Sequence

from .base import BenchAdapter, BenchTask, InstanceSpec, Outcome, Submission
from .ctf import safe_component
from ..agent import run_agent
from ..config import AuditConfig
from ..logger import get_logger

if TYPE_CHECKING:
    from ..db import AuditStore

logger = get_logger("bench.runner")

DEFAULT_MAX_TURNS = 100
FINAL_INSTRUCTION = (
    "\n\nWhen finished, end your reply with exactly: ANSWER: <the exact flag>"
)
_ANSWER_RE = re.compile(r"(?im)^\s*(?:ANSWER|FLAG)\s*:\s*(.+?)\s*$")
_FLAG_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_]{1,32}\{[^{}\n]{1,500}\}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9_{}.:/+=\-]{4,4096}")
_NOT_FLAGS = {"answer", "flag", "done", "none", "n/a"}

AgentRunner = Callable[..., Awaitable[str]]


class BenchRunError(RuntimeError):
    """A benchmark run could not start (preflight/list failure)."""


def extract_flag(text: str | None) -> str | None:
    """Extract the submitted flag, preferring the explicit ``ANSWER:`` marker."""
    if not text:
        return None
    matches = _ANSWER_RE.findall(text)
    if matches:
        candidate = _clean_marker(matches[-1])
        if candidate:
            return candidate
    flags = _FLAG_RE.findall(text)
    if flags:
        candidate = _clean_marker(flags[-1])
        if candidate:
            return candidate
    for line in reversed(text.splitlines()):
        candidate = _clean_token(line)
        if candidate and candidate.lower() not in _NOT_FLAGS:
            return candidate
    return None


def _strip_wrapping(value: str) -> str:
    candidate = value.strip()
    while candidate and candidate[0] in "`'\"([":
        candidate = candidate[1:].lstrip()
    while candidate and candidate[-1] in "`'\")].,;":
        candidate = candidate[:-1].rstrip()
    return candidate


def _clean_marker(value: str) -> str | None:
    """An explicit ANSWER/FLAG line may be a flag or a phrase."""
    candidate = _strip_wrapping(value)
    if not candidate or len(candidate) > 4096 or "\n" in candidate:
        return None
    # If the marker is followed by prose on the same line, keep the flag token.
    first, _, rest = candidate.partition(" ")
    if rest and _FLAG_RE.fullmatch(first):
        candidate = first
    return candidate or None


def _clean_token(value: str) -> str | None:
    candidate = _strip_wrapping(value)
    return candidate if candidate and _TOKEN_RE.fullmatch(candidate) else None


@dataclass
class BenchResult:
    instance_id: str
    benchmark: str
    status: str
    success: bool | None = None
    score: float = 0.0
    extracted: bool = False
    submitted_length: int = 0
    detail: Mapping[str, Any] = field(default_factory=dict)
    error: str = ""
    cleanup_error: str = ""
    agent_log: str = ""
    duration_seconds: float = 0.0

    def public(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "detail": dict(self.detail),
        }


@dataclass
class BenchRun:
    benchmark: str
    output_dir: str
    started_at: float
    finished_at: float | None = None
    db_run_id: int | None = None
    results: list[BenchResult] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        succeeded = sum(1 for item in self.results if item.status == "succeeded")
        failed = sum(1 for item in self.results if item.status == "failed")
        errors = len(self.results) - succeeded - failed
        return {
            "benchmark": self.benchmark,
            "db_run_id": self.db_run_id,
            "total": len(self.results),
            "succeeded": succeeded,
            "failed": failed,
            "errors": errors,
            "score": sum(item.score for item in self.results),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "results": [item.public() for item in self.results],
        }

    def write(self, output_dir: str | Path | None = None) -> None:
        root = Path(output_dir or self.output_dir)
        root.mkdir(parents=True, exist_ok=True)
        summary = self.summary()
        (root / "bench-results.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
        with (root / "bench-results.jsonl").open("w", encoding="utf-8") as handle:
            for result in self.results:
                handle.write(
                    json.dumps(result.public(), ensure_ascii=False, default=str) + "\n"
                )


class BenchRunner:
    """Run a benchmark adapter against the configured agent, sequentially."""

    def __init__(
        self,
        adapter: BenchAdapter,
        config: AuditConfig,
        *,
        output_dir: str | Path | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        capture_trajectory: bool = False,
        agent_runner: AgentRunner | None = None,
        final_instruction: str = FINAL_INSTRUCTION,
        store: "AuditStore | None" = None,
        db_run_id: int | None = None,
    ) -> None:
        self.adapter = adapter
        self.store = store
        self.db_run_id = db_run_id
        self.config = config
        self.run_dir = Path(output_dir) if output_dir is not None else Path(config.output_dir) / "bench"
        self.max_turns = max(1, int(max_turns))
        self.capture_trajectory = bool(capture_trajectory)
        self.agent_runner = agent_runner or run_agent
        self.final_instruction = final_instruction
        # Keep the agent's own output/trajectory layout inside the bench run.
        self.agent_config = replace(
            config,
            output_dir=str(self.run_dir),
            trajectory_enabled=self.capture_trajectory,
            trajectory_root=None,
            trajectory_root_dir=None,
        )

    async def run(
        self,
        instances: Sequence[InstanceSpec] | None = None,
        *,
        include_completed: bool = False,
    ) -> BenchRun:
        """Run all (or the given) instances; errors are recorded, not raised."""
        preflight = getattr(self.adapter, "preflight", None)
        if callable(preflight):
            try:
                await asyncio.to_thread(preflight)
            except Exception as exc:
                raise BenchRunError(f"Benchmark preflight failed: {exc}") from exc
        try:
            selected = (
                list(instances)
                if instances is not None
                else await asyncio.to_thread(
                    self._list_instances, include_completed=include_completed
                )
            )
        except TypeError:
            selected = list(instances) if instances is not None else list(self.adapter.list_instances())
        except Exception as exc:
            raise BenchRunError(f"Could not list benchmark instances: {exc}") from exc

        run = BenchRun(
            benchmark=getattr(self.adapter, "name", type(self.adapter).__name__),
            output_dir=str(self.run_dir),
            started_at=time.time(),
        )
        self.run_dir.mkdir(parents=True, exist_ok=True)
        if self.store is not None:
            if self.db_run_id is not None:
                run.db_run_id = self.db_run_id
            else:
                try:
                    run.db_run_id = self.store.create_bench_run(
                        benchmark=run.benchmark,
                        adapter=type(self.adapter).__name__,
                        repo_dir=str(getattr(self.adapter, "repo_dir", "") or ""),
                        output_dir=str(self.run_dir),
                        backend=self.config.backend,
                        model=self.config.model,
                        started_at=run.started_at,
                    )
                except Exception as exc:
                    raise BenchRunError(f"Could not record the benchmark run: {exc}") from exc

        status = "failed"
        error = "benchmark run did not finish"
        try:
            for instance in selected:
                result = await self._run_instance(instance)
                run.results.append(result)
                self._persist_result(run, result)
                run.write()
            status = "done"
            error = ""
        except asyncio.CancelledError:
            status = "cancelled"
            error = "cancelled"
            raise
        except Exception as exc:
            status = "failed"
            error = f"{type(exc).__name__}: {exc}"[:2000]
            raise
        finally:
            run.finished_at = time.time()
            self._persist_finish(run, status, error)
            run.write()
        return run

    def _persist_result(self, run: BenchRun, result: BenchResult) -> None:
        if self.store is None or run.db_run_id is None:
            return
        try:
            self.store.record_bench_result(run.db_run_id, result.public())
        except Exception as exc:
            logger.warning("Could not persist benchmark result %s: %s", result.instance_id, exc)

    def _persist_finish(self, run: BenchRun, status: str, error: str) -> None:
        if self.store is None or run.db_run_id is None:
            return
        try:
            self.store.finish_bench_run(
                run.db_run_id,
                status=status,
                error=error,
                ended_at=run.finished_at,
                summary=run.summary(),
            )
        except Exception as exc:
            logger.warning("Could not finalize benchmark run %s: %s", run.db_run_id, exc)

    def _list_instances(self, *, include_completed: bool) -> list[InstanceSpec]:
        try:
            return list(
                self.adapter.list_instances(  # type: ignore[call-arg]
                    include_completed=include_completed
                )
            )
        except TypeError:
            return list(self.adapter.list_instances())

    async def _run_instance(self, instance: InstanceSpec) -> BenchResult:
        instance_id = str(instance.instance_id)
        started = time.time()
        log_path = self.run_dir / safe_component(instance_id) / "agent.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        task: BenchTask | None = None
        expected = self._expected_flag(instance)
        submitted: str | None = None
        phase = "open"
        result = BenchResult(
            instance_id=instance_id,
            benchmark=getattr(self.adapter, "name", type(self.adapter).__name__),
            status="open_failed",
            agent_log=str(log_path.relative_to(self.run_dir)),
        )
        try:
            open_task = asyncio.create_task(
                asyncio.to_thread(self.adapter.open_task, instance)
            )
            try:
                task = await asyncio.shield(open_task)
            except asyncio.CancelledError:
                # to_thread cannot be cancelled; wait for it so a container or
                # workspace it created can be closed instead of leaking.
                opened: BenchTask | None = None
                with suppress(BaseException):
                    opened = await open_task
                if opened is not None:
                    with suppress(Exception):
                        await asyncio.to_thread(self.adapter.close, instance)
                raise
            phase = "agent"
            cwd = self._workspace(instance_id, task)
            output = await self.agent_runner(
                task.prompt + self.final_instruction,
                self.agent_config,
                cwd=str(cwd),
                max_turns=self.max_turns,
                log_file=str(log_path),
                trajectory=self.capture_trajectory,
            )
            submitted = extract_flag(output)
            result.extracted = submitted is not None
            result.submitted_length = len(submitted or "")
            if not submitted:
                result.status = "no_flag"
                result.error = "the agent reply did not contain an extractable flag"
                return result
            phase = "grade"
            outcome: Outcome = await asyncio.to_thread(
                self.adapter.grade,
                instance,
                Submission(instance_id=instance_id, kind="flag", value=submitted),
            )
            result.status = "succeeded" if outcome.success else "failed"
            result.success = bool(outcome.success)
            result.score = float(outcome.score)
            result.detail = dict(outcome.detail or {})
            return result
        except Exception as exc:
            result.status = f"{phase}_failed"
            result.error = f"{type(exc).__name__}: {exc}"[:2000]
            logger.warning("Benchmark instance %s failed: %s", instance_id, exc)
            return result
        finally:
            secrets = {value for value in (submitted, expected) if value}
            self._scrub_artifacts(secrets)
            if task is not None:
                try:
                    await asyncio.to_thread(self.adapter.close, instance)
                except Exception as exc:
                    result.cleanup_error = f"{type(exc).__name__}: {exc}"[:1000]
                    logger.warning("Benchmark cleanup failed for %s: %s", instance_id, exc)
            secrets_all = {value for value in (submitted, expected) if value}
            result.error = _redact_value(result.error, secrets_all)
            result.detail = _redact_value(dict(result.detail or {}), secrets_all)
            result.duration_seconds = time.time() - started

    def _workspace(self, instance_id: str, task: BenchTask) -> Path:
        configured = task.metadata.get("workdir")
        if isinstance(configured, str) and Path(configured).is_dir():
            return Path(configured)
        workspace = self.run_dir / "workspaces" / safe_component(instance_id)
        workspace.mkdir(parents=True, exist_ok=True)
        return workspace

    def _expected_flag(self, instance: InstanceSpec) -> str | None:
        provider = getattr(self.adapter, "expected_flag", None)
        if not callable(provider):
            return None
        try:
            value = provider(instance)
        except Exception:
            return None
        return value if isinstance(value, str) and value else None

    def _scrub_artifacts(self, secrets: Iterable[str]) -> None:
        values = tuple({value for value in secrets if value})
        if not values:
            return
        targets: list[Path] = []
        targets.extend(self.run_dir.glob("*/agent.log"))
        trajectory_dir = self.run_dir / "trajectories"
        if trajectory_dir.is_dir():
            targets.extend(path for path in trajectory_dir.rglob("*") if path.is_file())
        for path in targets:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            cleaned = text
            for secret in values:
                cleaned = cleaned.replace(secret, "[REDACTED]")
            if cleaned != text:
                try:
                    path.write_text(cleaned, encoding="utf-8")
                except OSError:
                    logger.warning("Could not scrub a benchmark artifact: %s", path)


def _redact_value(value: Any, secrets: set[str]) -> Any:
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, Mapping):
        return {key: _redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in value]
    return value
