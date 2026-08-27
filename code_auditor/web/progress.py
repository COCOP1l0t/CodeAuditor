"""Event bus, log capture, and progress reporting for the CodeAuditor web UI.

``WebProgressReporter`` implements the ``run_audit`` progress protocol with
``begin_stage`` / ``stage_progress`` /
``end_stage`` and publishes events to a per-job ``EventBus``, which streams
them to browsers over per-job SSE endpoints. Log records from the
``code_auditor`` logger are captured by a single process-wide
``WebLogHandler`` and routed to the owning job's bus via the
``CURRENT_JOB_KEY`` context variable (set by the job manager before spawning
each job task and inherited by its child tasks).
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Callable

MAX_WEB_LOG_MESSAGE_CHARS = 20_000
MAX_SSE_SUBSCRIBER_EVENTS = 500

#: Key of the web job the current asyncio task belongs to. The job manager
#: sets this before spawning a job task; ``asyncio.create_task`` copies the
#: context, so every agent sub-task inherits it and its log records route to
#: the correct per-job event bus.
CURRENT_JOB_KEY: ContextVar[str | None] = ContextVar(
    "code_auditor_web_job_key", default=None
)


def _priority_event(event: dict) -> bool:
    """Return whether an event must survive slow-client queue pressure."""
    if event.get("type") in {"job", "stage"}:
        return True
    return event.get("type") == "log" and event.get("level") in {
        "WARNING",
        "ERROR",
        "CRITICAL",
    }


class BoundedEventQueue:
    """Small asyncio-compatible queue that preserves lifecycle events.

    Ordinary live logs and progress updates are discarded oldest-first when a
    browser cannot consume SSE quickly enough. Job/stage transitions and
    warnings/errors displace ordinary events instead of being lost behind a
    burst of verbose Agent output.
    """

    def __init__(self, maxsize: int = MAX_SSE_SUBSCRIBER_EVENTS) -> None:
        if maxsize < 1:
            raise ValueError("maxsize must be positive")
        self.maxsize = maxsize
        self._items: deque[dict] = deque()
        self._ready = asyncio.Event()

    def qsize(self) -> int:
        return len(self._items)

    def empty(self) -> bool:
        return not self._items

    def full(self) -> bool:
        return len(self._items) >= self.maxsize

    def put_nowait(self, event: dict) -> None:
        if self.full():
            drop_index = next(
                (
                    index
                    for index, queued_event in enumerate(self._items)
                    if not _priority_event(queued_event)
                ),
                None,
            )
            if drop_index is None:
                if not _priority_event(event):
                    return
                drop_index = 0
            del self._items[drop_index]
        self._items.append(event)
        self._ready.set()

    async def get(self) -> dict:
        while not self._items:
            self._ready.clear()
            if self._items:
                break
            await self._ready.wait()
        event = self._items.popleft()
        if not self._items:
            self._ready.clear()
        return event


class EventBus:
    """Fan-out event bus with a replay buffer for late-joining SSE clients."""

    def __init__(
        self,
        max_buffer: int = 500,
        max_subscriber_events: int = MAX_SSE_SUBSCRIBER_EVENTS,
    ) -> None:
        self._buffer: deque[dict] = deque(maxlen=max_buffer)
        self._max_subscriber_events = max_subscriber_events
        self._subscribers: set[BoundedEventQueue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self) -> None:
        """Capture the running event loop (call from async context)."""
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    def clear(self) -> None:
        self._buffer.clear()

    def backlog(self) -> list[dict]:
        return list(self._buffer)

    def subscribe(self) -> BoundedEventQueue:
        self.bind_loop()
        queue = BoundedEventQueue(self._max_subscriber_events)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: BoundedEventQueue) -> None:
        self._subscribers.discard(queue)

    def publish(self, event: dict) -> None:
        event.setdefault("ts", time.time())
        self._buffer.append(event)
        if not self._subscribers:
            return
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._deliver, event)
        else:
            self._deliver(event)

    def _deliver(self, event: dict) -> None:
        for queue in self._subscribers:
            queue.put_nowait(event)


class WebLogHandler(logging.Handler):
    """Routes ``code_auditor`` log records to the owning job's event bus.

    One instance is installed process-wide at server startup. ``emit`` reads
    ``CURRENT_JOB_KEY`` to find the job that produced the record and looks up
    that job's bus; records logged outside any job task (startup, request
    handlers) are dropped from the web stream.
    """

    _FORMATTER = logging.Formatter()

    def __init__(self, bus_for_job: Callable[[str], "EventBus | None"]) -> None:
        super().__init__()
        self.bus_for_job = bus_for_job

    def emit(self, record: logging.LogRecord) -> None:
        job_key = CURRENT_JOB_KEY.get()
        if job_key is None:
            return
        bus = self.bus_for_job(job_key)
        if bus is None:
            return
        try:
            ts = self._FORMATTER.formatTime(record, datefmt="[%x %X]")
            message = record.getMessage()
            if record.exc_info:
                message = f"{message}\n{self._FORMATTER.formatException(record.exc_info)}"
            elif record.exc_text:
                message = f"{message}\n{record.exc_text}"
            if len(message) > MAX_WEB_LOG_MESSAGE_CHARS:
                message = (
                    message[:MAX_WEB_LOG_MESSAGE_CHARS]
                    + "\n… Web log event truncated; see agent.log for full output."
                )
            bus.publish(
                {
                    "type": "log",
                    "level": record.levelname,
                    "message": f"{ts} {record.levelname:<8} {message}",
                }
            )
        except Exception:
            self.handleError(record)


def install_web_log_handler(
    bus_for_job: Callable[[str], "EventBus | None"],
) -> WebLogHandler:
    """Attach the routing handler to the ``code_auditor`` logger once."""
    root = logging.getLogger("code_auditor")
    for handler in root.handlers:
        if isinstance(handler, WebLogHandler):
            handler.bus_for_job = bus_for_job
            return handler
    handler = WebLogHandler(bus_for_job)
    handler.setLevel(logging.DEBUG)
    root.addHandler(handler)
    return handler


@dataclass
class StageState:
    status: str = "pending"  # pending | running | done
    detail: str = ""
    items_done: int = 0
    items_total: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


class WebProgressReporter:
    """Publish audit stage updates to Web clients."""

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._stages: dict[int, StageState] = {}

    def begin_stage(self, stage: int, description: str) -> None:
        state = StageState(status="running", detail=description, start_time=time.time())
        self._stages[stage] = state
        self._bus.publish(
            {"type": "stage", "stage": stage, "status": "running", "detail": description}
        )

    def stage_progress(
        self,
        stage: int,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> None:
        state = self._stages.setdefault(stage, StageState(status="running"))
        state.items_done = items_done
        state.items_total = items_total
        if detail:
            state.detail = detail
        self._bus.publish(
            {
                "type": "progress",
                "stage": stage,
                "items_done": items_done,
                "items_total": items_total,
                "detail": detail,
            }
        )

    def end_stage(self, stage: int) -> None:
        state = self._stages.setdefault(stage, StageState())
        state.status = "done"
        state.end_time = time.time()
        self._bus.publish(
            {"type": "stage", "stage": stage, "status": "done", "detail": state.detail}
        )

    def snapshot(self) -> list[dict]:
        return [
            {
                "stage": stage,
                "status": state.status,
                "detail": state.detail,
                "items_done": state.items_done,
                "items_total": state.items_total,
                "elapsed": round((state.end_time or time.time()) - state.start_time, 1)
                if state.start_time
                else 0.0,
            }
            for stage, state in sorted(self._stages.items())
        ]
