"""ATIF v1.7 trajectory capture.

The Agent Trajectory Interchange Format (ATIF) is the JSON trajectory
specification published as RFC 0001 by the Harbor project
(https://github.com/harbor-framework/harbor/blob/main/rfcs/0001-trajectory-format.md).
This module writes ``ATIF-v1.7`` documents from the two agent backends the
audit pipeline drives: Claude (``claude-agent-sdk`` messages) and Codex
(``codex-app-server`` notifications).

Capture model
-------------
One *recorder* is one ATIF document. The pipeline creates:

* one run-level ``trajectories/trajectory.json`` whose ``steps`` hold the
  orchestration record (system/user/deterministic delegations), and
* one child document per agent invocation, referenced from the run-level
  document by ``observation.results[].subagent_trajectory_ref[].trajectory_path``.

The child document is also written when no run-level recorder exists (unit
tests, ``run_agent`` calls from maintenance paths), so capture degrades to
"one file per invocation" instead of failing.

Mapping (Claude)
----------------
===========================================  ==================================
SDK message / block                          ATIF
===========================================  ==================================
rendered ``prompts/stageN.md``               ``step`` with ``source="user"``
``SystemMessage``                            ``step`` with ``source="system"``
``TextBlock``                                ``step.message`` (source ``agent``)
``ThinkingBlock``                            ``step.reasoning_content``
``ToolUseBlock``                             ``step.tool_calls[]``
``ToolResultBlock``                          same step's ``observation.results[]``
``ResultMessage``                            ``step.metrics`` + ``num_turns``
===========================================  ==================================

The Codex backend maps ``item/started`` + ``item/completed`` to a tool step
(with its observation), ``item/agentMessage/delta`` to the turn's agent
message, ``item/reasoning`` to ``reasoning_content``, and
``*/tokenUsage/updated`` to ``metrics``.

Everything ATIF does not model (retry attempt number, duration, error flags,
raw provider payloads) goes into the ``extra`` dict of the step, tool call,
result, or trajectory: ATIF forbids unknown fields, so ``extra`` is the only
extension point.

Result content larger than ``max_inline_bytes`` is truncated inline and the
full text is written next to the trajectory under ``blobs/``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from uuid import uuid4

from .logger import get_logger

logger = get_logger("trajectory")

SCHEMA_VERSION = "ATIF-v1.7"
SUPPORTED_PREFIX = "ATIF-v1."
ROOT_FILENAME = "trajectory.json"
BLOBS_DIRNAME = "blobs"
DEFAULT_MAX_RESULT_BYTES = 64 * 1024
DEFAULT_MAX_TOTAL_INLINE_BYTES = 8 * 1024 * 1024
MAX_MESSAGE_BYTES = 256 * 1024
DEFAULT_AGENT_NAME = "code-auditor"
_TRUNCATION_NOTICE = "\n…[truncated by CodeAuditor]"

# Credentials and tokens that must never reach a trajectory file.
_REDACTION_PATTERNS = (
    re.compile(
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]+?"
        r"-----END (?:[A-Z ]+ )?PRIVATE KEY-----"
    ),
    re.compile(r"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(
        r"(?i)\b(?:bearer|token|api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|"
        r"password|passwd|authorization)\b\s*[:=]\s*\S+"
    ),
    re.compile(r"\b[A-Za-z0-9_\-]{24,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b"),
)
REDACTED = "[REDACTED]"

_STEP_SOURCES = frozenset({"system", "user", "agent"})
_CODEX_TOOL_ITEM_TYPES = frozenset(
    {
        "commandExecution",
        "fileChange",
        "mcpToolCall",
        "dynamicToolCall",
        "webSearch",
        "collabAgentToolCall",
    }
)
_AGENT_ONLY_FIELDS = (
    "model_name",
    "reasoning_effort",
    "reasoning_content",
    "tool_calls",
    "metrics",
)
_STEP_FIELDS = frozenset(
    {
        "step_id",
        "timestamp",
        "source",
        "model_name",
        "reasoning_effort",
        "message",
        "reasoning_content",
        "tool_calls",
        "observation",
        "metrics",
        "extra",
        "llm_call_count",
        "is_copied_context",
    }
)
_TOOL_CALL_FIELDS = frozenset({"tool_call_id", "function_name", "arguments", "extra"})
_RESULT_FIELDS = frozenset(
    {"source_call_id", "content", "subagent_trajectory_ref", "extra"}
)
_REF_FIELDS = frozenset({"trajectory_id", "trajectory_path", "session_id", "extra"})
_METRICS_FIELDS = frozenset(
    {
        "prompt_tokens",
        "completion_tokens",
        "cached_tokens",
        "cost_usd",
        "prompt_token_ids",
        "completion_token_ids",
        "logprobs",
        "perplexity",
        "reward",
        "extra",
    }
)
_FINAL_METRICS_FIELDS = frozenset(
    {
        "total_prompt_tokens",
        "total_completion_tokens",
        "total_cached_tokens",
        "total_cost_usd",
        "total_steps",
        "extra",
    }
)
_AGENT_FIELDS = frozenset({"name", "version", "model_name", "tool_definitions", "extra"})


def _unknown_fields(
    mapping: Mapping[str, Any], allowed: frozenset[str], prefix: str
) -> list[str]:
    unknown = sorted(set(mapping) - allowed)
    return [f"{prefix} has unknown fields: {unknown}"] if unknown else []


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def redact_text(value: str) -> str:
    """Replace credential-shaped substrings with a fixed marker."""
    text = value
    for pattern in _REDACTION_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text


def _enum_value(value: Any) -> str:
    inner = getattr(value, "value", value)
    return inner if isinstance(inner, str) else str(inner)


def _as_arguments(value: Any) -> dict[str, Any]:
    """Coerce a provider's tool arguments into ATIF's required JSON object."""
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if value is None:
        return {}
    if isinstance(value, str):
        return {"raw": value}
    if isinstance(value, (list, tuple)):
        return {"value": [_jsonable(item) for item in value]}
    return {"value": _jsonable(value)}


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return str(value)


def _text_of(value: Any) -> str | None:
    """Best-effort text extraction from SDK content payloads."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, Mapping):
        for key in ("text", "content", "message", "output", "stdout"):
            inner = _text_of(value.get(key))
            if inner:
                return inner
        return None
    if isinstance(value, (list, tuple)):
        parts = [_text_of(item) for item in value]
        joined = "\n".join(part for part in parts if part)
        return joined or None
    for attribute in ("text", "thinking", "content", "output", "stdout"):
        if hasattr(value, attribute):
            inner = _text_of(getattr(value, attribute))
            if inner:
                return inner
    return None


def _first_text(*values: Any) -> str | None:
    for value in values:
        text = _text_of(value)
        if text:
            return text
    return None


def _bounded(value: str, limit: int) -> str:
    if len(value.encode("utf-8", "replace")) <= limit:
        return value
    encoded = value.encode("utf-8", "replace")[:limit]
    return encoded.decode("utf-8", "ignore") + _TRUNCATION_NOTICE


def _atomic_write(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".tmp-{uuid4().hex[:8]}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_component(value: str, *, limit: int = 96) -> str:
    """One path component that can never escape the trajectory root.

    Dots are preserved (``stage6-disclosures/.dedupe-logs`` stays itself) but
    ``.`` and ``..`` are collapsed, so a hostile or accidental label cannot
    address a parent directory.
    """
    cleaned = _SAFE_COMPONENT.sub("_", value)
    if cleaned in {"", ".", ".."}:
        cleaned = "_"
    return cleaned[:limit]


def agent_version() -> str:
    try:
        from importlib.metadata import version

        return version("code-auditor")
    except Exception:  # pragma: no cover - packaging metadata is best effort
        return "0.1.0"


# --------------------------------------------------------------------------- #
# path layout
# --------------------------------------------------------------------------- #


def trajectories_root(config: Any) -> Path:
    """Return the directory holding this run's trajectory files."""
    configured = getattr(config, "trajectory_root_dir", None)
    if configured:
        return Path(configured)
    dirname = getattr(config, "trajectory_dirname", "trajectories")
    return Path(getattr(config, "output_dir", ".")) / dirname


def child_trajectory_path(config: Any, log_file: str | None, label: str | None = None) -> Path:
    """Derive the child trajectory path for one agent invocation.

    The layout mirrors the logical agent log location (``stage3-findings/logs``,
    ``stage5-pocs/H-12``, ...), computed against the *config the caller passed
    to* ``run_agent``. That keeps the path stable for the Stage 5/6 Docker
    scratch config, whose ``output_dir`` is a disposable directory while the
    trajectory itself must land in the real run output.
    """
    root = trajectories_root(config)
    relative: Path
    if label:
        relative = Path(*[_safe_component(part) for part in Path(label).parts])
    elif log_file:
        output_dir = getattr(config, "output_dir", "") or "."
        try:
            directory = os.path.relpath(os.path.dirname(log_file), output_dir)
        except ValueError:
            directory = "unattributed"
        if directory.startswith(".."):
            directory = "unattributed"
        relative = Path(directory) / _safe_component(Path(log_file).stem)
    else:
        relative = Path("unattributed") / f"agent-{uuid4().hex[:8]}"
    if relative.suffix != ".json":
        relative = relative.with_suffix(".json")
    return root / relative


# --------------------------------------------------------------------------- #
# recorder
# --------------------------------------------------------------------------- #


@dataclass
class _Pending:
    step_id: int
    tool_call_id: str


class TrajectoryRecorder:
    """Builds one ATIF-v1.7 document from agent events."""

    def __init__(
        self,
        *,
        session_id: str | None = None,
        trajectory_id: str | None = None,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_version_value: str | None = None,
        model_name: str | None = None,
        reasoning_effort: str | None = None,
        max_inline_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        max_total_inline_bytes: int = DEFAULT_MAX_TOTAL_INLINE_BYTES,
        redact: bool = True,
        blob_dir: Path | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        self.session_id = session_id
        self.trajectory_id = trajectory_id or uuid4().hex
        self.agent_name = agent_name
        self.agent_version = agent_version_value or agent_version()
        self.model_name = model_name
        self.reasoning_effort = reasoning_effort
        self.max_inline_bytes = max(0, int(max_inline_bytes))
        self.max_total_inline_bytes = max(0, int(max_total_inline_bytes))
        self._inline_bytes = 0
        self.redact = redact
        self.blob_dir = blob_dir
        self.extra: dict[str, Any] = dict(extra or {})
        self.steps: list[dict[str, Any]] = []
        self.final_metrics: dict[str, Any] | None = None
        self.start_time = time.time()
        self._pending: dict[str, _Pending] = {}
        self._last_agent_step: int | None = None
        self._lock = threading.Lock()
        self._codex_text: list[str] = []
        self._codex_reasoning: dict[str, str] = {}
        self._codex_calls: dict[str, dict[str, Any]] = {}
        self._codex_usage: dict[str, Any] | None = None
        self._codex_usage_total: dict[str, float] = {}
        self._pending_codex_usage: dict[str, float] = {}
        self._last_codex_message_step: int | None = None
        self._notes: list[str] = []

    # -- construction ------------------------------------------------------ #

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        max_inline_bytes: int = DEFAULT_MAX_RESULT_BYTES,
        max_total_inline_bytes: int = DEFAULT_MAX_TOTAL_INLINE_BYTES,
        redact: bool = True,
        blob_dir: Path | None = None,
    ) -> "TrajectoryRecorder | None":
        """Load a previously written document so a retry can append to it.

        Returns ``None`` when the file is missing or is not a trajectory this
        module wrote; the caller then starts a fresh document instead of
        appending to something it cannot interpret.
        """
        try:
            raw = path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        version = data.get("schema_version")
        if not isinstance(version, str) or not version.startswith(SUPPORTED_PREFIX):
            return None
        steps = data.get("steps")
        if not isinstance(steps, list):
            return None
        raw_agent = data.get("agent")
        agent: dict[str, Any] = dict(raw_agent) if isinstance(raw_agent, dict) else {}
        recorder = cls(
            session_id=data.get("session_id") if isinstance(data.get("session_id"), str) else None,
            trajectory_id=data.get("trajectory_id")
            if isinstance(data.get("trajectory_id"), str)
            else None,
            agent_name=str(agent.get("name") or DEFAULT_AGENT_NAME),
            agent_version_value=str(agent.get("version") or agent_version()),
            model_name=agent.get("model_name") if isinstance(agent.get("model_name"), str) else None,
            max_inline_bytes=max_inline_bytes,
            max_total_inline_bytes=max_total_inline_bytes,
            redact=redact,
            blob_dir=blob_dir,
            extra=data.get("extra") if isinstance(data.get("extra"), dict) else None,
        )
        recorder.steps = [step for step in steps if isinstance(step, dict)]
        recorder._inline_bytes = sum(
            len(content.encode("utf-8", "replace"))
            for step in recorder.steps
            for result in (step.get("observation") or {}).get("results", [])
            if isinstance(result, dict)
            for content in (result.get("content"),)
            if isinstance(content, str)
        )
        if isinstance(data.get("final_metrics"), dict):
            recorder.final_metrics = dict(data["final_metrics"])
        if isinstance(data.get("notes"), str) and data["notes"]:
            recorder._notes.append(data["notes"])
        for step in reversed(recorder.steps):
            if step.get("source") == "agent":
                recorder._last_agent_step = len(recorder.steps)
                break
        return recorder

    # -- normalisation ----------------------------------------------------- #

    def _redact_deep(self, value: Any) -> Any:
        """Redact string leaves inside nested argument/extra payloads."""
        if not self.redact:
            return value
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, Mapping):
            return {str(key): self._redact_deep(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._redact_deep(item) for item in value]
        return value

    def _clean(self, value: str | None) -> str | None:
        if value is None:
            return None
        text = value if isinstance(value, str) else str(value)
        if self.redact:
            text = redact_text(text)
        return _bounded(text, MAX_MESSAGE_BYTES)

    def _blob(self, content: str) -> str | None:
        """Persist over-long result content; return its relative path."""
        if self.blob_dir is None:
            return None
        encoded = content.encode("utf-8", "replace")
        digest = hashlib.sha256(encoded).hexdigest()[:32]
        path = self.blob_dir / f"{digest}.txt"
        if not path.exists():
            try:
                _atomic_write(path, content)
            except OSError as exc:
                logger.warning("Failed to persist trajectory blob: %s", exc)
                return None
        return path.name

    def _result_content(self, content: Any) -> tuple[str, dict[str, Any]]:
        """Normalise one tool result, spilling oversized payloads to blobs."""
        text = _text_of(content)
        if text is None:
            text = "" if content is None else json.dumps(_jsonable(content), ensure_ascii=False)
        if self.redact:
            text = redact_text(text)
        extra: dict[str, Any] = {}
        raw_size = len(text.encode("utf-8", "replace"))
        budget_exceeded = (
            self.max_total_inline_bytes > 0
            and self._inline_bytes >= self.max_total_inline_bytes
        )
        if raw_size > self.max_inline_bytes or budget_exceeded:
            blob = self._blob(text)
            extra["truncated"] = True
            extra["bytes"] = raw_size
            if blob:
                extra["blob"] = f"{BLOBS_DIRNAME}/{blob}"
            if budget_exceeded:
                extra["inline_budget_exceeded"] = True
                keep = min(self.max_inline_bytes, 4096)
            else:
                keep = self.max_inline_bytes
            text = _bounded(text, keep)
        self._inline_bytes += len(text.encode("utf-8", "replace"))
        return text, extra

    # -- step builders ----------------------------------------------------- #

    def _append(self, step: dict[str, Any]) -> int:
        with self._lock:
            step["step_id"] = len(self.steps) + 1
            self.steps.append(step)
            return step["step_id"]

    def system(self, message: str, *, extra: Mapping[str, Any] | None = None) -> int:
        step: dict[str, Any] = {"source": "system", "message": self._clean(message) or ""}
        step["timestamp"] = _iso_now()
        if extra:
            step["extra"] = _jsonable(self._redact_deep(dict(extra)))
        return self._append(step)

    def user(self, message: str, *, extra: Mapping[str, Any] | None = None) -> int:
        step: dict[str, Any] = {"source": "user", "message": self._clean(message) or ""}
        step["timestamp"] = _iso_now()
        if extra:
            step["extra"] = _jsonable(self._redact_deep(dict(extra)))
        return self._append(step)

    def agent_step(
        self,
        *,
        message: str = "",
        tool_calls: Sequence[Mapping[str, Any]] = (),
        reasoning: str | None = None,
        model: str | None = None,
        reasoning_effort: str | None = None,
        llm_call_count: int | None = None,
        extra: Mapping[str, Any] | None = None,
    ) -> int:
        """Append one ``source="agent"`` step and register its pending results."""
        step: dict[str, Any] = {
            "source": "agent",
            "message": self._clean(message) or "",
            "timestamp": _iso_now(),
        }
        resolved_model = model or self.model_name
        if resolved_model:
            step["model_name"] = resolved_model
        effort = reasoning_effort if reasoning_effort is not None else self.reasoning_effort
        if effort:
            step["reasoning_effort"] = effort
        cleaned_reasoning = self._clean(reasoning)
        if cleaned_reasoning:
            step["reasoning_content"] = cleaned_reasoning
        calls: list[dict[str, Any]] = []
        for index, raw in enumerate(tool_calls):
            call_id = str(raw.get("tool_call_id") or f"call-{uuid4().hex[:12]}-{index}")
            calls.append(
                {
                    "tool_call_id": call_id,
                    "function_name": str(raw.get("function_name") or "unknown"),
                    "arguments": self._redact_deep(_as_arguments(raw.get("arguments"))),
                    **(
                        {
                            "extra": _jsonable(
                                self._redact_deep(
                                    {str(k): v for k, v in raw["extra"].items()}
                                )
                            )
                        }
                        if isinstance(raw.get("extra"), Mapping)
                        else {}
                    ),
                }
            )
        if calls:
            step["tool_calls"] = calls
        step["llm_call_count"] = 1 if llm_call_count is None else max(0, int(llm_call_count))
        count = step["llm_call_count"]
        if count == 0:
            # ATIF: a deterministic step carries neither metrics nor reasoning.
            step.pop("reasoning_content", None)
        if extra:
            step["extra"] = _jsonable(self._redact_deep(dict(extra)))

        step_id = self._append(step)
        self._last_agent_step = step_id
        for call in calls:
            self._pending[call["tool_call_id"]] = _Pending(step_id=step_id, tool_call_id=call["tool_call_id"])
        return step_id

    def _step_by_id(self, step_id: int) -> dict[str, Any] | None:
        if 1 <= step_id <= len(self.steps):
            return self.steps[step_id - 1]
        return None

    def tool_result(
        self,
        tool_call_id: str,
        content: Any,
        *,
        is_error: bool = False,
        extra: Mapping[str, Any] | None = None,
        subagent_trajectory_ref: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        """Attach one result to the step that declared ``tool_call_id``.

        ``subagent_trajectory_ref`` is a first-class ATIF field of the result
        (not part of ``extra``); it is how a delegation points at the child
        trajectory document.
        """
        text, result_extra = self._result_content(content)
        result: dict[str, Any] = {"source_call_id": tool_call_id, "content": text}
        if subagent_trajectory_ref:
            result["subagent_trajectory_ref"] = [
                {str(key): _jsonable(value) for key, value in ref.items()}
                for ref in subagent_trajectory_ref
            ]
        merged = dict(result_extra)
        if is_error:
            merged["is_error"] = True
        if extra:
            merged.update({str(key): _jsonable(value) for key, value in extra.items()})
        if merged:
            result["extra"] = _jsonable(self._redact_deep(merged))

        with self._lock:
            pending = self._pending.pop(tool_call_id, None)
            target = self._step_by_id(pending.step_id) if pending else None
            if target is None:
                # A result whose call was declared by an earlier attempt (or by
                # a provider we did not see the start of) still has to be
                # recorded: keep it in its own deterministic step rather than
                # silently dropping evidence. ATIF only allows
                # ``source_call_id`` when the call is in the same step, so the
                # unresolvable id moves into ``extra``.
                target = {
                    "source": "agent",
                    "message": "",
                    "timestamp": _iso_now(),
                    "llm_call_count": 0,
                    "extra": {"orphan_result": True},
                }
                target["step_id"] = len(self.steps) + 1
                self.steps.append(target)
                result.pop("source_call_id", None)
                result.setdefault("extra", {})["unknown_source_call_id"] = tool_call_id
            observation = target.setdefault("observation", {"results": []})
            results = observation.get("results")
            if not isinstance(results, list):
                results = []
                observation["results"] = results
            results.append(result)

    def deterministic(
        self,
        *,
        message: str = "",
        tool_calls: Sequence[Mapping[str, Any]] = (),
        results: Sequence[Mapping[str, Any]] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> int:
        """Append a non-LLM step (grading, container launch, delegation)."""
        step_id = self.agent_step(
            message=message,
            tool_calls=tool_calls,
            llm_call_count=0,
            extra=extra,
        )
        for result in results:
            refs = result.get("subagent_trajectory_ref")
            self.tool_result(
                str(result.get("source_call_id") or ""),
                result.get("content"),
                is_error=bool(result.get("is_error")),
                extra=result.get("extra") if isinstance(result.get("extra"), Mapping) else None,
                subagent_trajectory_ref=refs if isinstance(refs, list) else None,
            )
        return step_id

    def has_subagent(self, trajectory_path: str) -> bool:
        """Return whether this document already references ``trajectory_path``."""
        return any(
            ref.get("trajectory_path") == trajectory_path
            for step in self.steps
            for result in (step.get("observation") or {}).get("results", [])
            for ref in result.get("subagent_trajectory_ref") or []
        )

    def add_subagent(
        self,
        trajectory_path: str,
        *,
        label: str,
        summary: str | None = None,
        trajectory_id: str | None = None,
    ) -> int:
        """Record a delegation step that points at a child trajectory file.

        A child document is created once per logical agent task, but that task
        may run several times (validation repair, resume). Those attempts are
        appended to the same child document, so the parent must reference it
        once rather than adding a duplicate delegation step per attempt.
        """
        if self.has_subagent(trajectory_path):
            for step in self.steps:
                for result in (step.get("observation") or {}).get("results", []):
                    for existing_ref in result.get("subagent_trajectory_ref") or []:
                        if existing_ref.get("trajectory_path") == trajectory_path:
                            extra = step.setdefault("extra", {})
                            extra["delegations"] = int(extra.get("delegations", 1)) + 1
                            return int(step.get("step_id") or 0)
        call_id = f"delegate-{uuid4().hex[:12]}"
        ref: dict[str, Any] = {"trajectory_path": trajectory_path}
        if trajectory_id:
            ref["trajectory_id"] = trajectory_id
        if self.session_id:
            ref["session_id"] = self.session_id
        return self.deterministic(
            message="",
            tool_calls=[
                {
                    "tool_call_id": call_id,
                    "function_name": "delegate_subagent",
                    "arguments": {"label": label},
                }
            ],
            results=[
                {
                    "source_call_id": call_id,
                    "content": summary or "",
                    "subagent_trajectory_ref": [ref],
                }
            ],
            extra={"label": label},
        )

    # -- metrics ----------------------------------------------------------- #

    def record_step_metrics(
        self,
        step_id: int | None,
        usage: Mapping[str, Any] | None,
        cost_usd: float | None = None,
        *,
        extra: Mapping[str, Any] | None = None,
    ) -> None:
        metrics = _metrics_from_usage(usage)
        if cost_usd is not None:
            metrics["cost_usd"] = float(cost_usd)
        if extra:
            merged = metrics.get("extra")
            metrics["extra"] = {**(merged if isinstance(merged, dict) else {}), **dict(extra)}
        if not metrics:
            return
        target = step_id or self._last_agent_step
        step = self._step_by_id(target) if target else None
        if step is None or step.get("llm_call_count") == 0:
            step = self._step_by_id(self._last_agent_step) if self._last_agent_step else None
        if step is None or step.get("llm_call_count") == 0:
            # ATIF forbids ``metrics`` on a deterministic (``llm_call_count:
            # 0``) step. A run-level document has only such steps, so a usage
            # event that arrives there is dropped rather than made invalid.
            return
        existing = step.get("metrics")
        if isinstance(existing, dict):
            for key, value in metrics.items():
                if key == "extra" and isinstance(value, dict):
                    merged_extra = existing.get("extra")
                    existing["extra"] = {
                        **(merged_extra if isinstance(merged_extra, dict) else {}),
                        **value,
                    }
                elif isinstance(value, (int, float)) and isinstance(existing.get(key), (int, float)):
                    # Codex reports cumulative turn totals and Anthropic sends
                    # one ResultMessage per query: the newest figure replaces
                    # the previous one instead of double counting it.
                    existing[key] = value
                elif key not in existing:
                    existing[key] = value
        else:
            step["metrics"] = metrics

    def record_usage(self, usage: Mapping[str, Any] | None, cost_usd: float | None = None) -> None:
        self.record_step_metrics(self._last_agent_step, usage, cost_usd)

    # -- Claude events ----------------------------------------------------- #

    def on_claude_message(self, message: Any, *, model: str | None = None) -> None:
        """Map one ``claude-agent-sdk`` message onto ATIF steps."""
        message_type = type(message).__name__
        if message_type == "ResultMessage":
            usage = getattr(message, "usage", None)
            cost = getattr(message, "total_cost_usd", None)
            extra: dict[str, Any] = {}
            for name, key in (("num_turns", "num_turns"), ("duration_ms", "duration_ms")):
                value = getattr(message, name, None)
                if isinstance(value, (int, float)):
                    extra[key] = value
            self.record_step_metrics(
                self._last_agent_step,
                usage if isinstance(usage, Mapping) else None,
                cost if isinstance(cost, (int, float)) else None,
                extra=extra or None,
            )
            if getattr(message, "is_error", False):
                self._notes.append("agent reported an error result")
            return

        if message_type == "SystemMessage":
            subtype = _enum_value(getattr(message, "subtype", "")) or "session"
            extra = {"subtype": subtype}
            for attribute in ("session_id", "uuid"):
                value = getattr(message, attribute, None)
                if isinstance(value, str) and value:
                    extra[attribute] = value
            body = _first_text(getattr(message, "message", None), getattr(message, "content", None))
            if subtype in {"compact_boundary", "compact", "compaction"}:
                extra["context_management"] = {"boundary": "replace"}
            self.system(body or f"session event: {subtype}", extra=extra)
            return

        content = getattr(message, "content", None)
        if isinstance(content, str):
            # Older SDK builds hand back plain text instead of content blocks.
            if content:
                self.agent_step(message=content, model=model)
            return
        if not isinstance(content, list):
            return

        texts: list[str] = []
        reasoning: list[str] = []
        calls: list[dict[str, Any]] = []
        results: list[tuple[str, Any, bool]] = []
        for index, block in enumerate(content):
            text = getattr(block, "text", None)
            if isinstance(text, str) and text:
                texts.append(text)
                continue
            tool_name = getattr(block, "name", None)
            if isinstance(tool_name, str) and tool_name:
                calls.append(
                    {
                        "tool_call_id": str(getattr(block, "id", None) or f"tool-{uuid4().hex[:12]}-{index}"),
                        "function_name": tool_name,
                        "arguments": getattr(block, "input", None),
                    }
                )
                continue
            tool_use_id = getattr(block, "tool_use_id", None)
            if isinstance(tool_use_id, str):
                results.append(
                    (
                        tool_use_id,
                        getattr(block, "content", None),
                        bool(getattr(block, "is_error", False)),
                    )
                )
                continue
            thinking = getattr(block, "thinking", None)
            if isinstance(thinking, str) and thinking:
                reasoning.append(thinking)

        if texts or calls or reasoning:
            self.agent_step(
                message="\n".join(texts).strip(),
                tool_calls=calls,
                reasoning="\n".join(reasoning).strip() or None,
                model=model,
            )
        for call_id, result_content, is_error in results:
            self.tool_result(call_id, result_content, is_error=is_error)

    # -- Codex events ------------------------------------------------------ #

    def on_codex_event(self, event: Any, *, model: str | None = None) -> None:
        """Map one Codex app-server notification onto ATIF steps."""
        method = getattr(event, "method", "") or ""
        payload = getattr(event, "payload", None)
        if not method:
            return

        if method.lower().endswith("tokenusage/updated"):
            usage = _codex_usage(payload)
            if usage:
                self._codex_usage = usage
                self._record_codex_usage_delta(usage)
            return

        if method == "item/agentMessage/delta":
            delta = getattr(payload, "delta", "")
            if isinstance(delta, str) and delta:
                self._codex_text.append(delta)
            return

        item = _unwrap_root_model(getattr(payload, "item", None))
        if item is None:
            if method == "turn/completed":
                self._flush_codex_message(model=model, payload=payload)
            return

        item_id = str(getattr(item, "id", "") or f"item-{uuid4().hex[:12]}")
        item_type = _enum_value(getattr(item, "type", "")) or "unknown"

        if item_type == "reasoning":
            text = _first_text(
                getattr(item, "text", None),
                getattr(item, "summary", None),
                getattr(item, "content", None),
            )
            if text:
                self._codex_reasoning[item_id] = text
            return

        if item_type in {"userMessage", "plan", "hookPrompt"}:
            return
        if item_type not in _CODEX_TOOL_ITEM_TYPES:
            return

        if method == "item/started":
            if item_type != "agentMessage":
                self._codex_calls[item_id] = {
                    "function_name": _codex_tool_name(item, item_type),
                    "arguments": _codex_tool_arguments(item, item_type),
                }
            return

        if method != "item/completed":
            return

        if item_type == "agentMessage":
            text = _first_text(getattr(item, "text", None), getattr(item, "content", None))
            if text and not self._codex_text:
                self._codex_text.append(text)
            return

        call = self._codex_calls.pop(item_id, None) or {
            "function_name": _codex_tool_name(item, item_type),
            "arguments": _codex_tool_arguments(item, item_type),
        }
        call_id = f"codex-{item_id}"
        reasoning = self._codex_reasoning.pop(item_id, None)
        self.agent_step(
            message="",
            tool_calls=[
                {
                    "tool_call_id": call_id,
                    "function_name": call["function_name"],
                    "arguments": call["arguments"],
                }
            ],
            reasoning=reasoning,
            model=model,
            llm_call_count=0,
        )
        error = getattr(item, "error", None)
        output = _first_text(
            getattr(item, "aggregatedOutput", None),
            getattr(item, "aggregated_output", None),
            getattr(item, "output", None),
            getattr(item, "stdout", None),
            getattr(item, "result", None),
        )
        self.tool_result(
            call_id,
            output if output is not None else (error if error is not None else ""),
            is_error=bool(error),
            extra={"codex_item_type": item_type},
        )

    def _flush_codex_message(self, *, model: str | None, payload: Any) -> None:
        text = "".join(self._codex_text).strip()
        reasoning = "\n".join(value for value in self._codex_reasoning.values()).strip()
        self._codex_text.clear()
        self._codex_reasoning.clear()
        turn = getattr(payload, "turn", None)
        usage = _codex_usage(getattr(turn, "usage", None)) if turn is not None else None
        if usage:
            self._record_codex_usage_delta(usage)
        if not text and not reasoning and not self._pending_codex_usage:
            return
        step_id = self.agent_step(
            message=text,
            reasoning=reasoning or None,
            model=model,
            extra={"codex_event": "turn/completed"},
            llm_call_count=1,
        )
        self._last_codex_message_step = step_id
        self._flush_codex_usage_delta()

    def _record_codex_usage_delta(self, usage: Mapping[str, Any]) -> None:
        """Record Codex's cumulative usage as a per-turn delta.

        ``thread/tokenUsage/updated`` carries cumulative thread totals, often
        several times per turn. Treating each update as a fresh charge makes
        per-step sums wildly inconsistent with the run-level usage counters.
        """
        current = _usage_numbers(usage)
        delta = _usage_delta(current, self._codex_usage_total)
        self._codex_usage_total = current
        for key, value in delta.items():
            self._pending_codex_usage[key] = (
                self._pending_codex_usage.get(key, 0.0) + value
            )
        self._flush_codex_usage_delta()

    def _flush_codex_usage_delta(self) -> None:
        if not self._pending_codex_usage or self._last_codex_message_step is None:
            return
        pending = dict(self._pending_codex_usage)
        self._pending_codex_usage.clear()
        self.record_step_metrics(self._last_codex_message_step, pending, None)

    # -- finalisation ------------------------------------------------------ #

    def finish(
        self,
        *,
        notes: Iterable[str] | None = None,
        usage_totals: Mapping[str, Any] | None = None,
    ) -> None:
        """Freeze step ids and aggregate ``final_metrics``.

        ``usage_totals`` carries run-level accounting (ATIF ``FinalMetrics``
        keys) for documents whose steps do not own the provider calls — the
        run-level document delegates to child trajectories, so its own steps
        carry no metrics.
        """
        with self._lock:
            for index, step in enumerate(self.steps, start=1):
                step["step_id"] = index
            totals: dict[str, Any] = {}
            for step in self.steps:
                metrics = step.get("metrics")
                if not isinstance(metrics, dict):
                    continue
                for key, target in (
                    ("prompt_tokens", "total_prompt_tokens"),
                    ("completion_tokens", "total_completion_tokens"),
                    ("cached_tokens", "total_cached_tokens"),
                ):
                    value = metrics.get(key)
                    if isinstance(value, (int, float)):
                        totals[target] = totals.get(target, 0) + value
                cost = metrics.get("cost_usd")
                if isinstance(cost, (int, float)):
                    totals["total_cost_usd"] = totals.get("total_cost_usd", 0.0) + float(cost)
            totals["total_steps"] = len(self.steps)
            if usage_totals:
                for key, value in usage_totals.items():
                    if key == "extra":
                        continue
                    if isinstance(value, (int, float)):
                        totals[key] = value
                extra = usage_totals.get("extra")
                if isinstance(extra, Mapping) and extra:
                    totals["extra"] = {str(k): _jsonable(v) for k, v in extra.items()}
            self.final_metrics = totals
        for note in notes or ():
            if note:
                self._notes.append(str(note))

    def extend_extra(self, values: Mapping[str, Any]) -> None:
        self.extra.update({str(key): _jsonable(value) for key, value in values.items()})

    def to_dict(self) -> dict[str, Any]:
        steps: list[dict[str, Any]] = []
        for index, raw in enumerate(self.steps, start=1):
            # ``step_id`` first: these documents are also read by humans.
            step: dict[str, Any] = {"step_id": index}
            for key, value in raw.items():
                if key == "step_id" or value is None:
                    continue
                step[key] = value
            if not isinstance(step.get("message", ""), (str, list)):
                step["message"] = str(step.get("message", ""))
            steps.append(step)
        document: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "agent": {
                "name": self.agent_name,
                "version": self.agent_version,
                **({"model_name": self.model_name} if self.model_name else {}),
            },
            "steps": steps,
            "final_metrics": self.final_metrics or {"total_steps": len(steps)},
        }
        if self.session_id:
            document["session_id"] = self.session_id
        document["trajectory_id"] = self.trajectory_id
        if self.extra:
            document["extra"] = dict(self.extra)
        if self._notes:
            document["notes"] = "; ".join(dict.fromkeys(self._notes))
        return document

    def write(self, path: Path) -> Path:
        document = self.to_dict()
        problems = validate_trajectory(document)
        if problems:
            # Never publish a document that violates ATIF; keep the evidence on
            # disk next to it so the defect can be diagnosed.
            logger.warning(
                "Trajectory %s failed ATIF validation (%s); written as .invalid.json",
                path,
                "; ".join(problems[:3]),
            )
            invalid = path.with_suffix(".invalid.json")
            _atomic_write(
                invalid,
                json.dumps(document, ensure_ascii=False, sort_keys=False),
            )
            return invalid
        _atomic_write(path, json.dumps(document, ensure_ascii=False, sort_keys=False))
        return path

    # -- introspection ----------------------------------------------------- #

    @property
    def step_count(self) -> int:
        return len(self.steps)

    def summary(self) -> str:
        """One-line description used as the parent's delegation result."""
        tokens = (self.final_metrics or {}).get("total_prompt_tokens", 0)
        return (
            f"{self.step_count} steps, {int(tokens)} prompt tokens, "
            f"{self.agent_name}"
        )


# --------------------------------------------------------------------------- #
# usage mapping
# --------------------------------------------------------------------------- #


def _metrics_from_usage(usage: Mapping[str, Any] | None) -> dict[str, Any]:
    """Map provider usage onto ATIF ``MetricsSchema``.

    Anthropic reports ``input_tokens`` *excluding* cache reads/writes, while
    ATIF defines ``prompt_tokens`` as "all input tokens, cached and
    non-cached". The sum is therefore used for ``prompt_tokens`` and the cache
    read count is the (subset) ``cached_tokens``.
    """
    if not isinstance(usage, Mapping):
        return {}
    metrics: dict[str, Any] = {}

    def number(*names: str) -> float | None:
        for name in names:
            value = usage.get(name)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return value
        return None

    explicit_prompt = number("prompt_tokens", "total_prompt_tokens")
    input_tokens = number("input_tokens", "inputTokens")
    cache_read = number("cache_read_input_tokens", "cachedInputTokens", "cached_tokens")
    cache_write = number(
        "cache_creation_input_tokens",
        "cacheCreationInputTokens",
        "cache_write_input_tokens",
    )
    output_tokens = number("output_tokens", "outputTokens", "completion_tokens")
    reasoning_tokens = number(
        "reasoningOutputTokens",
        "reasoning_output_tokens",
        "reasoning_tokens",
    )

    if explicit_prompt is not None:
        metrics["prompt_tokens"] = int(explicit_prompt)
    elif input_tokens is not None:
        total_prompt = input_tokens + (cache_read or 0) + (cache_write or 0)
        metrics["prompt_tokens"] = int(total_prompt)
    if output_tokens is not None:
        metrics["completion_tokens"] = int(output_tokens)
    if cache_read is not None:
        metrics["cached_tokens"] = int(cache_read)
    extras: dict[str, Any] = {}
    if cache_write:
        extras["cache_creation_input_tokens"] = int(cache_write)
    if reasoning_tokens:
        extras["reasoning_tokens"] = int(reasoning_tokens)
    if "cacheCreationInputTokens" in usage and cache_write:
        extras.setdefault("cache_creation_input_tokens", int(cache_write))
    if extras:
        metrics["extra"] = extras
    return metrics


def relative_trajectory_path(path: Path, root: Path) -> str:
    """Path of ``path`` relative to the run's trajectory root, POSIX-style."""
    return Path(os.path.relpath(path, root)).as_posix()


def merge_final_metrics(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Combine totals from an earlier run segment with this one.

    Resuming an audit loads its run-level document so previously completed
    delegations stay referenced, but ``config.usage_stats`` only covers the
    current process. The previous ``final_metrics`` are therefore added rather
    than replaced; ``total_steps`` is left to the freshly written document.
    """
    merged: dict[str, Any] = dict(current or {})
    for key, value in (previous or {}).items():
        if key == "total_steps":
            continue
        if key == "extra" and isinstance(value, Mapping):
            extra = dict(merged.get("extra") or {})
            for inner_key, inner_value in value.items():
                existing = extra.get(inner_key)
                if isinstance(inner_value, (int, float)) and isinstance(
                    existing, (int, float)
                ):
                    extra[str(inner_key)] = existing + inner_value
                elif inner_key not in extra:
                    extra[str(inner_key)] = inner_value
            merged["extra"] = extra
        elif isinstance(value, (int, float)) and isinstance(
            merged.get(key), (int, float)
        ):
            merged[key] = merged[key] + value
        elif key not in merged:
            merged[key] = value
    return merged


def atif_totals_from_usage_stats(stats: Mapping[str, Any] | None) -> dict[str, Any]:
    """Translate ``AuditConfig.usage_stats`` into ATIF ``FinalMetrics`` keys.

    ``usage_stats`` accumulates per-invocation provider usage across a run,
    including calls whose trajectory was not written (a status checker, a
    failed open). ATIF defines ``total_prompt_tokens`` as cached + non-cached
    input, so the cache counters are added rather than compared.
    """
    if not isinstance(stats, Mapping):
        return {}

    def number(*names: str) -> float | None:
        for name in names:
            value = stats.get(name)
            if isinstance(value, bool):
                continue
            if isinstance(value, (int, float)):
                return float(value)
        return None

    prompt_total = number("prompt_tokens", "total_prompt_tokens")
    inputs = number("input_tokens")
    outputs = number("output_tokens", "completion_tokens")
    cache_read = number("cache_read_input_tokens", "cached_tokens")
    cache_write = number("cache_creation_input_tokens")
    cost = number("cost_usd", "total_cost_usd")
    calls = number("agent_calls")

    totals: dict[str, Any] = {}
    if prompt_total is not None:
        totals["total_prompt_tokens"] = int(prompt_total)
    elif inputs is not None:
        totals["total_prompt_tokens"] = int(inputs + (cache_read or 0) + (cache_write or 0))
    if outputs is not None:
        totals["total_completion_tokens"] = int(outputs)
    if cache_read is not None:
        totals["total_cached_tokens"] = int(cache_read)
    if cost is not None:
        totals["total_cost_usd"] = float(cost)
    extras: dict[str, Any] = {}
    if cache_write:
        extras["cache_creation_input_tokens"] = int(cache_write)
    if calls is not None:
        extras["agent_calls"] = int(calls)
    if extras:
        totals["extra"] = extras
    return totals


def _codex_usage(payload: Any) -> dict[str, Any] | None:
    """Extract a Codex token-usage breakdown (mirrors ``agent._codex_usage_dict``)."""
    if payload is None:
        return None
    if isinstance(payload, dict):
        data: Any = payload
    else:
        model_dump = getattr(payload, "model_dump", None)
        if callable(model_dump):
            data = model_dump()
        else:
            data = {
                key: getattr(payload, key)
                for key in (
                    "totalTokens",
                    "inputTokens",
                    "cachedInputTokens",
                    "outputTokens",
                    "reasoningOutputTokens",
                )
                if getattr(payload, key, None) is not None
            }
    if not isinstance(data, dict):
        return None
    for key in ("total", "token_usage", "tokenUsage", "last"):
        inner = data.get(key)
        if isinstance(inner, dict):
            return _codex_usage(inner)
    return data or None


def _unwrap_root_model(value: Any) -> Any:
    """Unwrap Pydantic ``RootModel`` values used by generated SDK unions."""
    root = getattr(value, "root", None)
    return root if root is not None else value


_USAGE_NUMBER_ALIASES: dict[str, tuple[str, ...]] = {
    "input_tokens": ("input_tokens", "inputTokens"),
    "output_tokens": ("output_tokens", "outputTokens"),
    "total_tokens": ("total_tokens", "totalTokens"),
    "cache_read_input_tokens": (
        "cache_read_input_tokens",
        "cached_input_tokens",
        "cachedInputTokens",
    ),
    "cache_write_input_tokens": (
        "cache_write_input_tokens",
        "cache_creation_input_tokens",
        "cacheCreationInputTokens",
    ),
    "reasoning_output_tokens": (
        "reasoning_output_tokens",
        "reasoningOutputTokens",
    ),
}


def _usage_numbers(usage: Mapping[str, Any]) -> dict[str, float]:
    """Normalize one provider usage breakdown to numeric canonical keys."""
    result: dict[str, float] = {}
    for canonical, aliases in _USAGE_NUMBER_ALIASES.items():
        for alias in aliases:
            value = usage.get(alias)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                continue
            result[canonical] = float(value)
            break
    if "total_tokens" in result and "output_tokens" in result:
        result["prompt_tokens"] = max(
            0.0, result["total_tokens"] - result["output_tokens"]
        )
    else:
        result["prompt_tokens"] = (
            result.get("input_tokens", 0.0)
            + result.get("cache_read_input_tokens", 0.0)
            + result.get("cache_write_input_tokens", 0.0)
        )
    return result


def _usage_delta(
    current: Mapping[str, float], previous: Mapping[str, float]
) -> dict[str, float]:
    """Return non-negative per-key differences between two cumulative totals."""
    delta: dict[str, float] = {}
    for key, value in current.items():
        before = previous.get(key, 0.0)
        amount = value - before
        # A new turn/thread resets the provider counters. Treat that as a new
        # increment rather than silently dropping the first update.
        delta[key] = amount if amount >= 0 else value
    return delta


def _codex_tool_name(item: Any, item_type: str) -> str:
    if item_type == "commandExecution":
        return "shell"
    if item_type in {"fileChange", "patch", "file_write"}:
        return "apply_patch"
    if item_type in {"mcpToolCall", "dynamicToolCall"}:
        server = _enum_value(getattr(item, "server", "") or "")
        tool = _enum_value(getattr(item, "tool", "") or "")
        joined = "/".join(part for part in (server, tool) if part)
        return f"mcp:{joined}" if joined else f"mcp:{item_type}"
    if item_type == "webSearch":
        return "web_search"
    return item_type or "tool"


def _codex_tool_arguments(item: Any, item_type: str) -> dict[str, Any]:
    if item_type == "commandExecution":
        command = getattr(item, "command", None)
        return {"command": _jsonable(command)} if command is not None else {}
    if item_type in {"fileChange", "patch", "file_write"}:
        for name in ("changes", "patch", "diff", "path"):
            value = getattr(item, name, None)
            if value is not None:
                return {name: _jsonable(value)}
        return {}
    if item_type in {"mcpToolCall", "dynamicToolCall"}:
        server = getattr(item, "server", None)
        tool = getattr(item, "tool", None)
        arguments = getattr(item, "arguments", None)
        payload: dict[str, Any] = {}
        if server is not None:
            payload["server"] = _enum_value(server)
        if tool is not None:
            payload["tool"] = _enum_value(tool)
        if arguments is not None:
            payload["arguments"] = _as_arguments(arguments)
        return payload
    if item_type == "webSearch":
        query = getattr(item, "query", None)
        return {"query": _jsonable(query)} if query is not None else {}
    return {}


# --------------------------------------------------------------------------- #
# validator (mirrors the ATIF v1.7 constraints we rely on)
# --------------------------------------------------------------------------- #


def validate_trajectory(document: Any) -> list[str]:
    """Return ATIF v1.7 violations; an empty list means the document is valid.

    This is the runtime guard used before publishing a trajectory. It mirrors
    the constraints encoded by Harbor's Pydantic models (and the PyPI ``atif``
    package) without adding a runtime dependency on either.
    """
    problems: list[str] = []
    if not isinstance(document, dict):
        return ["trajectory must be a JSON object"]

    version = document.get("schema_version")
    if version != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION!r}")

    agent = document.get("agent")
    if not isinstance(agent, dict):
        problems.append("agent must be an object")
    else:
        for key in ("name", "version"):
            value = agent.get(key)
            if not isinstance(value, str) or not value:
                problems.append(f"agent.{key} must be a non-empty string")
        model_name = agent.get("model_name")
        if model_name is not None and not isinstance(model_name, str):
            problems.append("agent.model_name must be a string when present")
        problems.extend(_unknown_fields(agent, _AGENT_FIELDS, "agent"))
        tool_definitions = agent.get("tool_definitions")
        if tool_definitions is not None and not isinstance(tool_definitions, list):
            problems.append("agent.tool_definitions must be an array when present")
        if agent.get("extra") is not None and not isinstance(agent.get("extra"), dict):
            problems.append("agent.extra must be an object when present")

    session_id = document.get("session_id")
    if session_id is not None and not isinstance(session_id, str):
        problems.append("session_id must be a string when present")
    trajectory_id = document.get("trajectory_id")
    if trajectory_id is not None and not isinstance(trajectory_id, str):
        problems.append("trajectory_id must be a string when present")
    notes = document.get("notes")
    if notes is not None and not isinstance(notes, str):
        problems.append("notes must be a string when present")
    if document.get("extra") is not None and not isinstance(document.get("extra"), dict):
        problems.append("extra must be an object when present")
    if document.get("continued_trajectory_ref") is not None and not isinstance(
        document.get("continued_trajectory_ref"), str
    ):
        problems.append("continued_trajectory_ref must be a string when present")
    embedded = document.get("subagent_trajectories")
    if embedded is not None and not isinstance(embedded, list):
        problems.append("subagent_trajectories must be an array when present")

    unknown = set(document) - {
        "schema_version",
        "session_id",
        "trajectory_id",
        "agent",
        "steps",
        "notes",
        "final_metrics",
        "continued_trajectory_ref",
        "extra",
        "subagent_trajectories",
    }
    if unknown:
        problems.append(f"unknown root fields: {sorted(unknown)}")

    steps = document.get("steps")
    if not isinstance(steps, list):
        problems.append("steps must be an array")
        steps = []
    if not steps:
        problems.append("steps must not be empty")

    for index, step in enumerate(steps, start=1):
        prefix = f"steps[{index - 1}]"
        if not isinstance(step, dict):
            problems.append(f"{prefix} must be an object")
            continue
        if step.get("step_id") != index:
            problems.append(f"{prefix}.step_id must be {index} (sequential from 1)")
        problems.extend(_unknown_fields(step, _STEP_FIELDS, prefix))
        source = step.get("source")
        if source not in _STEP_SOURCES:
            problems.append(f"{prefix}.source must be one of {sorted(_STEP_SOURCES)}")
        message = step.get("message")
        if not isinstance(message, (str, list)):
            problems.append(f"{prefix}.message must be a string or ContentPart array")
        timestamp = step.get("timestamp")
        if timestamp is not None:
            if not isinstance(timestamp, str):
                problems.append(f"{prefix}.timestamp must be an ISO 8601 string")
            else:
                try:
                    datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    problems.append(f"{prefix}.timestamp is not ISO 8601")

        if source != "agent":
            for field_name in _AGENT_ONLY_FIELDS:
                if step.get(field_name) is not None:
                    problems.append(
                        f"{prefix}.{field_name} is only valid on source='agent' steps"
                    )

        reasoning_effort = step.get("reasoning_effort")
        if reasoning_effort is not None and not isinstance(
            reasoning_effort, (str, int, float)
        ):
            problems.append(f"{prefix}.reasoning_effort must be a string or number")
        elif isinstance(reasoning_effort, bool):
            problems.append(f"{prefix}.reasoning_effort must be a string or number")
        if step.get("is_copied_context") is not None and not isinstance(
            step.get("is_copied_context"), bool
        ):
            problems.append(f"{prefix}.is_copied_context must be a boolean")
        llm_call_count = step.get("llm_call_count")
        if llm_call_count is not None and (
            not isinstance(llm_call_count, int) or isinstance(llm_call_count, bool)
        ):
            problems.append(f"{prefix}.llm_call_count must be an integer")
        elif isinstance(llm_call_count, int) and llm_call_count < 0:
            problems.append(f"{prefix}.llm_call_count must not be negative")
        if llm_call_count == 0 and source == "agent":
            if step.get("metrics") is not None:
                problems.append(
                    f"{prefix}.metrics must be absent when llm_call_count is 0"
                )
            if step.get("reasoning_content") is not None:
                problems.append(
                    f"{prefix}.reasoning_content must be absent when llm_call_count is 0"
                )

        tool_calls = step.get("tool_calls")
        call_ids: set[str] = set()
        if tool_calls is not None:
            if not isinstance(tool_calls, list):
                problems.append(f"{prefix}.tool_calls must be an array")
                tool_calls = []
            for call_index, call in enumerate(tool_calls):
                call_prefix = f"{prefix}.tool_calls[{call_index}]"
                if not isinstance(call, dict):
                    problems.append(f"{call_prefix} must be an object")
                    continue
                call_id = call.get("tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    problems.append(f"{call_prefix}.tool_call_id must be a non-empty string")
                elif call_id in call_ids:
                    problems.append(f"{call_prefix}.tool_call_id must be unique in the step")
                else:
                    call_ids.add(call_id)
                if not isinstance(call.get("function_name"), str) or not call.get("function_name"):
                    problems.append(f"{call_prefix}.function_name must be a non-empty string")
                if not isinstance(call.get("arguments"), dict):
                    problems.append(f"{call_prefix}.arguments must be a JSON object")
                problems.extend(_unknown_fields(call, _TOOL_CALL_FIELDS, call_prefix))

        observation = step.get("observation")
        if observation is not None:
            if not isinstance(observation, dict):
                problems.append(f"{prefix}.observation must be an object")
            else:
                results = observation.get("results")
                if not isinstance(results, list):
                    problems.append(f"{prefix}.observation.results must be an array")
                    results = []
                for result_index, result in enumerate(results):
                    result_prefix = f"{prefix}.observation.results[{result_index}]"
                    if not isinstance(result, dict):
                        problems.append(f"{result_prefix} must be an object")
                        continue
                    source_call_id = result.get("source_call_id")
                    if source_call_id is not None:
                        if not isinstance(source_call_id, str):
                            problems.append(f"{result_prefix}.source_call_id must be a string")
                        elif source_call_id not in call_ids:
                            problems.append(
                                f"{result_prefix}.source_call_id does not match a "
                                f"tool_call in step {index}"
                            )
                    content = result.get("content")
                    if content is not None and not isinstance(content, (str, list)):
                        problems.append(
                            f"{result_prefix}.content must be a string or ContentPart array"
                        )
                    problems.extend(
                        _unknown_fields(result, _RESULT_FIELDS, result_prefix)
                    )
                    refs = result.get("subagent_trajectory_ref")
                    if refs is not None:
                        if not isinstance(refs, list):
                            problems.append(f"{result_prefix}.subagent_trajectory_ref must be an array")
                            continue
                        for ref_index, ref in enumerate(refs):
                            ref_prefix = f"{result_prefix}.subagent_trajectory_ref[{ref_index}]"
                            if not isinstance(ref, dict):
                                problems.append(f"{ref_prefix} must be an object")
                                continue
                            if not ref.get("trajectory_id") and not ref.get("trajectory_path"):
                                problems.append(
                                    f"{ref_prefix} must set trajectory_id or trajectory_path"
                                )
                            problems.extend(
                                _unknown_fields(ref, _REF_FIELDS, ref_prefix)
                            )
                            for key in ("trajectory_id", "trajectory_path", "session_id"):
                                value = ref.get(key)
                                if value is not None and not isinstance(value, str):
                                    problems.append(
                                        f"{ref_prefix}.{key} must be a string when present"
                                    )

    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        metrics = step.get("metrics")
        if metrics is None:
            continue
        prefix = f"steps[{index - 1}].metrics"
        if not isinstance(metrics, dict):
            problems.append(f"{prefix} must be an object")
            continue
        problems.extend(_unknown_fields(metrics, _METRICS_FIELDS, prefix))
        for key in ("prompt_tokens", "completion_tokens", "cached_tokens"):
            value = metrics.get(key)
            if value is not None and not (
                isinstance(value, int) and not isinstance(value, bool)
            ):
                problems.append(f"{prefix}.{key} must be an integer")
        cost = metrics.get("cost_usd")
        if cost is not None and not _is_number(cost):
            problems.append(f"{prefix}.cost_usd must be a number")
        if metrics.get("extra") is not None and not isinstance(
            metrics.get("extra"), dict
        ):
            problems.append(f"{prefix}.extra must be an object")

    final_metrics = document.get("final_metrics")
    if final_metrics is not None:
        if not isinstance(final_metrics, dict):
            problems.append("final_metrics must be an object")
        else:
            problems.extend(
                _unknown_fields(final_metrics, _FINAL_METRICS_FIELDS, "final_metrics")
            )
            for key in (
                "total_prompt_tokens",
                "total_completion_tokens",
                "total_cached_tokens",
                "total_steps",
            ):
                value = final_metrics.get(key)
                if value is not None and not (
                    isinstance(value, int) and not isinstance(value, bool)
                ):
                    problems.append(f"final_metrics.{key} must be an integer")
            cost = final_metrics.get("total_cost_usd")
            if cost is not None and not _is_number(cost):
                problems.append("final_metrics.total_cost_usd must be a number")
            if final_metrics.get("extra") is not None and not isinstance(
                final_metrics.get("extra"), dict
            ):
                problems.append("final_metrics.extra must be an object")

    for sub_index, sub in enumerate(document.get("subagent_trajectories") or []):
        if not isinstance(sub, dict) or not isinstance(sub.get("trajectory_id"), str):
            problems.append(
                f"subagent_trajectories[{sub_index}] must set trajectory_id when embedded"
            )

    return problems
