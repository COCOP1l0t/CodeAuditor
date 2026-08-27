from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import os
import re
import shutil
import signal
import subprocess
import time
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Protocol, TextIO
from uuid import uuid4

from .config import AuditConfig, ValidationIssue, resolve_agent_model
from .logger import get_logger
from .process_tree import AUDIT_PROCESS_MARKER_ENV, CURRENT_AUDIT_PROCESS_MARKER
from .utils import extract_json_object, format_validation_issues, record_agent_usage

if TYPE_CHECKING:
    from .sandbox import DockerScratch

AGENT_MAX_RETRIES = 3
AGENT_RETRY_BASE_DELAY = 10  # seconds
STATUS_CHECK_AGENT_TIMEOUT_SECONDS = 5 * 60
STATUS_CHECK_LOG_MAX_CHARS = 200_000
DEFAULT_CODEX_BIN = "/usr/local/bin/codex"
CODEX_BIN_ENV = "CODE_AUDITOR_CODEX_BIN"
AGENT_ACTIVITY_MAX_CHARS = 800
AGENT_SYSTEM_ACTIVITY_INTERVAL_SECONDS = 5.0
AGENT_NOISY_SYSTEM_EVENTS = {
    "thinking_tokens": "Reasoning in progress",
    "task_progress": "Task progress active",
}
AGENT_PROCESS_MARKER_ENV = "CODE_AUDITOR_AGENT_RUN_ID"
AGENT_PROCESS_TERM_TIMEOUT_SECONDS = 1.0
AGENT_PROCESS_KILL_TIMEOUT_SECONDS = 1.0
PROC_ROOT = "/proc"

logger = get_logger("agent")

# Errors that retrying cannot fix (quota/credit exhaustion, auth failures).
# Fail fast instead of burning AGENT_MAX_RETRIES attempts on each task.
_NON_RETRYABLE_AGENT_ERROR_PATTERN = re.compile(
    r"no left credit|insufficient\s*(credit|balance|quota)|quota exceeded"
    r"|invalid\s*api[\s_-]*key|authentication failed|unauthorized"
    r"|supported api model names|invalid[ _-]model|model not found|unknown model"
    r"|\b401\b|\b403\b",
    re.IGNORECASE,
)


def _is_non_retryable_agent_error(exc: BaseException) -> bool:
    return bool(_NON_RETRYABLE_AGENT_ERROR_PATTERN.search(str(exc)))

class _KillableProcess(Protocol):
    def kill(self) -> object:
        ...


_claude_sdk_patched = False
_modern_claude_sdk_patched = False
_CODEX_SERVICE_TIER_COMPAT_ATTR = "_code_auditor_service_tier_compat"
_AGENT_PROCESS_REGISTRAR: ContextVar[Callable[[_KillableProcess | None], None] | None] = ContextVar(
    "agent_process_registrar",
    default=None,
)


@dataclass
class _AgentRunControl:
    processes: list[_KillableProcess] = field(default_factory=list)
    killed_after_status_check: bool = False
    process_marker: str = field(default_factory=lambda: uuid4().hex)

    def register_process(self, process: _KillableProcess | None) -> None:
        if process is None or process in self.processes:
            return
        self.processes.append(process)

    def kill_processes(self, log_file: str, reason: str) -> None:
        self.killed_after_status_check = True
        if not self.processes:
            logger.warning(
                "Status checker decided the agent has finished, but no agent process was registered to kill: %s. Reason: %s",
                log_file,
                reason,
            )
            return

        for process in list(self.processes):
            pid = getattr(process, "pid", "?")
            logger.warning(
                "Status checker decided the agent has finished; killing agent process pid=%s: %s. Reason: %s",
                pid,
                log_file,
                reason,
            )
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.warning("Failed to kill stale agent process pid=%s: %s", pid, exc)

    def subprocess_env(self) -> dict[str, str]:
        """Environment inherited by the agent CLI and every command it starts."""
        env = {AGENT_PROCESS_MARKER_ENV: self.process_marker}
        audit_marker = CURRENT_AUDIT_PROCESS_MARKER.get()
        if audit_marker:
            env[AUDIT_PROCESS_MARKER_ENV] = audit_marker
        return env

    async def cleanup_processes(self) -> None:
        """Stop agent descendants that detached from their original parent."""
        pids = _marked_agent_process_ids(self.process_marker)
        if not pids:
            return

        logger.warning(
            "Cleaning up %d process(es) left by agent run %s: %s",
            len(pids),
            self.process_marker[:8],
            ", ".join(str(pid) for pid in pids),
        )
        _signal_marked_agent_processes(self.process_marker, pids, signal.SIGTERM)
        survivors = await _wait_for_marked_agent_processes(
            self.process_marker,
            AGENT_PROCESS_TERM_TIMEOUT_SECONDS,
        )
        if not survivors:
            return

        logger.warning(
            "Agent process(es) ignored SIGTERM; sending SIGKILL: %s",
            ", ".join(str(pid) for pid in survivors),
        )
        _signal_marked_agent_processes(
            self.process_marker,
            survivors,
            signal.SIGKILL,
        )
        survivors = await _wait_for_marked_agent_processes(
            self.process_marker,
            AGENT_PROCESS_KILL_TIMEOUT_SECONDS,
        )
        if survivors:
            logger.error(
                "Agent process cleanup could not stop pid(s): %s",
                ", ".join(str(pid) for pid in survivors),
            )


def _process_has_agent_marker(pid: int, process_marker: str) -> bool:
    """Return whether a live process inherited this exact agent-run marker."""
    if pid == os.getpid():
        return False
    expected = f"{AGENT_PROCESS_MARKER_ENV}={process_marker}".encode()
    try:
        with open(os.path.join(PROC_ROOT, str(pid), "environ"), "rb") as proc_env:
            return expected in proc_env.read().split(b"\0")
    except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
        return False


def _marked_agent_process_ids(process_marker: str) -> list[int]:
    """Find same-user descendants even after they have been reparented."""
    try:
        entries = os.scandir(PROC_ROOT)
    except OSError:
        logger.warning(
            "Cannot scan %s; detached agent process cleanup is unavailable.",
            PROC_ROOT,
        )
        return []

    with entries:
        pids = [
            int(entry.name)
            for entry in entries
            if entry.name.isdigit()
            and _process_has_agent_marker(int(entry.name), process_marker)
        ]
    return sorted(pids)


def _signal_marked_agent_processes(
    process_marker: str,
    pids: list[int],
    sig: signal.Signals,
) -> None:
    for pid in pids:
        # Recheck the marker immediately before signalling so a reused PID can
        # never target an unrelated process.
        if not _process_has_agent_marker(pid, process_marker):
            continue
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            pass
        except OSError as exc:
            logger.warning("Failed to signal stale agent process pid=%s: %s", pid, exc)


async def _wait_for_marked_agent_processes(
    process_marker: str,
    timeout_seconds: float,
) -> list[int]:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while True:
        survivors = _marked_agent_process_ids(process_marker)
        if not survivors or asyncio.get_running_loop().time() >= deadline:
            return survivors
        await asyncio.sleep(0.05)


def _register_current_agent_process(process: _KillableProcess | None) -> None:
    registrar = _AGENT_PROCESS_REGISTRAR.get()
    if registrar:
        registrar(process)


@dataclass(frozen=True)
class _AgentCompletionDecision:
    finished: bool
    reason: str


def _read_agent_log(log_file: str, max_chars: int | None = None) -> str:
    try:
        with open(log_file, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return ""
    if max_chars is not None and len(content) > max_chars:
        return content[-max_chars:]
    return content


def _parse_agent_completion_decision(response: str) -> _AgentCompletionDecision:
    json_text = extract_json_object(response)
    if json_text is None:
        raise ValueError("status-checking subagent did not return a JSON object")

    parsed = json.loads(json_text)
    if not isinstance(parsed, dict):
        raise ValueError("status-checking subagent JSON response is not an object")

    return _AgentCompletionDecision(
        finished=bool(parsed.get("finished", False)),
        reason=str(parsed.get("reason", "")).strip() or "no reason provided",
    )


def _build_status_check_prompt(log_file: str, log_excerpt: str) -> str:
    return (
        "You are a CodeAuditor status-checking subagent. Analyze the agent.log excerpt "
        "semantically and decide whether the code-auditor subagent has finished its "
        "analysis even though the parent process is still running.\n\n"
        "Return JSON only with this exact shape:\n"
        '{"finished": true|false, "reason": "short explanation"}\n\n'
        "Set finished=true only when the log clearly shows the agent completed the "
        "analysis or final output it was asked to produce. Set finished=false when the "
        "log shows ongoing work, active commands, pending investigation, retries, "
        "waiting, errors that still require action, or when the evidence is ambiguous.\n\n"
        f"Log file: {log_file}\n\n"
        "agent.log excerpt:\n"
        "```\n"
        f"{log_excerpt}\n"
        "```"
    )


async def _check_agent_log_semantically(
    config: AuditConfig,
    *,
    cwd: str,
    log_file: str,
    sandbox: DockerScratch | None = None,
) -> _AgentCompletionDecision:
    log_excerpt = _read_agent_log(log_file, max_chars=STATUS_CHECK_LOG_MAX_CHARS)
    if not log_excerpt.strip():
        return _AgentCompletionDecision(finished=False, reason="agent.log is empty or missing")

    prompt = _build_status_check_prompt(log_file, log_excerpt)
    try:
        response = await asyncio.wait_for(
            run_agent(
                prompt,
                config,
                cwd=cwd,
                allowed_tools=["Read"],
                max_turns=10,
                effort="low",
                log_file=None,
                sandbox=sandbox,
            ),
            timeout=STATUS_CHECK_AGENT_TIMEOUT_SECONDS,
        )
        return _parse_agent_completion_decision(response)
    except asyncio.TimeoutError:
        logger.warning("Status-checking subagent timed out for %s.", log_file)
    except Exception as exc:
        logger.warning("Status-checking subagent failed for %s: %s", log_file, exc)
    return _AgentCompletionDecision(finished=False, reason="status check failed")


async def _await_agent_with_semantic_timeout(
    agent_call: Coroutine[object, object, str],
    *,
    config: AuditConfig,
    cwd: str,
    log_file: str | None,
    run_control: _AgentRunControl,
    sandbox: DockerScratch | None = None,
) -> str:
    timeout_seconds = config.agent_timeout_seconds
    if not log_file or timeout_seconds is None:
        return await agent_call

    timeout_minutes = max(1, int(timeout_seconds // 60))
    agent_task = asyncio.create_task(agent_call)
    try:
        while True:
            done, _ = await asyncio.wait({agent_task}, timeout=timeout_seconds)
            if agent_task in done:
                return await agent_task

            logger.info(
                "Agent still running after %d minutes; launching semantic status checker for %s.",
                timeout_minutes,
                log_file,
            )
            decision = await _check_agent_log_semantically(
                config,
                cwd=cwd,
                log_file=log_file,
                sandbox=sandbox,
            )

            if agent_task.done():
                return await agent_task

            if not decision.finished:
                logger.info(
                    "Status checker says agent should continue for %s. Reason: %s",
                    log_file,
                    decision.reason,
                )
                continue

            run_control.kill_processes(log_file, decision.reason)
            agent_task.cancel()
            try:
                await asyncio.wait_for(agent_task, timeout=30)
            except asyncio.CancelledError:
                pass
            except asyncio.TimeoutError:
                logger.warning("Agent task did not exit after semantic status-check kill: %s", log_file)

            return _read_agent_log(log_file)
    finally:
        if not agent_task.done():
            agent_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await agent_task


def _patch_claude_sdk(sdk_client, mp, process_error, transport):  # type: ignore[no-untyped-def]
    """Patch Claude SDK compatibility issues after the SDK is imported."""
    # Patch SDK message parser to skip unknown message types instead of raising.
    # The installed SDK version (0.0.25) predates some newer event types
    # (e.g. rate_limit_event) emitted by the Claude Code backend.
    original_parse_message = mp.parse_message

    def patched_parse_message(data):  # type: ignore[no-untyped-def]
        try:
            return original_parse_message(data)
        except Exception:
            logger.debug("Skipping unknown SDK message type: %s", data.get("type", "?"))
            return None

    # Patch both the module-level reference and the client module's imported copy.
    mp.parse_message = patched_parse_message
    sdk_client.parse_message = patched_parse_message

    # Patch SubprocessCLITransport.connect to always capture stderr via PIPE,
    # and _read_messages_impl to include the captured stderr in the error message.
    original_connect = transport.SubprocessCLITransport.connect
    original_read_messages_impl = transport.SubprocessCLITransport._read_messages_impl

    async def patched_connect(self):  # type: ignore[no-untyped-def]
        """Patched connect that forces stderr=PIPE so we can read error output."""
        orig_debug_stderr = self._options.debug_stderr
        # The SDK only captures stderr when BOTH debug_stderr is set AND
        # "debug-to-stderr" is in extra_args.  We inject both temporarily
        # so the subprocess is launched with stderr=PIPE, then restore the
        # original values to avoid side-effects.
        self._options.debug_stderr = subprocess.PIPE
        had_debug_flag = "debug-to-stderr" in self._options.extra_args
        if not had_debug_flag:
            self._options.extra_args["debug-to-stderr"] = None

        try:
            await original_connect(self)
            if self._process:
                _register_current_agent_process(self._process)
        finally:
            self._options.debug_stderr = orig_debug_stderr
            if not had_debug_flag:
                self._options.extra_args.pop("debug-to-stderr", None)

    async def patched_read_messages_impl(self):  # type: ignore[no-untyped-def]
        """Patched _read_messages_impl that captures stderr on failure."""
        try:
            async for message in original_read_messages_impl(self):
                yield message
        except process_error as exc:
            # Try to read stderr for the real error details
            stderr_text = ""
            if self._process and self._process.stderr:
                try:
                    raw = await self._process.stderr.receive()
                    stderr_text = raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            if stderr_text:
                logger.error("Claude Code CLI stderr:\n%s", stderr_text)
                raise process_error(
                    f"{exc} — stderr: {stderr_text}",
                    exit_code=exc.exit_code,
                    stderr=stderr_text,
                ) from exc
            raise

    transport.SubprocessCLITransport.connect = patched_connect
    transport.SubprocessCLITransport._read_messages_impl = patched_read_messages_impl


def _load_claude_sdk():  # type: ignore[no-untyped-def]
    global _claude_sdk_patched, _modern_claude_sdk_patched
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk._internal.transport import subprocess_cli as transport

        if not _modern_claude_sdk_patched:
            original_connect = transport.SubprocessCLITransport.connect

            async def connect_and_register(self):  # type: ignore[no-untyped-def]
                await original_connect(self)
                _register_current_agent_process(getattr(self, "_process", None))

            transport.SubprocessCLITransport.connect = connect_and_register
            _modern_claude_sdk_patched = True
        return ClaudeAgentOptions, query
    except ImportError:
        pass

    try:
        from claude_code_sdk import ClaudeCodeOptions, query
        from claude_code_sdk._errors import ProcessError
        from claude_code_sdk._internal import client as sdk_client
        from claude_code_sdk._internal import message_parser as mp
        from claude_code_sdk._internal.transport import subprocess_cli as transport
    except ImportError as exc:
        raise RuntimeError(
            "Claude backend requires the claude-agent-sdk package. "
            "Install project dependencies before using --backend claude."
        ) from exc

    if not _claude_sdk_patched:
        _patch_claude_sdk(sdk_client, mp, ProcessError, transport)
        _claude_sdk_patched = True

    return ClaudeCodeOptions, query


def _accepts_keyword(callable_object: object, name: str) -> bool:
    try:
        parameters = inspect.signature(callable_object).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        parameter.name == name
        or parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )


def _custom_provider_values(config: AuditConfig) -> tuple[str, str]:
    base_url = (config.provider_base_url or "").strip()
    api_key = config.provider_api_key or ""
    if not base_url or not api_key:
        raise RuntimeError(
            f"Custom {config.backend} provider is missing its base URL or API key."
        )
    return base_url, api_key


DEFAULT_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit", "Bash"]


def _additional_directories(config: AuditConfig, cwd: str) -> list[str]:
    resolved_cwd = os.path.realpath(cwd)
    dirs: list[str] = []
    for candidate in [config.output_dir, config.wiki_path]:
        if not candidate:
            continue
        resolved = os.path.realpath(candidate)
        if resolved != resolved_cwd and os.path.isdir(resolved) and resolved not in dirs:
            dirs.append(resolved)
    return dirs


def _open_agent_log(log_file: str | None) -> TextIO | None:
    if not log_file:
        return None

    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    log_fh = open(log_file, "a")  # noqa: SIM115
    if log_fh.tell() > 0:
        log_fh.write("\n--- new agent invocation ---\n\n")
        log_fh.flush()
    else:
        os.utime(log_file, None)
    return log_fh


def _compact_agent_activity(value: object, max_chars: int = AGENT_ACTIVITY_MAX_CHARS) -> str:
    """Return one bounded line suitable for terminal, file, and Web logs."""
    text = " ".join(str(value or "").split())
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 1] + "…"


def _tool_input_summary(tool_name: str, tool_input: object) -> str:
    """Describe a tool call without dumping file contents or arbitrary payloads."""
    if not isinstance(tool_input, dict):
        return ""
    preferred_fields = {
        "Bash": ("command", "description"),
        "Read": ("file_path", "offset", "limit"),
        "Glob": ("pattern", "path"),
        "Grep": ("pattern", "path", "glob"),
        "Write": ("file_path",),
        "Edit": ("file_path",),
        "WebFetch": ("url",),
        "WebSearch": ("query",),
    }.get(tool_name, ("file_path", "path", "pattern", "query", "url"))
    fields = []
    for field_name in preferred_fields:
        value = tool_input.get(field_name)
        if value in (None, "", [], {}):
            continue
        fields.append(f"{field_name}={_compact_agent_activity(value, 300)}")
    return "; ".join(fields)


def _record_agent_activity(log_fh: TextIO | None, activity: str) -> None:
    """Persist one activity line and mirror it to the DEBUG log channel.

    Agent activity is per-tool-call noise: it always lands in the task's
    agent.log, but only surfaces on the console/Web log when the log level
    is DEBUG — INFO stays limited to stage-level milestones.
    """
    line = _compact_agent_activity(activity)
    if not line:
        return
    if log_fh:
        log_fh.write(f"[activity] {line}\n")
        log_fh.flush()
    logger.debug("Agent: %s", line)


def _codex_item_activity(method: str, payload: object) -> str | None:
    """Summarize tool-like Codex app-server item lifecycle notifications."""
    if method not in {"item/started", "item/completed"}:
        return None
    item = getattr(payload, "item", None)
    if item is None:
        return None
    item_type = getattr(item, "type", "")
    item_type = getattr(item_type, "value", item_type)
    if item_type in {"", "agentMessage", "reasoning"}:
        return None
    phase = "Started" if method == "item/started" else "Completed"
    if item_type == "commandExecution":
        command = _compact_agent_activity(getattr(item, "command", ""), 500)
        return f"{phase} command" + (f": {command}" if command else "")
    if item_type in {"mcpToolCall", "dynamicToolCall"}:
        server = _compact_agent_activity(getattr(item, "server", ""), 100)
        tool = _compact_agent_activity(getattr(item, "tool", ""), 200)
        name = "/".join(part for part in (server, tool) if part) or str(item_type)
        return f"{phase} tool {name}"
    return f"{phase} {item_type}"


def _resolve_codex_bin() -> str:
    configured = os.environ.get(CODEX_BIN_ENV)
    candidate = configured or shutil.which("codex") or DEFAULT_CODEX_BIN
    source = CODEX_BIN_ENV if configured else "PATH/default"
    if not os.path.isfile(candidate):
        raise RuntimeError(f"Codex CLI binary not found via {source}: {candidate}")
    if not os.access(candidate, os.X_OK):
        raise RuntimeError(f"Codex CLI binary is not executable via {source}: {candidate}")
    return candidate


@dataclass(frozen=True)
class _CodexSdk:
    flavor: str
    async_codex_cls: type[Any]
    app_server_config_cls: type[Any]
    app_server_client_cls: type[Any] | None
    approval_mode_cls: type[Any] | None
    ask_for_approval_cls: type[Any] | None
    reasoning_effort_cls: type[Any]
    sandbox_policy_cls: type[Any]
    text_input_cls: type[Any] | None


def _load_codex_sdk() -> _CodexSdk:
    try:
        from openai_codex import (  # type: ignore[import-not-found]
            AppServerConfig,
            ApprovalMode,
            AsyncCodex,
        )
        from openai_codex.client import AppServerClient  # type: ignore[import-not-found]
        from openai_codex.types import (  # type: ignore[import-not-found]
            ReasoningEffort,
            SandboxPolicy,
        )

        return _CodexSdk(
            flavor="openai_codex",
            async_codex_cls=AsyncCodex,
            app_server_config_cls=AppServerConfig,
            app_server_client_cls=AppServerClient,
            approval_mode_cls=ApprovalMode,
            ask_for_approval_cls=None,
            reasoning_effort_cls=ReasoningEffort,
            sandbox_policy_cls=SandboxPolicy,
            text_input_cls=None,
        )
    except ImportError as openai_codex_exc:
        try:
            from codex_app_server import (  # type: ignore[import-not-found]
                AskForApproval,
                AppServerConfig,
                AppServerClient,
                AsyncCodex,
                ReasoningEffort,
                SandboxPolicy,
                TextInput,
            )
        except ImportError as legacy_exc:
            raise RuntimeError(
                "Codex backend requires the OpenAI Codex Python SDK "
                "(`openai-codex` / `openai_codex`). The legacy "
                "`codex-app-server-sdk` package is still accepted as a fallback."
            ) from legacy_exc

        logger.debug("Using legacy codex-app-server-sdk fallback: %s", openai_codex_exc)
        return _CodexSdk(
            flavor="codex_app_server",
            async_codex_cls=AsyncCodex,
            app_server_config_cls=AppServerConfig,
            app_server_client_cls=AppServerClient,
            approval_mode_cls=None,
            ask_for_approval_cls=AskForApproval,
            reasoning_effort_cls=ReasoningEffort,
            sandbox_policy_cls=SandboxPolicy,
            text_input_cls=TextInput,
        )


def _normalize_codex_service_tier_response(value: Any) -> Any:
    """Map newer Codex service tier values to this SDK's generated enum."""
    if isinstance(value, dict):
        normalized: dict[Any, Any] = {}
        for key, item in value.items():
            if key in ("serviceTier", "service_tier") and item in (
                "default",
                "priority",
            ):
                normalized[key] = "flex"
            else:
                normalized[key] = _normalize_codex_service_tier_response(item)
        return normalized
    if isinstance(value, list):
        return [_normalize_codex_service_tier_response(item) for item in value]
    return value


def _patch_codex_sdk_service_tier_compat(app_server_client_cls: type[Any]) -> None:
    """Patch Codex SDK response decoding for older generated ServiceTier enums."""
    original_request_raw = app_server_client_cls._request_raw
    if getattr(original_request_raw, _CODEX_SERVICE_TIER_COMPAT_ATTR, False):
        return

    def patched_request_raw(self: Any, *args: Any, **kwargs: Any) -> Any:
        return _normalize_codex_service_tier_response(
            original_request_raw(self, *args, **kwargs)
        )

    setattr(patched_request_raw, _CODEX_SERVICE_TIER_COMPAT_ATTR, True)
    app_server_client_cls._request_raw = patched_request_raw


async def _run_claude_agent(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    model: str | None = None,
    effort: str | None = None,
    log_file: str | None = None,
    run_control: _AgentRunControl | None = None,
    sandbox: DockerScratch | None = None,
) -> str:
    ClaudeCodeOptions, query = _load_claude_sdk()
    tools = allowed_tools or DEFAULT_TOOLS
    add_dirs = _additional_directories(config, cwd)
    run_control = run_control or _AgentRunControl()

    extra_args: dict[str, str | None] = {
        # Keep Claude Code settings sources enabled so provider/auth
        # configuration from ~/.claude/settings.json is honored.
        "disable-slash-commands": None,
    }
    if effort:
        extra_args["effort"] = effort

    option_values: dict[str, Any] = dict(
        allowed_tools=tools,
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        model=resolve_agent_model(config, model),
        cwd=cwd,
        add_dirs=add_dirs,
        extra_args=extra_args,
        env=run_control.subprocess_env(),
    )
    if sandbox is not None:
        sandbox.ensure_backend("claude")
        option_values["cli_path"] = sandbox.wrapper_path("claude")
        option_values["env"].update(sandbox.wrapper_env(cwd))
    if _accepts_keyword(ClaudeCodeOptions, "setting_sources"):
        option_values["setting_sources"] = (
            ["user", "project", "local"]
            if config.provider_mode == "local"
            else []
        )
    if config.provider_mode == "custom":
        base_url, api_key = _custom_provider_values(config)
        option_values["env"].update(
            {
                "ANTHROPIC_BASE_URL": base_url,
                "ANTHROPIC_AUTH_TOKEN": api_key,
            }
        )
    options = ClaudeCodeOptions(**option_values)

    log_fh = _open_agent_log(log_file)

    last_exc: Exception | None = None
    try:
        for attempt in range(AGENT_MAX_RETRIES):
            try:
                text_parts: list[str] = []
                if log_fh and attempt > 0:
                    log_fh.write(f"\n--- retry attempt {attempt + 1} ---\n\n")
                    log_fh.flush()

                async def collect_messages(parts: list[str]) -> str:
                    token = _AGENT_PROCESS_REGISTRAR.set(run_control.register_process)
                    tool_names: dict[str, str] = {}
                    last_system_activity_at: dict[str, float] = {}
                    result_error: list[bool] = []
                    try:
                        async for message in query(prompt=prompt, options=options):
                            if message is None:
                                continue
                            content = getattr(message, "content", None)
                            if isinstance(content, list):
                                for block in content:
                                    text = getattr(block, "text", None)
                                    if isinstance(text, str) and text:
                                        parts.append(text)
                                        if log_fh:
                                            log_fh.write(text)
                                            log_fh.write("\n")
                                            log_fh.flush()
                                        _record_agent_activity(
                                            None,
                                            f"Response: {_compact_agent_activity(text)}",
                                        )
                                        continue

                                    tool_name = getattr(block, "name", None)
                                    tool_input = getattr(block, "input", None)
                                    tool_id = getattr(block, "id", None)
                                    if isinstance(tool_name, str) and tool_name:
                                        if isinstance(tool_id, str):
                                            tool_names[tool_id] = tool_name
                                        detail = _tool_input_summary(tool_name, tool_input)
                                        _record_agent_activity(
                                            log_fh,
                                            f"Started {tool_name}"
                                            + (f": {detail}" if detail else ""),
                                        )
                                        continue

                                    tool_use_id = getattr(block, "tool_use_id", None)
                                    if isinstance(tool_use_id, str):
                                        completed_tool = tool_names.get(
                                            tool_use_id, "tool call"
                                        )
                                        outcome = (
                                            "failed"
                                            if getattr(block, "is_error", False)
                                            else "completed"
                                        )
                                        _record_agent_activity(
                                            log_fh,
                                            f"{completed_tool} {outcome}",
                                        )

                            message_type = type(message).__name__
                            if message_type == "SystemMessage":
                                subtype = _compact_agent_activity(
                                    getattr(message, "subtype", "session"), 100
                                )
                                activity = AGENT_NOISY_SYSTEM_EVENTS.get(subtype)
                                if activity:
                                    now = time.monotonic()
                                    last_activity = last_system_activity_at.get(
                                        subtype, 0.0
                                    )
                                    if (
                                        now - last_activity
                                        < AGENT_SYSTEM_ACTIVITY_INTERVAL_SECONDS
                                    ):
                                        continue
                                    last_system_activity_at[subtype] = now
                                    _record_agent_activity(log_fh, activity)
                                else:
                                    _record_agent_activity(
                                        log_fh, f"Session event: {subtype}"
                                    )
                            elif message_type == "ResultMessage":
                                record_agent_usage(
                                    config,
                                    getattr(message, "usage", None),
                                    getattr(message, "total_cost_usd", None),
                                )
                                turns = getattr(message, "num_turns", None)
                                duration_ms = getattr(message, "duration_ms", None)
                                is_error = bool(getattr(message, "is_error", False))
                                result_parts = [
                                    "Agent result",
                                    "error" if is_error else "complete",
                                ]
                                if turns is not None:
                                    result_parts.append(f"turns={turns}")
                                if duration_ms is not None:
                                    result_parts.append(
                                        f"duration={float(duration_ms) / 1000:.1f}s"
                                    )
                                _record_agent_activity(
                                    log_fh, " ".join(result_parts)
                                )
                                if is_error:
                                    result_error.append(True)
                        if result_error:
                            # An error ResultMessage (e.g. API 429 quota
                            # exhaustion) must not be treated as success:
                            # callers would mark the task complete and skip it
                            # on resume with no usable output.
                            tail = _compact_agent_activity(" ".join(parts), 500)
                            raise RuntimeError(
                                "Agent ended with an error result: "
                                + (tail or "no error output")
                            )
                        return "\n".join(parts)
                    except Exception as exc:
                        if result_error:
                            # The SDK often raises a ProcessError carrying a
                            # debug-level stderr dump right after an error
                            # ResultMessage; the agent's own error text is far
                            # more useful for diagnosing the failure.
                            tail = _compact_agent_activity(" ".join(parts), 500)
                            raise RuntimeError(
                                "Agent ended with an error result: "
                                + (tail or "no error output")
                            ) from exc
                        raise
                    finally:
                        _AGENT_PROCESS_REGISTRAR.reset(token)

                return await collect_messages(text_parts)
            except Exception as exc:
                last_exc = exc
                if _is_non_retryable_agent_error(exc):
                    logger.error("Agent call failed with a non-retryable error: %s", exc)
                    raise
                if attempt < AGENT_MAX_RETRIES - 1:
                    delay = AGENT_RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "Agent call failed (attempt %d/%d), retrying in %ds: %s",
                        attempt + 1, AGENT_MAX_RETRIES, delay, exc,
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error("Agent call failed after %d attempts: %s", AGENT_MAX_RETRIES, exc)

        raise last_exc  # type: ignore[misc]
    finally:
        if log_fh and not log_fh.closed:
            log_fh.close()


def _codex_usage_dict(payload: Any) -> dict[str, Any] | None:
    """Best-effort extraction of a Codex token-usage breakdown as a dict."""
    if payload is None:
        return None
    if isinstance(payload, dict):
        data = payload
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
    # A TokenUsage notification wraps the breakdown under last/total; the
    # cumulative "total" is the number worth accounting.
    for key in ("total", "token_usage", "tokenUsage"):
        inner = data.get(key) if isinstance(data, dict) else None
        if inner is not None:
            return _codex_usage_dict(inner)
    return data or None


async def _run_codex_agent(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    model: str | None = None,
    effort: str | None = None,
    log_file: str | None = None,
    run_control: _AgentRunControl | None = None,
    sandbox: DockerScratch | None = None,
) -> str:
    codex_sdk = _load_codex_sdk()
    if codex_sdk.flavor == "codex_app_server" and codex_sdk.app_server_client_cls is not None:
        _patch_codex_sdk_service_tier_compat(codex_sdk.app_server_client_cls)

    if allowed_tools is not None:
        logger.debug("Codex backend does not map Claude allowed_tools directly; using Codex defaults.")
    if max_turns != 30:
        logger.debug("Codex backend runs one SDK turn per invocation; max_turns is not mapped directly.")

    selected_model = resolve_agent_model(config, model)
    if sandbox is not None:
        sandbox.ensure_backend("codex")
    codex_bin = sandbox.wrapper_path("codex") if sandbox is not None else _resolve_codex_bin()
    sandbox_policy = codex_sdk.sandbox_policy_cls.model_validate(
        {
            "type": "externalSandbox",
            "networkAccess": "enabled" if sandbox is not None and sandbox.network_enabled else "restricted",
        }
        if sandbox is not None
        else {"type": "dangerFullAccess"}
    )
    codex_effort = codex_sdk.reasoning_effort_cls(effort) if effort else None
    if codex_sdk.flavor == "openai_codex":
        if codex_sdk.approval_mode_cls is None:
            raise RuntimeError("Current Codex SDK import did not expose ApprovalMode.")
        approval_setting = codex_sdk.approval_mode_cls.deny_all
    else:
        if codex_sdk.ask_for_approval_cls is None:
            raise RuntimeError("Legacy Codex SDK import did not expose approval types.")
        approval_setting = codex_sdk.ask_for_approval_cls.model_validate("never")

    log_fh = _open_agent_log(log_file)
    run_control = run_control or _AgentRunControl()
    last_exc: Exception | None = None
    try:
        for attempt in range(AGENT_MAX_RETRIES):
            try:
                if log_fh and attempt > 0:
                    log_fh.write(f"\n--- retry attempt {attempt + 1} ---\n\n")
                    log_fh.flush()

                async def run_codex_turn() -> str:
                    app_server_values: dict[str, Any] = dict(
                        codex_bin=codex_bin,
                        cwd=cwd,
                        env=run_control.subprocess_env(),
                    )
                    if sandbox is not None:
                        app_server_values["env"].update(sandbox.wrapper_env(cwd))
                    if config.provider_mode == "custom":
                        base_url, api_key = _custom_provider_values(config)
                        app_server_values["config_overrides"] = (
                            'model_provider="codeauditor"',
                            'model_providers.codeauditor.name="CodeAuditor custom provider"',
                            f"model_providers.codeauditor.base_url={json.dumps(base_url)}",
                            'model_providers.codeauditor.env_key="CODEAUDITOR_PROVIDER_API_KEY"',
                            'model_providers.codeauditor.wire_api="responses"',
                        )
                        app_server_values["env"][
                            "CODEAUDITOR_PROVIDER_API_KEY"
                        ] = api_key
                    app_server_config = codex_sdk.app_server_config_cls(
                        **app_server_values
                    )
                    async with codex_sdk.async_codex_cls(config=app_server_config) as codex:
                        codex_client = getattr(codex, "_client", None)
                        sync_client = getattr(codex_client, "_sync", None)
                        run_control.register_process(getattr(sync_client, "_proc", None))
                        if codex_sdk.flavor == "openai_codex":
                            thread = await codex.thread_start(
                                approval_mode=approval_setting,
                                cwd=cwd,
                                model=selected_model,
                                service_tier="flex",
                            )
                            turn = await thread.turn(
                                prompt,
                                approval_mode=approval_setting,
                                cwd=cwd,
                                effort=codex_effort,
                                model=selected_model,
                                sandbox_policy=sandbox_policy,
                            )
                        else:
                            thread = await codex.thread_start(
                                approval_policy=approval_setting,
                                cwd=cwd,
                                model=selected_model,
                                service_tier="flex",
                            )
                            turn_input = (
                                codex_sdk.text_input_cls(prompt)
                                if codex_sdk.text_input_cls is not None
                                else prompt
                            )
                            turn = await thread.turn(
                                turn_input,
                                approval_policy=approval_setting,
                                cwd=cwd,
                                effort=codex_effort,
                                model=selected_model,
                                sandbox_policy=sandbox_policy,
                            )

                        stream = turn.stream()
                        completed = None
                        text_parts: list[str] = []
                        token_usage: dict[str, Any] | None = None
                        try:
                            async for event in stream:
                                payload = event.payload
                                if event.method.lower().endswith("tokenusage/updated"):
                                    token_usage = _codex_usage_dict(payload) or token_usage
                                activity = _codex_item_activity(
                                    event.method, payload
                                )
                                if activity:
                                    _record_agent_activity(log_fh, activity)
                                if (
                                    event.method == "item/agentMessage/delta"
                                    and getattr(payload, "turn_id", None) == turn.id
                                ):
                                    delta = getattr(payload, "delta", "")
                                    if delta:
                                        text_parts.append(delta)
                                        if log_fh:
                                            log_fh.write(delta)
                                            log_fh.flush()
                                    continue
                                if (
                                    event.method == "turn/completed"
                                    and getattr(getattr(payload, "turn", None), "id", None) == turn.id
                                ):
                                    completed = payload
                        finally:
                            await stream.aclose()

                        if completed is None:
                            raise RuntimeError("turn completed event not received")

                        turn_obj = getattr(completed, "turn", None)
                        if turn_obj is not None:
                            status = getattr(turn_obj, "status", None)
                            status_val = getattr(status, "value", str(status)) if status else ""
                            if status_val == "failed":
                                error = getattr(turn_obj, "error", None)
                                error_msg = getattr(error, "message", "") if error else ""
                                if error_msg:
                                    raise RuntimeError(error_msg)
                                raise RuntimeError(f"turn failed with status {status_val}")
                        if token_usage is None and turn_obj is not None:
                            token_usage = _codex_usage_dict(
                                getattr(turn_obj, "usage", None)
                            )
                        # Codex reports tokens but no dollar cost.
                        record_agent_usage(config, token_usage, None)

                        if log_fh:
                            log_fh.write("\n")
                            log_fh.flush()
                        return "".join(text_parts)

                return await run_codex_turn()
            except Exception as exc:
                last_exc = exc
                if _is_non_retryable_agent_error(exc):
                    logger.error("Codex agent call failed with a non-retryable error: %s", exc)
                    raise
                if attempt < AGENT_MAX_RETRIES - 1:
                    delay = AGENT_RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "Codex agent call failed (attempt %d/%d), retrying in %ds: %s",
                        attempt + 1, AGENT_MAX_RETRIES, delay, exc,
                    )
                    await asyncio.sleep(delay)
                else:
                    logger.error("Codex agent call failed after %d attempts: %s", AGENT_MAX_RETRIES, exc)

        raise last_exc  # type: ignore[misc]
    finally:
        if log_fh and not log_fh.closed:
            log_fh.close()


async def run_agent(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    model: str | None = None,
    effort: str | None = None,
    log_file: str | None = None,
    sandbox: DockerScratch | None = None,
) -> str:
    # Backend/provider settings are hot-swappable on the owning Web job.
    # Freeze them for this invocation so an already-running Codex call cannot
    # observe Claude provider fields (or vice versa) after a settings update.
    source = config.agent_settings_source or config
    invocation_config = replace(
        config,
        backend=source.backend,
        model=source.model,
        provider_mode=source.provider_mode,
        provider_base_url=source.provider_base_url,
        provider_api_key=source.provider_api_key,
        agent_settings_source=None,
    )
    if invocation_config.backend not in ("codex", "claude"):
        raise ValueError(f"Unsupported agent backend: {invocation_config.backend}")

    selected_model = resolve_agent_model(invocation_config, model)
    history_changed = False
    if invocation_config.backend not in config.backends_used:
        config.backends_used.append(invocation_config.backend)
        history_changed = True
    if selected_model not in config.models_used:
        config.models_used.append(selected_model)
        history_changed = True
    if history_changed and config.agent_history_changed is not None:
        try:
            config.agent_history_changed()
        except Exception as exc:
            # History reporting is observational and must never prevent the
            # selected agent invocation from running.
            logger.warning("Failed to publish live agent usage history: %s", exc)
    subagent_id = uuid4().hex[:8]
    started_at = time.monotonic()
    status = "failed"
    run_control = _AgentRunControl()

    logger.debug(
        "Creating %s subagent subagent_id=%s cwd=%s model=%s log_file=%s",
        invocation_config.backend,
        subagent_id,
        cwd,
        selected_model,
        log_file or "-",
    )

    try:
        if invocation_config.backend == "codex":
            agent_call = _run_codex_agent(
                prompt,
                invocation_config,
                cwd,
                allowed_tools=allowed_tools,
                max_turns=max_turns,
                model=model,
                effort=effort,
                log_file=log_file,
                run_control=run_control,
                sandbox=sandbox,
            )
        else:
            agent_call = _run_claude_agent(
                prompt,
                invocation_config,
                cwd,
                allowed_tools=allowed_tools,
                max_turns=max_turns,
                model=model,
                effort=effort,
                log_file=log_file,
                run_control=run_control,
                sandbox=sandbox,
            )

        result = await _await_agent_with_semantic_timeout(
            agent_call,
            config=invocation_config,
            cwd=cwd,
            log_file=log_file,
            run_control=run_control,
            sandbox=sandbox,
        )
        status = "killed_after_status_check" if run_control.killed_after_status_check else "completed"
        return result
    except asyncio.CancelledError:
        status = "cancelled"
        raise
    finally:
        try:
            await run_control.cleanup_processes()
        except Exception as exc:
            logger.error("Agent process cleanup failed: %s", exc)
        logger.debug(
            "Destroyed %s subagent subagent_id=%s status=%s elapsed=%.2fs",
            config.backend,
            subagent_id,
            status,
            time.monotonic() - started_at,
        )

async def run_with_validation(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    output_path: str,
    validator: Callable[[str], list[ValidationIssue]],
    max_retries: int = 2,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    skip_if_missing: bool = False,
    model: str | None = None,
    effort: str | None = None,
    log_file: str | None = None,
) -> tuple[bool, str]:
    """Run agent then validate output, retrying on failure. Returns (passed, result)."""
    result = await run_agent(prompt, config, cwd, allowed_tools, max_turns, model=model, effort=effort, log_file=log_file)

    for attempt in range(max_retries + 1):
        if skip_if_missing and not os.path.exists(output_path):
            logger.debug("No output file at %s (filtered or no findings).", output_path)
            return True, result

        issues = validator(output_path)
        if not issues:
            logger.debug("Validation passed for %s", output_path)
            return True, result

        if attempt == max_retries:
            return False, result

        repair_prompt = (
            f"The output file at `{output_path}` failed validation. "
            "Please fix all issues listed below, then save the corrected file.\n\n"
            f"Validation output:\n```\n{format_validation_issues(issues)}\n```"
        )
        result = await run_agent(
            repair_prompt,
            config,
            cwd,
            allowed_tools,
            max_turns=10,
            model=model,
            effort=effort,
            log_file=log_file,
        )

    return False, result
