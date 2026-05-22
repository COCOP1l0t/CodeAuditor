from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Protocol, TextIO
from uuid import uuid4

from .config import DEFAULT_CLAUDE_MODEL, DEFAULT_CODEX_MODEL, AuditConfig, ValidationIssue
from .logger import get_logger
from .utils import format_validation_issues

AGENT_MAX_RETRIES = 3
AGENT_RETRY_BASE_DELAY = 10  # seconds
STALE_AGENT_LOG_TIMEOUT_SECONDS = 20 * 60
STALE_AGENT_LOG_CHECK_INTERVAL_SECONDS = 5 * 60
DEFAULT_CODEX_BIN = "/usr/local/bin/codex"

logger = get_logger("agent")

class _KillableProcess(Protocol):
    def kill(self) -> object:
        ...


_claude_sdk_patched = False
_CODEX_SERVICE_TIER_COMPAT_ATTR = "_code_auditor_service_tier_compat"
_AGENT_PROCESS_REGISTRAR: ContextVar[Callable[[_KillableProcess | None], None] | None] = ContextVar(
    "agent_process_registrar",
    default=None,
)


class AgentLogStaleError(RuntimeError):
    """Raised when an agent log stops updating and the backend process is killed."""


@dataclass
class _AgentRunControl:
    processes: list[_KillableProcess] = field(default_factory=list)
    killed_due_to_stale_log: bool = False

    def register_process(self, process: _KillableProcess | None) -> None:
        if process is None or process in self.processes:
            return
        self.processes.append(process)

    def kill_processes(self, log_file: str) -> None:
        self.killed_due_to_stale_log = True
        if not self.processes:
            logger.warning(
                "Agent log file has not been updated for %d minutes, but no agent process was registered to kill: %s",
                STALE_AGENT_LOG_TIMEOUT_SECONDS // 60,
                log_file,
            )
            return

        for process in list(self.processes):
            pid = getattr(process, "pid", "?")
            logger.warning(
                "Agent log file has not been updated for %d minutes; killing agent process pid=%s: %s",
                STALE_AGENT_LOG_TIMEOUT_SECONDS // 60,
                pid,
                log_file,
            )
            try:
                process.kill()
            except ProcessLookupError:
                pass
            except Exception as exc:
                logger.warning("Failed to kill stale agent process pid=%s: %s", pid, exc)


def _register_current_agent_process(process: _KillableProcess | None) -> None:
    registrar = _AGENT_PROCESS_REGISTRAR.get()
    if registrar:
        registrar(process)


async def _watch_agent_log_for_staleness(log_file: str, run_control: _AgentRunControl) -> None:
    last_seen_update = time.time()
    while True:
        await asyncio.sleep(STALE_AGENT_LOG_CHECK_INTERVAL_SECONDS)
        try:
            last_seen_update = os.stat(log_file).st_mtime
        except FileNotFoundError:
            pass

        stale_seconds = time.time() - last_seen_update
        if stale_seconds >= STALE_AGENT_LOG_TIMEOUT_SECONDS:
            run_control.kill_processes(log_file)
            raise AgentLogStaleError(
                f"Agent log file has not been updated for {stale_seconds:.0f}s: {log_file}"
            )


async def _run_agent_attempt_with_stale_log_watch(
    attempt: Coroutine[object, object, str],
    *,
    log_file: str | None,
    run_control: _AgentRunControl,
    enable_stale_watch: bool = True,
) -> str:
    if not log_file or not enable_stale_watch:
        return await attempt

    agent_task = asyncio.create_task(attempt)
    watcher_task = asyncio.create_task(_watch_agent_log_for_staleness(log_file, run_control))
    try:
        done, _ = await asyncio.wait(
            {agent_task, watcher_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if watcher_task in done:
            exc = watcher_task.exception()
            agent_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await asyncio.wait_for(agent_task, timeout=5)
            if exc:
                raise exc
            raise AgentLogStaleError(f"Agent log watcher exited unexpectedly: {log_file}")

        watcher_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watcher_task
        return await agent_task
    finally:
        if not watcher_task.done():
            watcher_task.cancel()


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
    global _claude_sdk_patched
    try:
        from claude_code_sdk import ClaudeCodeOptions, query
        from claude_code_sdk._errors import ProcessError
        from claude_code_sdk._internal import client as sdk_client
        from claude_code_sdk._internal import message_parser as mp
        from claude_code_sdk._internal.transport import subprocess_cli as transport
    except ImportError as exc:
        raise RuntimeError(
            "Claude backend requires the claude-code-sdk package. "
            "Install project dependencies before using --backend claude."
        ) from exc

    if not _claude_sdk_patched:
        _patch_claude_sdk(sdk_client, mp, ProcessError, transport)
        _claude_sdk_patched = True

    return ClaudeCodeOptions, query


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


def _resolve_codex_bin() -> str:
    if not os.path.isfile(DEFAULT_CODEX_BIN):
        raise RuntimeError(f"Codex CLI binary not found: {DEFAULT_CODEX_BIN}")
    if not os.access(DEFAULT_CODEX_BIN, os.X_OK):
        raise RuntimeError(f"Codex CLI binary is not executable: {DEFAULT_CODEX_BIN}")
    return DEFAULT_CODEX_BIN


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
    service_tier_cls: type[Any] | None


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
            service_tier_cls=None,
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
                ServiceTier,
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
            service_tier_cls=ServiceTier,
        )


def _normalize_codex_service_tier_response(value: Any) -> Any:
    """Map newer Codex service tier values to this SDK's generated enum."""
    if isinstance(value, dict):
        normalized: dict[Any, Any] = {}
        for key, item in value.items():
            if key in ("serviceTier", "service_tier") and item == "priority":
                normalized[key] = "fast"
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
) -> str:
    ClaudeCodeOptions, query = _load_claude_sdk()
    tools = allowed_tools or DEFAULT_TOOLS
    add_dirs = _additional_directories(config, cwd)

    extra_args: dict[str, str | None] = {
        # Keep Claude Code settings sources enabled so provider/auth
        # configuration from ~/.claude/settings.json is honored.
        "disable-slash-commands": None,
    }
    if effort:
        extra_args["effort"] = effort

    options = ClaudeCodeOptions(
        allowed_tools=tools,
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        model=model or config.model or DEFAULT_CLAUDE_MODEL,
        cwd=cwd,
        add_dirs=add_dirs,
        extra_args=extra_args,
    )

    log_fh = _open_agent_log(log_file)
    run_control = run_control or _AgentRunControl()

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
                    try:
                        async for message in query(prompt=prompt, options=options):
                            if message is None:
                                continue
                            if hasattr(message, "content"):
                                for block in message.content:
                                    if hasattr(block, "text"):
                                        parts.append(block.text)
                                        if log_fh:
                                            log_fh.write(block.text)
                                            log_fh.write("\n")
                                            log_fh.flush()
                        return "\n".join(parts)
                    finally:
                        _AGENT_PROCESS_REGISTRAR.reset(token)

                return await _run_agent_attempt_with_stale_log_watch(
                    collect_messages(text_parts),
                    log_file=log_file,
                    run_control=run_control,
                )
            except AgentLogStaleError as exc:
                logger.warning("Claude agent stopped because its log file went stale: %s", exc)
                return "\n".join(text_parts)
            except Exception as exc:
                last_exc = exc
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
) -> str:
    codex_sdk = _load_codex_sdk()
    if codex_sdk.flavor == "codex_app_server" and codex_sdk.app_server_client_cls is not None:
        _patch_codex_sdk_service_tier_compat(codex_sdk.app_server_client_cls)

    if allowed_tools is not None:
        logger.debug("Codex backend does not map Claude allowed_tools directly; using Codex defaults.")
    if max_turns != 30:
        logger.debug("Codex backend runs one SDK turn per invocation; max_turns is not mapped directly.")

    selected_model = model or config.model or DEFAULT_CODEX_MODEL
    codex_bin = _resolve_codex_bin()
    sandbox_policy = codex_sdk.sandbox_policy_cls.model_validate({"type": "dangerFullAccess"})
    codex_effort = codex_sdk.reasoning_effort_cls(effort) if effort else None
    if codex_sdk.flavor == "openai_codex":
        if codex_sdk.approval_mode_cls is None:
            raise RuntimeError("Current Codex SDK import did not expose ApprovalMode.")
        approval_setting = codex_sdk.approval_mode_cls.deny_all
        codex_service_tier: object = "fast"
    else:
        if codex_sdk.ask_for_approval_cls is None or codex_sdk.service_tier_cls is None:
            raise RuntimeError("Legacy Codex SDK import did not expose approval or service-tier types.")
        approval_setting = codex_sdk.ask_for_approval_cls.model_validate("never")
        codex_service_tier = codex_sdk.service_tier_cls.fast

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
                    app_server_config = codex_sdk.app_server_config_cls(
                        codex_bin=codex_bin,
                        cwd=cwd,
                        config_overrides=('service_tier="fast"',),
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
                                service_tier=codex_service_tier,
                            )
                            result = await thread.run(
                                prompt,
                                approval_mode=approval_setting,
                                cwd=cwd,
                                effort=codex_effort,
                                model=selected_model,
                                sandbox_policy=sandbox_policy,
                                service_tier=codex_service_tier,
                            )
                        else:
                            thread = await codex.thread_start(
                                approval_policy=approval_setting,
                                cwd=cwd,
                                model=selected_model,
                                service_tier=codex_service_tier,
                            )
                            result = await thread.run(
                                prompt,
                                approval_policy=approval_setting,
                                cwd=cwd,
                                effort=codex_effort,
                                model=selected_model,
                                sandbox_policy=sandbox_policy,
                                service_tier=codex_service_tier,
                            )
                    return result.final_response or ""

                text = await _run_agent_attempt_with_stale_log_watch(
                    run_codex_turn(),
                    log_file=log_file,
                    run_control=run_control,
                    enable_stale_watch=False,
                )
                if log_fh:
                    log_fh.write(text)
                    log_fh.write("\n")
                    log_fh.flush()
                return text
            except AgentLogStaleError as exc:
                logger.warning("Codex agent stopped because its log file went stale: %s", exc)
                return ""
            except Exception as exc:
                last_exc = exc
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
) -> str:
    if config.backend not in ("codex", "claude"):
        raise ValueError(f"Unsupported agent backend: {config.backend}")

    selected_model = (
        model
        or config.model
        or (DEFAULT_CODEX_MODEL if config.backend == "codex" else DEFAULT_CLAUDE_MODEL)
    )
    subagent_id = uuid4().hex[:8]
    started_at = time.monotonic()
    status = "failed"
    run_control = _AgentRunControl()

    logger.info(
        "Creating %s subagent subagent_id=%s cwd=%s model=%s log_file=%s",
        config.backend,
        subagent_id,
        cwd,
        selected_model,
        log_file or "-",
    )

    try:
        if config.backend == "codex":
            result = await _run_codex_agent(
                prompt,
                config,
                cwd,
                allowed_tools=allowed_tools,
                max_turns=max_turns,
                model=model,
                effort=effort,
                log_file=log_file,
                run_control=run_control,
            )
        else:
            result = await _run_claude_agent(
                prompt,
                config,
                cwd,
                allowed_tools=allowed_tools,
                max_turns=max_turns,
                model=model,
                effort=effort,
                log_file=log_file,
                run_control=run_control,
            )
        status = "killed_stale_log" if run_control.killed_due_to_stale_log else "completed"
        return result
    except asyncio.CancelledError:
        status = "cancelled"
        raise
    finally:
        logger.info(
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
            logger.info("No output file at %s (filtered or no findings).", output_path)
            return True, result

        issues = validator(output_path)
        if not issues:
            logger.info("Validation passed for %s", output_path)
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
