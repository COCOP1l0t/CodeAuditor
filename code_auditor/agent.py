from __future__ import annotations

import asyncio
import os
import subprocess
from typing import Callable, TextIO

from .config import DEFAULT_CLAUDE_MODEL, DEFAULT_CODEX_MODEL, AuditConfig, ValidationIssue
from .logger import get_logger
from .utils import format_validation_issues

AGENT_MAX_RETRIES = 3
AGENT_RETRY_BASE_DELAY = 10  # seconds
DEFAULT_CODEX_BIN = "/usr/local/bin/codex"

logger = get_logger("agent")

_claude_sdk_patched = False


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
    for candidate in [config.output_dir]:
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
    return log_fh


def _resolve_codex_bin() -> str:
    if not os.path.isfile(DEFAULT_CODEX_BIN):
        raise RuntimeError(f"Codex CLI binary not found: {DEFAULT_CODEX_BIN}")
    if not os.access(DEFAULT_CODEX_BIN, os.X_OK):
        raise RuntimeError(f"Codex CLI binary is not executable: {DEFAULT_CODEX_BIN}")
    return DEFAULT_CODEX_BIN


async def _run_claude_agent(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    model: str | None = None,
    effort: str | None = None,
    log_file: str | None = None,
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

    last_exc: Exception | None = None
    try:
        for attempt in range(AGENT_MAX_RETRIES):
            try:
                text_parts: list[str] = []
                if log_fh and attempt > 0:
                    log_fh.write(f"\n--- retry attempt {attempt + 1} ---\n\n")
                    log_fh.flush()
                async for message in query(prompt=prompt, options=options):
                    if message is None:
                        continue
                    if hasattr(message, "content"):
                        for block in message.content:
                            if hasattr(block, "text"):
                                text_parts.append(block.text)
                                if log_fh:
                                    log_fh.write(block.text)
                                    log_fh.write("\n")
                                    log_fh.flush()
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
) -> str:
    try:
        from codex_app_server import (  # type: ignore[import-not-found]
            AskForApproval,
            AppServerConfig,
            AsyncCodex,
            ReasoningEffort,
            SandboxPolicy,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Codex backend requires the codex-app-server-sdk package. "
            "Install project dependencies again after this change."
        ) from exc

    if allowed_tools is not None:
        logger.debug("Codex backend does not map Claude allowed_tools directly; using Codex defaults.")
    if max_turns != 30:
        logger.debug("Codex backend runs one SDK turn per invocation; max_turns is not mapped directly.")

    selected_model = model or config.model or DEFAULT_CODEX_MODEL
    codex_bin = _resolve_codex_bin()
    approval_policy = AskForApproval.model_validate("never")
    sandbox_policy = SandboxPolicy.model_validate({"type": "dangerFullAccess"})
    codex_effort = ReasoningEffort(effort) if effort else None

    log_fh = _open_agent_log(log_file)
    last_exc: Exception | None = None
    try:
        for attempt in range(AGENT_MAX_RETRIES):
            try:
                if log_fh and attempt > 0:
                    log_fh.write(f"\n--- retry attempt {attempt + 1} ---\n\n")
                    log_fh.flush()

                app_server_config = AppServerConfig(codex_bin=codex_bin, cwd=cwd)
                async with AsyncCodex(config=app_server_config) as codex:
                    thread = await codex.thread_start(
                        cwd=cwd,
                        model=selected_model,
                    )
                    result = await thread.run(
                        prompt,
                        approval_policy=approval_policy,
                        cwd=cwd,
                        effort=codex_effort,
                        model=selected_model,
                        sandbox_policy=sandbox_policy,
                    )

                text = result.final_response or ""
                if log_fh:
                    log_fh.write(text)
                    log_fh.write("\n")
                    log_fh.flush()
                return text
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
    if config.backend == "codex":
        return await _run_codex_agent(
            prompt,
            config,
            cwd,
            allowed_tools=allowed_tools,
            max_turns=max_turns,
            model=model,
            effort=effort,
            log_file=log_file,
        )
    if config.backend == "claude":
        return await _run_claude_agent(
            prompt,
            config,
            cwd,
            allowed_tools=allowed_tools,
            max_turns=max_turns,
            model=model,
            effort=effort,
            log_file=log_file,
        )
    raise ValueError(f"Unsupported agent backend: {config.backend}")


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
