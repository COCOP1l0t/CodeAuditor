from __future__ import annotations

import asyncio
import os
import subprocess
from typing import Callable

from claude_code_sdk import ClaudeCodeOptions, query
from claude_code_sdk._internal import client as _sdk_client
from claude_code_sdk._internal import message_parser as _mp
from claude_code_sdk._errors import ProcessError as _ProcessError
from claude_code_sdk._internal.transport import subprocess_cli as _transport

from .config import AuditConfig, ValidationIssue
from .logger import get_logger
from .utils import format_validation_issues

AGENT_MAX_RETRIES = 3
AGENT_RETRY_BASE_DELAY = 10  # seconds

logger = get_logger("agent")

# Patch SDK message parser to skip unknown message types instead of raising.
# The installed SDK version (0.0.25) predates some newer event types
# (e.g. rate_limit_event) emitted by the Claude Code backend.
_original_parse_message = _mp.parse_message


def _patched_parse_message(data):  # type: ignore[no-untyped-def]
    try:
        return _original_parse_message(data)
    except Exception:
        logger.debug("Skipping unknown SDK message type: %s", data.get("type", "?"))
        return None


# Patch both the module-level reference and the client module's imported copy.
_mp.parse_message = _patched_parse_message
_sdk_client.parse_message = _patched_parse_message

# Patch SubprocessCLITransport.connect to always capture stderr via PIPE,
# and _read_messages_impl to include the captured stderr in the error message.
_original_connect = _transport.SubprocessCLITransport.connect
_original_read_messages_impl = _transport.SubprocessCLITransport._read_messages_impl


async def _patched_connect(self):  # type: ignore[no-untyped-def]
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
        await _original_connect(self)
    finally:
        self._options.debug_stderr = orig_debug_stderr
        if not had_debug_flag:
            self._options.extra_args.pop("debug-to-stderr", None)


async def _patched_read_messages_impl(self):  # type: ignore[no-untyped-def]
    """Patched _read_messages_impl that captures stderr on failure."""
    try:
        async for message in _original_read_messages_impl(self):
            yield message
    except _ProcessError as exc:
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
            raise _ProcessError(
                f"{exc} — stderr: {stderr_text}",
                exit_code=exc.exit_code,
                stderr=stderr_text,
            ) from exc
        raise


_transport.SubprocessCLITransport.connect = _patched_connect  # type: ignore[assignment]
_transport.SubprocessCLITransport._read_messages_impl = _patched_read_messages_impl  # type: ignore[assignment]

DEFAULT_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit", "Bash"]


def _additional_directories(config: AuditConfig, cwd: str) -> list[str]:
    resolved_cwd = os.path.realpath(cwd)
    dirs: list[str] = []
    for candidate in [config.output_dir]:
        resolved = os.path.realpath(candidate)
        if resolved != resolved_cwd and os.path.isdir(resolved) and resolved not in dirs:
            dirs.append(resolved)
    return dirs


async def run_agent(
    prompt: str,
    config: AuditConfig,
    cwd: str,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
) -> str:
    tools = allowed_tools or DEFAULT_TOOLS
    add_dirs = _additional_directories(config, cwd)

    options = ClaudeCodeOptions(
        allowed_tools=tools,
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        model=config.model,
        cwd=cwd,
        add_dirs=add_dirs,
        extra_args={
            # Run sub-agents like a clean Claude Code install: no user/project
            # settings, no plugins, no hooks, no CLAUDE.md, no slash commands.
            "setting-sources": "",
            "disable-slash-commands": None,
        },
    )

    last_exc: Exception | None = None
    for attempt in range(AGENT_MAX_RETRIES):
        try:
            text_parts: list[str] = []
            async for message in query(prompt=prompt, options=options):
                if message is None:
                    continue
                if hasattr(message, "content"):
                    for block in message.content:
                        if hasattr(block, "text"):
                            text_parts.append(block.text)
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
) -> tuple[bool, str]:
    """Run agent then validate output, retrying on failure. Returns (passed, result)."""
    result = await run_agent(prompt, config, cwd, allowed_tools, max_turns)

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
        result = await run_agent(repair_prompt, config, cwd, allowed_tools, max_turns=10)

    return False, result
