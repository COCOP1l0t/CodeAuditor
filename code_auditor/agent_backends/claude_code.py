from __future__ import annotations

import asyncio
import os
import subprocess

from claude_code_sdk import ClaudeCodeOptions, query
from claude_code_sdk._errors import ProcessError as _ProcessError
from claude_code_sdk._internal import client as _sdk_client
from claude_code_sdk._internal import message_parser as _mp
from claude_code_sdk._internal.transport import subprocess_cli as _transport

from ..config import AuditConfig
from ..logger import get_logger

AGENT_MAX_RETRIES = 3
AGENT_RETRY_BASE_DELAY = 10  # seconds
DEFAULT_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit", "Bash"]

logger = get_logger("agent.claude_code")

_PATCHED = False


def _patch_sdk() -> None:
    global _PATCHED
    if _PATCHED:
        return

    original_parse_message = _mp.parse_message

    def patched_parse_message(data):  # type: ignore[no-untyped-def]
        try:
            return original_parse_message(data)
        except Exception:
            logger.debug("Skipping unknown SDK message type: %s", data.get("type", "?"))
            return None

    _mp.parse_message = patched_parse_message
    _sdk_client.parse_message = patched_parse_message

    original_connect = _transport.SubprocessCLITransport.connect
    original_read_messages_impl = _transport.SubprocessCLITransport._read_messages_impl

    async def patched_connect(self):  # type: ignore[no-untyped-def]
        orig_debug_stderr = self._options.debug_stderr
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
        try:
            async for message in original_read_messages_impl(self):
                yield message
        except _ProcessError as exc:
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
                    f"{exc} - stderr: {stderr_text}",
                    exit_code=exc.exit_code,
                    stderr=stderr_text,
                ) from exc
            raise

    _transport.SubprocessCLITransport.connect = patched_connect  # type: ignore[assignment]
    _transport.SubprocessCLITransport._read_messages_impl = patched_read_messages_impl
    _PATCHED = True


def _additional_directories(config: AuditConfig, cwd: str) -> list[str]:
    resolved_cwd = os.path.realpath(cwd)
    dirs: list[str] = []
    for candidate in [config.output_dir]:
        resolved = os.path.realpath(candidate)
        if resolved != resolved_cwd and os.path.isdir(resolved) and resolved not in dirs:
            dirs.append(resolved)
    return dirs


class ClaudeCodeBackend:
    async def run(
        self,
        prompt: str,
        config: AuditConfig,
        cwd: str,
        allowed_tools: list[str] | None = None,
        max_turns: int = 30,
        model: str | None = None,
        effort: str | None = None,
        log_file: str | None = None,
    ) -> str:
        _patch_sdk()

        tools = allowed_tools or DEFAULT_TOOLS
        add_dirs = _additional_directories(config, cwd)

        extra_args: dict[str, str | None] = {
            "setting-sources": "",
            "disable-slash-commands": None,
        }
        if effort:
            extra_args["effort"] = effort

        options = ClaudeCodeOptions(
            allowed_tools=tools,
            permission_mode="bypassPermissions",
            max_turns=max_turns,
            model=model or config.model,
            cwd=cwd,
            add_dirs=add_dirs,
            extra_args=extra_args,
        )

        log_fh = None
        if log_file:
            os.makedirs(os.path.dirname(log_file), exist_ok=True)
            log_fh = open(log_file, "a")  # noqa: SIM115
            if log_fh.tell() > 0:
                log_fh.write("\n--- new agent invocation ---\n\n")
                log_fh.flush()

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
