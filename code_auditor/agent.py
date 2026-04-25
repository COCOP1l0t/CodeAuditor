from __future__ import annotations

import os
from typing import Callable

from .agent_backends import AgentBackend
from .config import AuditConfig, ValidationIssue
from .logger import get_logger
from .utils import format_validation_issues

logger = get_logger("agent")


def _get_backend(config: AuditConfig) -> AgentBackend:
    if config.agent_backend == "claude-code":
        from .agent_backends.claude_code import ClaudeCodeBackend

        return ClaudeCodeBackend()

    if config.agent_backend == "codex":
        from .agent_backends.codex import CodexBackend

        return CodexBackend()

    raise ValueError(f"Unsupported agent backend: {config.agent_backend}")


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
    backend = _get_backend(config)
    return await backend.run(
        prompt=prompt,
        config=config,
        cwd=cwd,
        allowed_tools=allowed_tools,
        max_turns=max_turns,
        model=model,
        effort=effort,
        log_file=log_file,
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
    result = await run_agent(
        prompt,
        config,
        cwd,
        allowed_tools,
        max_turns,
        model=model,
        effort=effort,
        log_file=log_file,
    )

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
            log_file=log_file,
        )

    return False, result
