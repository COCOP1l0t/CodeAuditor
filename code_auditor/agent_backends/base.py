from __future__ import annotations

from typing import Protocol

from ..config import AuditConfig


class AgentBackend(Protocol):
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
        """Run one agent task and return collected assistant text."""
