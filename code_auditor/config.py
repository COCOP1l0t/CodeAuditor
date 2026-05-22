from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

AgentBackend = Literal["claude", "codex"]

DEFAULT_BACKEND: AgentBackend = "claude"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
DEFAULT_CLAUDE_POC_MODEL = "claude-opus-4-6"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_CODEX_POC_MODEL = "gpt-5.5"
DEFAULT_AGENT_TIMEOUT_SECONDS = 20 * 60

DEFAULT_THREAT_MODEL = (
    "Network attacker with full control over protocol messages. "
    "The attacker can send arbitrary bytes, malformed messages, "
    "and exploit any parsing or handling vulnerability."
)


@dataclass
class AuditConfig:
    target: str
    output_dir: str
    discovered_path: str = ""
    wiki_path: str | None = None
    max_parallel: int = 1
    threat_model: str = DEFAULT_THREAT_MODEL
    scope: str = ""
    skip_stages: list[int] = field(default_factory=list)
    resume: bool = True
    log_level: str = "INFO"
    backend: AgentBackend = DEFAULT_BACKEND
    model: str | None = None
    target_au_count: int = 10
    agent_timeout_seconds: int | None = None


def select_poc_model(config: AuditConfig) -> str:
    if config.model:
        return config.model
    if config.backend == "claude":
        return DEFAULT_CLAUDE_POC_MODEL
    if config.backend == "codex":
        return DEFAULT_CODEX_POC_MODEL
    raise ValueError(f"Unsupported agent backend: {config.backend}")


def resolve_discovered_path(config: AuditConfig) -> str:
    if config.discovered_path:
        return config.discovered_path
    return str(Path(config.target) / "reproduced-bugs.html")


@dataclass
class Module:
    id: str
    name: str
    description: str
    files_dir: str
    analyze: bool = True


@dataclass
class AnalysisUnit:
    id: str
    au_file_path: str


@dataclass
class ValidationIssue:
    description: str
    expected: str
    fix: str
