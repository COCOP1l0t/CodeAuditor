from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

AgentBackend = Literal["claude", "codex"]

DEFAULT_BACKEND: AgentBackend = "claude"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
DEFAULT_CLAUDE_POC_MODEL = "claude-opus-4-6"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_CODEX_POC_MODEL = "gpt-5.5"

DEFAULT_THREAT_MODEL = (
    "Network attacker with full control over protocol messages. "
    "The attacker can send arbitrary bytes, malformed messages, "
    "and exploit any parsing or handling vulnerability."
)


@dataclass
class AuditConfig:
    target: str
    output_dir: str
    max_parallel: int = 1
    threat_model: str = DEFAULT_THREAT_MODEL
    scope: str = ""
    skip_stages: list[int] = field(default_factory=list)
    resume: bool = True
    log_level: str = "INFO"
    backend: AgentBackend = DEFAULT_BACKEND
    model: str | None = None
    target_au_count: int = 10


def select_poc_model(config: AuditConfig) -> str:
    if config.model:
        return config.model
    if config.backend == "claude":
        return DEFAULT_CLAUDE_POC_MODEL
    return DEFAULT_CODEX_POC_MODEL


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
