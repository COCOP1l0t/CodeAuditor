from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Literal

AgentBackend = Literal["claude", "codex"]

DEFAULT_BACKEND: AgentBackend = "claude"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
DEFAULT_CLAUDE_POC_MODEL = "claude-opus-4-6"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_CODEX_POC_MODEL = "gpt-5.5"
DEFAULT_AGENT_TIMEOUT_SECONDS = 20 * 60

# Default target analysis-unit count: -1 means "no ceiling — explore as many
# analysis units as genuinely warrant deep analysis".
UNLIMITED_AU_COUNT = -1

DEFAULT_THREAT_MODEL = (
    "Network attacker with full control over protocol messages. "
    "The attacker can send arbitrary bytes, malformed messages, "
    "and exploit any parsing or handling vulnerability."
)


@dataclass
class AuditConfig:
    target: str
    output_dir: str
    wiki_path: str | None = None
    max_parallel: int = 1
    threat_model: str = DEFAULT_THREAT_MODEL
    scope: str = ""
    resume: bool = True
    update_repo: bool = True
    log_level: str = "INFO"
    backend: AgentBackend = DEFAULT_BACKEND
    model: str | None = None
    target_au_count: int = UNLIMITED_AU_COUNT
    agent_timeout_seconds: int | None = DEFAULT_AGENT_TIMEOUT_SECONDS
    known_disclosures: tuple[dict[str, Any], ...] = field(
        default_factory=tuple, repr=False
    )


def select_poc_model(config: AuditConfig) -> str:
    if config.model:
        return config.model
    if config.backend == "claude":
        return DEFAULT_CLAUDE_POC_MODEL
    if config.backend == "codex":
        return DEFAULT_CODEX_POC_MODEL
    raise ValueError(f"Unsupported agent backend: {config.backend}")


def default_output_dir(target: str) -> str:
    return os.path.join(target, f"audit-output-{date.today().strftime('%Y%m%d')}")


def resolve_wiki_arg(path: str | None) -> str | None:
    """Resolve the --wiki CLI/web argument to an absolute path, or None.

    Raises ValueError if the path does not exist or is not a directory.
    """
    if not path:
        return None
    resolved = os.path.realpath(path)
    if not os.path.exists(resolved):
        raise ValueError(f"Wiki directory not found: {resolved}")
    if not os.path.isdir(resolved):
        raise ValueError(f"Wiki path is not a directory: {resolved}")
    return resolved


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
