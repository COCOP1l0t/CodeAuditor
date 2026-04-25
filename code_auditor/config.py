from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
DEFAULT_CODEX_MODEL = "gpt-5.4"

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
    model: str = DEFAULT_CLAUDE_MODEL
    target_au_count: int = 10
    agent_backend: str = "claude-code"
    codex_bin: str | None = None
    codex_sdk_path: str | None = None
    codex_sandbox: str = "workspace-write"
    codex_approval_policy: str = "never"
    codex_network_access: bool = False
    codex_extra_writable_roots: list[str] = field(default_factory=list)


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
