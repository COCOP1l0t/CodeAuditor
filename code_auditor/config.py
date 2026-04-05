from __future__ import annotations

from dataclasses import dataclass, field

DEFAULT_THREAT_MODEL = (
    "Network attacker with full control over protocol messages. "
    "The attacker can send arbitrary bytes, malformed messages, "
    "and exploit any parsing or handling vulnerability."
)


@dataclass
class AuditConfig:
    target: str
    output_dir: str
    max_parallel: int = 2
    threat_model: str = DEFAULT_THREAT_MODEL
    scope: str = ""
    skip_stages: list[int] = field(default_factory=list)
    resume: bool = False
    log_level: str = "INFO"
    model: str = "claude-sonnet-4-6"


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
