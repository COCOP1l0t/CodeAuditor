from __future__ import annotations

import json
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
    # Runtime-only collector for per-task agent failures (stage3-6). Entries
    # are summarized into the run record's error field at the end of the audit.
    task_errors: list[str] = field(default_factory=list, repr=False)
    # Model ids actually used by agent invocations, in first-use order.
    models_used: list[str] = field(default_factory=list, repr=False)
    # Runtime-only accumulator of token/cost usage across agent invocations.
    # Keys: agent_calls, input_tokens, output_tokens,
    # cache_creation_input_tokens, cache_read_input_tokens, cost_usd.
    usage_stats: dict[str, float] = field(default_factory=dict, repr=False)


def local_claude_model(
    settings_path: str | None = None,
    keys: tuple[str, ...] = ("ANTHROPIC_MODEL",),
) -> str | None:
    """Read the model id from the local Claude config, fresh on every call.

    The Claude Code CLI is configured through ``~/.claude/settings.json``;
    its ``env`` section maps ``ANTHROPIC_MODEL`` (and the per-tier
    ``ANTHROPIC_DEFAULT_*_MODEL`` variants) to the provider's current model
    id. Reading it at each call keeps audits on the configured model even
    when the provider renames ids — a stored copy goes stale.
    """
    path = settings_path or os.path.join(
        os.path.expanduser("~"), ".claude", "settings.json"
    )
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    env = data.get("env")
    if isinstance(env, dict):
        for key in keys:
            value = env.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    if "ANTHROPIC_MODEL" in keys:
        top_level = data.get("model")
        if isinstance(top_level, str) and top_level.strip():
            return top_level.strip()
    return None


def resolve_agent_model(config: AuditConfig, model: str | None = None) -> str:
    """Resolve the effective model id for one agent invocation.

    Priority: explicit per-call model > local Claude config (claude backend)
    > stored config value > built-in default.
    """
    if model:
        return model
    if config.backend == "claude":
        return local_claude_model() or config.model or DEFAULT_CLAUDE_MODEL
    return config.model or DEFAULT_CODEX_MODEL


def select_poc_model(config: AuditConfig) -> str:
    if config.backend == "claude":
        return (
            local_claude_model(
                keys=("ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_MODEL")
            )
            or config.model
            or DEFAULT_CLAUDE_POC_MODEL
        )
    if config.model:
        return config.model
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
