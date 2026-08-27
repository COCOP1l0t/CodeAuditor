from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

AgentBackend = Literal["claude", "codex"]
ProviderMode = Literal["local", "custom"]
SandboxMode = Literal["docker-networked", "docker-isolated", "local-worktree"]

DEFAULT_BACKEND: AgentBackend = "claude"
DEFAULT_CLAUDE_MODEL = "claude-sonnet-4-6"
DEFAULT_CLAUDE_POC_MODEL = "claude-opus-4-6"
DEFAULT_CODEX_MODEL = "gpt-5.4"
DEFAULT_CODEX_POC_MODEL = "gpt-5.5"
DEFAULT_AGENT_TIMEOUT_SECONDS = 20 * 60
DEFAULT_SANDBOX_MODE: SandboxMode = "docker-networked"
DEFAULT_SANDBOX_IMAGE = "code-auditor-sandbox:latest"
DEFAULT_SANDBOX_ROOT = "/tmp/code-auditor"
DEFAULT_SANDBOX_MIN_FREE_BYTES = 8 * 1024 * 1024 * 1024
DEFAULT_RETAIN_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_RETAIN_MAX_TOTAL_BYTES = 256 * 1024 * 1024


def sandbox_mode_flags(mode: SandboxMode) -> tuple[bool, bool]:
    """Map a Web-facing sandbox mode to the two runtime switches."""
    return mode != "local-worktree", mode == "docker-networked"


def sandbox_mode_from_flags(enabled: bool, network_enabled: bool) -> SandboxMode:
    """Return the Web-facing mode represented by the runtime switches."""
    if not enabled:
        return "local-worktree"
    return "docker-networked" if network_enabled else "docker-isolated"


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
    provider_mode: ProviderMode = "local"
    provider_base_url: str | None = None
    provider_api_key: str | None = field(default=None, repr=False)
    # Derived configs (for example, a Stage 5/6 Docker scratch) keep their own
    # filesystem paths but resolve backend/provider settings from the owning
    # Web job. ``run_agent`` snapshots these fields at invocation time so a
    # settings change affects the next call without mutating an in-flight one.
    agent_settings_source: "AuditConfig | None" = field(default=None, repr=False)
    target_au_count: int = UNLIMITED_AU_COUNT
    agent_timeout_seconds: int | None = DEFAULT_AGENT_TIMEOUT_SECONDS
    known_disclosures: tuple[dict[str, Any], ...] = field(
        default_factory=tuple, repr=False
    )
    # Runtime-only collector for per-task agent failures (stage3-6). Entries
    # are summarized into the run record's error field at the end of the audit.
    task_errors: list[str] = field(default_factory=list, repr=False)
    # Isolated worktree for Stage 5/6 PoC agents; set up by the orchestrator.
    poc_worktree: str | None = None
    # Stage 5/6 use a disposable Docker workspace by default; Web settings may
    # instead select a detached host worktree. The only writable Docker bind
    # mount is a per-task directory below sandbox_root.
    sandbox_enabled: bool = True
    sandbox_root: str = field(
        default_factory=lambda: os.environ.get(
            "CODE_AUDITOR_SANDBOX_ROOT", DEFAULT_SANDBOX_ROOT
        )
    )
    sandbox_image: str = field(
        default_factory=lambda: os.environ.get(
            "CODE_AUDITOR_SANDBOX_IMAGE", DEFAULT_SANDBOX_IMAGE
        )
    )
    sandbox_docker_bin: str = field(
        default_factory=lambda: os.environ.get("CODE_AUDITOR_DOCKER_BIN", "docker")
    )
    sandbox_network_enabled: bool = True
    sandbox_memory: str = "16g"
    sandbox_cpus: str = "8"
    sandbox_pids_limit: int = 2048
    sandbox_min_free_bytes: int = DEFAULT_SANDBOX_MIN_FREE_BYTES
    retain_max_file_bytes: int = DEFAULT_RETAIN_MAX_FILE_BYTES
    retain_max_total_bytes: int = DEFAULT_RETAIN_MAX_TOTAL_BYTES
    # Agent backends and model ids actually used by invocations, in first-use
    # order. Repeated switches/calls do not add duplicates.
    backends_used: list[str] = field(default_factory=list, repr=False)
    models_used: list[str] = field(default_factory=list, repr=False)
    # Web jobs attach a runtime-only observer so History can publish and
    # persist a newly used backend/model as soon as the invocation starts.
    agent_history_changed: Callable[[], None] | None = field(
        default=None, repr=False
    )
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


def local_codex_model(config_path: str | None = None) -> str | None:
    """Read the active model from the local Codex CLI configuration."""
    path = config_path or os.path.join(
        os.path.expanduser("~"), ".codex", "config.toml"
    )
    try:
        with open(path, "rb") as stream:
            data = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    profile_name = data.get("profile")
    profiles = data.get("profiles")
    if isinstance(profile_name, str) and isinstance(profiles, dict):
        profile = profiles.get(profile_name)
        if isinstance(profile, dict):
            model = profile.get("model")
            if isinstance(model, str) and model.strip():
                return model.strip()
    model = data.get("model")
    if isinstance(model, str) and model.strip():
        return model.strip()
    return None


def resolve_agent_model(config: AuditConfig, model: str | None = None) -> str:
    """Resolve the effective model id for one agent invocation.

    Priority: explicit per-call model, then the selected provider's model or
    local CLI configuration, then the built-in backend default.
    """
    if model:
        return model
    if config.backend == "claude" and config.provider_mode == "local":
        return local_claude_model() or config.model or DEFAULT_CLAUDE_MODEL
    if config.backend == "codex" and config.provider_mode == "local":
        return config.model or local_codex_model() or DEFAULT_CODEX_MODEL
    if config.backend == "claude":
        return config.model or DEFAULT_CLAUDE_MODEL
    return config.model or DEFAULT_CODEX_MODEL


def select_poc_model(config: AuditConfig) -> str:
    if config.backend == "claude" and config.provider_mode == "local":
        return (
            local_claude_model(
                keys=("ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_MODEL")
            )
            or config.model
            or DEFAULT_CLAUDE_POC_MODEL
        )
    if config.backend == "claude":
        return config.model or DEFAULT_CLAUDE_POC_MODEL
    if config.model:
        return config.model
    if config.backend == "codex":
        return local_codex_model() or DEFAULT_CODEX_POC_MODEL
    raise ValueError(f"Unsupported agent backend: {config.backend}")


def resolve_wiki_arg(path: str | None) -> str | None:
    """Resolve a Web-selected Wiki path to an absolute path, or None.

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
class AnalysisUnit:
    id: str
    au_file_path: str


@dataclass
class ValidationIssue:
    description: str
    expected: str
    fix: str
