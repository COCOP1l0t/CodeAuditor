"""Benchmark integration primitives.

CodeAuditor's audit pipeline assumes a local git repository. A benchmark
adapter describes one benchmark's deviations from that assumption: how to
enumerate instances, how to open a task (remote target, supplied repo, or
container), and how the benchmark's own oracle grades a submission. The
adapter never decides success itself; it only translates.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Mapping, Protocol, runtime_checkable

from ..runtime_capabilities import current_platform_name

Scenario = Literal["repo", "remote-target", "container", "workspace"]
SubmissionKind = Literal["flag", "patch", "poc", "report"]
PlatformName = Literal["linux", "macos", "windows"]


@dataclass(frozen=True)
class BenchmarkPlatformPrerequisites:
    """Static platform and command requirements for one benchmark adapter."""

    supported_platforms: tuple[PlatformName, ...]
    required_commands: tuple[str, ...] = ()
    optional_commands: tuple[str, ...] = ()
    notes: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "supported_platforms": list(self.supported_platforms),
            "required_commands": list(self.required_commands),
            "optional_commands": list(self.optional_commands),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class BenchmarkPlatformCapability:
    benchmark: str
    platform: str
    available: bool
    reason: str
    prerequisites: BenchmarkPlatformPrerequisites

    def public(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "platform": self.platform,
            "available": self.available,
            "reason": self.reason,
            **self.prerequisites.public(),
        }


_BENCHMARK_PLATFORM_PREREQUISITES = {
    "tsecbench": BenchmarkPlatformPrerequisites(
        supported_platforms=("linux", "macos", "windows"),
        notes=(
            "Requires network access to the TSecBench API and a working VPN. "
            "No local Docker or bash installation is required."
        ),
    ),
    "ctftiny": BenchmarkPlatformPrerequisites(
        supported_platforms=("linux", "macos", "windows"),
        optional_commands=("docker",),
        notes=(
            "File-only challenges need no container runtime. Challenges marked "
            "compose require Docker Compose; native Windows should use Docker "
            "Desktop with Linux containers."
        ),
    ),
    "cybench": BenchmarkPlatformPrerequisites(
        supported_platforms=("linux", "macos"),
        required_commands=("bash",),
        optional_commands=("docker",),
        notes=(
            "CyBench executes dataset bash scripts. Docker-network tasks also "
            "require Docker. Native Windows must run CodeAuditor in WSL2/Linux."
        ),
    ),
}


def benchmark_platform_prerequisites(
    name: str,
) -> BenchmarkPlatformPrerequisites:
    try:
        return _BENCHMARK_PLATFORM_PREREQUISITES[name.strip().lower()]
    except KeyError:
        raise KeyError(f"No platform prerequisites registered for {name!r}.") from None


def benchmark_platform_capability(
    name: str,
    *,
    platform_name: str | None = None,
    command_exists: Callable[[str], str | None] = shutil.which,
) -> BenchmarkPlatformCapability:
    """Report whether a benchmark adapter can run on the current platform."""
    key = name.strip().lower()
    prerequisites = benchmark_platform_prerequisites(key)
    platform = platform_name or current_platform_name()
    if platform not in prerequisites.supported_platforms:
        return BenchmarkPlatformCapability(
            benchmark=key,
            platform=platform,
            available=False,
            reason=(
                f"{key} does not support {platform}; supported platforms: "
                f"{', '.join(prerequisites.supported_platforms)}. "
                f"{prerequisites.notes}"
            ).strip(),
            prerequisites=prerequisites,
        )
    missing = [
        command
        for command in prerequisites.required_commands
        if command_exists(command) is None
    ]
    if missing:
        return BenchmarkPlatformCapability(
            benchmark=key,
            platform=platform,
            available=False,
            reason=f"{key} requires missing command(s): {', '.join(missing)}.",
            prerequisites=prerequisites,
        )
    return BenchmarkPlatformCapability(
        benchmark=key,
        platform=platform,
        available=True,
        reason=prerequisites.notes or "Platform prerequisites are satisfied.",
        prerequisites=prerequisites,
    )


@dataclass(frozen=True)
class InstanceSpec:
    """One addressable benchmark instance (a task, challenge, or case)."""

    benchmark: str
    instance_id: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "instance_id": self.instance_id,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class BenchTask:
    """The agent-facing contract of one opened instance."""

    instance: InstanceSpec
    prompt: str
    target: str
    scenario: Scenario = "remote-target"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "instance": self.instance.public(),
            "target": self.target,
            "scenario": self.scenario,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Submission:
    """An artifact produced by the agent and handed to the benchmark oracle."""

    instance_id: str
    kind: SubmissionKind
    value: str
    evidence: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Outcome:
    """The benchmark oracle's verdict, kept separate from agent prose."""

    instance_id: str
    success: bool
    score: float = 0.0
    detail: Mapping[str, Any] = field(default_factory=dict)

    def public(self) -> dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "success": self.success,
            "score": self.score,
            "detail": dict(self.detail),
        }


@runtime_checkable
class BenchAdapter(Protocol):
    """Minimal contract every benchmark adapter implements."""

    name: str

    def list_instances(self) -> list[InstanceSpec]: ...

    def open_task(self, instance: InstanceSpec) -> BenchTask: ...

    def grade(self, instance: InstanceSpec, submission: Submission) -> Outcome: ...

    def close(self, instance: InstanceSpec) -> None: ...
