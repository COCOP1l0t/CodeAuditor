"""Benchmark integration primitives.

CodeAuditor's audit pipeline assumes a local git repository. A benchmark
adapter describes one benchmark's deviations from that assumption: how to
enumerate instances, how to open a task (remote target, supplied repo, or
container), and how the benchmark's own oracle grades a submission. The
adapter never decides success itself; it only translates.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping, Protocol, runtime_checkable

Scenario = Literal["repo", "remote-target", "container"]
SubmissionKind = Literal["flag", "patch", "poc", "report"]


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
