"""Benchmark integration surface.

``code_auditor.bench`` intentionally is not wired into the audit orchestrator
yet: adapters are exercised by tests and by the analysis in
``docs/tsecbench-integration.md`` first, so the remote-target flow can be
validated against a real TSecBench deployment before it changes stage 0-6.
"""

from __future__ import annotations

from .adapters import CTFTinyAdapter, TSecBenchAdapter
from .base import (
    BenchAdapter,
    BenchTask,
    InstanceSpec,
    Outcome,
    Scenario,
    Submission,
    SubmissionKind,
)
from .registry import create, register, registered

__all__ = [
    "BenchAdapter",
    "BenchTask",
    "InstanceSpec",
    "Outcome",
    "Scenario",
    "Submission",
    "SubmissionKind",
    "CTFTinyAdapter",
    "TSecBenchAdapter",
    "create",
    "register",
    "registered",
]
