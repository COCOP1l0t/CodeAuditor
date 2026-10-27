"""Benchmark integration surface.

``code_auditor.bench`` intentionally is not wired into the audit orchestrator
yet: adapters are exercised by tests and by the analysis in
``docs/tsecbench-integration.md`` first, so the remote-target flow can be
validated against a real TSecBench deployment before it changes stage 0-6.
"""

from __future__ import annotations

from .adapters import CTFTinyAdapter, CyBenchAdapter, TSecBenchAdapter
from .base import (
    BenchAdapter,
    BenchmarkPlatformCapability,
    BenchmarkPlatformPrerequisites,
    BenchTask,
    InstanceSpec,
    Outcome,
    PlatformName,
    Scenario,
    Submission,
    SubmissionKind,
    benchmark_platform_capability,
    benchmark_platform_prerequisites,
)
from .registry import create, register, registered
from .runner import (
    BenchResult,
    BenchRun,
    BenchRunner,
    BenchRunError,
    extract_flag,
)

__all__ = [
    "BenchAdapter",
    "BenchmarkPlatformCapability",
    "BenchmarkPlatformPrerequisites",
    "BenchResult",
    "BenchRun",
    "BenchRunner",
    "BenchRunError",
    "BenchTask",
    "InstanceSpec",
    "Outcome",
    "PlatformName",
    "Scenario",
    "Submission",
    "SubmissionKind",
    "benchmark_platform_capability",
    "benchmark_platform_prerequisites",
    "CTFTinyAdapter",
    "CyBenchAdapter",
    "TSecBenchAdapter",
    "create",
    "extract_flag",
    "register",
    "registered",
]
