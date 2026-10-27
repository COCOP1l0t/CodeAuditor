"""Benchmark integration surface.

``code_auditor.bench`` provides the built-in TSECBench adapter and the shared
sequential runner. The runner is independent of the audit stages and persists
results through the Web/DB benchmark surface.
"""

from __future__ import annotations

from .adapters import TSecBenchAdapter
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
    "TSecBenchAdapter",
    "create",
    "extract_flag",
    "register",
    "registered",
]
