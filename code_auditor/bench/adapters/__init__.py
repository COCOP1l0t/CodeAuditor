"""Benchmark adapters. Importing this package registers the built-ins."""

from __future__ import annotations

from ..registry import register
from .tsecbench import TSecBenchAdapter

register("tsecbench", TSecBenchAdapter)

__all__ = ["TSecBenchAdapter"]
