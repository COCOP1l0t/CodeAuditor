"""Benchmark adapters. Importing this package registers the built-ins."""

from __future__ import annotations

from ..registry import register
from .ctftiny import CTFTinyAdapter
from .cybench import CyBenchAdapter
from .tsecbench import TSecBenchAdapter

register("tsecbench", TSecBenchAdapter)
register("ctftiny", CTFTinyAdapter)
register("cybench", CyBenchAdapter)

__all__ = ["CTFTinyAdapter", "CyBenchAdapter", "TSecBenchAdapter"]
