"""Registry of benchmark adapters, keyed by the name used on the CLI/API."""

from __future__ import annotations

from typing import Callable

from .base import BenchAdapter

_FACTORIES: dict[str, Callable[..., BenchAdapter]] = {}


def register(name: str, factory: Callable[..., BenchAdapter]) -> None:
    """Register an adapter factory under a stable lower-case name."""
    key = name.strip().lower()
    if not key:
        raise ValueError("A benchmark adapter needs a non-empty name.")
    _FACTORIES[key] = factory


def create(name: str, **options: object) -> BenchAdapter:
    """Instantiate a registered adapter; extra options go to its factory."""
    key = name.strip().lower()
    try:
        factory = _FACTORIES[key]
    except KeyError:
        available = ", ".join(registered()) or "none"
        raise KeyError(
            f"Unknown benchmark adapter {name!r} (registered: {available})."
        ) from None
    return factory(**options)


def registered() -> list[str]:
    return sorted(_FACTORIES)
