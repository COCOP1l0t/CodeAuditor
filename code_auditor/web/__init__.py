"""Web UI for CodeAuditor."""
from __future__ import annotations

from .server import create_app, run_web_server

__all__ = ["create_app", "run_web_server"]
