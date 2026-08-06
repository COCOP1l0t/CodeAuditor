"""Web UI for CodeAuditor (``code-auditor --web``)."""
from __future__ import annotations

from .server import create_app, run_web_server

__all__ = ["create_app", "run_web_server"]
