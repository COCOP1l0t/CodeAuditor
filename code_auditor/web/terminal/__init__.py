"""Platform-dispatched PTY-to-WebSocket bridge for PoC working directories."""
from __future__ import annotations

import os

_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    from .terminal_win import serve_poc_terminal
else:
    from .terminal_posix import serve_poc_terminal

__all__ = ["serve_poc_terminal", "_IS_WINDOWS"]

