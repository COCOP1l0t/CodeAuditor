from __future__ import annotations

import os

if os.name == "nt":
    from .windows import ProcessJob
else:
    from .posix import ProcessJob

__all__ = ["ProcessJob"]
