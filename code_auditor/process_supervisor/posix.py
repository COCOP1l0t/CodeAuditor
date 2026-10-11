from __future__ import annotations

import contextlib
import os
import signal


class ProcessJob:
    """Own one POSIX process group."""

    def __init__(self) -> None:
        self.pid: int | None = None

    def assign_pid(self, pid: int) -> None:
        self.pid = pid

    def pids(self) -> tuple[int, ...]:
        return (self.pid,) if self.pid is not None else ()

    def terminate(self, exit_code: int = 1) -> None:
        if self.pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.pid, signal.SIGKILL)

    def close(self) -> None:
        self.pid = None

    def __enter__(self) -> "ProcessJob":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
