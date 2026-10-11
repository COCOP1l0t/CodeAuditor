from __future__ import annotations

import contextlib

import win32api
import win32con
import win32job


class ProcessJob:
    """Own a Windows process tree through a kill-on-close Job Object."""

    def __init__(self) -> None:
        self._handle = win32job.CreateJobObject(None, "")
        limits = win32job.QueryInformationJobObject(
            self._handle, win32job.JobObjectExtendedLimitInformation
        )
        limits["BasicLimitInformation"]["LimitFlags"] |= (
            win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        win32job.SetInformationJobObject(
            self._handle, win32job.JobObjectExtendedLimitInformation, limits
        )
        self._closed = False

    def assign_pid(self, pid: int) -> None:
        if self._closed:
            raise RuntimeError("process job is closed")
        process = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA
            | win32con.PROCESS_TERMINATE
            | win32con.PROCESS_QUERY_INFORMATION,
            False,
            pid,
        )
        try:
            win32job.AssignProcessToJobObject(self._handle, process)
        finally:
            process.Close()

    def pids(self) -> tuple[int, ...]:
        if self._closed:
            return ()
        info = win32job.QueryInformationJobObject(
            self._handle, win32job.JobObjectBasicProcessIdList
        )
        return tuple(int(pid) for pid in info)

    def terminate(self, exit_code: int = 1) -> None:
        if not self._closed:
            win32job.TerminateJobObject(self._handle, exit_code)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with contextlib.suppress(Exception):
            self._handle.Close()

    def __enter__(self) -> "ProcessJob":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
