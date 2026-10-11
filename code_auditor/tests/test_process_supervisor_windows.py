from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from code_auditor.process_supervisor import ProcessJob

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job Object semantics")


def test_windows_job_tracks_and_terminates_process() -> None:
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    job = ProcessJob()
    try:
        job.assign_pid(process.pid)
        assert process.pid in job.pids()
        job.terminate()
        process.wait(timeout=5)
        assert process.returncode is not None
    finally:
        job.close()
        if process.poll() is None:
            process.kill()
