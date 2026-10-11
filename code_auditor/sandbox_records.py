"""Host-written execution records, kept outside container bind mounts.

These records describe individual container launches, not all artifacts in a
resumed audit. Old audits without records have unknown execution environments.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .secure_fs import SecureFSError, require_regular_file, write_private_bytes_atomic

EXECUTION_DIRECTORY = ".sandbox-executions"
MAX_RECORD_BYTES = 32 * 1024
_RECORD_NAME = re.compile(r"[0-9a-f]{32}\.json\Z")


def create_execution_directory(output_dir: str, scratch_id: str) -> Path:
    if not isinstance(scratch_id, str) or _RECORD_NAME.fullmatch(
        f"{scratch_id}.json"
    ) is None:
        raise ValueError("execution record identifier must be 32 hex characters")
    root = Path(output_dir).expanduser().resolve() / EXECUTION_DIRECTORY
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or root.is_symlink():
        raise ValueError("execution record directory must be a real directory")
    if os.name != "nt" and info.st_uid != os.getuid():
        raise ValueError("execution record directory must be host-owned")
    if os.name != "nt":
        root.chmod(0o700)
    directory = root / scratch_id
    directory.mkdir(mode=0o700)
    return directory


def write_execution_record(directory: Path, record: dict[str, Any]) -> None:
    filename = f"{record['execution_id']}.json"
    if not _RECORD_NAME.fullmatch(filename):
        raise ValueError("invalid execution record id")
    # Do not record argv, environment variables, auth files, or raw Docker
    # inspect output: each can contain provider credentials.
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n"
    if len(payload.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("execution record is too large")
    write_private_bytes_atomic(directory / filename, payload.encode("utf-8"))


def read_execution_records(
    directory: Path | str, *, parent_fd: int | None = None,
) -> list[dict[str, Any]]:
    if os.name == "nt":
        if parent_fd is not None:
            return []
        directory_path = Path(directory)
        if not directory_path.is_dir() or directory_path.is_symlink():
            return []
        records: list[dict[str, Any]] = []
        for path in directory_path.iterdir():
            if not _RECORD_NAME.fullmatch(path.name):
                continue
            try:
                info = require_regular_file(path)
                if info.st_size > MAX_RECORD_BYTES:
                    continue
                payload = path.read_bytes()
                if len(payload) > MAX_RECORD_BYTES:
                    continue
                record = json.loads(payload)
                if (
                    isinstance(record, dict)
                    and record.get("schema_version") in {1, 2}
                    and f"{record.get('execution_id')}.json" == path.name
                ):
                    records.append(record)
            except (OSError, SecureFSError, ValueError, UnicodeError):
                continue
        return records

    records = []
    # History passes a pinned parent descriptor to avoid directory replacement
    # races while opening a scratch's records.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        directory_fd = os.open(directory, flags, dir_fd=parent_fd)
    except OSError:
        return records
    try:
        for name in os.listdir(directory_fd):
            if not _RECORD_NAME.fullmatch(name):
                continue
            fd = -1
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory_fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    continue
                if info.st_size > MAX_RECORD_BYTES:
                    continue
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    payload = stream.read(MAX_RECORD_BYTES + 1)
                if len(payload) > MAX_RECORD_BYTES:
                    continue
                record = json.loads(payload)
                if (isinstance(record, dict) and record.get("schema_version") in {1, 2}
                        and f"{record.get('execution_id')}.json" == name):
                    records.append(record)
            except (OSError, ValueError, UnicodeError):
                continue
            finally:
                if fd >= 0:
                    os.close(fd)
    finally:
        os.close(directory_fd)
    return records


def list_sandbox_executions(
    output_dir: str, *, run_id: int | None = None, job_key: str | None = None,
) -> list[dict[str, Any]]:
    root = Path(output_dir) / EXECUTION_DIRECTORY
    if os.name == "nt":
        if not root.is_dir() or root.is_symlink():
            return []
        records: list[dict[str, Any]] = []
        for child in root.iterdir():
            if re.fullmatch(r"[0-9a-f]{32}", child.name):
                records.extend(read_execution_records(child))
    else:
        try:
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            return []
        records = []
        try:
            for name in os.listdir(root_fd):
                if re.fullmatch(r"[0-9a-f]{32}", name):
                    records.extend(read_execution_records(name, parent_fd=root_fd))
        finally:
            os.close(root_fd)
    if run_id is not None:
        records = [row for row in records if row.get("audit_run_id") == run_id]
    if job_key is not None:
        records = [row for row in records if row.get("job_key") == job_key]

    def started_at(record: dict[str, Any]) -> float:
        value = record.get("started_at")
        return float(value) if isinstance(value, (int, float)) else 0.0

    return sorted(records, key=started_at, reverse=True)
