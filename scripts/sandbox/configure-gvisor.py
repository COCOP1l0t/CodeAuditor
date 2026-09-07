#!/usr/bin/env python3
"""Merge a runsc runtime into daemon.json; preserve other settings and default runtime."""
from __future__ import annotations

import argparse
import copy
import fcntl
import json
import os
import shutil
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("daemon.json contains duplicate keys")
        result[key] = value
    return result


def merge_runtime(raw: bytes, runsc: Path, replace: bool = False) -> dict:
    data = json.loads(raw, object_pairs_hook=unique_keys) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("daemon.json must contain an object")
    updated = copy.deepcopy(data)
    runtimes = updated.setdefault("runtimes", {})
    if not isinstance(runtimes, dict):
        raise ValueError("daemon.json runtimes must be an object")
    desired = {"path": str(runsc)}
    if "runsc" in runtimes and runtimes["runsc"] != desired and not replace:
        raise ValueError("runsc already has different settings; review them and use --replace if intended")
    runtimes["runsc"] = desired
    return updated


def read_config(path: Path) -> tuple[bytes, int]:
    if not path.exists() and not path.is_symlink():
        return b"", 0o644
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("daemon.json must be a regular file with one link")
    return path.read_bytes(), stat.S_IMODE(info.st_mode)


def apply_config(config: Path, runsc: Path, replace: bool, dockerd: str) -> Path | None:
    config.parent.mkdir(parents=True, exist_ok=True)
    lock = os.open(config.parent / ".code-auditor-daemon.lock",
                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before, permissions = read_config(config)
        updated = merge_runtime(before, runsc, replace)
        if before and json.loads(before) == updated:
            return None
        payload = (json.dumps(updated, indent=2) + "\n").encode()
        fd, filename = tempfile.mkstemp(prefix=".daemon-candidate-", suffix=".json", dir=config.parent)
        candidate = Path(filename)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            subprocess.run([dockerd, "--validate", "--config-file", str(candidate)],
                           check=True, timeout=30, capture_output=True, text=True)
            if read_config(config) != (before, permissions):
                raise ValueError("daemon.json changed during validation; rerun the merge")
            backup = None
            if config.exists():
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                backup = config.with_name(f"{config.name}.code-auditor-{stamp}-{uuid4().hex[:8]}.bak")
                backup_fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(backup_fd, "wb") as stream:
                    stream.write(before)
                    stream.flush()
                    os.fsync(stream.fileno())
                info = config.stat()
                os.chown(candidate, info.st_uid, info.st_gid)
            candidate.chmod(permissions)
            os.replace(candidate, config)
            directory_fd = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return backup
        finally:
            candidate.unlink(missing_ok=True)
    finally:
        os.close(lock)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runsc", required=True, type=Path, help="absolute path of the installed runsc")
    parser.add_argument("--config", type=Path, default=Path("/etc/docker/daemon.json"))
    parser.add_argument("--replace", action="store_true", help="replace an existing, different runsc entry")
    parser.add_argument("--dockerd", default="dockerd", help="daemon binary used only for --validate")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="validate, back up and atomically write configuration")
    mode.add_argument("--dry-run", action="store_true", help="preview only (default)")
    args = parser.parse_args()
    try:
        runsc = args.runsc.expanduser().resolve(strict=True)
        if not runsc.is_file() or not os.access(runsc, os.X_OK):
            raise ValueError("runsc must be an installed executable")
        if runsc.stat().st_mode & 0o022:
            raise ValueError("runsc must not be writable by group or others")
        config = args.config.expanduser().absolute()
        before, _ = read_config(config)
        updated = merge_runtime(before, runsc, args.replace)
        print(f"Configuration: {config}")
        print("Proposed runtimes.runsc: " + json.dumps(updated["runtimes"]["runsc"]))
        print("All other entries, including default-runtime, are preserved.")
        if not args.apply:
            print("Preview only. Use --apply to validate, back up and write. Docker will not be reloaded.")
            return 0
        dockerd = shutil.which(args.dockerd)
        if dockerd is None:
            raise ValueError("dockerd is required to validate the candidate configuration")
        backup = apply_config(config, runsc, args.replace, dockerd)
        print(f"Backup: {backup}" if backup else "No previous content required a backup.")
        print("Configuration ready. Run sudo systemctl reload docker, then sandboxctl.py check --runtime runsc.")
        return 0
    except subprocess.CalledProcessError:
        # Do not echo daemon diagnostics containing unrelated configuration secrets.
        parser.exit(1, "dockerd rejected the candidate; original configuration was preserved.\n")
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"Docker runtime configuration failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
