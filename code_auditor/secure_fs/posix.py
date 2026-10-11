from __future__ import annotations

import os
import stat
from pathlib import Path


def inspect_regular_file(path: Path, *, single_link: bool = True) -> os.stat_result:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"path is not a regular file: {path}")
    if single_link and info.st_nlink != 1:
        raise ValueError(f"file must not be hard-linked: {path}")
    return info


def harden_private_file(path: str | os.PathLike[str]) -> None:
    path = Path(path)
    inspect_regular_file(path)
    path.chmod(0o600)


def private_file_is_secure(path: str | os.PathLike[str]) -> bool:
    try:
        info = inspect_regular_file(Path(path))
    except (OSError, ValueError):
        return False
    return stat.S_IMODE(info.st_mode) & 0o077 == 0
