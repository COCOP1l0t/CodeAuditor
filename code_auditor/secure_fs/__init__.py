from __future__ import annotations

import os
import tempfile
from pathlib import Path

if os.name == "nt":
    from .windows import (
        harden_private_file,
        inspect_regular_file,
        private_file_is_secure,
    )
else:
    from .posix import (
        harden_private_file,
        inspect_regular_file,
        private_file_is_secure,
    )


class SecureFSError(ValueError):
    """Raised when a filesystem object violates the secure-file contract."""


def read_private_bytes(path: str | os.PathLike[str]) -> bytes:
    path = Path(path)
    require_regular_file(path)
    if not private_file_is_secure(path):
        raise SecureFSError(f"file is not private to the current user: {path}")
    return path.read_bytes()


def write_private_bytes_atomic(
    path: str | os.PathLike[str], data: bytes, *, exclusive: bool = False
) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        harden_private_file(temporary)
        if exclusive and path.exists():
            raise FileExistsError(path)
        os.replace(temporary, path)
        harden_private_file(path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def require_regular_file(
    path: str | os.PathLike[str], *, single_link: bool = True
) -> os.stat_result:
    """Inspect a real regular file without accepting path indirection."""
    try:
        return inspect_regular_file(Path(path), single_link=single_link)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if getattr(exc, "winerror", None) in {2, 3} or (
            getattr(exc, "args", ()) and exc.args[0] in {2, 3}
        ):
            raise FileNotFoundError(path) from exc
        raise SecureFSError(str(exc)) from exc
    except Exception as exc:
        # pywintypes.error is not consistently exposed as OSError across
        # pywin32 builds, but retains the Win32 error code as args[0].
        if getattr(exc, "args", ()) and exc.args[0] in {2, 3}:
            raise FileNotFoundError(path) from exc
        if isinstance(exc, ValueError):
            raise SecureFSError(str(exc)) from exc
        raise


__all__ = [
    "SecureFSError",
    "harden_private_file",
    "private_file_is_secure",
    "read_private_bytes",
    "require_regular_file",
    "write_private_bytes_atomic",
]
