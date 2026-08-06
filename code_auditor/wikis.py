"""Discovery of local, server-managed Wiki knowledge bases."""
from __future__ import annotations

import os
import re

DEFAULT_WIKIS_DIR = os.path.join("~", ".code_auditor", "wiki")
_SAFE_WIKI_NAME = re.compile(
    r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
)


def list_local_wikis(
    wikis_dir: str = DEFAULT_WIKIS_DIR,
) -> list[dict[str, str]]:
    """List local Wiki roots without exposing arbitrary filesystem paths.

    A directory is considered a Wiki when it is a Git checkout or contains an
    ``index.md`` file. Nested roots are returned by a stable path relative to
    the managed Wiki directory.
    """
    base = os.path.realpath(os.path.expanduser(wikis_dir))
    if not os.path.isdir(base):
        return []

    wikis: list[dict[str, str]] = []
    for root, dirs, files in os.walk(base, followlinks=False):
        resolved = os.path.realpath(root)
        if resolved != base and not resolved.startswith(base + os.sep):
            dirs[:] = []
            continue

        is_wiki = resolved != base and (
            ".git" in dirs or "index.md" in files
        )
        if is_wiki:
            name = os.path.relpath(resolved, base)
            if (
                _SAFE_WIKI_NAME.fullmatch(name)
                and all(segment not in {".", ".."} for segment in name.split("/"))
            ):
                wikis.append({"name": name, "path": resolved})
            dirs[:] = []
            continue

        dirs[:] = [
            directory
            for directory in dirs
            if not directory.startswith(".") and not os.path.islink(
                os.path.join(root, directory)
            )
        ]

    wikis.sort(key=lambda wiki: wiki["name"])
    return wikis
