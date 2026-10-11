from __future__ import annotations

import os
from pathlib import Path

import pytest

from code_auditor.secure_fs import (
    harden_private_file,
    private_file_is_secure,
    require_regular_file,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows security semantics")


def test_windows_private_file_dacl(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    path.write_text("{}", encoding="utf-8")

    assert private_file_is_secure(path) is False
    harden_private_file(path)
    assert private_file_is_secure(path) is True


def test_windows_rejects_hardlinked_regular_file(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    alias = tmp_path / "alias.txt"
    source.write_text("secret", encoding="utf-8")
    os.link(source, alias)

    with pytest.raises(ValueError, match="hard-linked"):
        require_regular_file(source)
