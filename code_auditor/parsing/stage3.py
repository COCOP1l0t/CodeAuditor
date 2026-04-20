from __future__ import annotations

import json
import os
import re

from ..config import AnalysisUnit


def parse_au_files(result_dir: str) -> list[AnalysisUnit]:
    """Read all AU-*.json files from result_dir and return AnalysisUnit list."""
    pattern = re.compile(r"^AU-(\d+)\.json$")
    units: list[AnalysisUnit] = []

    if not os.path.isdir(result_dir):
        return units

    for name in sorted(os.listdir(result_dir)):
        m = pattern.match(name)
        if not m:
            continue
        path = os.path.join(result_dir, name)
        try:
            with open(path) as f:
                json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        au_id = f"AU-{m.group(1)}"
        units.append(AnalysisUnit(id=au_id, au_file_path=path))

    return units


def parse_auditing_focus(path: str) -> tuple[str, str]:
    """Extract scope-modules and historical-hot-spots sections from the auditing focus directive.

    Returns (scope_modules, hot_spots) body text.
    """
    try:
        content = open(path).read()
    except OSError:
        return "", ""

    def _extract_section(heading: str) -> str:
        escaped = re.escape(heading)
        pattern = re.compile(rf"(?:^|\n)##\s+{escaped}\s*\n([\s\S]*?)(?=\n## |$)")
        m = pattern.search(content)
        if m is None:
            return ""
        return m.group(1).strip()

    scope_modules = _extract_section("Explicit In-Scope and Out-of-Scope Modules")
    hot_spots = _extract_section("Historical Hot Spots")
    return scope_modules, hot_spots
