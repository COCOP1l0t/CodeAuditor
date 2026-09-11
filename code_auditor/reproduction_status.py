from __future__ import annotations

import re
from pathlib import Path

REPRODUCED_STATUSES = {"reproduced"}
FAILED_STATUSES = {"partially-reproduced", "not-reproduced", "false-positive"}
VALID_STATUSES = REPRODUCED_STATUSES | FAILED_STATUSES

_COMPOUND_STATUS_PATTERN = re.compile(
    r"(partially[-\s]+reproduced|not[-\s]+reproduced|false[-\s]+positive)",
    re.IGNORECASE,
)
# An affirmative status value, optionally after a "Reproduction Status:" label
# or list bullet. Checked before the negation heuristic so a genuine success
# whose narrative mentions an earlier failed attempt is not misread.
_LEADING_REPRODUCED_PATTERN = re.compile(
    r"^\s*(?:[-*+]\s*)?(?:reproduction\s+status\s*[:=\-]\s*)?reproduced\b",
    re.IGNORECASE,
)
_BARE_REPRODUCED_PATTERN = re.compile(r"\breproduced\b", re.IGNORECASE)
_NEGATED_REPRODUCTION_PATTERN = re.compile(
    r"\b(?:not|never)\s+(?:successfully\s+)?(?:be\s+)?reproduced\b"
    r"|\bnon[-\s]?reproduc\w*\b"
    r"|\bcould\s+not\s+be\s+reproduced\b"
    r"|\bcould\s+not\s+reproduce\b"
    r"|\b(?:failed|unable)\s+to\s+reproduce\b"
    r"|\b(?:was|were|is|are)\s+not\s+able\s+to\s+reproduce\b",
    re.IGNORECASE,
)


def _normalize_status(raw_status: str) -> str:
    return re.sub(r"\s+", "-", raw_status.strip().lower())


def _find_status_value(text: str) -> str | None:
    match = _COMPOUND_STATUS_PATTERN.search(text)
    if match:
        status = _normalize_status(match.group(1))
        return status if status in VALID_STATUSES else None

    if _LEADING_REPRODUCED_PATTERN.match(text):
        return "reproduced"

    if _NEGATED_REPRODUCTION_PATTERN.search(text):
        return "not-reproduced"

    if _BARE_REPRODUCED_PATTERN.search(text):
        return "reproduced"
    return None


def read_reproduction_status(report_path: str) -> str | None:
    """Extract a Stage 5 reproduction status from a report.

    The Stage 5 prompt asks for a ``Reproduction Status`` section, but older
    runs and noncompliant agent output sometimes put the status in a table or
    title. Prefer explicit status lines, then fall back to the opening text.
    """
    try:
        content = Path(report_path).read_text(errors="replace")
    except OSError:
        return None

    lines = content.splitlines()
    for index, line in enumerate(lines):
        if "reproduction status" not in line.lower():
            continue

        status = _find_status_value(line)
        if status:
            return status

        for next_line in lines[index + 1 : index + 6]:
            stripped = next_line.strip()
            if not stripped:
                continue
            status = _find_status_value(stripped)
            if status:
                return status
            if stripped.startswith("#"):
                break

    opening = "\n".join(line for line in lines[:12] if line.strip())
    status = _find_status_value(opening)
    if status:
        return status

    success_match = re.search(r"\bsuccessfully\s+reproduced\b", content[:4000], re.IGNORECASE)
    if success_match:
        window = content[max(0, success_match.start() - 40) : success_match.end()]
        if not _NEGATED_REPRODUCTION_PATTERN.search(window):
            return "reproduced"

    return None


def is_reproduced_status(status: str | None) -> bool:
    return status in REPRODUCED_STATUSES


def is_failed_status(status: str | None) -> bool:
    return status in FAILED_STATUSES
