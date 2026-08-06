"""Stable identities and metadata helpers for database-backed disclosures."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _single_line(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def _display_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [_single_line(item) for item in value if _single_line(item)]
    text = _single_line(value)
    return [text] if text else []


def _normalize_text(value: Any) -> str:
    return " ".join(_single_line(value).lower().split())


def _normalize_path_text(value: Any) -> str:
    return " ".join(_single_line(value).replace("\\", "/").split())


def _normalize_list(value: Any) -> list[str]:
    return sorted(
        {
            _normalize_text(item)
            for item in _display_list(value)
            if _normalize_text(item)
        }
    )


def build_dedupe_key(finding: dict[str, Any], repo_url: str | None) -> str:
    """Build a stable cross-run key for the same vulnerability shape."""
    trace = finding.get("data_flow_trace")
    trace_data = trace if isinstance(trace, dict) else {}
    stable_payload = {
        "repo": _normalize_text(repo_url or ""),
        "location": _normalize_path_text(finding.get("location")),
        "cwe": _normalize_list(finding.get("cwe_id") or finding.get("cwe")),
        "vulnerability_class": _normalize_list(
            finding.get("vulnerability_class")
        ),
        "trigger": _normalize_text(finding.get("trigger")),
        "trace_root": _normalize_path_text(
            trace_data.get("root_path")
            or trace_data.get("root")
            or trace_data.get("source")
            or trace_data.get("entry_point")
        ),
        "trace_sink": _normalize_path_text(trace_data.get("sink")),
    }
    encoded = json.dumps(
        stable_payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def extract_email_subject(email_path: str | None) -> str | None:
    """Extract a possibly folded Subject header from a disclosure email."""
    if not email_path:
        return None
    try:
        content = Path(email_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = content.splitlines()
    for index, line in enumerate(lines):
        if not line.lower().startswith("subject:"):
            continue
        parts = [line.split(":", 1)[1].strip()]
        for next_line in lines[index + 1 :]:
            if not next_line.strip():
                break
            if next_line[0] in " \t":
                parts.append(next_line.strip())
                continue
            header_name, separator, _value = next_line.partition(":")
            if separator and header_name.replace("-", "").isalpha():
                break
            parts.append(next_line.strip())
        subject = " ".join(part for part in parts if part)
        return subject or None
    return None
