from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tomllib
from datetime import date
from pathlib import Path
from typing import Any


_HEADER = "# Reproduced Bugs\n\n"
_COMMENT_PREFIX = "code-auditor:discovered"
_COMMENT_RE = re.compile(r"<!--\s*code-auditor:discovered\s+(.+?)\s*-->", re.DOTALL)


def read_discovered_keys(path: str) -> set[str]:
    """Read dedupe keys from embedded discovered-bug JSON comments."""
    discovered_path = Path(path)
    if not discovered_path.exists():
        return set()

    try:
        content = discovered_path.read_text(encoding="utf-8")
    except OSError:
        return set()

    keys: set[str] = set()
    for match in _COMMENT_RE.finditer(content):
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue

        if isinstance(payload, dict):
            dedupe_key = payload.get("dedupe_key")
            if isinstance(dedupe_key, str) and dedupe_key:
                keys.add(dedupe_key)
    return keys


def build_dedupe_key(finding: dict[str, Any], repo_url: str | None) -> str:
    """Build a stable cross-run key for the same vulnerability shape."""
    trace = finding.get("data_flow_trace")
    trace_data = trace if isinstance(trace, dict) else {}
    stable_payload = {
        "repo": _normalize_text(repo_url or ""),
        "location": _normalize_path_text(finding.get("location")),
        "cwe": _normalize_list(finding.get("cwe_id") or finding.get("cwe")),
        "vulnerability_class": _normalize_list(finding.get("vulnerability_class")),
        "trigger": _normalize_text(finding.get("trigger")),
        "trace_root": _normalize_path_text(
            trace_data.get("root_path")
            or trace_data.get("root")
            or trace_data.get("source")
            or trace_data.get("entry_point")
        ),
        "trace_sink": _normalize_path_text(trace_data.get("sink")),
    }
    encoded = json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def collect_repo_snapshot(target: str, audit_finished_date: str | None = None) -> dict[str, str]:
    """Collect best-effort repository metadata without requiring a git repo."""
    target_path = os.path.realpath(target)
    repo_url = _run_git(target_path, ["config", "--get", "remote.origin.url"])
    audited_commit = _run_git(target_path, ["rev-parse", "HEAD"])
    status = _run_git(target_path, ["status", "--porcelain"])

    version, description = _read_project_metadata(target_path)
    if status is None:
        dirty_status = "unknown"
    else:
        dirty_status = "dirty" if status else "clean"

    return {
        "target_path": target_path,
        "repo_url": repo_url or "",
        "audited_commit": audited_commit or "",
        "version": version,
        "description": description,
        "dirty_status": dirty_status,
        "audit_finished_date": audit_finished_date or date.today().isoformat(),
    }


def build_discovered_entry(
    finding: dict[str, Any],
    repo_snapshot: dict[str, str],
    *,
    discovered_path: str | None = None,
    stage4_finding_path: str | None = None,
    stage5_report_path: str | None = None,
    stage6_report_path: str | None = None,
    stage6_email_path: str | None = None,
    stage6_zip_path: str | None = None,
) -> str:
    """Build one human-readable markdown entry with machine-readable metadata."""
    title = _single_line(finding.get("title")) or "Untitled vulnerability"
    repo_url = repo_snapshot.get("repo_url", "")
    audited_commit = repo_snapshot.get("audited_commit", "")
    audit_finished_date = repo_snapshot.get("audit_finished_date", "")
    dedupe_key = build_dedupe_key(finding, repo_url)

    metadata = {
        "dedupe_key": dedupe_key,
        "title": title,
        "repo_url": repo_url,
        "audited_commit": audited_commit,
        "audit_finished_date": audit_finished_date,
    }
    metadata_json = json.dumps(metadata, sort_keys=True, separators=(",", ":"))

    lines = [
        f"## {title}",
        "",
        f"<!-- {_COMMENT_PREFIX} {metadata_json} -->",
        "",
        f"- **Repository:** {_visible_value(repo_url or repo_snapshot.get('target_path'))}",
        f"- **Version:** {_visible_value(repo_snapshot.get('version'))}",
        f"- **Description:** {_visible_value(repo_snapshot.get('description'))}",
        f"- **Audited Commit:** `{_visible_value(audited_commit)}`",
        f"- **Dirty Status:** {_visible_value(repo_snapshot.get('dirty_status'))}",
        f"- **Audit Finished:** {_visible_value(audit_finished_date)}",
        f"- **Severity:** {_severity_cvss(finding)}",
        f"- **CWE:** {_visible_value(', '.join(_display_list(finding.get('cwe_id') or finding.get('cwe'))))}",
        f"- **Vulnerability Class:** {_visible_value(', '.join(_display_list(finding.get('vulnerability_class'))))}",
        f"- **Location:** `{_visible_value(finding.get('location'))}`",
    ]

    sections = [
        ("Summary", finding.get("summary") or finding.get("description")),
        ("Impact", finding.get("impact")),
        ("Trigger", finding.get("trigger")),
    ]
    for heading, value in sections:
        text = _paragraph(value)
        if text:
            lines.extend(["", f"**{heading}**", "", text])

    links = _artifact_links(
        discovered_path=discovered_path,
        stage4_finding_path=stage4_finding_path,
        stage5_report_path=stage5_report_path,
        stage6_report_path=stage6_report_path,
        stage6_email_path=stage6_email_path,
        stage6_zip_path=stage6_zip_path,
    )
    if links:
        lines.extend(["", "**Artifacts**", ""])
        lines.extend(f"- {link}" for link in links)

    return "\n".join(lines).rstrip() + "\n"


def append_entries(path: str, entries: list[str]) -> None:
    """Append discovered-bug entries, creating the file and header when needed."""
    blocks = [entry.strip() for entry in entries if entry.strip()]
    if not blocks:
        return

    discovered_path = Path(path)
    discovered_path.parent.mkdir(parents=True, exist_ok=True)

    if discovered_path.exists():
        content = discovered_path.read_text(encoding="utf-8")
    else:
        content = ""

    if content.strip():
        content = content.rstrip() + "\n\n"
    else:
        content = _HEADER

    content += "\n\n".join(blocks).rstrip() + "\n"
    discovered_path.write_text(content, encoding="utf-8")


def _run_git(target_path: str, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", target_path, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _read_project_metadata(target_path: str) -> tuple[str, str]:
    pyproject_path = Path(target_path) / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with pyproject_path.open("rb") as f:
                data = tomllib.load(f)
            project = data.get("project", {})
            if isinstance(project, dict):
                return str(project.get("version", "") or ""), str(project.get("description", "") or "")
        except (OSError, tomllib.TOMLDecodeError):
            pass

    package_json_path = Path(target_path) / "package.json"
    if package_json_path.exists():
        try:
            data = json.loads(package_json_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return str(data.get("version", "") or ""), str(data.get("description", "") or "")
        except (OSError, json.JSONDecodeError):
            pass

    return "", ""


def _artifact_links(
    *,
    discovered_path: str | None,
    stage4_finding_path: str | None,
    stage5_report_path: str | None,
    stage6_report_path: str | None,
    stage6_email_path: str | None,
    stage6_zip_path: str | None,
) -> list[str]:
    candidates = [
        ("Stage 4 Finding", stage4_finding_path),
        ("Stage 5 Report", stage5_report_path),
        ("Stage 6 Report", stage6_report_path),
        ("Stage 6 Email", stage6_email_path),
        ("Stage 6 Zip", stage6_zip_path),
    ]
    return [
        f"[{label}]({_markdown_path(path, discovered_path)})"
        for label, path in candidates
        if path
    ]


def _markdown_path(path: str, discovered_path: str | None) -> str:
    target = os.path.realpath(path)
    if discovered_path:
        try:
            base_dir = os.path.dirname(os.path.realpath(discovered_path))
            common_path = os.path.commonpath([base_dir, target])
            if common_path and common_path != Path(common_path).anchor:
                return os.path.relpath(target, base_dir).replace(os.sep, "/")
        except ValueError:
            pass
    return target.replace(os.sep, "/")


def _severity_cvss(finding: dict[str, Any]) -> str:
    severity = _single_line(finding.get("severity"))
    cvss = _single_line(finding.get("cvss_score") or finding.get("cvss"))
    if severity and cvss:
        return f"{severity} / CVSS {cvss}"
    if severity:
        return severity
    if cvss:
        return f"CVSS {cvss}"
    return "unknown"


def _display_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [_single_line(item) for item in value if _single_line(item)]
    text = _single_line(value)
    return [text] if text else []


def _normalize_list(value: Any) -> list[str]:
    return sorted({_normalize_text(item) for item in _display_list(value) if _normalize_text(item)})


def _normalize_text(value: Any) -> str:
    return " ".join(_single_line(value).lower().split())


def _normalize_path_text(value: Any) -> str:
    return " ".join(_single_line(value).replace("\\", "/").split())


def _single_line(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def _paragraph(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "\n".join(f"- {_single_line(item)}" for item in value if _single_line(item))
    return str(value).strip()


def _visible_value(value: Any) -> str:
    return _single_line(value) or "unknown"
