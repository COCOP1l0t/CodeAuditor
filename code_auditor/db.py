"""SQLite persistence for audit runs and their artifacts.

Every Web audit is recorded in a local SQLite database
(default ``~/.code_auditor/audits.db``). Run metadata
comes from the :class:`~code_auditor.config.AuditConfig`; artifacts are parsed
from the output directory layout produced by stages 3-6.

Only stdlib ``sqlite3`` is used. A fresh connection is opened per operation,
which keeps the store safe to share between the web server's thread pool and
the asyncio event loop.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .config import AuditConfig
from .disclosures import build_dedupe_key, extract_email_subject
from .logger import get_logger
from .poc_artifacts import (
    ASAN_REPORT_FILENAME,
    TRIGGER_GRAPH_FILENAME,
    load_asan_report,
    load_trigger_graph,
)
from .repos import DEFAULT_REPOS_DIR, capture_repo_identity, list_cloned_repos
from .retention import RetentionError, load_retain_manifest
from .reproduction_status import (
    FAILED_STATUSES,
    REPRODUCED_STATUSES,
    read_reproduction_status,
)
from .utils import natural_sort_key

DEFAULT_DB_PATH = os.path.join("~", ".code_auditor", "audits.db")

RUN_RUNNING = "running"
RUN_DONE = "done"
RUN_FAILED = "failed"
RUN_CANCELLED = "cancelled"
RUN_IMPORTED = "imported"
RUN_SUPERSEDED = "superseded"
RUN_KIND_AUDIT = "audit"
RUN_KIND_MAINTENANCE = "maintenance"
RUN_KINDS = frozenset({RUN_KIND_AUDIT, RUN_KIND_MAINTENANCE})
RUN_STATUSES = frozenset(
    {
        RUN_RUNNING,
        RUN_DONE,
        RUN_FAILED,
        RUN_CANCELLED,
        RUN_IMPORTED,
        RUN_SUPERSEDED,
    }
)
_POC_BACKFILL_OUTPUT_SUFFIX = "-poc-backfill"
_POC_BACKFILL_OUTPUT_LIKE = f"%{_POC_BACKFILL_OUTPUT_SUFFIX}"
DISCLOSURE_REVIEW_STATUSES = {
    "unreviewed",
    "reported",
    "confirmed",
    "rejected",
    "duplicated",
    "triage",
    "bug",
    "slop",
}
DISCLOSURE_TRASH_RETENTION_DAYS = 30
DISCLOSURE_TRASH_RETENTION_SECONDS = DISCLOSURE_TRASH_RETENTION_DAYS * 86400
logger = get_logger("db")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    output_dir TEXT NOT NULL,
    wiki_path TEXT,
    backend TEXT,
    model TEXT,
    max_parallel INTEGER,
    target_au_count INTEGER,
    log_level TEXT,
    status TEXT NOT NULL,
    run_kind TEXT NOT NULL DEFAULT 'audit',
    error TEXT DEFAULT '',
    started_at REAL,
    ended_at REAL,
    duration_seconds REAL NOT NULL DEFAULT 0,
    active_started_at REAL,
    duration_known INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    findings_count INTEGER DEFAULT 0,
    vulns_count INTEGER DEFAULT 0,
    pocs_reproduced_count INTEGER DEFAULT 0,
    disclosures_count INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    au_id TEXT,
    title TEXT,
    location TEXT,
    vulnerability_class TEXT,
    root_cause TEXT,
    preliminary_severity TEXT,
    raw_json TEXT NOT NULL,
    UNIQUE(run_id, finding_key)
);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL,
    severity TEXT,
    cvss_score REAL,
    title TEXT,
    location TEXT,
    trigger TEXT,
    cwe_ids TEXT,
    vulnerability_class TEXT,
    entry_point TEXT,
    sink TEXT,
    propagation_chain TEXT,
    neutralizing_checks TEXT,
    prerequisites TEXT,
    impact TEXT,
    code_snippet TEXT,
    dedupe_key TEXT,
    raw_json TEXT NOT NULL,
    UNIQUE(run_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_run ON vulnerabilities(run_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_dedupe ON vulnerabilities(dedupe_key);
CREATE TABLE IF NOT EXISTS pocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL,
    status TEXT NOT NULL,
    report_path TEXT,
    trigger_graph_path TEXT,
    asan_report_path TEXT,
    UNIQUE(run_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_pocs_run ON pocs(run_id);
CREATE TABLE IF NOT EXISTS disclosures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL,
    report_path TEXT,
    email_path TEXT,
    zip_path TEXT,
    trigger_graph_path TEXT,
    asan_report_path TEXT,
    UNIQUE(run_id, vuln_id)
);
CREATE INDEX IF NOT EXISTS idx_disclosures_run ON disclosures(run_id);
CREATE TABLE IF NOT EXISTS disclosed_bugs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    title TEXT,
    location TEXT,
    cwe TEXT,
    vulnerability_class TEXT,
    trigger TEXT,
    summary TEXT,
    repo_url TEXT,
    audited_commit TEXT,
    audit_finished_date TEXT,
    model_backend TEXT,
    review_status TEXT,
    artifact_links TEXT NOT NULL DEFAULT '[]',
    deleted_at REAL,
    updated_at REAL,
    UNIQUE(project, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_disclosed_status ON disclosed_bugs(review_status);
CREATE INDEX IF NOT EXISTS idx_disclosed_project ON disclosed_bugs(project);
CREATE TABLE IF NOT EXISTS reproduction_runs (
    job_key TEXT PRIMARY KEY,
    disclosure_id INTEGER REFERENCES disclosed_bugs(id) ON DELETE SET NULL,
    project TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    source_run_id INTEGER,
    source_vuln_id TEXT,
    repo_url TEXT,
    base_commit TEXT,
    target_ref TEXT,
    tested_commit TEXT,
    state TEXT NOT NULL,
    outcome TEXT,
    disposition TEXT,
    evidence_level TEXT,
    summary TEXT,
    source_analysis TEXT,
    disclosure_update TEXT,
    backend TEXT,
    model TEXT,
    sandbox_mode TEXT,
    sandbox_runtime TEXT,
    output_dir TEXT NOT NULL,
    result_path TEXT,
    assessment_path TEXT,
    retest_report_path TEXT,
    draft_path TEXT,
    error TEXT DEFAULT '',
    started_at REAL NOT NULL,
    ended_at REAL,
    applied_at REAL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reproduction_disclosure
    ON reproduction_runs(project, dedupe_key, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_reproduction_state
    ON reproduction_runs(state, started_at DESC);
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    project TEXT NOT NULL,
    year INTEGER NOT NULL,
    cvss_score REAL,
    severity TEXT,
    project_url TEXT,
    cve_url TEXT NOT NULL,
    reference_links TEXT NOT NULL DEFAULT '[]',
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cves_project ON cves(project);
CREATE TABLE IF NOT EXISTS cve_links (
    cve_id TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    dedupe_key TEXT NOT NULL,
    PRIMARY KEY(cve_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_cve_links_dedupe ON cve_links(dedupe_key);
CREATE TABLE IF NOT EXISTS analysis_units (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    au_id TEXT NOT NULL,
    description TEXT,
    files TEXT,
    focus TEXT,
    raw_json TEXT NOT NULL,
    target_key TEXT DEFAULT '',
    UNIQUE(run_id, au_id)
);
CREATE INDEX IF NOT EXISTS idx_analysis_units_run ON analysis_units(run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_units_target_key ON analysis_units(target_key);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at REAL NOT NULL,
    last_login_at REAL
);
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_digest TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    revoked_at REAL
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_digest);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
"""

_OUTPUT_DIR_DATE_RE = re.compile(r"audit-output-(\d{4})(\d{2})(\d{2})")


def _find_output_dirs(root: str) -> list[str]:
    """Locate ``audit-output-*`` directories below ``root`` (any depth)."""
    found: list[str] = []
    for dirpath, dirnames, _filenames in os.walk(root):
        for name in dirnames:
            if name.startswith("audit-output"):
                found.append(os.path.join(dirpath, name))
        # Never descend into output directories or git internals.
        dirnames[:] = [
            d for d in dirnames if not d.startswith("audit-output") and d != ".git"
        ]
    return sorted(found)


def _map_repo_target(output_dir: str, cloned: list[dict[str, str]]) -> str:
    """Map an output directory to a cloned repo path when names match."""
    project = os.path.basename(os.path.dirname(output_dir))
    for repo in cloned:
        if repo["name"] == project or os.path.basename(repo["path"]) == project:
            return repo["path"]
    return os.path.dirname(output_dir)


def _parse_output_dir_date(name: str) -> float | None:
    match = _OUTPUT_DIR_DATE_RE.search(name)
    if not match:
        return None
    try:
        return datetime(
            int(match.group(1)), int(match.group(2)), int(match.group(3))
        ).timestamp()
    except ValueError:
        return None


# Extra run columns added after the initial schema; migrated via
# ALTER TABLE in AuditStore._init_schema for existing databases.
_RUN_EXTRA_COLUMNS = {
    "repo_name": "\"repo_name\" TEXT DEFAULT ''",
    "repo_url": "\"repo_url\" TEXT DEFAULT ''",
    "branch": "\"branch\" TEXT DEFAULT ''",
    "commit": "\"commit\" TEXT DEFAULT ''",
    "dirty": '"dirty" INTEGER DEFAULT 0',
    "submodules": "\"submodules\" TEXT DEFAULT '[]'",
    "target_key": "\"target_key\" TEXT DEFAULT ''",
    "backends_used": "\"backends_used\" TEXT DEFAULT '[]'",
    "models_used": "\"models_used\" TEXT DEFAULT '[]'",
    "usage_stats": "\"usage_stats\" TEXT DEFAULT '{}'",
    "duration_seconds": '"duration_seconds" REAL NOT NULL DEFAULT 0',
    "active_started_at": '"active_started_at" REAL',
    "duration_known": '"duration_known" INTEGER NOT NULL DEFAULT 1',
    "run_kind": "\"run_kind\" TEXT NOT NULL DEFAULT 'audit'",
    # A terminal maintenance run may carry a non-fatal cleanup note. Keep it
    # separate from ``error`` so the History badge does not report a completed
    # batch as ``done ⚠`` while retaining the diagnostic for the detail view.
    "warning": "\"warning\" TEXT DEFAULT ''",
}

_DISCLOSED_BUGS_V2_SCHEMA = """
CREATE TABLE disclosed_bugs_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    title TEXT,
    location TEXT,
    cwe TEXT,
    vulnerability_class TEXT,
    trigger TEXT,
    summary TEXT,
    repo_url TEXT,
    audited_commit TEXT,
    audit_finished_date TEXT,
    model_backend TEXT,
    review_status TEXT,
    artifact_links TEXT NOT NULL DEFAULT '[]',
    deleted_at REAL,
    updated_at REAL,
    UNIQUE(project, dedupe_key)
)
"""


def compute_target_key(identity: dict) -> str:
    """Stable key for (repo name, commit, submodule commits)."""
    commit = identity.get("commit") or ""
    if not commit:
        return ""
    payload = {
        "repo": identity.get("repo_name") or "",
        "commit": commit,
        "submodules": sorted(
            (s.get("path", ""), s.get("commit", ""))
            for s in identity.get("submodules") or []
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _as_list(value: Any) -> list[str]:
    """Normalize a str-or-list field to a list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _as_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _lower(value: Any) -> str:
    return str(value).strip().lower() if value else ""


def _project_name_from_repo_url(repo_url: str, fallback: str) -> str:
    normalized = repo_url.strip().removesuffix(".git").rstrip("/")
    if normalized:
        name = normalized.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        if re.fullmatch(r"[A-Za-z0-9._-]+", name):
            return name
    return fallback


def _run_project(run: dict) -> str:
    """Return the Disclosure project identity used when a Run was synced."""
    fallback = str(run.get("repo_name") or "") or os.path.basename(
        os.path.realpath(str(run.get("target") or run.get("output_dir") or ""))
    )
    return _project_name_from_repo_url(str(run.get("repo_url") or ""), fallback)


def _has_local_disclosure_report(artifacts: list[dict[str, Any]]) -> bool:
    return any(
        isinstance(artifact, dict)
        and artifact.get("label") == "Stage 6 Report"
        and os.path.isfile(str(artifact.get("path") or ""))
        for artifact in artifacts
    )


def _stage5_terminal_paths(
    artifacts: list[dict[str, Any]],
) -> tuple[str, str, str, str] | None:
    """Resolve a registered Stage 5 report to its output and PoC directories."""
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("label") != "Stage 5 Report":
            continue
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            continue
        report_file = os.path.realpath(os.path.expanduser(path))
        poc_dir = os.path.dirname(report_file)
        stage5_dir = os.path.dirname(poc_dir)
        vuln_id = os.path.basename(poc_dir)
        if (
            os.path.basename(stage5_dir) != "stage5-pocs"
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vuln_id) is None
            or not os.path.isfile(report_file)
        ):
            continue
        return os.path.dirname(stage5_dir), poc_dir, report_file, vuln_id
    return None


def _registered_stage5_report(output_dir: str, report_value: object) -> str | None:
    """Resolve a reproduced PoC report only when it is still on disk."""
    if not output_dir:
        return None
    if not isinstance(report_value, str) or not report_value or "\x00" in report_value:
        return None
    root = os.path.realpath(os.path.expanduser(output_dir))
    if not root:
        return None
    resolved = os.path.realpath(
        report_value
        if os.path.isabs(report_value)
        else os.path.join(root, report_value)
    )
    if not resolved.startswith(root + os.sep) or not os.path.isfile(resolved):
        return None
    report = Path(resolved)
    if (
        report.name != "report.md"
        or report.parent.parent.name != "stage5-pocs"
        or report.parent.name.endswith("_fp")
        or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", report.parent.name) is None
    ):
        return None
    return resolved


def _stage6_terminal_paths(
    artifacts: list[dict[str, Any]],
) -> tuple[str, str, str, str] | None:
    """Resolve a retained Stage 6 reproducer to its disclosure directory."""
    for artifact in artifacts:
        if not isinstance(artifact, dict) or artifact.get("label") != "Stage 6 Report":
            continue
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            continue
        report_file = os.path.realpath(os.path.expanduser(path))
        disclosure_dir = os.path.dirname(report_file)
        vuln_dir = os.path.dirname(disclosure_dir)
        stage6_dir = os.path.dirname(vuln_dir)
        vuln_id = os.path.basename(vuln_dir)
        if (
            os.path.basename(disclosure_dir) != "disclosure"
            or os.path.basename(stage6_dir) != "stage6-disclosures"
            or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vuln_id) is None
            or not os.path.isfile(report_file)
        ):
            continue
        relative_report = Path(report_file).relative_to(disclosure_dir).as_posix()
        try:
            manifest = load_retain_manifest(
                disclosure_dir,
                required_paths=[relative_report],
            )
        except RetentionError:
            continue
        entrypoint = os.path.realpath(os.path.join(disclosure_dir, manifest.entrypoint))
        if not entrypoint.startswith(disclosure_dir + os.sep) or not os.path.isfile(
            entrypoint
        ):
            continue
        return os.path.dirname(stage6_dir), disclosure_dir, report_file, vuln_id
    return None


def _terminal_paths(
    artifacts: list[dict[str, Any]],
) -> tuple[str, str, str, str] | None:
    """Prefer a portable Stage 6 reproducer, with legacy Stage 5 fallback."""
    return _stage6_terminal_paths(artifacts) or _stage5_terminal_paths(artifacts)


def _retained_stage6_evidence(
    disclosure_dir: Path,
    vuln_id: str,
) -> tuple[str, str]:
    """Return only manifest-retained, validated Stage 6 runtime evidence."""
    try:
        manifest = load_retain_manifest(disclosure_dir)
    except RetentionError:
        return "", ""

    evidence_paths = {
        retained.path for retained in manifest.files if retained.role == "evidence"
    }

    trigger_graph_path = ""
    if TRIGGER_GRAPH_FILENAME in evidence_paths:
        graph = disclosure_dir / TRIGGER_GRAPH_FILENAME
        _, graph_errors = load_trigger_graph(str(graph), expected_finding_id=vuln_id)
        if graph_errors:
            logger.warning(
                "Ignoring invalid retained Stage 6 trigger graph %s: %s",
                graph,
                "; ".join(graph_errors),
            )
        else:
            trigger_graph_path = str(graph)

    asan_report_path = ""
    if ASAN_REPORT_FILENAME in evidence_paths:
        asan = disclosure_dir / ASAN_REPORT_FILENAME
        _, asan_errors = load_asan_report(str(asan))
        if asan_errors:
            logger.warning(
                "Ignoring invalid retained Stage 6 ASan report %s: %s",
                asan,
                "; ".join(asan_errors),
            )
        else:
            asan_report_path = str(asan)

    return trigger_graph_path, asan_report_path


def _parse_finding(path: Path, output_dir: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    finding_key = path.stem
    au_id = finding_key.split("-F-")[0] if "-F-" in finding_key else ""
    return {
        "finding_key": finding_key,
        "au_id": au_id,
        "title": data.get("title") or "",
        "location": data.get("location") or "",
        "vulnerability_class": _json_text(_as_list(data.get("vulnerability_class"))),
        "root_cause": data.get("root_cause") or "",
        "preliminary_severity": _lower(data.get("preliminary_severity")),
        "raw_json": _json_text(data),
    }


def _parse_vuln(
    path: Path, output_dir: Path, repo_url: str = ""
) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    trace = data.get("data_flow_trace")
    trace = trace if isinstance(trace, dict) else {}
    try:
        dedupe_key = build_dedupe_key(data, repo_url=repo_url)
    except Exception:
        dedupe_key = ""
    return {
        "vuln_id": str(data.get("id") or path.stem),
        "severity": _lower(data.get("severity")),
        "cvss_score": _as_float(data.get("cvss_score")),
        "title": data.get("title") or "",
        "location": data.get("location") or "",
        "trigger": data.get("trigger") or "",
        "cwe_ids": _json_text(_as_list(data.get("cwe_id") or data.get("cwe"))),
        "vulnerability_class": _json_text(_as_list(data.get("vulnerability_class"))),
        "entry_point": trace.get("entry_point") or "",
        "sink": trace.get("sink") or "",
        "propagation_chain": _json_text(_as_list(trace.get("propagation_chain"))),
        "neutralizing_checks": trace.get("neutralizing_checks") or "",
        "prerequisites": data.get("prerequisites") or "",
        "impact": data.get("impact") or "",
        "code_snippet": data.get("code_snippet") or "",
        "dedupe_key": dedupe_key,
        "raw_json": _json_text(data),
    }


def scan_output_dir(
    output_dir: str, repo_url: str = ""
) -> dict[str, list[dict[str, Any]]]:
    """Parse stage 2-6 artifacts under an output directory."""
    base = Path(output_dir)
    result: dict[str, list[dict[str, Any]]] = {
        "analysis_units": [],
        "findings": [],
        "vulnerabilities": [],
        "pocs": [],
        "disclosures": [],
    }
    if not base.is_dir():
        return result

    aus_dir = base / "stage2-analysis-units"
    if aus_dir.is_dir():
        for path in sorted(aus_dir.glob("AU-*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            result["analysis_units"].append(
                {
                    "au_id": path.stem,
                    "description": data.get("description") or "",
                    "files": _json_text(_as_list(data.get("files"))),
                    "focus": data.get("focus") or "",
                    "raw_json": _json_text(data),
                }
            )

    for path in (
        sorted((base / "stage3-findings").glob("*.json"))
        if (base / "stage3-findings").is_dir()
        else []
    ):
        finding = _parse_finding(path, base)
        if finding:
            result["findings"].append(finding)

    vuln_dir = base / "stage4-vulnerabilities"
    if vuln_dir.is_dir():
        for path in sorted(vuln_dir.glob("*.json")):
            vuln = _parse_vuln(path, base, repo_url)
            if vuln:
                result["vulnerabilities"].append(vuln)

    pocs_dir = base / "stage5-pocs"
    if pocs_dir.is_dir():
        scanned_vuln_ids: set[str] = set()
        for report in sorted(pocs_dir.glob("*/report.md")):
            vuln_id = report.parent.name
            if vuln_id.endswith("_fp"):
                vuln_id = vuln_id[: -len("_fp")]
            scanned_vuln_ids.add(vuln_id)
            status = read_reproduction_status(str(report)) or "unknown"
            # The directory suffix is the stage contract for a failed or
            # otherwise non-actionable reproduction.  Normalize stale agent
            # prose (for example, ``partially-reproduced``) so maintenance
            # backfills do not retry the same failed candidate indefinitely.
            if report.parent.name.endswith("_fp"):
                status = "false-positive"
            trigger_graph = report.parent / TRIGGER_GRAPH_FILENAME
            trigger_graph_path = ""
            if trigger_graph.is_file():
                _, graph_errors = load_trigger_graph(
                    str(trigger_graph), expected_finding_id=vuln_id
                )
                if graph_errors:
                    logger.warning(
                        "Ignoring invalid Stage 5 trigger graph %s: %s",
                        trigger_graph,
                        "; ".join(graph_errors),
                    )
                else:
                    trigger_graph_path = str(trigger_graph.relative_to(base))
            asan_report = report.parent / ASAN_REPORT_FILENAME
            asan_report_path = ""
            if asan_report.is_file():
                _, asan_errors = load_asan_report(str(asan_report))
                if asan_errors:
                    logger.warning(
                        "Ignoring invalid Stage 5 ASan report %s: %s",
                        asan_report,
                        "; ".join(asan_errors),
                    )
                else:
                    asan_report_path = str(asan_report.relative_to(base))
            result["pocs"].append(
                {
                    "vuln_id": vuln_id,
                    "status": status,
                    "report_path": str(report.relative_to(base)),
                    "trigger_graph_path": trigger_graph_path,
                    "asan_report_path": asan_report_path,
                }
            )
        # PoC tasks whose agent died before writing a report (e.g. API quota
        # exhaustion) leave a directory without report.md. Record them as
        # errors so History shows the gap instead of hiding it.
        for entry in sorted(pocs_dir.iterdir()):
            if not entry.is_dir() or (entry / "report.md").is_file():
                continue
            vuln_id = entry.name
            if vuln_id.endswith("_fp"):
                vuln_id = vuln_id[: -len("_fp")]
            if (
                vuln_id in scanned_vuln_ids
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vuln_id) is None
            ):
                continue
            result["pocs"].append(
                {
                    "vuln_id": vuln_id,
                    "status": "error",
                    "report_path": "",
                    "trigger_graph_path": "",
                    "asan_report_path": "",
                }
            )

    disclosures_dir = base / "stage6-disclosures"
    if disclosures_dir.is_dir():
        for entry in sorted(disclosures_dir.iterdir()):
            disclosure = entry / "disclosure"
            if not entry.is_dir() or not disclosure.is_dir():
                continue

            def _rel(name: str) -> str:
                p = disclosure / name
                return str(p.relative_to(base)) if p.is_file() else ""

            trigger_graph_path, asan_report_path = _retained_stage6_evidence(
                disclosure, entry.name
            )

            def _evidence_rel(path: str) -> str:
                return str(Path(path).relative_to(base)) if path else ""

            result["disclosures"].append(
                {
                    "vuln_id": entry.name,
                    "report_path": _rel("report.md"),
                    "email_path": _rel("email.txt"),
                    "zip_path": _rel("disclosure.zip"),
                    "trigger_graph_path": _evidence_rel(trigger_graph_path),
                    "asan_report_path": _evidence_rel(asan_report_path),
                }
            )

    return result


class AuditStore:
    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        *,
        managed_results_dir: str | None = None,
    ) -> None:
        self.db_path = os.path.realpath(os.path.expanduser(db_path))
        self.managed_results_dir = (
            os.path.realpath(os.path.expanduser(managed_results_dir))
            if managed_results_dir
            else None
        )
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()
        self._backfill_identities()
        self._backfill_vulnerability_dedupe_keys()
        try:
            self.backfill_retained_stage6_evidence()
        except Exception as exc:
            # Evidence discovery is a compatibility backfill and must not
            # prevent the history database from opening.
            logger.warning("Stage 6 evidence backfill failed: %s", exc)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        # Concurrent web jobs write run/artifact rows from multiple tasks;
        # WAL + a busy timeout keep readers and writers from tripping over
        # each other's short transactions.
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    # ── Web authentication ────────────────────────────────────────────────

    def auth_user_count(self) -> int:
        """Return the number of accounts, used to gate first-run setup."""
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"] if row else 0)

    @staticmethod
    def _public_user(row: sqlite3.Row | dict) -> dict[str, object]:
        return {
            "id": int(row["id"]),
            "username": str(row["username"]),
            "role": str(row["role"]),
            "is_active": bool(row["is_active"]),
            "created_at": float(row["created_at"]),
            "last_login_at": (
                float(row["last_login_at"])
                if row["last_login_at"] is not None
                else None
            ),
        }

    def create_auth_user(
        self, username: str, password_hash: str, *, role: str = "user"
    ) -> dict[str, object]:
        now = time.time()
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users(username, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (username, password_hash, role, now),
            )
            row = conn.execute(
                "SELECT id, username, role, is_active, created_at, last_login_at "
                "FROM users WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:  # pragma: no cover - SQLite guarantees the row exists
            raise RuntimeError("created user could not be loaded")
        return self._public_user(row)

    def create_initial_auth_admin(
        self, username: str, password_hash: str
    ) -> dict[str, object]:
        """Atomically create the one allowed first-run administrator."""
        now = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None:
                raise ValueError("administrator setup has already been completed")
            cursor = conn.execute(
                """
                INSERT INTO users(username, password_hash, role, created_at)
                VALUES (?, ?, 'admin', ?)
                """,
                (username, password_hash, now),
            )
            row = conn.execute(
                "SELECT id, username, role, is_active, created_at, last_login_at "
                "FROM users WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        if row is None:  # pragma: no cover - SQLite guarantees the row exists
            raise RuntimeError("created administrator could not be loaded")
        return self._public_user(row)

    def get_auth_user_by_username(self, username: str) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id, username, password_hash, role, is_active,
                       created_at, last_login_at
                FROM users WHERE username = ? COLLATE NOCASE
                """,
                (username,),
            ).fetchone()
        return dict(row) if row is not None else None

    def mark_auth_login(self, user_id: int, now: float | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET last_login_at = ? WHERE id = ?",
                (time.time() if now is None else now, user_id),
            )

    def create_auth_session(
        self,
        user_id: int,
        token_digest: str,
        *,
        created_at: float,
        expires_at: float,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sessions(
                    user_id, token_digest, created_at, expires_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, token_digest, created_at, expires_at, created_at),
            )

    def get_auth_user_by_session(
        self, token_digest: str, *, now: float | None = None
    ) -> dict[str, object] | None:
        current = time.time() if now is None else now
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.id, u.username, u.role, u.is_active,
                       u.created_at, u.last_login_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_digest = ?
                  AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                  AND u.is_active = 1
                """,
                (token_digest, current),
            ).fetchone()
            if row is not None:
                conn.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE token_digest = ?",
                    (current, token_digest),
                )
        return self._public_user(row) if row is not None else None

    def revoke_auth_session(
        self, token_digest: str, *, now: float | None = None
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE sessions SET revoked_at = ? "
                "WHERE token_digest = ? AND revoked_at IS NULL",
                (time.time() if now is None else now, token_digest),
            )

    def purge_expired_auth_sessions(self, *, now: float | None = None) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM sessions WHERE expires_at <= ? OR revoked_at IS NOT NULL",
                (time.time() if now is None else now,),
            )
        return int(cursor.rowcount)

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            existing = {
                row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()
            }
            duration_missing = "duration_seconds" not in existing
            active_started_missing = "active_started_at" not in existing
            duration_known_missing = "duration_known" not in existing
            backends_used_missing = "backends_used" not in existing
            for column, ddl in _RUN_EXTRA_COLUMNS.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE runs ADD COLUMN {ddl}")
            # The PoC recovery command predates explicit run kinds. Reapply
            # this stable classification on every open so an older backfill
            # process sharing a newly migrated database cannot create an
            # audit-looking maintenance row.
            conn.execute(
                "UPDATE runs SET run_kind = ? "
                "WHERE output_dir LIKE ? AND run_kind != ?",
                (
                    RUN_KIND_MAINTENANCE,
                    _POC_BACKFILL_OUTPUT_LIKE,
                    RUN_KIND_MAINTENANCE,
                ),
            )
            # Preserve the original backend for pre-history rows. New runs
            # append only when an agent invocation actually starts, matching
            # models_used semantics.
            if backends_used_missing and "backend" in existing:
                legacy_backends = conn.execute(
                    "SELECT id, backend FROM runs"
                ).fetchall()
                conn.executemany(
                    "UPDATE runs SET backends_used = ? WHERE id = ?",
                    [
                        (
                            json.dumps([str(row["backend"])], ensure_ascii=False)
                            if row["backend"]
                            else "[]",
                            row["id"],
                        )
                        for row in legacy_backends
                    ],
                )
            # Existing terminal runs only have wall-clock timestamps. Retain
            # that raw migration baseline for diagnostics, but mark every
            # pre-accounting row unknown so the API/UI never presents it as an
            # accurate active duration. A legacy running row likewise has no
            # recoverable session start because started_at may predate pauses.
            if duration_missing and {"started_at", "ended_at"} <= existing:
                conn.execute(
                    """
                    UPDATE runs
                    SET duration_seconds = CASE
                        WHEN status = ? THEN 0
                        WHEN started_at IS NOT NULL AND ended_at IS NOT NULL
                        THEN MAX(0, ended_at - started_at)
                        ELSE 0
                    END
                    """,
                    (RUN_IMPORTED,),
                )
            if active_started_missing:
                conn.execute("UPDATE runs SET active_started_at = NULL")
            if duration_known_missing:
                conn.execute("UPDATE runs SET duration_known = 0")
            poc_existing = {
                row[1] for row in conn.execute("PRAGMA table_info(pocs)").fetchall()
            }
            if "trigger_graph_path" not in poc_existing:
                conn.execute("ALTER TABLE pocs ADD COLUMN trigger_graph_path TEXT")
            if "asan_report_path" not in poc_existing:
                conn.execute("ALTER TABLE pocs ADD COLUMN asan_report_path TEXT")
            disclosure_existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(disclosures)").fetchall()
            }
            if "trigger_graph_path" not in disclosure_existing:
                conn.execute(
                    "ALTER TABLE disclosures ADD COLUMN trigger_graph_path TEXT"
                )
            if "asan_report_path" not in disclosure_existing:
                conn.execute("ALTER TABLE disclosures ADD COLUMN asan_report_path TEXT")
            if "discovered_path" in existing:
                conn.execute("ALTER TABLE runs DROP COLUMN discovered_path")
            disclosed_existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(disclosed_bugs)").fetchall()
            }
            if "source_html" in disclosed_existing:
                if "artifact_links" not in disclosed_existing:
                    conn.execute(
                        "ALTER TABLE disclosed_bugs ADD COLUMN "
                        "artifact_links TEXT NOT NULL DEFAULT '[]'"
                    )
                self._migrate_disclosed_bugs(conn)
            disclosed_existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(disclosed_bugs)").fetchall()
            }
            if "deleted_at" not in disclosed_existing:
                conn.execute("ALTER TABLE disclosed_bugs ADD COLUMN deleted_at REAL")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_disclosed_deleted "
                "ON disclosed_bugs(deleted_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_target_key ON runs(target_key)"
            )
            self._clear_nonconfirmed_cve_links(conn)
            self._purge_expired_disclosures(conn, time.time())

    @staticmethod
    def _clear_nonconfirmed_cve_links(conn: sqlite3.Connection) -> None:
        """Enforce that only confirmed Disclosures can own CVE links."""
        conn.execute(
            """
            DELETE FROM cve_links
            WHERE NOT EXISTS (
                SELECT 1 FROM disclosed_bugs
                WHERE disclosed_bugs.dedupe_key = cve_links.dedupe_key
                  AND disclosed_bugs.review_status = 'confirmed'
            )
            """
        )
        conn.execute(
            """
            DELETE FROM cves
            WHERE NOT EXISTS (
                SELECT 1 FROM cve_links WHERE cve_links.cve_id = cves.cve_id
            )
            """
        )

    @staticmethod
    def _path_is_within(path: str, root: str) -> bool:
        return path == root or path.startswith(root + os.sep)

    def _stage6_disclosure_dirs(
        self,
        artifacts_json: str,
        registered_stage6_dirs: set[str],
    ) -> set[str]:
        """Resolve only registered Stage 6 ``<vuln>/disclosure`` directories.

        Artifact paths are database input, so structural checks alone are not
        enough for a recursive delete.  A candidate must also live below the
        configured Web results root or exactly below a run output directory
        already registered in this database.
        """
        try:
            artifacts = json.loads(artifacts_json or "[]")
        except (json.JSONDecodeError, TypeError):
            return set()
        if not isinstance(artifacts, list):
            return set()

        result: set[str] = set()
        for artifact in artifacts:
            if not isinstance(artifact, dict) or not str(
                artifact.get("label") or ""
            ).startswith("Stage 6 "):
                continue
            path = artifact.get("path")
            if not isinstance(path, str) or not path or "\x00" in path:
                continue
            artifact_path = os.path.realpath(os.path.expanduser(path))
            disclosure_dir = os.path.dirname(artifact_path)
            vuln_dir = os.path.dirname(disclosure_dir)
            stage6_dir = os.path.dirname(vuln_dir)
            vuln_id = os.path.basename(vuln_dir)
            if (
                os.path.basename(disclosure_dir) != "disclosure"
                or os.path.basename(stage6_dir) != "stage6-disclosures"
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vuln_id) is None
                or not self._path_is_within(artifact_path, disclosure_dir)
            ):
                continue

            below_managed_results = bool(
                self.managed_results_dir
                and self._path_is_within(stage6_dir, self.managed_results_dir)
            )
            if below_managed_results or stage6_dir in registered_stage6_dirs:
                result.add(disclosure_dir)
        return result

    def _stage5_poc_dirs(
        self,
        artifacts_json: str,
        registered_stage5_dirs: set[str],
    ) -> set[str]:
        """Resolve only registered Stage 5 ``<vuln>`` PoC directories."""
        try:
            artifacts = json.loads(artifacts_json or "[]")
        except (json.JSONDecodeError, TypeError):
            return set()
        if not isinstance(artifacts, list):
            return set()

        result: set[str] = set()
        for artifact in artifacts:
            if (
                not isinstance(artifact, dict)
                or artifact.get("label") != "Stage 5 Report"
            ):
                continue
            path = artifact.get("path")
            if not isinstance(path, str) or not path or "\x00" in path:
                continue
            artifact_path = os.path.realpath(os.path.expanduser(path))
            poc_dir = os.path.dirname(artifact_path)
            stage5_dir = os.path.dirname(poc_dir)
            vuln_id = os.path.basename(poc_dir)
            if (
                os.path.basename(stage5_dir) != "stage5-pocs"
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}", vuln_id) is None
                or not self._path_is_within(artifact_path, poc_dir)
            ):
                continue

            below_managed_results = bool(
                self.managed_results_dir
                and self._path_is_within(stage5_dir, self.managed_results_dir)
            )
            if below_managed_results or stage5_dir in registered_stage5_dirs:
                result.add(poc_dir)
        return result

    def _purge_expired_disclosures(
        self,
        conn: sqlite3.Connection,
        now: float,
        identities: set[tuple[str, str]] | None = None,
    ) -> int:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        cutoff = now - DISCLOSURE_TRASH_RETENTION_SECONDS
        expired = conn.execute(
            """
            SELECT project, dedupe_key, artifact_links FROM disclosed_bugs
            WHERE deleted_at IS NOT NULL AND deleted_at <= ?
            """,
            (cutoff,),
        ).fetchall()
        if identities is not None:
            expired = [
                row
                for row in expired
                if (str(row["project"]), str(row["dedupe_key"])) in identities
            ]
        if not expired:
            return 0

        registered_stage6_runs: dict[str, list[int]] = {}
        registered_stage5_runs: dict[str, list[int]] = {}
        for row in conn.execute(
            """
            SELECT id, output_dir FROM runs
            WHERE output_dir IS NOT NULL AND output_dir != ''
            """
        ).fetchall():
            stage6_dir = os.path.join(
                os.path.realpath(os.path.expanduser(str(row["output_dir"]))),
                "stage6-disclosures",
            )
            stage5_dir = os.path.join(
                os.path.realpath(os.path.expanduser(str(row["output_dir"]))),
                "stage5-pocs",
            )
            registered_stage6_runs.setdefault(stage6_dir, []).append(int(row["id"]))
            registered_stage5_runs.setdefault(stage5_dir, []).append(int(row["id"]))
        registered_stage6_dirs = set(registered_stage6_runs)
        registered_stage5_dirs = set(registered_stage5_runs)
        protected_disclosure_dirs: set[str] = set()
        protected_poc_dirs: set[str] = set()
        purge_identities = {
            (str(row["project"]), str(row["dedupe_key"])) for row in expired
        }
        for row in conn.execute(
            """
            SELECT project, dedupe_key, artifact_links FROM disclosed_bugs
            """,
        ).fetchall():
            if (str(row["project"]), str(row["dedupe_key"])) in purge_identities:
                continue
            protected_disclosure_dirs.update(
                self._stage6_disclosure_dirs(
                    row["artifact_links"] or "[]", registered_stage6_dirs
                )
            )
            protected_poc_dirs.update(
                self._stage5_poc_dirs(
                    row["artifact_links"] or "[]", registered_stage5_dirs
                )
            )

        deleted_disclosure_dirs: set[str] = set()
        deleted_poc_dirs: set[str] = set()
        for row in expired:
            deleted_disclosure_dirs.update(
                self._stage6_disclosure_dirs(
                    row["artifact_links"] or "[]", registered_stage6_dirs
                )
                - protected_disclosure_dirs
            )
            deleted_poc_dirs.update(
                self._stage5_poc_dirs(
                    row["artifact_links"] or "[]", registered_stage5_dirs
                )
                - protected_poc_dirs
            )

        # Stage every managed artifact directory with same-filesystem renames
        # before changing SQLite. A failure restores the entire batch, avoiding
        # a record whose Stage 5 directory vanished while Stage 6 remained.
        quarantined: list[tuple[str, str]] = []
        try:
            for artifact_dir in sorted(deleted_disclosure_dirs | deleted_poc_dirs):
                if not os.path.lexists(artifact_dir):
                    continue
                quarantine = os.path.join(
                    os.path.dirname(artifact_dir),
                    f".{os.path.basename(artifact_dir)}.purge-{uuid4().hex}",
                )
                os.replace(artifact_dir, quarantine)
                quarantined.append((artifact_dir, quarantine))
        except OSError as exc:
            for artifact_dir, quarantine in reversed(quarantined):
                try:
                    if os.path.lexists(quarantine) and not os.path.lexists(
                        artifact_dir
                    ):
                        os.replace(quarantine, artifact_dir)
                except OSError:
                    logger.exception(
                        "Could not restore Disclosure artifact after cleanup staging "
                        "failed: %s",
                        artifact_dir,
                    )
            logger.warning(
                "Retaining %d expired Disclosure record(s) because artifact cleanup "
                "could not be staged: %s",
                len(expired),
                exc,
            )
            return 0

        removed = 0
        try:
            for row in expired:
                cursor = conn.execute(
                    """
                    DELETE FROM disclosed_bugs
                    WHERE project = ? AND dedupe_key = ?
                      AND deleted_at IS NOT NULL AND deleted_at <= ?
                    """,
                    (row["project"], row["dedupe_key"], cutoff),
                )
                removed += cursor.rowcount

            affected_run_ids: set[int] = set()
            for disclosure_dir in deleted_disclosure_dirs:
                vuln_dir = os.path.dirname(disclosure_dir)
                stage6_dir = os.path.dirname(vuln_dir)
                vuln_id = os.path.basename(vuln_dir)
                for run_id in registered_stage6_runs.get(stage6_dir, []):
                    cursor = conn.execute(
                        "DELETE FROM disclosures WHERE run_id = ? AND vuln_id = ?",
                        (run_id, vuln_id),
                    )
                    if cursor.rowcount:
                        affected_run_ids.add(run_id)
            for poc_dir in deleted_poc_dirs:
                stage5_dir = os.path.dirname(poc_dir)
                vuln_id = os.path.basename(poc_dir)
                for run_id in registered_stage5_runs.get(stage5_dir, []):
                    cursor = conn.execute(
                        "DELETE FROM pocs WHERE run_id = ? AND vuln_id = ?",
                        (run_id, vuln_id),
                    )
                    if cursor.rowcount:
                        affected_run_ids.add(run_id)
            reproduced_statuses = sorted(REPRODUCED_STATUSES)
            reproduced_placeholders = ",".join("?" * len(reproduced_statuses))
            for run_id in affected_run_ids:
                conn.execute(
                    f"""
                    UPDATE runs SET pocs_reproduced_count = (
                        SELECT COUNT(*) FROM pocs
                        WHERE pocs.run_id = runs.id
                          AND pocs.status IN ({reproduced_placeholders})
                    ), disclosures_count = (
                        SELECT COUNT(*) FROM disclosures WHERE disclosures.run_id = runs.id
                    ) WHERE id = ?
                    """,
                    (*reproduced_statuses, run_id),
                )
            self._clear_nonconfirmed_cve_links(conn)
            conn.commit()
        except BaseException:
            conn.rollback()
            for artifact_dir, quarantine in reversed(quarantined):
                try:
                    if os.path.lexists(quarantine) and not os.path.lexists(
                        artifact_dir
                    ):
                        os.replace(quarantine, artifact_dir)
                except OSError:
                    logger.exception(
                        "Could not restore Disclosure artifact after database cleanup "
                        "failed: %s",
                        artifact_dir,
                    )
            raise

        for _artifact_dir, quarantine in quarantined:
            try:
                shutil.rmtree(quarantine)
            except OSError:
                logger.exception(
                    "Disclosure metadata was removed but quarantined artifacts could "
                    "not be erased: %s",
                    quarantine,
                )
        return removed

    @staticmethod
    def _migrate_disclosed_bugs(conn: sqlite3.Connection) -> None:
        """Collapse legacy file-backed rows into one database-owned record."""
        rows = conn.execute("SELECT * FROM disclosed_bugs").fetchall()
        grouped: dict[tuple[str, str], list[sqlite3.Row]] = {}
        for row in rows:
            key = (str(row["project"] or ""), str(row["dedupe_key"] or ""))
            if key[0] and key[1]:
                grouped.setdefault(key, []).append(row)

        conn.execute("DROP TABLE IF EXISTS disclosed_bugs_v2")
        conn.execute(_DISCLOSED_BUGS_V2_SCHEMA)

        def artifact_score(row: sqlite3.Row) -> tuple[int, float, int]:
            try:
                artifacts = json.loads(row["artifact_links"] or "[]")
            except (json.JSONDecodeError, TypeError):
                artifacts = []
            existing_files = sum(
                1
                for artifact in artifacts
                if isinstance(artifact, dict)
                and os.path.isfile(str(artifact.get("path") or ""))
            )
            return (
                existing_files,
                float(row["updated_at"] or 0),
                int(row["id"] or 0),
            )

        for project, dedupe_key in sorted(grouped):
            candidates = grouped[(project, dedupe_key)]
            chosen = max(candidates, key=artifact_score)
            status_candidates = [
                row
                for row in candidates
                if row["review_status"] in DISCLOSURE_REVIEW_STATUSES
            ]
            status_row = max(status_candidates, key=artifact_score, default=None)
            review_status = (
                str(status_row["review_status"])
                if status_row is not None
                else "unreviewed"
            )
            conn.execute(
                """
                INSERT INTO disclosed_bugs_v2 (
                    project, dedupe_key, title, location, cwe,
                    vulnerability_class, trigger, summary, repo_url,
                    audited_commit, audit_finished_date, model_backend,
                    review_status, artifact_links, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    project,
                    dedupe_key,
                    chosen["title"] or "",
                    chosen["location"] or "",
                    chosen["cwe"] or "",
                    chosen["vulnerability_class"] or "",
                    chosen["trigger"] or "",
                    chosen["summary"] or "",
                    chosen["repo_url"] or "",
                    chosen["audited_commit"] or "",
                    chosen["audit_finished_date"] or "",
                    chosen["model_backend"] or "",
                    review_status,
                    chosen["artifact_links"] or "[]",
                    chosen["updated_at"] or time.time(),
                ),
            )

        conn.execute("DROP TABLE disclosed_bugs")
        conn.execute("ALTER TABLE disclosed_bugs_v2 RENAME TO disclosed_bugs")
        conn.execute(
            "CREATE INDEX idx_disclosed_status ON disclosed_bugs(review_status)"
        )
        conn.execute("CREATE INDEX idx_disclosed_project ON disclosed_bugs(project)")

    def _backfill_identities(self) -> None:
        """Best-effort identity capture for rows recorded before it existed."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, target FROM runs WHERE target_key = ''"
                ).fetchall()
            for row in rows:
                identity = capture_repo_identity(row["target"])
                if identity["commit"]:
                    self.set_run_identity(row["id"], identity)
        except Exception:
            # Identity backfill must never break store initialization.
            pass

    def _backfill_vulnerability_dedupe_keys(self) -> None:
        """Rebuild legacy vulnerability keys with the run's repository URL."""
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT v.id, v.raw_json, v.dedupe_key, r.repo_url
                    FROM vulnerabilities v
                    JOIN runs r ON r.id = v.run_id
                    """
                ).fetchall()
                updates = []
                for row in rows:
                    try:
                        raw = json.loads(row["raw_json"])
                        if not isinstance(raw, dict):
                            continue
                        dedupe_key = build_dedupe_key(
                            raw, repo_url=row["repo_url"] or ""
                        )
                    except (TypeError, json.JSONDecodeError):
                        continue
                    if dedupe_key != row["dedupe_key"]:
                        updates.append((dedupe_key, row["id"]))
                conn.executemany(
                    "UPDATE vulnerabilities SET dedupe_key = ? WHERE id = ?",
                    updates,
                )
        except Exception:
            # A compatibility migration must never prevent opening the history DB.
            pass

    def backfill_retained_stage6_evidence(self) -> dict[str, int]:
        """Register validated runtime evidence already retained by Stage 6.

        The backfill deliberately ignores report prose and ZIP contents.  Only
        exact root-level evidence files listed with the ``evidence`` role in a
        valid retention manifest can be registered.
        """
        with self._connect() as conn:
            registered_stage6_dirs = {
                os.path.join(
                    os.path.realpath(os.path.expanduser(str(row["output_dir"]))),
                    "stage6-disclosures",
                )
                for row in conn.execute(
                    "SELECT output_dir FROM runs "
                    "WHERE output_dir IS NOT NULL AND output_dir != ''"
                ).fetchall()
            }
            disclosure_rows = conn.execute(
                """
                SELECT d.id, d.vuln_id, d.report_path, r.output_dir
                FROM disclosures d JOIN runs r ON r.id = d.run_id
                WHERE d.report_path IS NOT NULL AND d.report_path != ''
                """
            ).fetchall()
            catalogue_rows = conn.execute(
                """
                SELECT id, artifact_links FROM disclosed_bugs
                WHERE deleted_at IS NULL
                """
            ).fetchall()

            cache: dict[str, tuple[str, str]] = {}

            def evidence_for(disclosure_dir: str) -> tuple[str, str]:
                resolved = os.path.realpath(disclosure_dir)
                if resolved not in cache:
                    cache[resolved] = _retained_stage6_evidence(
                        Path(resolved), os.path.basename(os.path.dirname(resolved))
                    )
                return cache[resolved]

            updated_disclosure_rows = 0
            for row in disclosure_rows:
                output_dir = os.path.realpath(
                    os.path.expanduser(str(row["output_dir"] or ""))
                )
                report_value = str(row["report_path"] or "")
                report_path = os.path.realpath(
                    report_value
                    if os.path.isabs(report_value)
                    else os.path.join(output_dir, report_value)
                )
                disclosure_dir = os.path.dirname(report_path)
                expected_dir = os.path.join(
                    output_dir,
                    "stage6-disclosures",
                    str(row["vuln_id"]),
                    "disclosure",
                )
                if disclosure_dir != expected_dir or not os.path.isfile(report_path):
                    continue
                graph_path, asan_path = evidence_for(disclosure_dir)

                def stored_path(path: str) -> str:
                    return os.path.relpath(path, output_dir) if path else ""

                cursor = conn.execute(
                    """
                    UPDATE disclosures
                    SET trigger_graph_path = ?, asan_report_path = ?
                    WHERE id = ? AND (
                        COALESCE(trigger_graph_path, '') != ? OR
                        COALESCE(asan_report_path, '') != ?
                    )
                    """,
                    (
                        stored_path(graph_path),
                        stored_path(asan_path),
                        row["id"],
                        stored_path(graph_path),
                        stored_path(asan_path),
                    ),
                )
                updated_disclosure_rows += cursor.rowcount

            registered_graphs = 0
            registered_asan_reports = 0
            updated_catalogue_rows = 0
            for row in catalogue_rows:
                try:
                    artifacts = json.loads(row["artifact_links"] or "[]")
                except (json.JSONDecodeError, TypeError):
                    continue
                if not isinstance(artifacts, list):
                    continue

                disclosure_dirs = self._stage6_disclosure_dirs(
                    row["artifact_links"] or "[]", registered_stage6_dirs
                )
                evidence: list[tuple[str, str]] = []
                for disclosure_dir in sorted(disclosure_dirs):
                    graph_path, asan_path = evidence_for(disclosure_dir)
                    if graph_path:
                        evidence.append(("Stage 5 Trigger Graph", graph_path))
                    if asan_path:
                        evidence.append(("Stage 5 ASan Report", asan_path))

                valid_stage6_paths = {path for _label, path in evidence}
                retained_artifacts: list[dict[str, Any]] = []
                for artifact in artifacts:
                    if not isinstance(artifact, dict):
                        retained_artifacts.append(artifact)
                        continue
                    label = artifact.get("label")
                    path = artifact.get("path")
                    if (
                        label in {"Stage 5 Trigger Graph", "Stage 5 ASan Report"}
                        and isinstance(path, str)
                        and any(
                            self._path_is_within(
                                os.path.realpath(os.path.expanduser(path)),
                                disclosure_dir,
                            )
                            for disclosure_dir in disclosure_dirs
                        )
                        and os.path.realpath(os.path.expanduser(path))
                        not in valid_stage6_paths
                    ):
                        continue
                    retained_artifacts.append(artifact)

                known_paths = {
                    os.path.realpath(os.path.expanduser(str(artifact.get("path"))))
                    for artifact in retained_artifacts
                    if isinstance(artifact, dict) and artifact.get("path")
                }
                for label, path in evidence:
                    if path in known_paths:
                        continue
                    retained_artifacts.append({"label": label, "path": path})
                    known_paths.add(path)
                    if label == "Stage 5 Trigger Graph":
                        registered_graphs += 1
                    else:
                        registered_asan_reports += 1

                if retained_artifacts != artifacts:
                    conn.execute(
                        "UPDATE disclosed_bugs SET artifact_links = ?, updated_at = ? "
                        "WHERE id = ?",
                        (
                            json.dumps(retained_artifacts, ensure_ascii=False),
                            time.time(),
                            row["id"],
                        ),
                    )
                    updated_catalogue_rows += 1

        return {
            "disclosure_rows": updated_disclosure_rows,
            "catalogue_rows": updated_catalogue_rows,
            "trigger_graphs": registered_graphs,
            "asan_reports": registered_asan_reports,
        }

    def set_run_identity(self, run_id: int, identity: dict) -> None:
        """Store the repo identity (repo name, commit, submodule commits)."""
        target_key = compute_target_key(identity)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs SET repo_name = ?, repo_url = ?, branch = ?,
                    "commit" = ?, dirty = ?, submodules = ?, target_key = ?
                WHERE id = ?
                """,
                (
                    identity.get("repo_name") or "",
                    identity.get("repo_url") or "",
                    identity.get("branch") or "",
                    identity.get("commit") or "",
                    1 if identity.get("dirty") else 0,
                    json.dumps(identity.get("submodules") or [], ensure_ascii=False),
                    target_key,
                    run_id,
                ),
            )
            conn.execute(
                "UPDATE analysis_units SET target_key = ? WHERE run_id = ?",
                (target_key, run_id),
            )

    # ── Writes ───────────────────────────────────────────────────────────

    def create_run(
        self,
        config: AuditConfig,
        status: str = RUN_RUNNING,
        started_at: float | None = None,
        *,
        run_kind: str = RUN_KIND_AUDIT,
    ) -> int:
        if run_kind not in RUN_KINDS:
            raise ValueError(f"Unsupported run kind: {run_kind}")
        active_started_at = started_at if status == RUN_RUNNING else None
        duration_known = 0 if status == RUN_IMPORTED else 1
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO runs (
                    target, output_dir, wiki_path,
                    backend, model, max_parallel, target_au_count, log_level,
                    status, run_kind, started_at, active_started_at,
                    duration_known, created_at, backends_used
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    config.target,
                    config.output_dir,
                    config.wiki_path,
                    config.backend,
                    config.model,
                    config.max_parallel,
                    config.target_au_count,
                    config.log_level,
                    status,
                    run_kind,
                    started_at,
                    active_started_at,
                    duration_known,
                    time.time(),
                    json.dumps(config.backends_used, ensure_ascii=False),
                ),
            )
            return int(cursor.lastrowid)

    def finish_run(
        self,
        run_id: int,
        status: str,
        error: str = "",
        ended_at: float | None = None,
        backends_used: list[str] | None = None,
        models_used: list[str] | None = None,
        usage_stats: dict[str, float] | None = None,
        warning: str | None = None,
    ) -> None:
        finished_at = time.time() if ended_at is None else ended_at
        with self._connect() as conn:
            row = conn.execute(
                "SELECT target, output_dir, target_key FROM runs WHERE id = ?",
                (run_id,),
            ).fetchone()
        if row and not row["target_key"]:
            # Captured at the end of the audit, i.e. after stage 0's git pull:
            # the identity pins the exact code that was audited.
            identity = capture_repo_identity(row["target"])
            if identity["commit"]:
                self.set_run_identity(run_id, identity)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET status = ?, error = ?, ended_at = ?,
                    duration_seconds = MAX(0, COALESCE(duration_seconds, 0)) +
                        CASE WHEN active_started_at IS NOT NULL
                             THEN MAX(0, ? - active_started_at)
                             ELSE 0 END,
                    active_started_at = NULL
                WHERE id = ?
                """,
                (status, error, finished_at, finished_at, run_id),
            )
            if backends_used is not None:
                conn.execute(
                    "UPDATE runs SET backends_used = ? WHERE id = ?",
                    (json.dumps(backends_used, ensure_ascii=False), run_id),
                )
            if models_used is not None:
                conn.execute(
                    "UPDATE runs SET models_used = ? WHERE id = ?",
                    (json.dumps(models_used, ensure_ascii=False), run_id),
                )
            if usage_stats is not None:
                conn.execute(
                    "UPDATE runs SET usage_stats = ? WHERE id = ?",
                    (json.dumps(usage_stats, ensure_ascii=False), run_id),
                )
            if warning is not None:
                conn.execute(
                    "UPDATE runs SET warning = ? WHERE id = ?",
                    (warning, run_id),
                )
        if row and row["output_dir"]:
            self.persist_artifacts(run_id, row["output_dir"])

    @staticmethod
    def _maintenance_report_path(output_dir: str, value: object) -> str | None:
        """Resolve a Stage 5 report for either a reproduced or FP outcome."""
        if not isinstance(value, str) or not value or "\x00" in value:
            return None
        root = os.path.realpath(os.path.expanduser(output_dir or ""))
        if not root:
            return None
        resolved = os.path.realpath(
            value if os.path.isabs(value) else os.path.join(root, value)
        )
        if not resolved.startswith(root + os.sep) or not os.path.isfile(resolved):
            return None
        report = Path(resolved)
        poc_dir = report.parent
        if (
            report.name != "report.md"
            or poc_dir.parent.name != "stage5-pocs"
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,63}(?:_fp)?", poc_dir.name)
        ):
            return None
        return resolved

    def repair_maintenance_statuses(self, *, apply: bool = False) -> dict[str, Any]:
        """Reconcile stale PoC-backfill lifecycle rows using later evidence.

        A maintenance row is only marked ``superseded`` when a later clean
        maintenance run at the same repository commit has a registered Stage 5
        outcome for every vulnerability in the old row. This preserves failed
        attempts as history while removing them from the actionable failure
        queue. A completed run whose sole error is the Docker "removal already
        in progress" race is normalized to ``done`` with a separate warning
        after its affected PoC report is confirmed on disk.

        The default is a read-only plan. ``apply=True`` performs one atomic
        update and returns the same plan with ``applied`` set to true.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, target, output_dir, status, error, warning, target_key,
                       "commit"
                FROM runs
                WHERE run_kind = ? OR output_dir LIKE ?
                ORDER BY id
                """,
                (RUN_KIND_MAINTENANCE, _POC_BACKFILL_OUTPUT_LIKE),
            ).fetchall()

            run_data: dict[int, dict[str, Any]] = {}
            for row in rows:
                run_id = int(row["id"])
                vuln_ids = {
                    str(item[0])
                    for item in conn.execute(
                        "SELECT vuln_id FROM vulnerabilities WHERE run_id = ?",
                        (run_id,),
                    ).fetchall()
                    if item[0]
                }
                poc_rows = conn.execute(
                    "SELECT vuln_id, report_path FROM pocs WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
                run_data[run_id] = {
                    "row": row,
                    "vuln_ids": vuln_ids,
                    "pocs": {
                        str(item["vuln_id"]): item["report_path"] for item in poc_rows
                    },
                }

            clean_later: dict[int, list[tuple[int, set[str]]]] = {}
            for run_id, data in run_data.items():
                row = data["row"]
                if row["status"] not in {
                    RUN_FAILED,
                    RUN_DONE,
                    RUN_SUPERSEDED,
                }:
                    continue
                identity = str(row["target_key"] or "") or (
                    str(row["target"] or ""),
                    str(row["commit"] or ""),
                )
                for later_id, later in run_data.items():
                    if later_id <= run_id:
                        continue
                    later_row = later["row"]
                    later_identity = str(later_row["target_key"] or "") or (
                        str(later_row["target"] or ""),
                        str(later_row["commit"] or ""),
                    )
                    if later_identity != identity:
                        continue
                    if (
                        later_row["status"] != RUN_DONE
                        or str(later_row["error"] or "").strip()
                    ):
                        continue
                    clean_later.setdefault(run_id, []).append(
                        (later_id, set(later["pocs"]))
                    )

            changes: list[dict[str, Any]] = []
            for run_id, data in run_data.items():
                row = data["row"]
                status = str(row["status"] or "")
                error = str(row["error"] or "").strip()
                if not error or status not in {RUN_FAILED, RUN_DONE}:
                    continue
                vuln_ids = data["vuln_ids"]
                superseded_by = next(
                    (
                        later_id
                        for later_id, covered in clean_later.get(run_id, [])
                        if vuln_ids and vuln_ids <= covered
                    ),
                    None,
                )
                if superseded_by is not None:
                    changes.append(
                        {
                            "run_id": run_id,
                            "from_status": status,
                            "to_status": RUN_SUPERSEDED,
                            "superseded_by": superseded_by,
                            "warning": (
                                f"Superseded by Run #{superseded_by}. "
                                f"Original error: {error}"
                            ),
                        }
                    )
                    continue

                # Docker's asynchronous removal race is non-fatal when the
                # affected task already left a valid report. Do not hide any
                # other task error behind this normalization.
                lowered = error.casefold()
                cleanup_race = (
                    "cannot remove sandbox container" in lowered
                    and "already in progress" in lowered
                )
                if status == RUN_DONE and cleanup_race:
                    affected = error.split(":", 1)[0].strip().split("/")[-1]
                    if self._maintenance_report_path(
                        str(row["output_dir"] or ""), data["pocs"].get(affected)
                    ):
                        changes.append(
                            {
                                "run_id": run_id,
                                "from_status": status,
                                "to_status": RUN_DONE,
                                "warning": f"Non-fatal cleanup warning: {error}",
                            }
                        )

            if apply and changes:
                conn.execute("BEGIN IMMEDIATE")
                for change in changes:
                    conn.execute(
                        "UPDATE runs SET status = ?, error = '', warning = ? "
                        "WHERE id = ? AND status = ?",
                        (
                            change["to_status"],
                            change["warning"],
                            change["run_id"],
                            change["from_status"],
                        ),
                    )

        return {
            "inspected": len(rows),
            "planned": len(changes),
            "applied": bool(apply),
            "changes": changes,
            "unresolved": [
                {
                    "run_id": int(data["row"]["id"]),
                    "status": str(data["row"]["status"]),
                    "error": str(data["row"]["error"] or ""),
                }
                for data in run_data.values()
                if str(data["row"]["error"] or "").strip()
                and int(data["row"]["id"])
                not in {int(change["run_id"]) for change in changes}
            ],
        }

    def cancel_running_run(
        self,
        run_id: int,
        error: str,
        *,
        ended_at: float | None = None,
    ) -> bool:
        """Atomically make one orphaned running audit resumable."""
        finished_at = time.time() if ended_at is None else ended_at
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs
                SET status = ?, error = ?, ended_at = ?,
                    duration_seconds = MAX(0, COALESCE(duration_seconds, 0)) +
                        CASE WHEN active_started_at IS NOT NULL
                             THEN MAX(0, ? - active_started_at)
                             ELSE 0 END,
                    active_started_at = NULL
                WHERE id = ? AND status = ? AND run_kind = ?
                    AND output_dir NOT LIKE ?
                """,
                (
                    RUN_CANCELLED,
                    error,
                    finished_at,
                    finished_at,
                    run_id,
                    RUN_RUNNING,
                    RUN_KIND_AUDIT,
                    _POC_BACKFILL_OUTPUT_LIKE,
                ),
            )
            return cursor.rowcount == 1

    def cancel_running_runs(
        self,
        error: str,
        *,
        ended_at: float | None = None,
    ) -> list[int]:
        """Make all running rows left by a previous Web worker resumable."""
        finished_at = time.time() if ended_at is None else ended_at
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            run_ids = [
                int(row["id"])
                for row in conn.execute(
                    "SELECT id FROM runs "
                    "WHERE status = ? AND run_kind = ? "
                    "AND output_dir NOT LIKE ? ORDER BY id",
                    (
                        RUN_RUNNING,
                        RUN_KIND_AUDIT,
                        _POC_BACKFILL_OUTPUT_LIKE,
                    ),
                ).fetchall()
            ]
            if run_ids:
                conn.execute(
                    """
                    UPDATE runs
                    SET status = ?, error = ?, ended_at = ?,
                        duration_seconds = MAX(0, COALESCE(duration_seconds, 0)) +
                            CASE WHEN active_started_at IS NOT NULL
                                 THEN MAX(0, ? - active_started_at)
                                 ELSE 0 END,
                        active_started_at = NULL
                    WHERE status = ? AND run_kind = ?
                        AND output_dir NOT LIKE ?
                    """,
                    (
                        RUN_CANCELLED,
                        error,
                        finished_at,
                        finished_at,
                        RUN_RUNNING,
                        RUN_KIND_AUDIT,
                        _POC_BACKFILL_OUTPUT_LIKE,
                    ),
                )
        return run_ids

    def resume_cancelled_run(
        self,
        run_id: int,
        *,
        resumed_at: float | None = None,
        backend: str | None = None,
        model: str | None = None,
    ) -> bool:
        """Atomically move one resumable run back to the running state.

        Resumable means cancelled, failed, or done with recorded task errors
        (partial failure). The original row and ``started_at`` are preserved
        so History keeps one lifecycle for a checkpoint-resumed audit instead
        of inventing a second audit record for the same output tree. Duration
        is accumulated separately from each active session, excluding gaps.
        """
        active_started_at = time.time() if resumed_at is None else resumed_at
        with self._connect() as conn:
            if backend is None:
                cursor = conn.execute(
                    """
                    UPDATE runs
                    SET status = ?, error = '', ended_at = NULL,
                        active_started_at = ?
                    WHERE id = ? AND run_kind = ?
                        AND output_dir NOT LIKE ?
                        AND (status IN (?, ?) OR (status = ? AND error != ''))
                    """,
                    (
                        RUN_RUNNING,
                        active_started_at,
                        run_id,
                        RUN_KIND_AUDIT,
                        _POC_BACKFILL_OUTPUT_LIKE,
                        RUN_CANCELLED,
                        RUN_FAILED,
                        RUN_DONE,
                    ),
                )
            else:
                cursor = conn.execute(
                    """
                    UPDATE runs
                    SET status = ?, error = '', ended_at = NULL,
                        active_started_at = ?, backend = ?, model = ?
                    WHERE id = ? AND run_kind = ?
                        AND output_dir NOT LIKE ?
                        AND (status IN (?, ?) OR (status = ? AND error != ''))
                    """,
                    (
                        RUN_RUNNING,
                        active_started_at,
                        backend,
                        model,
                        run_id,
                        RUN_KIND_AUDIT,
                        _POC_BACKFILL_OUTPUT_LIKE,
                        RUN_CANCELLED,
                        RUN_FAILED,
                        RUN_DONE,
                    ),
                )
            return cursor.rowcount == 1

    def update_running_run_agent_settings(
        self, run_id: int, *, backend: str, model: str | None
    ) -> bool:
        """Record the backend/model selected for the active execution segment."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs SET backend = ?, model = ?
                WHERE id = ? AND status = ?
                """,
                (backend, model, run_id, RUN_RUNNING),
            )
            return cursor.rowcount == 1

    def update_running_run_agent_history(
        self,
        run_id: int,
        *,
        backends_used: list[str],
        models_used: list[str],
    ) -> bool:
        """Persist actual agent usage while a run is still active."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs SET backends_used = ?, models_used = ?
                WHERE id = ? AND status = ?
                """,
                (
                    json.dumps(backends_used, ensure_ascii=False),
                    json.dumps(models_used, ensure_ascii=False),
                    run_id,
                    RUN_RUNNING,
                ),
            )
            return cursor.rowcount == 1

    def update_run_output_dir(self, run_id: int, output_dir: str) -> None:
        """Update the output directory of an existing run.

        Used when a git-clone audit's preliminary output_dir (date-based) is
        replaced by the commit-stamped directory after cloning completes.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE runs SET output_dir = ? WHERE id = ?",
                (output_dir, run_id),
            )

    def record_run(
        self,
        config: AuditConfig,
        status: str,
        error: str = "",
        started_at: float | None = None,
        ended_at: float | None = None,
    ) -> int:
        """Create a completed run row and scan its filesystem artifacts."""
        run_id = self.create_run(config, status=status, started_at=started_at)
        identity = capture_repo_identity(config.target)
        if identity["commit"]:
            self.set_run_identity(run_id, identity)
        finished_at = time.time() if ended_at is None else ended_at
        duration_seconds = (
            max(0.0, finished_at - started_at) if started_at is not None else 0.0
        )
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET error = ?, ended_at = ?, duration_seconds = ?,
                    active_started_at = NULL, backends_used = ?, models_used = ?,
                    usage_stats = ?
                WHERE id = ?
                """,
                (
                    error,
                    finished_at,
                    duration_seconds,
                    json.dumps(config.backends_used, ensure_ascii=False),
                    json.dumps(config.models_used, ensure_ascii=False),
                    json.dumps(config.usage_stats, ensure_ascii=False),
                    run_id,
                ),
            )
        self.persist_artifacts(run_id, config.output_dir)
        return run_id

    def import_output_dir(
        self,
        output_dir: str,
        target: str | None = None,
        started_at: float | None = None,
    ) -> int:
        """Backfill a run row from an existing output directory."""
        output_dir = os.path.realpath(output_dir)
        if not os.path.isdir(output_dir):
            raise ValueError(f"Output directory not found: {output_dir}")
        target = target or os.path.dirname(output_dir)
        latest_mtime = max(
            (p.stat().st_mtime for p in Path(output_dir).rglob("*") if p.is_file()),
            default=None,
        )
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO runs (
                    target, output_dir, status, started_at, ended_at,
                    duration_known, created_at
                ) VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    target,
                    output_dir,
                    RUN_IMPORTED,
                    started_at,
                    latest_mtime,
                    time.time(),
                ),
            )
            run_id = int(cursor.lastrowid)
        identity = capture_repo_identity(target)
        if identity["commit"]:
            self.set_run_identity(run_id, identity)
        self.persist_artifacts(run_id, output_dir)
        return run_id

    def import_results_tree(
        self, root: str, repos_dir: str = DEFAULT_REPOS_DIR
    ) -> list[int]:
        """Batch-import every ``audit-output-*`` directory found under ``root``.

        Targets are mapped to matching cloned repositories under ``repos_dir``
        (by project directory name) when one exists, so history links up with
        the web UI's repository selector; otherwise the output directory's
        parent is used. ``started_at`` is derived from the directory date.
        """
        root = os.path.realpath(os.path.expanduser(root))
        if not os.path.isdir(root):
            raise ValueError(f"Directory not found: {root}")
        output_dirs = _find_output_dirs(root)
        if not output_dirs:
            raise ValueError(f"No audit-output-* directories found under {root}")

        cloned = list_cloned_repos(repos_dir)
        run_ids = []
        for output_dir in output_dirs:
            target = _map_repo_target(output_dir, cloned)
            started_at = _parse_output_dir_date(os.path.basename(output_dir))
            run_ids.append(
                self.import_output_dir(output_dir, target=target, started_at=started_at)
            )
        return run_ids

    def persist_artifacts(self, run_id: int, output_dir: str) -> None:
        """Scan the output directory and upsert artifacts; refresh run counts."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT target_key, repo_url FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            target_key = str(row["target_key"] or "") if row else ""
            repo_url = str(row["repo_url"] or "") if row else ""
        artifacts = scan_output_dir(output_dir, repo_url=repo_url)
        with self._connect() as conn:
            for au in artifacts["analysis_units"]:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO analysis_units (
                        run_id, au_id, description, files, focus, raw_json, target_key
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        au["au_id"],
                        au["description"],
                        au["files"],
                        au["focus"],
                        au["raw_json"],
                        target_key,
                    ),
                )
            for finding in artifacts["findings"]:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        run_id, finding_key, au_id, title, location,
                        vulnerability_class, root_cause, preliminary_severity, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        *[
                            finding[k]
                            for k in (
                                "finding_key",
                                "au_id",
                                "title",
                                "location",
                                "vulnerability_class",
                                "root_cause",
                                "preliminary_severity",
                                "raw_json",
                            )
                        ],
                    ),
                )
            for vuln in artifacts["vulnerabilities"]:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO vulnerabilities (
                        run_id, vuln_id, severity, cvss_score, title, location,
                        trigger, cwe_ids, vulnerability_class, entry_point, sink,
                        propagation_chain, neutralizing_checks, prerequisites,
                        impact, code_snippet, dedupe_key, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        *[
                            vuln[k]
                            for k in (
                                "vuln_id",
                                "severity",
                                "cvss_score",
                                "title",
                                "location",
                                "trigger",
                                "cwe_ids",
                                "vulnerability_class",
                                "entry_point",
                                "sink",
                                "propagation_chain",
                                "neutralizing_checks",
                                "prerequisites",
                                "impact",
                                "code_snippet",
                                "dedupe_key",
                                "raw_json",
                            )
                        ],
                    ),
                )
            for poc in artifacts["pocs"]:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO pocs (
                        run_id, vuln_id, status, report_path,
                        trigger_graph_path, asan_report_path
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        poc["vuln_id"],
                        poc["status"],
                        poc["report_path"],
                        poc["trigger_graph_path"],
                        poc["asan_report_path"],
                    ),
                )
            for disclosure in artifacts["disclosures"]:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO disclosures (
                        run_id, vuln_id, report_path, email_path, zip_path,
                        trigger_graph_path, asan_report_path
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        disclosure["vuln_id"],
                        disclosure["report_path"],
                        disclosure["email_path"],
                        disclosure["zip_path"],
                        disclosure["trigger_graph_path"],
                        disclosure["asan_report_path"],
                    ),
                )
            reproduced = sum(
                1 for p in artifacts["pocs"] if p["status"] in REPRODUCED_STATUSES
            )
            conn.execute(
                """
                UPDATE runs SET findings_count = ?, vulns_count = ?,
                    pocs_reproduced_count = ?, disclosures_count = ?
                WHERE id = ?
                """,
                (
                    len(artifacts["findings"]),
                    len(artifacts["vulnerabilities"]),
                    reproduced,
                    sum(1 for d in artifacts["disclosures"] if d["report_path"]),
                    run_id,
                ),
            )
            self._sync_disclosures_from_run(conn, run_id, output_dir)

    @staticmethod
    def _sync_disclosures_from_run(
        conn: sqlite3.Connection, run_id: int, output_dir: str,
        *, vuln_id: str | None = None,
    ) -> None:
        """Upsert Stage 6 records directly into the Web Disclosure catalogue."""
        output_root = os.path.realpath(output_dir)

        def resolved_file(path: str | None) -> str | None:
            if not path or "\x00" in path:
                return None
            candidate = os.path.realpath(
                path if os.path.isabs(path) else os.path.join(output_root, path)
            )
            if not candidate.startswith(output_root + os.sep):
                return None
            return candidate if os.path.isfile(candidate) else None

        # A cleared report path must not hide a later negative/partial result.
        # Keep the evidence and human decisions: only unreviewed records move
        # to triage, and another retained successful run takes precedence.
        bad_rows = conn.execute(
            """
            SELECT b.id, b.dedupe_key, b.summary, p.status
            FROM disclosed_bugs b
            JOIN vulnerabilities v ON v.dedupe_key = b.dedupe_key
            JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
            WHERE v.run_id = ? AND (? IS NULL OR v.vuln_id = ?)
              AND b.deleted_at IS NULL
              AND b.review_status = 'unreviewed'
              AND p.status != 'reproduced'
            """,
            (run_id, vuln_id, vuln_id),
        ).fetchall()
        for bad in bad_rows:
            if bad["status"] not in FAILED_STATUSES:
                # Unknown/in-progress evidence is not a completed negative review.
                continue
            alternatives = conn.execute(
                """
                SELECT r.output_dir, p.report_path, d.report_path AS disclosure_report
                FROM vulnerabilities v JOIN runs r ON r.id = v.run_id
                JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                LEFT JOIN disclosures d ON d.run_id = v.run_id AND d.vuln_id = v.vuln_id
                WHERE v.dedupe_key = ? AND p.status = 'reproduced'
                """,
                (bad["dedupe_key"],),
            ).fetchall()
            retained_success = False
            for alternative in alternatives:
                root = Path(alternative["output_dir"]).resolve()
                for name in ("report_path", "disclosure_report"):
                    raw = alternative[name]
                    if not raw:
                        continue
                    path = Path(raw)
                    path = (path if path.is_absolute() else root / path).resolve()
                    if path.is_relative_to(root) and path.is_file():
                        retained_success = True
            if retained_success:
                continue
            note = (
                f"Evidence review required: run {run_id} records Stage 5 "
                f"status {bad['status']}; no retained successful run was found."
            )
            summary = "\n\n".join(value for value in (bad["summary"], note) if value)
            conn.execute(
                """UPDATE disclosed_bugs SET review_status = 'triage',
                   summary = ?, updated_at = ? WHERE id = ? AND review_status = 'unreviewed'""",
                (summary, time.time(), bad["id"]),
            )

        rows = conn.execute(
            """
            SELECT v.vuln_id, v.title, v.location, v.trigger, v.cwe_ids,
                   v.vulnerability_class, v.dedupe_key, v.raw_json,
                   d.report_path, d.email_path, d.zip_path,
                   d.trigger_graph_path AS disclosure_trigger_graph_path,
                   d.asan_report_path AS disclosure_asan_report_path,
                   p.report_path AS poc_report_path,
                   p.trigger_graph_path AS poc_trigger_graph_path,
                   p.asan_report_path AS poc_asan_report_path,
                   p.status AS p_status,
                   r.repo_name, r.repo_url, r.target, r."commit",
                   r.backend, r.ended_at, r.started_at, r.created_at
            FROM disclosures d
            JOIN vulnerabilities v
              ON v.run_id = d.run_id AND v.vuln_id = d.vuln_id
            JOIN runs r ON r.id = d.run_id
            LEFT JOIN pocs p
              ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
            WHERE d.run_id = ? AND (? IS NULL OR v.vuln_id = ?)
              AND d.report_path != ''
            """,
            (run_id, vuln_id, vuln_id),
        ).fetchall()
        reproduced = REPRODUCED_STATUSES
        now = time.time()
        for row in rows:
            if row["p_status"] not in reproduced:
                continue
            report_path = resolved_file(row["report_path"])
            if report_path is None or not row["dedupe_key"]:
                continue
            email_path = resolved_file(row["email_path"])
            zip_path = resolved_file(row["zip_path"])
            poc_path = resolved_file(row["poc_report_path"])
            trigger_graph_path = resolved_file(
                row["disclosure_trigger_graph_path"]
            ) or resolved_file(row["poc_trigger_graph_path"])
            asan_report_path = resolved_file(
                row["disclosure_asan_report_path"]
            ) or resolved_file(row["poc_asan_report_path"])
            finding_path = resolved_file(
                os.path.join("stage4-vulnerabilities", f"{row['vuln_id']}.json")
            )
            stage_artifacts = (
                ("Stage 4 Finding", finding_path),
                ("Stage 5 Report", poc_path),
                ("Stage 5 Trigger Graph", trigger_graph_path),
                ("Stage 5 ASan Report", asan_report_path),
                ("Stage 6 Report", report_path),
                ("Stage 6 Email", email_path),
                ("Stage 6 Zip", zip_path),
            )
            artifacts = []
            for label, path in stage_artifacts:
                if path:
                    artifacts.append({"label": label, "path": path})
            try:
                finding = json.loads(row["raw_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                finding = {}
            if not isinstance(finding, dict):
                finding = {}
            try:
                cwe_values = json.loads(row["cwe_ids"] or "[]")
            except (json.JSONDecodeError, TypeError):
                cwe_values = []
            try:
                class_values = json.loads(row["vulnerability_class"] or "[]")
            except (json.JSONDecodeError, TypeError):
                class_values = []
            project_fallback = row["repo_name"] or os.path.basename(
                os.path.realpath(row["target"] or output_root)
            )
            project = _project_name_from_repo_url(
                row["repo_url"] or "", project_fallback
            )
            # Refresh generated links while retaining registered review notes
            # and other supplemental attachments across future run syncs.
            previous = conn.execute(
                "SELECT artifact_links FROM disclosed_bugs WHERE project = ? AND dedupe_key = ?",
                (project, row["dedupe_key"]),
            ).fetchone()
            try:
                supplements = (
                    json.loads(previous["artifact_links"] or "[]") if previous else []
                )
            except (json.JSONDecodeError, TypeError):
                supplements = []
            stage_labels = {label for label, _ in stage_artifacts}
            known_paths = {artifact["path"] for artifact in artifacts}
            for attachment in supplements if isinstance(supplements, list) else []:
                if (
                    not isinstance(attachment, dict)
                    or not isinstance(attachment.get("label"), str)
                    or not isinstance(attachment.get("path"), str)
                    or not attachment["path"]
                    or attachment["label"] in stage_labels
                    or attachment["path"] in known_paths
                ):
                    continue
                artifacts.append(attachment)
                known_paths.add(attachment["path"])
            finished_at = row["ended_at"] or row["started_at"] or row["created_at"]
            audit_date = (
                datetime.fromtimestamp(float(finished_at)).date().isoformat()
                if finished_at
                else ""
            )
            conn.execute(
                """
                INSERT INTO disclosed_bugs (
                    project, dedupe_key, title, location, cwe,
                    vulnerability_class, trigger, summary, repo_url,
                    audited_commit, audit_finished_date, model_backend,
                    review_status, artifact_links, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project, dedupe_key) DO UPDATE SET
                    title = CASE WHEN excluded.title != ''
                        AND disclosed_bugs.review_status = 'unreviewed'
                        THEN excluded.title ELSE disclosed_bugs.title END,
                    location = CASE WHEN excluded.location != ''
                        THEN excluded.location ELSE disclosed_bugs.location END,
                    cwe = CASE WHEN excluded.cwe != ''
                        THEN excluded.cwe ELSE disclosed_bugs.cwe END,
                    vulnerability_class = CASE
                        WHEN excluded.vulnerability_class != ''
                        THEN excluded.vulnerability_class
                        ELSE disclosed_bugs.vulnerability_class END,
                    trigger = CASE WHEN excluded.trigger != ''
                        THEN excluded.trigger ELSE disclosed_bugs.trigger END,
                    summary = CASE WHEN COALESCE(disclosed_bugs.summary, '') = ''
                        THEN excluded.summary ELSE disclosed_bugs.summary END,
                    repo_url = CASE WHEN excluded.repo_url != ''
                        THEN excluded.repo_url ELSE disclosed_bugs.repo_url END,
                    audited_commit = CASE WHEN excluded.audited_commit != ''
                        THEN excluded.audited_commit
                        ELSE disclosed_bugs.audited_commit END,
                    audit_finished_date = CASE
                        WHEN excluded.audit_finished_date != ''
                        THEN excluded.audit_finished_date
                        ELSE disclosed_bugs.audit_finished_date END,
                    model_backend = CASE WHEN excluded.model_backend != ''
                        THEN excluded.model_backend
                        ELSE disclosed_bugs.model_backend END,
                    artifact_links = excluded.artifact_links,
                    updated_at = excluded.updated_at
                """,
                (
                    project,
                    row["dedupe_key"],
                    extract_email_subject(email_path) or row["title"] or "",
                    row["location"] or "",
                    ", ".join(str(value) for value in _as_list(cwe_values)),
                    ", ".join(str(value) for value in _as_list(class_values)),
                    row["trigger"] or "",
                    finding.get("summary") or finding.get("description") or "",
                    row["repo_url"] or "",
                    row["commit"] or "",
                    audit_date,
                    row["backend"] or "",
                    "unreviewed",
                    json.dumps(artifacts, ensure_ascii=False),
                    now,
                ),
            )

    # ── Reads ────────────────────────────────────────────────────────────

    def list_runs(
        self,
        limit: int = 100,
        offset: int = 0,
        target: str | None = None,
        target_key: str | None = None,
        status: str | None = None,
        run_kind: str | None = None,
        query: str | None = None,
    ) -> tuple[list[dict], int]:
        clauses = []
        args: list = []
        if target:
            clauses.append("r.target = ?")
            args.append(target)
        if target_key:
            clauses.append("r.target_key = ?")
            args.append(target_key)
        if status:
            if status not in RUN_STATUSES:
                raise ValueError(f"Unsupported run status: {status}")
            clauses.append("r.status = ?")
            args.append(status)
        if run_kind:
            if run_kind not in RUN_KINDS:
                raise ValueError(f"Unsupported run kind: {run_kind}")
            if run_kind == RUN_KIND_MAINTENANCE:
                clauses.append("(r.run_kind = ? OR r.output_dir LIKE ?)")
                args.extend([run_kind, _POC_BACKFILL_OUTPUT_LIKE])
            else:
                clauses.append("r.run_kind = ? AND r.output_dir NOT LIKE ?")
                args.extend([run_kind, _POC_BACKFILL_OUTPUT_LIKE])
        if query and (needle := query.strip().lower()):
            searchable = (
                "CAST(r.id AS TEXT)",
                "COALESCE(r.repo_name, '')",
                "COALESCE(r.target, '')",
                "COALESCE(r.output_dir, '')",
                "COALESCE(r.\"commit\", '')",
                "COALESCE(r.backend, '')",
                "COALESCE(r.backends_used, '')",
                "COALESCE(r.models_used, '')",
            )
            clauses.append(
                "("
                + " OR ".join(f"instr(lower({field}), ?) > 0" for field in searchable)
                + ")"
            )
            args.extend([needle] * len(searchable))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        statuses = sorted(REPRODUCED_STATUSES)
        status_placeholders = ",".join("?" * len(statuses))
        with self._connect() as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM runs r {where}", args
            ).fetchone()[0]
            rows = conn.execute(
                f"""
                SELECT r.*, (
                    SELECT COUNT(*)
                    FROM vulnerabilities v
                    JOIN pocs p
                      ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    WHERE v.run_id = r.id
                      AND p.status IN ({status_placeholders})
                ) AS reproduced_vulns_count
                FROM runs r
                {where}
                ORDER BY r.id DESC
                LIMIT ? OFFSET ?
                """,
                (*statuses, *args, limit, offset),
            ).fetchall()
            link_rows = []
            registry_rows = []
            if rows:
                run_ids = [row["id"] for row in rows]
                placeholders = ",".join("?" * len(run_ids))
                link_rows = conn.execute(
                    f"""
                    SELECT v.run_id, v.vuln_id, v.dedupe_key
                    FROM vulnerabilities v
                    JOIN pocs p
                      ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    WHERE v.run_id IN ({placeholders})
                      AND p.status IN ({status_placeholders})
                    """,
                    (*run_ids, *statuses),
                ).fetchall()
                registry_rows = conn.execute(
                    """SELECT project, dedupe_key, deleted_at
                    FROM disclosed_bugs"""
                ).fetchall()
        result = [dict(row) for row in rows]
        by_run = {run["id"]: run for run in result}
        registry = {
            (row["project"], row["dedupe_key"]): row for row in registry_rows
        }
        for run in result:
            run["disclosure_counts"] = {"active": 0, "trashed": 0, "missing": 0}
        for link in link_rows:
            run = by_run[link["run_id"]]
            entry = registry.get((_run_project(run), link["dedupe_key"]))
            state = (
                "trashed" if entry and entry["deleted_at"] is not None
                else "active" if entry else "missing"
            )
            run["disclosure_counts"][state] += 1
        for run in result:
            if str(run.get("output_dir") or "").endswith(_POC_BACKFILL_OUTPUT_SUFFIX):
                run["run_kind"] = RUN_KIND_MAINTENANCE
        return result, total

    def list_running_maintenance_runs(self) -> list[dict]:
        """Return database-owned maintenance rows for the Web job snapshot."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs WHERE status = ? "
                "AND (run_kind = ? OR output_dir LIKE ?) ORDER BY id",
                (
                    RUN_RUNNING,
                    RUN_KIND_MAINTENANCE,
                    _POC_BACKFILL_OUTPUT_LIKE,
                ),
            ).fetchall()
        result = [dict(row) for row in rows]
        for run in result:
            run["run_kind"] = RUN_KIND_MAINTENANCE
        return result

    def dashboard_summary(self) -> dict[str, Any]:
        """Return compact aggregate counts for the Web dashboard."""
        reproduced_statuses = sorted(REPRODUCED_STATUSES)
        status_placeholders = ",".join("?" * len(reproduced_statuses))
        with self._connect() as conn:
            run_counts = {
                str(row["status"]): int(row["total"])
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS total FROM runs GROUP BY status"
                ).fetchall()
            }
            reproduced = int(
                conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM vulnerabilities v
                    JOIN pocs p
                      ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    WHERE p.status IN ({status_placeholders})
                    """,
                    reproduced_statuses,
                ).fetchone()[0]
            )
            disclosure_counts = {
                str(row["review_status"] or "unreviewed"): int(row["total"])
                for row in conn.execute(
                    """
                    SELECT review_status, COUNT(*) AS total
                    FROM disclosed_bugs
                    WHERE deleted_at IS NULL
                    GROUP BY review_status
                    """
                ).fetchall()
            }
            trash_total = int(
                conn.execute(
                    "SELECT COUNT(*) FROM disclosed_bugs WHERE deleted_at IS NOT NULL"
                ).fetchone()[0]
            )
            cve_total = int(conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])

        return {
            "runs": {
                "total": sum(run_counts.values()),
                "counts": run_counts,
                "reproduced": reproduced,
            },
            "disclosures": {
                "total": sum(disclosure_counts.values()),
                "counts": disclosure_counts,
            },
            "cves": {"total": cve_total},
            "trash": {"total": trash_total},
        }

    def get_run(self, run_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            run = dict(row)
            if str(run.get("output_dir") or "").endswith(_POC_BACKFILL_OUTPUT_SUFFIX):
                run["run_kind"] = RUN_KIND_MAINTENANCE
            statuses = sorted(REPRODUCED_STATUSES)
            status_placeholders = ",".join("?" * len(statuses))
            run["vulnerabilities"] = [
                dict(r)
                for r in conn.execute(
                    f"""
                    SELECT v.*, p.status AS poc_status, p.report_path AS poc_report_path,
                           d.report_path AS disclosure_report_path,
                           d.email_path AS disclosure_email_path,
                           d.zip_path AS disclosure_zip_path
                    FROM vulnerabilities v
                    JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    LEFT JOIN disclosures d ON d.run_id = v.run_id AND d.vuln_id = v.vuln_id
                    WHERE v.run_id = ? AND p.status IN ({status_placeholders})
                    ORDER BY v.vuln_id
                    """,
                    (run_id, *statuses),
                ).fetchall()
            ]
            project = _run_project(run)
            registry = {}
            for raw in conn.execute(
                """
                SELECT * FROM disclosed_bugs
                WHERE project = ?
                """,
                (project,),
            ).fetchall():
                entry = dict(raw)
                entry.pop("artifact_links", None)
                registry[entry["dedupe_key"]] = entry
            disclosure_counts = {"active": 0, "trashed": 0, "missing": 0}
            for vuln in run["vulnerabilities"]:
                entry = registry.get(vuln.get("dedupe_key") or "")
                if entry is None:
                    state = "missing"
                    reason = (
                        "not_registered"
                        if vuln.get("disclosure_report_path")
                        else "no_stage6"
                    )
                else:
                    state = (
                        "trashed" if entry.get("deleted_at") is not None else "active"
                    )
                    reason = None
                vuln["disclosure_project"] = project
                vuln["disclosure_state"] = state
                vuln["disclosure_missing_reason"] = reason
                vuln["disclosure"] = entry
                disclosure_counts[state] += 1
            run["disclosure_counts"] = disclosure_counts
            run["reproduced_vulns_count"] = len(run["vulnerabilities"])
            # Non-reproduced PoC outcomes (error/false-positive/not-reproduced)
            # so the detail view can show which tasks did not produce a PoC.
            run["poc_issues"] = [
                dict(r)
                for r in conn.execute(
                    f"""
                    SELECT v.vuln_id, v.severity, v.cvss_score, v.title,
                           p.status AS poc_status
                    FROM vulnerabilities v
                    JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    WHERE v.run_id = ? AND p.status NOT IN ({status_placeholders})
                    ORDER BY v.vuln_id
                    """,
                    (run_id, *statuses),
                ).fetchall()
            ]
            aus = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM analysis_units WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            ]
            aus.sort(key=lambda a: natural_sort_key(a["au_id"]))
            run["analysis_units"] = aus
            if run.get("target_key"):
                run["related_run_ids"] = [
                    row[0]
                    for row in conn.execute(
                        "SELECT id FROM runs WHERE target_key = ? AND id != ?"
                        " ORDER BY id DESC",
                        (run["target_key"], run_id),
                    ).fetchall()
                ]
            else:
                run["related_run_ids"] = []
        return run

    def register_history_disclosure(self, run_id: int, vuln_id: str) -> dict:
        """Create the catalogue link from one retained reproduced Run finding."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT r.*, v.dedupe_key, d.report_path
                FROM runs r
                JOIN vulnerabilities v ON v.run_id = r.id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                JOIN disclosures d
                  ON d.run_id = v.run_id AND d.vuln_id = v.vuln_id
                WHERE r.id = ? AND v.vuln_id = ? AND p.status = 'reproduced'
                """,
                (run_id, vuln_id),
            ).fetchone()
            if row is None or not row["dedupe_key"] or not row["report_path"]:
                raise ValueError(
                    "No reproduced finding with a retained Stage 6 report."
                )
            project = _run_project(dict(row))
            identity = (project, row["dedupe_key"])
            existing = conn.execute(
                """SELECT deleted_at FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ?""",
                identity,
            ).fetchone()
            if existing is not None:
                if existing["deleted_at"] is not None:
                    raise ValueError(
                        "Disclosure is in the recycle bin; restore that entry instead."
                    )
                return {"project": project, "dedupe_key": row["dedupe_key"]}
            self._sync_disclosures_from_run(
                conn, run_id, row["output_dir"], vuln_id=vuln_id
            )
            linked = conn.execute(
                """SELECT 1 FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL""",
                identity,
            ).fetchone()
            if linked is None:
                raise ValueError("The retained Stage 6 report is no longer available.")
        return {"project": project, "dedupe_key": row["dedupe_key"]}

    def list_history_reproduction_candidates(self) -> list[dict]:
        """List historical vulnerabilities with an exactly reproduced PoC."""
        with self._connect() as conn:
            rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT v.run_id, v.vuln_id, v.severity, v.cvss_score,
                           v.dedupe_key,
                           v.title, v.location, r.repo_name, r.repo_url,
                           r.branch, r."commit", r.target, r.output_dir,
                           p.status AS poc_status,
                           p.report_path AS poc_report_path
                    FROM vulnerabilities v
                    JOIN runs r ON r.id = v.run_id
                    JOIN pocs p
                      ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                    WHERE p.status = 'reproduced'
                    ORDER BY r.repo_name, r.id DESC, v.vuln_id
                    """
                ).fetchall()
            ]
        rows.sort(
            key=lambda item: (
                item.get("repo_name") or "",
                -item["run_id"],
                natural_sort_key(item["vuln_id"]),
            )
        )
        return rows

    def _disclosure_reproduction_source(
        self,
        conn: sqlite3.Connection,
        dedupe_key: str,
        project: str,
    ) -> dict | None:
        rows = conn.execute(
            """
            SELECT v.run_id, v.vuln_id, v.severity, v.cvss_score, v.title,
                   v.location, v.raw_json, r.repo_name, r.repo_url, r.branch,
                   r."commit", r.target, r.output_dir, r.wiki_path,
                   p.status AS poc_status, p.report_path AS poc_report_path
            FROM vulnerabilities v
            JOIN runs r ON r.id = v.run_id
            LEFT JOIN pocs p
              ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
            WHERE v.dedupe_key = ?
            ORDER BY CASE WHEN p.status = 'reproduced' THEN 0 ELSE 1 END,
                     r.id DESC
            """,
            (dedupe_key,),
        ).fetchall()
        rows = [
            row
            for row in rows
            if _project_name_from_repo_url(
                str(row["repo_url"] or ""),
                str(row["repo_name"] or "")
                or os.path.basename(
                    os.path.realpath(str(row["target"] or row["output_dir"] or ""))
                ),
            )
            == project
        ]
        if not rows:
            return None
        # Prefer a still-present source checkout, while retaining a database
        # source row when the checkout can be reacquired from repo_url.
        for row in rows:
            if os.path.isdir(str(row["target"] or "")):
                return dict(row)
        return dict(rows[0])

    def _registered_disclosure_reference(self, artifact_links: str) -> str:
        try:
            artifacts = json.loads(artifact_links or "[]")
        except (json.JSONDecodeError, TypeError):
            return ""
        if not isinstance(artifacts, list):
            return ""
        preferred = ("Stage 6 Report", "Stage 5 Report")
        for label in preferred:
            for artifact in artifacts:
                if not isinstance(artifact, dict) or artifact.get("label") != label:
                    continue
                raw = artifact.get("path")
                if not isinstance(raw, str) or not raw or "\x00" in raw:
                    continue
                path = os.path.realpath(raw)
                if not os.path.isfile(path):
                    continue
                if self.managed_results_dir and not self._path_is_within(
                    path, self.managed_results_dir
                ):
                    continue
                return os.path.dirname(path)
        return ""

    def list_reproduction_candidates(self) -> list[dict]:
        """List active Disclosure records that can be retested on remote HEAD."""
        latest: dict[tuple[str, str], dict] = {}
        for row in self.list_reproductions():
            latest.setdefault((row["project"], row["dedupe_key"]), row)
        candidates: list[dict] = []
        with self._connect() as conn:
            disclosures = conn.execute(
                """
                SELECT * FROM disclosed_bugs
                WHERE deleted_at IS NULL
                ORDER BY project, audit_finished_date DESC, id
                """
            ).fetchall()
            for disclosure in disclosures:
                item = dict(disclosure)
                source = self._disclosure_reproduction_source(
                    conn,
                    str(item.get("dedupe_key") or ""),
                    str(item.get("project") or ""),
                )
                if source:
                    item.update(source)
                item["source_run_id"] = source.get("run_id") if source else None
                item["source_vuln_id"] = source.get("vuln_id") if source else ""
                # Preserve the public candidate names used by the existing UI
                # and operator API while making Disclosure identity canonical.
                item["run_id"] = item["source_run_id"]
                item["vuln_id"] = item["source_vuln_id"]
                item["commit"] = item.get("audited_commit") or item.get("commit") or ""
                item["reference_dir"] = self._registered_disclosure_reference(
                    str(item.get("artifact_links") or "[]")
                )
                reasons: list[str] = []
                if source is None or not item.get("raw_json"):
                    reasons.append(
                        "No linked Stage 4 vulnerability record is available."
                    )
                target = str(item.get("target") or "")
                repo_url = str(item.get("repo_url") or "")
                if not (os.path.isdir(os.path.join(target, ".git")) or repo_url):
                    reasons.append("No Git checkout or repository URL is available.")
                if not item.get("reference_dir"):
                    reasons.append(
                        "No retained Stage 5/6 reproduction context is registered."
                    )
                item["can_reproduce"] = not reasons
                item["unavailable_reasons"] = reasons
                item["latest_reproduction"] = latest.get(
                    (str(item.get("project") or ""), str(item.get("dedupe_key") or ""))
                )
                item.pop("artifact_links", None)
                item.pop("deleted_at", None)
                item.pop("updated_at", None)
                item.pop("raw_json", None)
                candidates.append(item)
        return candidates

    def get_disclosure_reproduction_candidate(
        self, project: str, dedupe_key: str
    ) -> dict | None:
        """Return one active Disclosure plus the source finding used to retest it."""
        with self._connect() as conn:
            disclosure = conn.execute(
                """
                SELECT * FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (project, dedupe_key),
            ).fetchone()
            if disclosure is None:
                return None
            item = dict(disclosure)
            source = self._disclosure_reproduction_source(conn, dedupe_key, project)
        if source is None:
            return None
        item.update(source)
        item["disclosure_id"] = int(disclosure["id"])
        item["project"] = project
        item["dedupe_key"] = dedupe_key
        item["source_run_id"] = source["run_id"]
        item["source_vuln_id"] = source["vuln_id"]
        item["run_id"] = source["run_id"]
        item["vuln_id"] = source["vuln_id"]
        item["base_commit"] = item.get("audited_commit") or source.get("commit") or ""
        item["reference_dir"] = self._registered_disclosure_reference(
            str(disclosure["artifact_links"] or "[]")
        )
        return item

    def create_reproduction(
        self,
        *,
        job_key: str,
        candidate: dict,
        output_dir: str,
        backend: str,
        model: str | None,
        sandbox_mode: str,
        sandbox_runtime: str,
        started_at: float,
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO reproduction_runs (
                    job_key, disclosure_id, project, dedupe_key,
                    source_run_id, source_vuln_id, repo_url, base_commit,
                    state, backend, model, sandbox_mode, sandbox_runtime,
                    output_dir, started_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_key,
                    candidate.get("disclosure_id"),
                    candidate.get("project") or "",
                    candidate.get("dedupe_key") or "",
                    candidate.get("source_run_id") or candidate.get("run_id"),
                    candidate.get("source_vuln_id") or candidate.get("vuln_id"),
                    candidate.get("repo_url") or "",
                    candidate.get("base_commit")
                    or candidate.get("audited_commit")
                    or "",
                    backend,
                    model,
                    sandbox_mode,
                    sandbox_runtime,
                    output_dir,
                    started_at,
                    time.time(),
                ),
            )

    def set_reproduction_revision(
        self, job_key: str, *, target_ref: str, tested_commit: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE reproduction_runs SET target_ref = ?, tested_commit = ?
                WHERE job_key = ? AND state = 'running'
                """,
                (target_ref, tested_commit, job_key),
            )

    def finish_reproduction(
        self,
        job_key: str,
        *,
        state: str,
        ended_at: float,
        outcome: str = "",
        disposition: str = "",
        evidence_level: str = "",
        summary: str = "",
        source_analysis: str = "",
        disclosure_update: str = "",
        result_path: str = "",
        assessment_path: str = "",
        retest_report_path: str = "",
        draft_path: str = "",
        error: str = "",
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE reproduction_runs
                SET state = ?, ended_at = ?, outcome = ?, disposition = ?,
                    evidence_level = ?, summary = ?, source_analysis = ?,
                    disclosure_update = ?, result_path = ?, assessment_path = ?,
                    retest_report_path = ?, draft_path = ?, error = ?
                WHERE job_key = ?
                """,
                (
                    state,
                    ended_at,
                    outcome,
                    disposition,
                    evidence_level,
                    summary,
                    source_analysis,
                    disclosure_update,
                    result_path,
                    assessment_path,
                    retest_report_path,
                    draft_path,
                    error,
                    job_key,
                ),
            )

    def cancel_running_reproductions(self, error: str) -> list[str]:
        ended_at = time.time()
        with self._connect() as conn:
            keys = [
                str(row[0])
                for row in conn.execute(
                    "SELECT job_key FROM reproduction_runs WHERE state = 'running'"
                ).fetchall()
            ]
            if keys:
                conn.execute(
                    """
                    UPDATE reproduction_runs
                    SET state = 'cancelled', error = ?, ended_at = ?
                    WHERE state = 'running'
                    """,
                    (error, ended_at),
                )
        return keys

    def get_reproduction(self, job_key: str) -> dict | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM reproduction_runs WHERE job_key = ?", (job_key,)
            ).fetchone()
        return dict(row) if row is not None else None

    def list_reproductions(
        self, *, project: str | None = None, dedupe_key: str | None = None
    ) -> list[dict]:
        clauses: list[str] = []
        values: list[object] = []
        if project:
            clauses.append("project = ?")
            values.append(project)
        if dedupe_key:
            clauses.append("dedupe_key = ?")
            values.append(dedupe_key)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM reproduction_runs"
                + where
                + " ORDER BY started_at DESC, job_key DESC",
                values,
            ).fetchall()
        return [dict(row) for row in rows]

    def mark_reproduction_applied(self, job_key: str, disclosure_dir: str) -> bool:
        """Make a validated local draft the active Disclosure artifact set."""
        active = Path(disclosure_dir).resolve()
        files = {
            "Stage 6 Report": active / "report.md",
            "Stage 6 Email": active / "email.txt",
            "Stage 6 Zip": active / "disclosure.zip",
            "Stage 5 Trigger Graph": active / TRIGGER_GRAPH_FILENAME,
            "Stage 5 ASan Report": active / ASAN_REPORT_FILENAME,
        }
        with self._connect() as conn:
            # Serialize the eligibility check with the metadata update so two
            # concurrent Apply requests cannot both replace the active row.
            conn.execute("BEGIN IMMEDIATE")
            reproduction = conn.execute(
                """
                SELECT * FROM reproduction_runs
                WHERE job_key = ? AND state = 'done' AND outcome = 'reproduced'
                  AND applied_at IS NULL
                """,
                (job_key,),
            ).fetchone()
            if reproduction is None:
                return False
            disclosure = conn.execute(
                """
                SELECT artifact_links FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (reproduction["project"], reproduction["dedupe_key"]),
            ).fetchone()
            if disclosure is None:
                return False
            try:
                previous = json.loads(disclosure["artifact_links"] or "[]")
            except (json.JSONDecodeError, TypeError):
                previous = []
            replaced_labels = set(files)
            artifacts = [
                artifact
                for artifact in previous
                if isinstance(artifact, dict)
                and artifact.get("label") not in replaced_labels
            ]
            artifacts.extend(
                {"label": label, "path": str(path)}
                for label, path in files.items()
                if path.is_file()
            )
            now = time.time()
            conn.execute(
                """
                UPDATE disclosed_bugs
                SET audited_commit = ?, audit_finished_date = ?, model_backend = ?,
                    artifact_links = ?, updated_at = ?
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (
                    reproduction["tested_commit"] or "",
                    datetime.fromtimestamp(now).date().isoformat(),
                    reproduction["backend"] or "",
                    json.dumps(artifacts, ensure_ascii=False),
                    now,
                    reproduction["project"],
                    reproduction["dedupe_key"],
                ),
            )
            cursor = conn.execute(
                "UPDATE reproduction_runs SET applied_at = ? "
                "WHERE job_key = ? AND applied_at IS NULL",
                (now, job_key),
            )
        return cursor.rowcount == 1

    def get_reproduction_candidate(self, run_id: int, vuln_id: str) -> dict | None:
        """Return one exactly reproduced vulnerability and its source run."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT v.*, r.repo_name, r.repo_url, r.branch, r."commit",
                       r.target, r.output_dir, r.wiki_path,
                       p.status AS poc_status,
                       p.report_path AS poc_report_path
                FROM vulnerabilities v
                JOIN runs r ON r.id = v.run_id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                WHERE v.run_id = ? AND v.vuln_id = ?
                  AND p.status = 'reproduced'
                """,
                (run_id, vuln_id),
            ).fetchone()
        if row is None:
            return None
        candidate = dict(row)
        fallback = candidate.get("repo_name") or os.path.basename(
            os.path.realpath(
                candidate.get("target") or candidate.get("output_dir") or ""
            )
        )
        candidate["project"] = _project_name_from_repo_url(
            str(candidate.get("repo_url") or ""), str(fallback or "")
        )
        return candidate

    def get_poc_terminal_candidate(self, run_id: int, vuln_id: str) -> dict | None:
        """Resolve one reproduced PoC to its server-owned working directory."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT v.run_id, v.vuln_id, v.title, v.dedupe_key,
                       r.repo_name, r.output_dir, p.status AS poc_status,
                       p.report_path AS poc_report_path,
                       d.report_path AS disclosure_report_path
                FROM vulnerabilities v
                JOIN runs r ON r.id = v.run_id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                LEFT JOIN disclosures d
                  ON d.run_id = v.run_id AND d.vuln_id = v.vuln_id
                WHERE v.run_id = ? AND v.vuln_id = ?
                  AND p.status = 'reproduced'
                """,
                (run_id, vuln_id),
            ).fetchone()
        if row is None:
            return None
        candidate = dict(row)
        output_dir = os.path.realpath(candidate["output_dir"])

        def registered_file(value: object) -> str | None:
            if not isinstance(value, str) or not value or "\x00" in value:
                return None
            resolved = os.path.realpath(
                value if os.path.isabs(value) else os.path.join(output_dir, value)
            )
            if not resolved.startswith(output_dir + os.sep):
                return None
            return resolved if os.path.isfile(resolved) else None

        artifacts = []
        for label, value in (
            ("Stage 6 Report", candidate.get("disclosure_report_path")),
            ("Stage 5 Report", candidate.get("poc_report_path")),
        ):
            report_file = registered_file(value)
            if report_file:
                artifacts.append({"label": label, "path": report_file})
        terminal_paths = _terminal_paths(artifacts)
        if terminal_paths is None or terminal_paths[0] != output_dir:
            return None
        candidate["poc_dir"] = terminal_paths[1]
        candidate["poc_report_path"] = terminal_paths[2]
        return candidate

    def get_target_merged(self, target_key: str) -> dict | None:
        """Merged view of all runs sharing one target identity.

        Reproduced vulnerabilities from every run are unioned (they carry
        their source run id). Distinct analysis units are merged across all
        runs, with identical definitions collapsed and attributed to every
        source run.
        """
        runs, total = self.list_runs(limit=1000, target_key=target_key)
        if total == 0:
            return None
        vulns: list[dict] = []
        with self._connect() as conn:
            run_ids = [r["id"] for r in runs]
            placeholders = ",".join("?" * len(run_ids))
            statuses = sorted(REPRODUCED_STATUSES)
            status_placeholders = ",".join("?" * len(statuses))
            rows = conn.execute(
                f"""
                SELECT v.*, p.status AS poc_status, p.report_path AS poc_report_path,
                       d.report_path AS disclosure_report_path,
                       d.zip_path AS disclosure_zip_path
                FROM vulnerabilities v
                JOIN pocs p ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                LEFT JOIN disclosures d ON d.run_id = v.run_id AND d.vuln_id = v.vuln_id
                WHERE v.run_id IN ({placeholders})
                  AND p.status IN ({status_placeholders})
                """,
                (*run_ids, *statuses),
            ).fetchall()
            vulns = [dict(r) for r in rows]
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        vulns.sort(
            key=lambda v: (
                severity_rank.get(v.get("severity") or "", 4),
                -(v.get("cvss_score") or 0.0),
                v["run_id"],
                v["vuln_id"],
            )
        )
        return {
            "target_key": target_key,
            "runs": runs,
            "vulnerabilities": vulns,
            "analysis_units": self.merged_analysis_units(target_key),
        }

    def latest_analysis_units(self, target_key: str) -> list[dict]:
        """Analysis units from the most recent run with this target identity."""
        if not target_key:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM analysis_units
                WHERE target_key = ? AND run_id = (
                    SELECT MAX(run_id) FROM analysis_units WHERE target_key = ?
                )
                ORDER BY au_id
                """,
                (target_key, target_key),
            ).fetchall()
        return [dict(row) for row in rows]

    def merged_analysis_units(self, target_key: str) -> list[dict]:
        """Merge distinct AU definitions from every run of one target.

        Runs are considered newest-first. An AU is identical only when its
        description, normalized file list, and focus all match; overlapping
        file lists with different audit guidance remain separate work units.
        Each result carries its source run/AU pairs and receives a stable,
        sequential merged AU id suitable for seeding a new output directory.
        """
        if not target_key:
            return []
        with self._connect() as conn:
            rows = [
                dict(row)
                for row in conn.execute(
                    """
                    SELECT * FROM analysis_units
                    WHERE target_key = ?
                    ORDER BY run_id DESC
                    """,
                    (target_key,),
                ).fetchall()
            ]

        rows.sort(key=lambda au: (-au["run_id"], natural_sort_key(au["au_id"])))
        merged: list[dict] = []
        by_definition: dict[tuple[str, tuple[str, ...], str], dict] = {}
        for au in rows:
            try:
                stored_files = json.loads(au["files"] or "[]")
            except (TypeError, json.JSONDecodeError):
                stored_files = []
            files = tuple(sorted(set(_as_list(stored_files))))
            definition = (
                (au.get("description") or "").strip(),
                files,
                (au.get("focus") or "").strip(),
            )
            source = {"run_id": au["run_id"], "au_id": au["au_id"]}
            existing = by_definition.get(definition)
            if existing is not None:
                existing["source_units"].append(source)
                continue

            item = dict(au)
            item["original_au_id"] = au["au_id"]
            item["source_units"] = [source]
            by_definition[definition] = item
            merged.append(item)

        for index, au in enumerate(merged, start=1):
            au["au_id"] = f"AU-{index}"
        return merged

    def seed_analysis_units(self, target_key: str, output_dir: str) -> int:
        """Copy a previous run's analysis units into a fresh output directory.

        Stage 2's resume logic validates and reuses existing AU files, so
        seeding lets a new audit of the same repo+commit skip decomposition.
        Returns the number of seeded files (0 when nothing was seeded).
        """
        if not target_key:
            return 0
        result_dir = Path(output_dir) / "stage2-analysis-units"
        if result_dir.is_dir() and list(result_dir.glob("AU-*.json")):
            return 0
        aus = self.merged_analysis_units(target_key)
        if not aus:
            return 0
        result_dir.mkdir(parents=True, exist_ok=True)
        for au in aus:
            (result_dir / f"{au['au_id']}.json").write_text(
                au["raw_json"], encoding="utf-8"
            )
        return len(aus)

    # ── Database-backed Disclosure catalogue ───────────────────────────

    def _entry_has_local_disclosure_report(self, entry: dict[str, Any]) -> bool:
        return entry.get("has_disclosure_report") is True

    def list_cve_import_candidates(self) -> list[dict[str, Any]]:
        """Return confirmed local Disclosures that can be associated with a CVE."""
        result = []
        for entry in self.list_disclosed():
            if (
                not self._entry_has_local_disclosure_report(entry)
                or entry.get("review_status") != "confirmed"
            ):
                continue
            result.append(
                {
                    "dedupe_key": entry["dedupe_key"],
                    "project": entry["project"],
                    "title": entry.get("title") or "",
                    "review_status": entry.get("review_status") or "unreviewed",
                    "location": entry.get("location") or "",
                    "trigger": entry.get("trigger") or "",
                    "repo_url": entry.get("repo_url") or "",
                    "artifacts": entry.get("artifacts") or [],
                }
            )
        return result

    def import_cve(self, record: dict[str, Any]) -> dict[str, Any]:
        """Create or replace one CVE explicitly linked to local disclosures."""
        dedupe_keys = list(dict.fromkeys(record.get("dedupe_keys") or []))
        available = {
            entry["dedupe_key"]: entry for entry in self.list_cve_import_candidates()
        }
        missing = [key for key in dedupe_keys if key not in available]
        if not dedupe_keys or missing:
            raise ValueError(
                "Every selected vulnerability must be confirmed and have a local "
                "Stage 6 disclosure report."
            )
        selected = [available[key] for key in dedupe_keys]
        project_names = {entry["project"].casefold() for entry in selected}
        if len(project_names) != 1:
            raise ValueError("All selected vulnerabilities must belong to one project.")

        cve_id = str(record["cve_id"])
        project = selected[0]["project"]
        project_url = str(record.get("project_url") or selected[0]["repo_url"] or "")
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cves (
                    cve_id, project, year, cvss_score, severity,
                    project_url, cve_url, reference_links, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    project = excluded.project,
                    year = excluded.year,
                    cvss_score = excluded.cvss_score,
                    severity = excluded.severity,
                    project_url = excluded.project_url,
                    cve_url = excluded.cve_url,
                    reference_links = excluded.reference_links,
                    updated_at = excluded.updated_at
                """,
                (
                    cve_id,
                    project,
                    int(cve_id.split("-")[1]),
                    record.get("cvss_score"),
                    record.get("severity") or "",
                    project_url,
                    record["cve_url"],
                    json.dumps(record.get("references") or [], ensure_ascii=False),
                    now,
                ),
            )
            conn.execute("DELETE FROM cve_links WHERE cve_id = ?", (cve_id,))
            conn.executemany(
                "INSERT INTO cve_links (cve_id, dedupe_key) VALUES (?, ?)",
                [(cve_id, dedupe_key) for dedupe_key in dedupe_keys],
            )
        return next(entry for entry in self.list_cves() if entry["cve_id"] == cve_id)

    def update_cve(self, cve_id: str, record: dict[str, Any]) -> dict[str, Any] | None:
        """Update an existing CVE while keeping its identifier immutable."""
        with self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        if exists is None:
            return None
        return self.import_cve({**record, "cve_id": cve_id})

    def list_cves(self, project: str | None = None) -> list[dict]:
        """Return manually imported CVEs backed by local disclosure reports."""
        local_disclosures = {
            entry["dedupe_key"]: entry for entry in self.list_cve_import_candidates()
        }
        with self._connect() as conn:
            if project:
                rows = conn.execute(
                    "SELECT * FROM cves WHERE lower(project) = lower(?)",
                    (project,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM cves").fetchall()
            links = conn.execute("SELECT cve_id, dedupe_key FROM cve_links").fetchall()
            candidates = conn.execute(
                """
                SELECT l.cve_id, v.run_id, v.vuln_id, v.title, v.dedupe_key,
                       r.repo_name, r."commit", r.output_dir,
                       p.report_path AS poc_report_path
                FROM cve_links l
                JOIN vulnerabilities v ON v.dedupe_key = l.dedupe_key
                JOIN runs r ON r.id = v.run_id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                WHERE p.status = 'reproduced'
                ORDER BY v.run_id DESC, v.vuln_id
                """
            ).fetchall()

        keys_by_cve: dict[str, list[str]] = {}
        for link in links:
            if link["dedupe_key"] in local_disclosures:
                keys_by_cve.setdefault(link["cve_id"], []).append(link["dedupe_key"])
        pocs_by_cve: dict[str, list[dict]] = {}
        seen_pocs: set[tuple[str, int, str]] = set()
        for raw in candidates:
            item = dict(raw)
            identity = (item["cve_id"], item["run_id"], item["vuln_id"])
            if identity in seen_pocs:
                continue
            seen_pocs.add(identity)
            pocs_by_cve.setdefault(item.pop("cve_id"), []).append(item)

        result = []
        for raw in rows:
            item = dict(raw)
            if item["cve_id"] not in keys_by_cve:
                continue
            try:
                item["references"] = json.loads(item.pop("reference_links") or "[]")
            except json.JSONDecodeError:
                item["references"] = []
            item.pop("updated_at", None)
            item["dedupe_keys"] = keys_by_cve.get(item["cve_id"], [])
            item["project"] = local_disclosures[item["dedupe_keys"][0]]["project"]
            item["local_disclosures"] = [
                local_disclosures[key] for key in item["dedupe_keys"]
            ]
            item["confirmed_disclosures"] = [
                entry
                for entry in item["local_disclosures"]
                if entry.get("review_status") == "confirmed"
            ]
            item["pocs"] = pocs_by_cve.get(item["cve_id"], [])
            result.append(item)

        def cve_sort_key(item: dict) -> tuple[int, int]:
            parts = item["cve_id"].split("-")
            return (-int(parts[1]), -int(parts[2]))

        result.sort(key=cve_sort_key)
        return result

    def list_disclosed(
        self,
        status: str | None = None,
        project: str | None = None,
        search: str | None = None,
        *,
        trashed: bool = False,
    ) -> list[dict]:
        self.purge_expired_disclosures()
        deletion_filter = "deleted_at IS NOT NULL" if trashed else "deleted_at IS NULL"
        with self._connect() as conn:
            entries = [
                dict(row)
                for row in conn.execute(
                    f"""
                SELECT * FROM disclosed_bugs
                WHERE {deletion_filter}
                ORDER BY project, audit_finished_date DESC, id
                """
                ).fetchall()
            ]
        with self._connect() as conn:
            cve_rows = conn.execute(
                """
                SELECT l.dedupe_key, c.cve_id, c.cve_url
                FROM cve_links l JOIN cves c ON c.cve_id = l.cve_id
                ORDER BY c.cve_id
                """
            ).fetchall()
            poc_rows = conn.execute(
                """
                SELECT v.dedupe_key, v.run_id, v.vuln_id, v.title,
                       p.report_path AS poc_report_path, r.output_dir,
                       r.repo_name, r.repo_url, r.target
                FROM vulnerabilities v
                JOIN runs r ON r.id = v.run_id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                WHERE p.status = 'reproduced'
                ORDER BY v.run_id DESC
                """
            ).fetchall()
            history_rows = conn.execute(
                """
                SELECT v.dedupe_key, v.run_id, v.vuln_id, v.title,
                       r."commit", r.repo_name, r.repo_url, r.target, r.output_dir,
                       p.status AS poc_status
                FROM vulnerabilities v
                JOIN runs r ON r.id = v.run_id
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                WHERE p.status = 'reproduced'
                ORDER BY v.run_id DESC, v.vuln_id
                """
            ).fetchall()
        cves_by_key: dict[str, list[dict[str, str]]] = {}
        keys_by_cve: dict[str, list[str]] = {}
        for cve in cve_rows:
            cves_by_key.setdefault(cve["dedupe_key"], []).append(
                {"cve_id": cve["cve_id"], "cve_url": cve["cve_url"]}
            )
            keys_by_cve.setdefault(cve["cve_id"], []).append(cve["dedupe_key"])
        history_by_identity: dict[tuple[str, str], list[dict]] = {}
        for raw in history_rows:
            source = dict(raw)
            identity = (_run_project(source), source["dedupe_key"])
            for field in ("repo_name", "repo_url", "target", "output_dir"):
                source.pop(field, None)
            history_by_identity.setdefault(identity, []).append(source)
        poc_by_key: dict[tuple[str, str], dict] = {}
        for poc in poc_rows:
            report_path = _registered_stage5_report(
                str(poc["output_dir"] or ""), poc["poc_report_path"]
            )
            if report_path is None:
                # A stale historical ``reproduced`` row without a retained
                # report is not a runnable Terminal target.  Leave it out so
                # the Disclosure view can show the explicit missing reason.
                continue
            item = dict(poc)
            identity = (_run_project(item), poc["dedupe_key"])
            for field in ("repo_name", "repo_url", "target", "output_dir"):
                item.pop(field, None)
            poc_by_key.setdefault(identity, item)
        latest_reproductions: dict[tuple[str, str], dict] = {}
        for reproduction in self.list_reproductions():
            latest_reproductions.setdefault(
                (reproduction["project"], reproduction["dedupe_key"]),
                reproduction,
            )
        for row in entries:
            identity = (row["project"], row["dedupe_key"])
            row["history_sources"] = history_by_identity.get(identity, [])
            try:
                artifacts = json.loads(row.pop("artifact_links") or "[]")
            except (json.JSONDecodeError, TypeError):
                artifacts = []
            terminal_paths = _terminal_paths(artifacts)
            row["has_disclosure_report"] = _has_local_disclosure_report(artifacts)
            row["artifacts"] = [
                {"index": index, "label": artifact.get("label") or "Artifact"}
                for index, artifact in enumerate(artifacts)
                if isinstance(artifact, dict) and artifact.get("path")
            ]
            row["terminal"] = (
                {
                    "vuln_id": terminal_paths[3],
                    "title": row.get("title") or terminal_paths[3],
                }
                if terminal_paths is not None and not trashed
                else None
            )
            row["cves"] = (
                cves_by_key.get(row.get("dedupe_key") or "", [])
                if row.get("review_status") == "confirmed"
                else []
            )
            row["poc"] = poc_by_key.get(identity)
            row["latest_reproduction"] = latest_reproductions.get(
                (str(row.get("project") or ""), str(row.get("dedupe_key") or ""))
            )
            if row["poc"] is None:
                for cve in row["cves"]:
                    row["poc"] = next(
                        (
                            poc_by_key[(row["project"], key)]
                            for key in keys_by_cve.get(cve["cve_id"], [])
                            if (row["project"], key) in poc_by_key
                        ),
                        None,
                    )
                    if row["poc"] is not None:
                        break
        if status:
            entries = [row for row in entries if row["review_status"] == status]
        if project:
            entries = [row for row in entries if row["project"] == project]
        terms = (search or "").casefold().split()
        if terms:
            filtered: list[dict] = []
            for row in entries:
                values = [
                    row.get("project"),
                    row.get("title"),
                    row.get("location"),
                    row.get("cwe"),
                    row.get("vulnerability_class"),
                    row.get("trigger"),
                    row.get("summary"),
                    row.get("repo_url"),
                    row.get("audited_commit"),
                    row.get("audit_finished_date"),
                    row.get("model_backend"),
                    row.get("review_status"),
                    row.get("dedupe_key"),
                ]
                values.extend(
                    value
                    for cve in row.get("cves") or []
                    for value in (cve.get("cve_id"), cve.get("cve_url"))
                )
                values.extend(
                    value
                    for source in row.get("history_sources") or []
                    for value in (f"Run #{source['run_id']}", source["vuln_id"], source["title"])
                )
                poc = row.get("terminal") or row.get("poc") or {}
                values.extend((poc.get("run_id"), poc.get("vuln_id"), poc.get("title")))
                values.extend(
                    artifact.get("label") for artifact in row.get("artifacts") or []
                )
                haystack = "\n".join(
                    str(value).casefold() for value in values if value is not None
                )
                if all(term in haystack for term in terms):
                    filtered.append(row)
            entries = filtered
        return entries

    def list_disclosure_trash(
        self,
        project: str | None = None,
        search: str | None = None,
    ) -> list[dict]:
        """Return recoverable Disclosure records awaiting expiry."""
        entries = self.list_disclosed(project=project, search=search, trashed=True)
        for entry in entries:
            deleted_at = float(entry.get("deleted_at") or 0)
            entry["purge_at"] = deleted_at + DISCLOSURE_TRASH_RETENTION_SECONDS
        return entries

    def purge_expired_disclosures(self, *, now: float | None = None) -> int:
        """Permanently remove Disclosure records after the trash retention period."""
        with self._connect() as conn:
            return self._purge_expired_disclosures(
                conn, time.time() if now is None else now
            )

    def purge_all_trashed_disclosures(self) -> int:
        """Permanently remove every Disclosure record currently in the trash."""
        with self._connect() as conn:
            return self._purge_expired_disclosures(
                conn, time.time() + DISCLOSURE_TRASH_RETENTION_SECONDS + 1
            )

    def purge_trashed_disclosures(self, identities: Iterable[tuple[str, str]]) -> int:
        """Permanently remove selected Disclosure records from the trash."""
        selected = {
            (str(project), str(dedupe_key))
            for project, dedupe_key in identities
            if project and dedupe_key
        }
        if not selected:
            return 0
        with self._connect() as conn:
            return self._purge_expired_disclosures(
                conn,
                time.time() + DISCLOSURE_TRASH_RETENTION_SECONDS + 1,
                selected,
            )

    def trash_disclosure(
        self,
        project: str,
        dedupe_key: str,
        *,
        deleted_at: float | None = None,
    ) -> bool:
        """Move one active Disclosure into recoverable trash."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE disclosed_bugs
                SET deleted_at = ?, updated_at = ?
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (
                    time.time() if deleted_at is None else deleted_at,
                    time.time(),
                    project,
                    dedupe_key,
                ),
            )
        return cursor.rowcount > 0

    def restore_disclosure(self, project: str, dedupe_key: str) -> bool:
        """Restore one Disclosure from trash with its prior status intact."""
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE disclosed_bugs
                SET deleted_at = NULL, updated_at = ?
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NOT NULL
                """,
                (time.time(), project, dedupe_key),
            )
        return cursor.rowcount > 0

    def disclosure_dedupe_index(self) -> list[dict[str, str]]:
        """Return minimal database metadata used by Stage 6 deduplication."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT dedupe_key, title, location, cwe,
                       vulnerability_class, trigger, summary
                FROM disclosed_bugs
                ORDER BY project, id
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def get_disclosed_terminal_candidate(
        self, project: str, dedupe_key: str
    ) -> dict | None:
        """Resolve one Disclosure's registered Stage 5 report directory."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT project, title, artifact_links
                FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (project, dedupe_key),
            ).fetchone()
        if row is None:
            return None
        try:
            artifacts = json.loads(row["artifact_links"] or "[]")
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(artifacts, list):
            return None
        terminal_paths = _terminal_paths(artifacts)
        if terminal_paths is None:
            return None
        output_dir, poc_dir, report_file, vuln_id = terminal_paths

        run_id = 0
        poc_status = ""
        with self._connect() as conn:
            run_rows = conn.execute(
                """
                SELECT r.id, r.output_dir, p.status AS poc_status
                FROM runs r
                LEFT JOIN pocs p
                  ON p.run_id = r.id AND p.vuln_id = ?
                ORDER BY r.id DESC
                """,
                (vuln_id,),
            ).fetchall()
        for run_row in run_rows:
            if os.path.realpath(run_row["output_dir"] or "") == output_dir:
                run_id = int(run_row["id"])
                poc_status = run_row["poc_status"] or ""
                break
        return {
            "run_id": run_id,
            "vuln_id": vuln_id,
            "title": row["title"] or vuln_id,
            "project": row["project"] or "",
            "dedupe_key": dedupe_key,
            "output_dir": output_dir,
            "poc_dir": poc_dir,
            "poc_report_path": report_file,
            "poc_status": poc_status,
        }

    def get_disclosed_artifact(
        self, project: str, dedupe_key: str, artifact_index: int
    ) -> dict | None:
        """Resolve one indexed artifact from a database Disclosure record."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT artifact_links FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (project, dedupe_key),
            ).fetchone()
        if row is None:
            return None
        try:
            artifacts = json.loads(row["artifact_links"] or "[]")
        except (json.JSONDecodeError, TypeError):
            return None
        if (
            not isinstance(artifacts, list)
            or artifact_index < 0
            or artifact_index >= len(artifacts)
            or not isinstance(artifacts[artifact_index], dict)
        ):
            return None
        artifact = artifacts[artifact_index]
        path = artifact.get("path")
        if not isinstance(path, str) or not path:
            return None
        return {"label": artifact.get("label") or "Artifact", "path": path}

    def disclosed_summary(self) -> dict:
        entries = self.list_disclosed()
        counts: dict[str, int] = {}
        for entry in entries:
            review_status = entry["review_status"]
            counts[review_status] = counts.get(review_status, 0) + 1
        projects = sorted({entry["project"] for entry in entries})
        return {"counts": counts, "projects": projects}

    def set_disclosed_status(self, project: str, dedupe_key: str, status: str) -> bool:
        """Persist one disclosure review status exclusively in SQLite."""
        if status not in DISCLOSURE_REVIEW_STATUSES:
            return False
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE disclosed_bugs SET review_status = ?, updated_at = ?
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (status, time.time(), project, dedupe_key),
            )
            if cursor.rowcount > 0 and status != "confirmed":
                conn.execute(
                    "DELETE FROM cve_links WHERE dedupe_key = ?", (dedupe_key,)
                )
                conn.execute(
                    """
                    DELETE FROM cves
                    WHERE NOT EXISTS (
                        SELECT 1 FROM cve_links
                        WHERE cve_links.cve_id = cves.cve_id
                    )
                    """
                )
        return cursor.rowcount > 0

    def update_disclosed_entry(
        self,
        project: str,
        dedupe_key: str,
        metadata: dict[str, str],
        *,
        cve_ids: list[str] | None = None,
    ) -> bool:
        """Update metadata and, for confirmed records, CVE associations atomically."""
        fields = (
            "title",
            "location",
            "cwe",
            "vulnerability_class",
            "trigger",
            "summary",
            "repo_url",
            "audited_commit",
            "audit_finished_date",
            "model_backend",
        )
        values = [str(metadata.get(field) or "") for field in fields]
        assignments = ", ".join(f"{field} = ?" for field in fields)
        with self._connect() as conn:
            disclosed = conn.execute(
                """
                SELECT review_status FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (project, dedupe_key),
            ).fetchone()
            if disclosed is None:
                return False

            normalized_cve_ids = (
                list(dict.fromkeys(cve_ids)) if cve_ids is not None else None
            )
            if normalized_cve_ids is not None:
                if disclosed["review_status"] != "confirmed":
                    raise ValueError(
                        "CVE associations can only be edited for confirmed Disclosures."
                    )
                placeholders = ", ".join("?" for _ in normalized_cve_ids)
                cve_rows = (
                    conn.execute(
                        f"SELECT cve_id, project FROM cves "
                        f"WHERE cve_id IN ({placeholders})",
                        normalized_cve_ids,
                    ).fetchall()
                    if normalized_cve_ids
                    else []
                )
                found = {row["cve_id"]: row["project"] for row in cve_rows}
                missing = [
                    cve_id for cve_id in normalized_cve_ids if cve_id not in found
                ]
                if missing:
                    raise ValueError(f"Unknown CVE: {', '.join(missing)}")
                wrong_project = [
                    cve_id
                    for cve_id, cve_project in found.items()
                    if str(cve_project).casefold() != project.casefold()
                ]
                if wrong_project:
                    raise ValueError(
                        "CVE project does not match this Disclosure: "
                        + ", ".join(wrong_project)
                    )

            cursor = conn.execute(
                f"""
                UPDATE disclosed_bugs
                SET {assignments}, updated_at = ?
                WHERE project = ? AND dedupe_key = ? AND deleted_at IS NULL
                """,
                (*values, time.time(), project, dedupe_key),
            )
            if normalized_cve_ids is not None:
                conn.execute(
                    "DELETE FROM cve_links WHERE dedupe_key = ?", (dedupe_key,)
                )
                conn.executemany(
                    "INSERT INTO cve_links (cve_id, dedupe_key) VALUES (?, ?)",
                    [(cve_id, dedupe_key) for cve_id in normalized_cve_ids],
                )
        return cursor.rowcount > 0
