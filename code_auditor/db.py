"""SQLite persistence for audit runs and their artifacts.

Every audit (CLI, TUI, or web mode) is recorded in a local SQLite database
(default ``~/.code_auditor/audits.db``, override with ``--db``). Run metadata
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
from typing import Any

from .config import AuditConfig
from .disclosures import build_dedupe_key, extract_email_subject
from .logger import get_logger
from .poc_artifacts import (
    ASAN_REPORT_FILENAME,
    TRIGGER_GRAPH_FILENAME,
    load_trigger_graph,
)
from .repos import DEFAULT_REPOS_DIR, capture_repo_identity, list_cloned_repos
from .reproduction_status import REPRODUCED_STATUSES, read_reproduction_status
from .utils import natural_sort_key

DEFAULT_DB_PATH = os.path.join("~", ".code_auditor", "audits.db")

RUN_RUNNING = "running"
RUN_DONE = "done"
RUN_FAILED = "failed"
RUN_CANCELLED = "cancelled"
RUN_IMPORTED = "imported"
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
    error TEXT DEFAULT '',
    started_at REAL,
    ended_at REAL,
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


# Extra run-identity columns added after the initial schema; migrated via
# ALTER TABLE in AuditStore._init_schema for existing databases.
_RUN_EXTRA_COLUMNS = {
    "repo_name": '"repo_name" TEXT DEFAULT \'\'',
    "repo_url": '"repo_url" TEXT DEFAULT \'\'',
    "branch": '"branch" TEXT DEFAULT \'\'',
    "commit": '"commit" TEXT DEFAULT \'\'',
    "dirty": '"dirty" INTEGER DEFAULT 0',
    "submodules": '"submodules" TEXT DEFAULT \'[]\'',
    "target_key": '"target_key" TEXT DEFAULT \'\'',
    "models_used": '"models_used" TEXT DEFAULT \'[]\'',
    "usage_stats": '"usage_stats" TEXT DEFAULT \'{}\'',
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
        if (
            not isinstance(artifact, dict)
            or artifact.get("label") != "Stage 5 Report"
        ):
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

    for path in sorted((base / "stage3-findings").glob("*.json")) if (base / "stage3-findings").is_dir() else []:
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
            result["pocs"].append(
                {
                    "vuln_id": vuln_id,
                    "status": status,
                    "report_path": str(report.relative_to(base)),
                    "trigger_graph_path": trigger_graph_path,
                    "asan_report_path": (
                        str(asan_report.relative_to(base))
                        if asan_report.is_file()
                        else ""
                    ),
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

            result["disclosures"].append(
                {
                    "vuln_id": entry.name,
                    "report_path": _rel("report.md"),
                    "email_path": _rel("email.txt"),
                    "zip_path": _rel("disclosure.zip"),
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

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            existing = {
                row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()
            }
            for column, ddl in _RUN_EXTRA_COLUMNS.items():
                if column not in existing:
                    conn.execute(f"ALTER TABLE runs ADD COLUMN {ddl}")
            poc_existing = {
                row[1] for row in conn.execute("PRAGMA table_info(pocs)").fetchall()
            }
            if "trigger_graph_path" not in poc_existing:
                conn.execute("ALTER TABLE pocs ADD COLUMN trigger_graph_path TEXT")
            if "asan_report_path" not in poc_existing:
                conn.execute("ALTER TABLE pocs ADD COLUMN asan_report_path TEXT")
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
            if (
                not isinstance(artifact, dict)
                or not str(artifact.get("label") or "").startswith("Stage 6 ")
            ):
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

    def _purge_expired_disclosures(
        self, conn: sqlite3.Connection, now: float
    ) -> int:
        cutoff = now - DISCLOSURE_TRASH_RETENTION_SECONDS
        expired = conn.execute(
            """
            SELECT project, dedupe_key, artifact_links FROM disclosed_bugs
            WHERE deleted_at IS NOT NULL AND deleted_at <= ?
            """,
            (cutoff,),
        ).fetchall()
        if not expired:
            return 0

        registered_stage6_runs: dict[str, list[int]] = {}
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
            registered_stage6_runs.setdefault(stage6_dir, []).append(int(row["id"]))
        registered_stage6_dirs = set(registered_stage6_runs)
        protected_dirs: set[str] = set()
        for row in conn.execute(
            """
            SELECT artifact_links FROM disclosed_bugs
            WHERE deleted_at IS NULL OR deleted_at > ?
            """,
            (cutoff,),
        ).fetchall():
            protected_dirs.update(
                self._stage6_disclosure_dirs(
                    row["artifact_links"] or "[]", registered_stage6_dirs
                )
            )

        purgeable: list[tuple[str, str]] = []
        deleted_disclosure_dirs: set[str] = set()
        for row in expired:
            disclosure_dirs = self._stage6_disclosure_dirs(
                row["artifact_links"] or "[]", registered_stage6_dirs
            ) - protected_dirs
            try:
                for disclosure_dir in disclosure_dirs:
                    if os.path.lexists(disclosure_dir):
                        shutil.rmtree(disclosure_dir)
            except OSError as exc:
                logger.warning(
                    "Retaining expired Disclosure %s/%s because Stage 6 "
                    "cleanup failed: %s",
                    row["project"],
                    row["dedupe_key"],
                    exc,
                )
                continue
            deleted_disclosure_dirs.update(disclosure_dirs)
            purgeable.append((str(row["project"]), str(row["dedupe_key"])))

        if not purgeable:
            return 0
        removed = 0
        for project, dedupe_key in purgeable:
            cursor = conn.execute(
                """
                DELETE FROM disclosed_bugs
                WHERE project = ? AND dedupe_key = ?
                  AND deleted_at IS NOT NULL AND deleted_at <= ?
                """,
                (project, dedupe_key, cutoff),
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
        for run_id in affected_run_ids:
            conn.execute(
                """
                UPDATE runs SET disclosures_count = (
                    SELECT COUNT(*) FROM disclosures WHERE disclosures.run_id = runs.id
                ) WHERE id = ?
                """,
                (run_id,),
            )
        self._clear_nonconfirmed_cve_links(conn)
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
        conn.execute(
            "CREATE INDEX idx_disclosed_project ON disclosed_bugs(project)"
        )

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
    ) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO runs (
                    target, output_dir, wiki_path,
                    backend, model, max_parallel, target_au_count, log_level,
                    status, started_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    started_at,
                    time.time(),
                ),
            )
            return int(cursor.lastrowid)

    def finish_run(
        self,
        run_id: int,
        status: str,
        error: str = "",
        ended_at: float | None = None,
        models_used: list[str] | None = None,
        usage_stats: dict[str, float] | None = None,
    ) -> None:
        finished_at = ended_at or time.time()
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
                "UPDATE runs SET status = ?, error = ?, ended_at = ? WHERE id = ?",
                (status, error, finished_at, run_id),
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
        if row and row["output_dir"]:
            self.persist_artifacts(run_id, row["output_dir"])

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
                SET status = ?, error = ?, ended_at = ?
                WHERE id = ? AND status = ?
                """,
                (RUN_CANCELLED, error, finished_at, run_id, RUN_RUNNING),
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
                    "SELECT id FROM runs WHERE status = ? ORDER BY id",
                    (RUN_RUNNING,),
                ).fetchall()
            ]
            if run_ids:
                conn.execute(
                    """
                    UPDATE runs
                    SET status = ?, error = ?, ended_at = ?
                    WHERE status = ?
                    """,
                    (RUN_CANCELLED, error, finished_at, RUN_RUNNING),
                )
        return run_ids

    def resume_cancelled_run(self, run_id: int) -> bool:
        """Atomically move one resumable run back to the running state.

        Resumable means cancelled, failed, or done with recorded task errors
        (partial failure). The original row and ``started_at`` are preserved
        so History keeps one lifecycle for a checkpoint-resumed audit instead
        of inventing a second audit record for the same output tree.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE runs
                SET status = ?, error = '', ended_at = NULL
                WHERE id = ? AND (status IN (?, ?) OR (status = ? AND error != ''))
                """,
                (RUN_RUNNING, run_id, RUN_CANCELLED, RUN_FAILED, RUN_DONE),
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
        """One-shot persistence for CLI/TUI runs: create row + scan artifacts."""
        run_id = self.create_run(config, status=status, started_at=started_at)
        identity = capture_repo_identity(config.target)
        if identity["commit"]:
            self.set_run_identity(run_id, identity)
        with self._connect() as conn:
            conn.execute(
                "UPDATE runs SET error = ?, ended_at = ?, models_used = ?, usage_stats = ? WHERE id = ?",
                (
                    error,
                    ended_at or time.time(),
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
        config = AuditConfig(target=target, output_dir=output_dir)
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO runs (target, output_dir, status, started_at, ended_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (target, output_dir, RUN_IMPORTED, started_at, latest_mtime, time.time()),
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
                    (run_id, *[finding[k] for k in (
                        "finding_key", "au_id", "title", "location",
                        "vulnerability_class", "root_cause",
                        "preliminary_severity", "raw_json",
                    )]),
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
                    (run_id, *[vuln[k] for k in (
                        "vuln_id", "severity", "cvss_score", "title", "location",
                        "trigger", "cwe_ids", "vulnerability_class", "entry_point",
                        "sink", "propagation_chain", "neutralizing_checks",
                        "prerequisites", "impact", "code_snippet", "dedupe_key",
                        "raw_json",
                    )]),
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
                        run_id, vuln_id, report_path, email_path, zip_path
                    ) VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        disclosure["vuln_id"],
                        disclosure["report_path"],
                        disclosure["email_path"],
                        disclosure["zip_path"],
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
                    sum(
                        1
                        for d in artifacts["disclosures"]
                        if d["report_path"]
                    ),
                    run_id,
                ),
            )
            self._sync_disclosures_from_run(conn, run_id, output_dir)

    @staticmethod
    def _sync_disclosures_from_run(
        conn: sqlite3.Connection, run_id: int, output_dir: str
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

        rows = conn.execute(
            """
            SELECT v.vuln_id, v.title, v.location, v.trigger, v.cwe_ids,
                   v.vulnerability_class, v.dedupe_key, v.raw_json,
                   d.report_path, d.email_path, d.zip_path,
                   p.report_path AS poc_report_path,
                   p.trigger_graph_path, p.asan_report_path,
                   p.status AS p_status,
                   r.repo_name, r.repo_url, r.target, r."commit",
                   r.backend, r.ended_at, r.started_at, r.created_at
            FROM disclosures d
            JOIN vulnerabilities v
              ON v.run_id = d.run_id AND v.vuln_id = d.vuln_id
            JOIN runs r ON r.id = d.run_id
            LEFT JOIN pocs p
              ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
            WHERE d.run_id = ? AND d.report_path != ''
            """,
            (run_id,),
        ).fetchall()
        reproduced = REPRODUCED_STATUSES
        # Remove any previously-synced entries for this run whose PoC is no
        # longer reproduced (e.g. re-runs that flipped to false-positive).
        non_reproduced_keys = [
            row["dedupe_key"]
            for row in rows
            if row["dedupe_key"] and (row["p_status"] not in reproduced)
        ]
        if non_reproduced_keys:
            placeholders = ",".join("?" * len(non_reproduced_keys))
            conn.execute(
                f"DELETE FROM disclosed_bugs WHERE dedupe_key IN ({placeholders})",
                non_reproduced_keys,
            )
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
            trigger_graph_path = resolved_file(row["trigger_graph_path"])
            asan_report_path = resolved_file(row["asan_report_path"])
            finding_path = resolved_file(
                os.path.join(
                    "stage4-vulnerabilities", f"{row['vuln_id']}.json"
                )
            )
            artifacts = []
            for label, path in (
                ("Stage 4 Finding", finding_path),
                ("Stage 5 Report", poc_path),
                ("Stage 5 Trigger Graph", trigger_graph_path),
                ("Stage 5 ASan Report", asan_report_path),
                ("Stage 6 Report", report_path),
                ("Stage 6 Email", email_path),
                ("Stage 6 Zip", zip_path),
            ):
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
                    summary = CASE WHEN excluded.summary != ''
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
    ) -> tuple[list[dict], int]:
        clauses = []
        args: list = []
        if target:
            clauses.append("r.target = ?")
            args.append(target)
        if target_key:
            clauses.append("r.target_key = ?")
            args.append(target_key)
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
        return [dict(row) for row in rows], total

    def get_run(self, run_id: int) -> dict | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            run = dict(row)
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

    def list_reproduction_candidates(self) -> list[dict]:
        """List vulnerabilities with an exactly reproduced PoC.

        ``partially-reproduced`` is intentionally excluded: it is treated as
        an unsuccessful reproduction throughout the Web UI and disclosure
        pipeline.
        """
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
        return dict(row) if row is not None else None

    def get_poc_terminal_candidate(
        self, run_id: int, vuln_id: str
    ) -> dict | None:
        """Resolve one reproduced PoC to its server-owned working directory."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT v.run_id, v.vuln_id, v.title, v.dedupe_key,
                       r.repo_name, r.output_dir, p.status AS poc_status,
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
        output_dir = os.path.realpath(candidate["output_dir"])
        report_path = candidate.get("poc_report_path") or ""
        report_file = os.path.realpath(os.path.join(output_dir, report_path))
        poc_dir = os.path.dirname(report_file)
        if (
            not report_path
            or not os.path.isfile(report_file)
            or (poc_dir != output_dir and not poc_dir.startswith(output_dir + os.sep))
        ):
            return None
        candidate["poc_dir"] = poc_dir
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
        poc_by_run: dict[int, dict[str, dict]] = {}
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

    def prune_cves_without_local_disclosures(self) -> dict[str, int]:
        """Remove stale CVEs and links that have no local Stage 6 report."""
        valid_keys = {
            entry["dedupe_key"] for entry in self.list_cve_import_candidates()
        }
        with self._connect() as conn:
            links = conn.execute("SELECT cve_id, dedupe_key FROM cve_links").fetchall()
            invalid_links = [
                (link["cve_id"], link["dedupe_key"])
                for link in links
                if link["dedupe_key"] not in valid_keys
            ]
            conn.executemany(
                "DELETE FROM cve_links WHERE cve_id = ? AND dedupe_key = ?",
                invalid_links,
            )
            before = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
            conn.execute(
                "DELETE FROM cves WHERE NOT EXISTS "
                "(SELECT 1 FROM cve_links WHERE cve_links.cve_id = cves.cve_id)"
            )
            after = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        return {"cves": before - after, "links": len(invalid_links)}

    def list_cves(self, project: str | None = None) -> list[dict]:
        """Return manually imported CVEs backed by local disclosure reports."""
        local_disclosures = {
            entry["dedupe_key"]: entry
            for entry in self.list_cve_import_candidates()
        }
        with self._connect() as conn:
            if project:
                rows = conn.execute(
                    "SELECT * FROM cves WHERE lower(project) = lower(?)",
                    (project,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM cves").fetchall()
            links = conn.execute(
                "SELECT cve_id, dedupe_key FROM cve_links"
            ).fetchall()
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
                       p.report_path AS poc_report_path
                FROM vulnerabilities v
                JOIN pocs p
                  ON p.run_id = v.run_id AND p.vuln_id = v.vuln_id
                WHERE p.status = 'reproduced'
                ORDER BY v.run_id DESC
                """
            ).fetchall()
        cves_by_key: dict[str, list[dict[str, str]]] = {}
        keys_by_cve: dict[str, list[str]] = {}
        for cve in cve_rows:
            cves_by_key.setdefault(cve["dedupe_key"], []).append(
                {"cve_id": cve["cve_id"], "cve_url": cve["cve_url"]}
            )
            keys_by_cve.setdefault(cve["cve_id"], []).append(cve["dedupe_key"])
        poc_by_key: dict[str, dict] = {}
        for poc in poc_rows:
            poc_by_key.setdefault(poc["dedupe_key"], dict(poc))
        for row in entries:
            try:
                artifacts = json.loads(row.pop("artifact_links") or "[]")
            except (json.JSONDecodeError, TypeError):
                artifacts = []
            terminal_paths = _stage5_terminal_paths(artifacts)
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
            row["poc"] = poc_by_key.get(row.get("dedupe_key") or "")
            if row["poc"] is None:
                for cve in row["cves"]:
                    row["poc"] = next(
                        (
                            poc_by_key[key]
                            for key in keys_by_cve.get(cve["cve_id"], [])
                            if key in poc_by_key
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
                poc = row.get("terminal") or row.get("poc") or {}
                values.extend(
                    (poc.get("run_id"), poc.get("vuln_id"), poc.get("title"))
                )
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
        terminal_paths = _stage5_terminal_paths(artifacts)
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

    def set_disclosed_status(
        self, project: str, dedupe_key: str, status: str
    ) -> bool:
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
                missing = [cve_id for cve_id in normalized_cve_ids if cve_id not in found]
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
