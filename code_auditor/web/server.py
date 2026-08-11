"""FastAPI application for the CodeAuditor web UI."""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
from contextlib import asynccontextmanager, suppress
from datetime import date
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..db import (
    DEFAULT_DB_PATH,
    DISCLOSURE_TRASH_RETENTION_DAYS,
    AuditStore,
)
from ..logger import configure_logging, get_logger
from ..repos import RepoError, list_cloned_repos, validate_remote_repo_url
from ..wikis import list_local_wikis
from .job import (
    JOB_AUDIT,
    JOB_REPRODUCTION,
    STATE_RUNNING,
    AuditJobManager,
    AuditStartParams,
    JobConflictError,
    JobValidationError,
    ReproductionStartParams,
)
from .settings import (
    DEFAULT_SETTINGS_PATH,
    WebSettings,
    load_web_settings,
)
from .terminal import serve_poc_terminal

logger = get_logger("web.server")

STATIC_DIR = Path(__file__).parent / "static"

_AGENT_LOG_PATTERNS = (
    "stage1-security-context/agent.log",
    "stage2-analysis-units/agent.log",
    "stage3-findings/logs/*.log",
    "stage5-pocs/*/agent.log",
    "stage6-disclosures/*/agent.log",
)

_REPOSITORY_NAME_PATTERN = r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
_VULN_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9_-]{0,63}$"
_DEDUPE_KEY_PATTERN = r"^sha256:[0-9a-f]{64}$"
DisclosureStatus = Literal[
    "unreviewed",
    "reported",
    "confirmed",
    "rejected",
    "duplicated",
    "triage",
    "bug",
    "slop",
]


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AuditStartRequest(StrictRequest):
    repository: str | None = Field(
        default=None, min_length=1, max_length=512, pattern=_REPOSITORY_NAME_PATTERN
    )
    git_url: str | None = Field(default=None, min_length=1, max_length=2048)
    wiki: str | None = Field(
        default=None, min_length=1, max_length=512, pattern=_REPOSITORY_NAME_PATTERN
    )
    max_parallel: int = Field(default=1, ge=1, le=16)

    @field_validator("repository", "wiki")
    @classmethod
    def validate_repository_segments(cls, value: str | None) -> str | None:
        if value is not None and any(
            segment in {".", ".."} for segment in value.split("/")
        ):
            raise ValueError("selection cannot contain dot path segments")
        return value


class ReproductionStartRequest(StrictRequest):
    run_id: int = Field(ge=1, le=9_223_372_036_854_775_807)
    vuln_id: str = Field(min_length=1, max_length=64, pattern=_VULN_ID_PATTERN)


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _scan_results(output_dir: str) -> dict:
    """List audit artifacts under the output directory (relative paths)."""
    base = Path(output_dir)

    def rel(pattern: str) -> list[str]:
        if not base.is_dir():
            return []
        return sorted(
            str(p.relative_to(base)) for p in base.glob(pattern) if p.is_file()
        )

    return {
        "output_dir": output_dir,
        "vulnerabilities": rel("stage4-vulnerabilities/*.json"),
        "poc_reports": rel("stage5-pocs/*/report.md"),
        "disclosures": rel("stage6-disclosures/*/disclosure/*"),
        "agent_logs": [
            str(path.relative_to(base)) for path in _agent_log_paths(output_dir)
        ],
    }


def _agent_log_paths(output_dir: str) -> list[Path]:
    base = Path(output_dir)
    if not base.is_dir():
        return []
    paths = {
        path
        for pattern in _AGENT_LOG_PATTERNS
        for path in base.glob(pattern)
        if path.is_file()
    }
    return sorted(paths, key=lambda path: (path.stat().st_mtime, str(path)))


def _latest_agent_log(output_dir: str) -> tuple[Path, str] | None:
    paths = _agent_log_paths(output_dir)
    if not paths:
        return None
    path = paths[-1]
    return path, str(path.relative_to(Path(output_dir)))


def _count_json_files(base: Path, pattern: str) -> int:
    directory = base / pattern.split("/")[0]
    if not directory.is_dir():
        return 0
    return sum(1 for p in base.glob(pattern) if p.is_file())


def _run_stage_summary(run: dict) -> list[dict]:
    """Reconstruct per-stage status for a finished run from on-disk evidence.

    Live runs get stage updates from the progress reporter instead; this
    summary lets the History detail page show Stages for completed, failed,
    cancelled, and imported runs. Completion is derived from checkpoint
    markers (``.markers/``), falling back to artifact presence for runs that
    predate marker-based tracking.
    """
    base = Path(run.get("output_dir") or "")
    markers: set[str] = set()
    markers_dir = base / ".markers"
    if markers_dir.is_dir():
        markers = {p.name for p in markers_dir.iterdir() if p.is_file()}

    au_total = len(run.get("analysis_units") or [])
    findings_total = _count_json_files(base, "stage3-findings/*.json")
    vuln_total = len(run.get("vulnerabilities") or []) + len(
        run.get("poc_issues") or []
    )
    reproduced_total = int(run.get("reproduced_vulns_count") or 0)
    failed = run.get("status") == "failed"

    def entry(
        stage: int,
        done: bool,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> dict:
        if done:
            status = "done"
        elif failed and items_done > 0:
            status = "failed"
        else:
            status = "pending"
        return {
            "stage": stage,
            "status": status,
            "detail": detail,
            "items_done": items_done,
            "items_total": items_total,
        }

    def marked(prefix: str, total: int, artifacts_exist: bool) -> tuple[bool, int]:
        done_count = sum(1 for name in markers if name.startswith(prefix))
        if done_count == 0 and not markers:
            # Run predates checkpoint markers: fall back to artifact presence.
            return artifacts_exist, total if artifacts_exist else 0
        return total > 0 and done_count >= total, done_count

    s3_done, s3_count = marked("stage3-", au_total, findings_total > 0)
    s4_done, s4_count = marked("stage4-", findings_total, vuln_total > 0)
    s5_done, s5_count = marked("stage5-", vuln_total, vuln_total > 0)
    disclosures_exist = (base / "stage6-disclosures").is_dir() and any(
        (base / "stage6-disclosures").iterdir()
    )
    s6_done, s6_count = marked("stage6-", reproduced_total, disclosures_exist)

    return [
        entry(0, base.is_dir()),
        entry(
            1,
            (base / "stage1-security-context" / "stage-1-security-context.json").is_file(),
        ),
        entry(2, "stage2" in markers or au_total > 0, au_total, au_total),
        entry(3, s3_done, min(s3_count, au_total), au_total),
        entry(4, s4_done, min(s4_count, findings_total), findings_total),
        entry(5, s5_done, min(s5_count, vuln_total), vuln_total),
        entry(6, s6_done, min(s6_count, reproduced_total), reproduced_total),
    ]


def _resolve_output_file(output_dir: str, rel_path: str) -> str:
    if (
        not rel_path
        or len(rel_path) > 4096
        or "\x00" in rel_path
        or os.path.isabs(rel_path)
    ):
        raise HTTPException(status_code=400, detail="Invalid output file path.")
    base = os.path.realpath(output_dir)
    full = os.path.realpath(os.path.join(base, rel_path))
    if full != base and not full.startswith(base + os.sep):
        raise HTTPException(status_code=400, detail="Path escapes the output directory.")
    if not os.path.isfile(full):
        raise HTTPException(status_code=404, detail=f"File not found: {rel_path}")
    return full


def _resolve_managed_repository(repository: str, repos_dir: str) -> str:
    """Resolve an opaque repository name against the managed checkout list."""
    for candidate in list_cloned_repos(repos_dir):
        if candidate["name"] == repository:
            return candidate["path"]
    raise HTTPException(
        status_code=400,
        detail="Selected repository is not present in the managed repository list.",
    )


def _resolve_managed_wiki(wiki: str, wikis_dir: str) -> str:
    """Resolve an opaque Wiki name against the managed local Wiki list."""
    for candidate in list_local_wikis(wikis_dir):
        if candidate["name"] == wiki:
            return candidate["path"]
    raise HTTPException(
        status_code=400,
        detail="Selected Wiki is not present in the managed local Wiki list.",
    )


def _resolve_managed_import_path(path: str, results_dir: str) -> str:
    if "\x00" in path:
        raise HTTPException(status_code=400, detail="Invalid import path.")
    resolved = os.path.realpath(os.path.expanduser(path))
    root = os.path.realpath(results_dir)
    if resolved != root and not resolved.startswith(root + os.sep):
        raise HTTPException(
            status_code=400,
            detail=f"Import path must stay under the managed results directory: {root}",
        )
    if not os.path.isdir(resolved):
        raise HTTPException(status_code=400, detail=f"Directory not found: {resolved}")
    return resolved


def _is_managed_path(path: str, root: str) -> bool:
    resolved = os.path.realpath(path)
    managed_root = os.path.realpath(root)
    return resolved == managed_root or resolved.startswith(managed_root + os.sep)


def _websocket_origin_allowed(websocket: WebSocket) -> bool:
    """Reject browser WebSockets initiated by a different web origin."""
    origin = websocket.headers.get("origin")
    if not origin:
        return True
    parsed = urlsplit(origin)
    return parsed.scheme in {"http", "https"} and parsed.netloc == websocket.headers.get(
        "host", ""
    )


class ImportRequest(StrictRequest):
    output_dir: str = Field(min_length=1, max_length=4096)


class DisclosureStatusRequest(StrictRequest):
    project: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
    )
    dedupe_key: str = Field(
        min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
    )
    status: DisclosureStatus


class DisclosureIdentityRequest(StrictRequest):
    project: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
    )
    dedupe_key: str = Field(
        min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
    )


class DisclosureUpdateRequest(StrictRequest):
    project: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
    )
    dedupe_key: str = Field(
        min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
    )
    title: str = Field(default="", max_length=512)
    location: str = Field(default="", max_length=4096)
    cwe: str = Field(default="", max_length=512)
    vulnerability_class: str = Field(default="", max_length=1024)
    trigger: str = Field(default="", max_length=8192)
    summary: str = Field(default="", max_length=16384)
    repo_url: str = Field(default="", max_length=2048)
    audited_commit: str = Field(default="", max_length=256)
    audit_finished_date: str = Field(
        default="", max_length=10, pattern=r"^(?:|[0-9]{4}-[0-9]{2}-[0-9]{2})$"
    )
    model_backend: str = Field(default="", max_length=256)
    cve_ids: list[str] | None = Field(default=None, max_length=32)

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL must use http or https")
        return value

    @field_validator("audit_finished_date")
    @classmethod
    def validate_audit_date(cls, value: str) -> str:
        if value:
            date.fromisoformat(value)
        return value

    @field_validator("cve_ids", mode="before")
    @classmethod
    def normalize_cve_ids(cls, values: object) -> object:
        if values is None or not isinstance(values, list):
            return values
        normalized = [
            value.strip().upper() if isinstance(value, str) else value
            for value in values
        ]
        if any(
            not isinstance(value, str)
            or re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", value) is None
            for value in normalized
        ):
            raise ValueError("invalid CVE ID")
        return list(dict.fromkeys(normalized))


class CveReferenceRequest(StrictRequest):
    label: str = Field(min_length=1, max_length=256)
    url: str = Field(min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL must use http or https")
        return value


class CveImportRequest(StrictRequest):
    cve_id: str = Field(
        min_length=13, max_length=32, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$"
    )
    dedupe_keys: list[str] = Field(min_length=1, max_length=32)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    severity: Literal["", "low", "medium", "high", "critical"] = ""
    cve_url: str = Field(default="", max_length=2048)
    project_url: str = Field(default="", max_length=2048)
    reference_label: str = Field(default="", max_length=256)
    reference_url: str = Field(default="", max_length=2048)
    references: list[CveReferenceRequest] = Field(default_factory=list, max_length=32)

    @field_validator("cve_id", mode="before")
    @classmethod
    def normalize_cve_id(cls, value: object) -> object:
        return value.strip().upper() if isinstance(value, str) else value

    @field_validator("dedupe_keys")
    @classmethod
    def validate_dedupe_keys(cls, values: list[str]) -> list[str]:
        if any(re.fullmatch(_DEDUPE_KEY_PATTERN, value) is None for value in values):
            raise ValueError("invalid vulnerability identity")
        return values

    @field_validator("cve_url", "project_url", "reference_url")
    @classmethod
    def validate_http_url(cls, value: str) -> str:
        if not value:
            return value
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL must use http or https")
        return value


def _cve_references(request: CveImportRequest) -> list[dict[str, str]]:
    """Normalize the current multi-reference form and legacy single reference."""
    has_legacy_reference = bool(request.reference_label or request.reference_url)
    if request.references and has_legacy_reference:
        raise HTTPException(
            status_code=400,
            detail="Use either references or the legacy reference fields, not both.",
        )
    if bool(request.reference_label) != bool(request.reference_url):
        raise HTTPException(
            status_code=400,
            detail="Reference label and URL must be provided together.",
        )
    if request.references:
        return [reference.model_dump() for reference in request.references]
    return (
        [{"label": request.reference_label, "url": request.reference_url}]
        if request.reference_url
        else []
    )


def create_app(
    defaults: dict | None = None,
    db_path: str | None = None,
    *,
    web_settings: WebSettings | None = None,
    config_path: str = DEFAULT_SETTINGS_PATH,
) -> FastAPI:
    defaults = defaults or {}
    settings = web_settings or load_web_settings(config_path)
    store = AuditStore(
        db_path or defaults.get("db_path") or DEFAULT_DB_PATH,
        managed_results_dir=settings.results_dir,
    )

    async def purge_disclosure_trash() -> None:
        while True:
            await asyncio.sleep(3600)
            try:
                purged = await asyncio.to_thread(store.purge_expired_disclosures)
                if purged:
                    logger.info(
                        "Permanently removed %d expired Disclosure records and "
                        "linked Stage 6 artifacts.",
                        purged,
                    )
            except Exception:
                logger.exception("Failed to purge expired Disclosure trash records.")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        manager.recover_interrupted_runs()
        purge_task = asyncio.create_task(purge_disclosure_trash())
        try:
            yield
        finally:
            await manager.shutdown()
            purge_task.cancel()
            with suppress(asyncio.CancelledError):
                await purge_task

    app = FastAPI(title="CodeAuditor", lifespan=lifespan)
    app.state.store = store
    app.state.web_settings = settings
    manager = AuditJobManager(store=store)
    app.state.manager = manager
    app.state.terminal_token = secrets.token_urlsafe(32)
    app.state.active_terminals = 0

    @app.middleware("http")
    async def require_web_asset_revalidation(request, call_next):
        """Prevent an old app.js from being paired with a newer index page."""
        response = await call_next(request)
        if request.url.path == "/":
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/api/config")
    async def get_config() -> dict:
        return {
            "defaults": {
                "git_url": defaults.get("git_url") or "",
                "max_parallel": settings.max_parallel,
            },
            "config_path": settings.config_path,
            "repos_dir": settings.repos_dir,
            "wikis_dir": settings.wikis_dir,
            "results_dir": settings.results_dir,
            "terminal_enabled": True,
            "terminal_token": app.state.terminal_token,
        }

    @app.post("/api/audit", status_code=202)
    async def start_audit(request: AuditStartRequest) -> dict:
        if bool(request.repository) == bool(request.git_url):
            raise HTTPException(
                status_code=400,
                detail="Select exactly one existing repository or Git repository URL.",
            )
        target = None
        git_url = None
        wiki_path = (
            _resolve_managed_wiki(request.wiki, settings.wikis_dir)
            if request.wiki
            else None
        )
        if request.repository:
            target = _resolve_managed_repository(
                request.repository, settings.repos_dir
            )
        else:
            try:
                git_url = validate_remote_repo_url(request.git_url or "")
            except RepoError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        try:
            await manager.start(
                AuditStartParams(
                    target=target,
                    git_url=git_url,
                    wiki=wiki_path,
                    max_parallel=request.max_parallel,
                    backend=settings.backend,
                    target_au_count=-1,
                    log_level=settings.log_level,
                    repos_dir=settings.repos_dir,
                    results_dir=settings.results_dir,
                )
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return manager.status()

    @app.post("/api/audit/stop")
    async def stop_audit() -> dict:
        if manager.kind != JOB_AUDIT or not manager.stop():
            raise HTTPException(status_code=409, detail="No audit is running.")
        return manager.status()

    @app.get("/api/audit/status")
    async def audit_status() -> dict:
        return manager.status()

    @app.get("/api/audit/events")
    async def audit_events() -> StreamingResponse:
        queue = manager.bus.subscribe()

        async def stream():
            try:
                for event in manager.bus.backlog():
                    yield _sse(event)
                while True:
                    event = await queue.get()
                    yield _sse(event)
            except asyncio.CancelledError:
                pass
            finally:
                manager.bus.unsubscribe(queue)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/api/results")
    async def results() -> dict:
        if manager.config is None:
            raise HTTPException(status_code=404, detail="No audit has been started yet.")
        return _scan_results(manager.config.output_dir)

    @app.get("/api/results/file")
    async def result_file(
        path: str = Query(min_length=1, max_length=4096)
    ) -> PlainTextResponse:
        if manager.config is None:
            raise HTTPException(status_code=404, detail="No audit has been started yet.")
        full = _resolve_output_file(manager.config.output_dir, path)
        try:
            content = Path(full).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return PlainTextResponse(content)

    @app.get("/api/results/agent-log")
    async def latest_agent_log(download: bool = Query(default=False)):
        if manager.config is None:
            raise HTTPException(status_code=404, detail="No audit has been started yet.")
        latest = _latest_agent_log(manager.config.output_dir)
        if latest is None:
            raise HTTPException(status_code=404, detail="No Agent log is available yet.")
        path, relative_path = latest
        if download:
            return FileResponse(
                path,
                media_type="text/plain; charset=utf-8",
                filename=f"{path.parent.name}-{path.name}",
            )
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return PlainTextResponse(
            content,
            headers={"X-CodeAuditor-Log-Path": relative_path},
        )

    # ── Standalone reproduction ────────────────────────────────────────────

    @app.get("/api/reproduction/candidates")
    def reproduction_candidates() -> dict:
        candidates = store.list_reproduction_candidates()
        return {"candidates": candidates, "total": len(candidates)}

    # ── CVE catalogue and interactive PoC terminals ───────────────────────

    @app.get("/api/cves")
    def list_cves(
        project: str | None = Query(
            default=None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9._-]+$",
        ),
    ) -> dict:
        entries = store.list_cves(project=project)
        return {
            "entries": entries,
            "total": len(entries),
            "projects": sorted({entry["project"] for entry in store.list_cves()}),
        }

    @app.get("/api/cves/candidates")
    def cve_import_candidates() -> dict:
        entries = store.list_cve_import_candidates()
        return {"entries": entries, "total": len(entries)}

    @app.post("/api/cves", status_code=201)
    def import_cve(request: CveImportRequest) -> dict:
        references = _cve_references(request)
        try:
            entry = store.import_cve(
                {
                    "cve_id": request.cve_id,
                    "dedupe_keys": request.dedupe_keys,
                    "cvss_score": request.cvss_score,
                    "severity": request.severity,
                    "cve_url": request.cve_url
                    or f"https://www.cve.org/CVERecord?id={request.cve_id}",
                    "project_url": request.project_url,
                    "references": references,
                }
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return {"entry": entry}

    @app.put("/api/cves/{cve_id}")
    def update_cve(cve_id: str, request: CveImportRequest) -> dict:
        normalized_id = cve_id.strip().upper()
        if normalized_id != request.cve_id:
            raise HTTPException(status_code=400, detail="CVE ID cannot be changed.")
        references = _cve_references(request)
        try:
            entry = store.update_cve(
                normalized_id,
                {
                    "dedupe_keys": request.dedupe_keys,
                    "cvss_score": request.cvss_score,
                    "severity": request.severity,
                    "cve_url": request.cve_url
                    or f"https://www.cve.org/CVERecord?id={normalized_id}",
                    "project_url": request.project_url,
                    "references": references,
                },
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        if entry is None:
            raise HTTPException(status_code=404, detail="CVE not found.")
        return {"entry": entry}

    @app.websocket("/ws/terminal/{run_id}/{vuln_id}")
    async def poc_terminal(
        websocket: WebSocket,
        run_id: int,
        vuln_id: str,
        token: str = Query(default="", max_length=128),
    ) -> None:
        if (
            not hmac.compare_digest(token, app.state.terminal_token)
            or not _websocket_origin_allowed(websocket)
        ):
            await websocket.close(code=1008, reason="Terminal authorization failed.")
            return
        if (
            run_id < 1
            or re.fullmatch(_VULN_ID_PATTERN, vuln_id) is None
            or app.state.active_terminals >= 16
        ):
            await websocket.close(code=1008, reason="Invalid terminal request.")
            return
        candidate = store.get_poc_terminal_candidate(run_id, vuln_id)
        if candidate is None or not (
            _is_managed_path(candidate["output_dir"], settings.results_dir)
            and _is_managed_path(candidate["poc_dir"], settings.results_dir)
        ):
            await websocket.close(code=1008, reason="PoC terminal target not found.")
            return
        app.state.active_terminals += 1
        try:
            await serve_poc_terminal(websocket, candidate)
        finally:
            app.state.active_terminals -= 1

    @app.websocket("/ws/disclosure-terminal")
    async def disclosure_terminal(
        websocket: WebSocket,
        project: str = Query(
            min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
        ),
        dedupe_key: str = Query(
            min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
        ),
        token: str = Query(default="", max_length=128),
    ) -> None:
        if (
            not hmac.compare_digest(token, app.state.terminal_token)
            or not _websocket_origin_allowed(websocket)
        ):
            await websocket.close(code=1008, reason="Terminal authorization failed.")
            return
        if app.state.active_terminals >= 16:
            await websocket.close(code=1008, reason="Invalid terminal request.")
            return
        candidate = store.get_disclosed_terminal_candidate(project, dedupe_key)
        if candidate is None or not (
            _is_managed_path(candidate["output_dir"], settings.results_dir)
            and _is_managed_path(candidate["poc_dir"], settings.results_dir)
        ):
            await websocket.close(
                code=1008, reason="Disclosure terminal target not found."
            )
            return
        app.state.active_terminals += 1
        try:
            await serve_poc_terminal(websocket, candidate)
        finally:
            app.state.active_terminals -= 1

    @app.post("/api/reproduction", status_code=202)
    async def start_reproduction(request: ReproductionStartRequest) -> dict:
        try:
            await manager.start_reproduction(
                ReproductionStartParams(
                    run_id=request.run_id,
                    vuln_id=request.vuln_id,
                    backend=settings.backend,
                    log_level=settings.log_level,
                    reproductions_dir=settings.reproductions_dir,
                    wikis_dir=settings.wikis_dir,
                )
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return manager.status()

    @app.post("/api/reproduction/stop")
    async def stop_reproduction() -> dict:
        if manager.kind != JOB_REPRODUCTION or not manager.stop():
            raise HTTPException(status_code=409, detail="No reproduction is running.")
        return manager.status()

    @app.get("/api/reproduction/status")
    async def reproduction_status() -> dict:
        return manager.status()

    @app.get("/api/reproduction/results")
    async def reproduction_results() -> dict:
        if manager.kind != JOB_REPRODUCTION or manager.config is None:
            raise HTTPException(
                status_code=404, detail="No reproduction has been started yet."
            )
        return _scan_results(manager.config.output_dir)

    @app.get("/api/reproduction/results/file")
    async def reproduction_result_file(
        path: str = Query(min_length=1, max_length=4096),
    ) -> PlainTextResponse:
        if manager.kind != JOB_REPRODUCTION or manager.config is None:
            raise HTTPException(
                status_code=404, detail="No reproduction has been started yet."
            )
        full = _resolve_output_file(manager.config.output_dir, path)
        try:
            content = Path(full).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return PlainTextResponse(content)

    # ── History (SQLite-backed) ──────────────────────────────────────────

    def _get_history_run(run_id: int) -> dict:
        run = store.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        run["stages"] = _run_stage_summary(run)
        return run

    @app.get("/api/repos")
    def list_repos() -> dict:
        """Cloned repositories available for selection as audit targets."""
        return {
            "repos_dir": settings.repos_dir,
            "repos": [
                {"name": repo["name"]}
                for repo in list_cloned_repos(settings.repos_dir)
            ],
        }

    @app.get("/api/wikis")
    def list_wikis() -> dict:
        """Local Wiki knowledge bases available for optional audit context."""
        return {
            "wikis_dir": settings.wikis_dir,
            "wikis": [
                {"name": wiki["name"]}
                for wiki in list_local_wikis(settings.wikis_dir)
            ],
        }

    @app.get("/api/history")
    def list_history(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        repository: str | None = Query(
            default=None,
            min_length=1,
            max_length=512,
            pattern=_REPOSITORY_NAME_PATTERN,
        ),
        target_key: str | None = Query(
            default=None, min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
        ),
    ) -> dict:
        target = (
            _resolve_managed_repository(repository, settings.repos_dir)
            if repository
            else None
        )
        runs, total = store.list_runs(
            limit=limit, offset=offset, target=target, target_key=target_key
        )
        return {"runs": runs, "total": total, "db_path": store.db_path}

    @app.get("/api/history/{run_id}")
    def history_run(run_id: int) -> dict:
        return _get_history_run(run_id)

    @app.post("/api/history/{run_id}/resume", status_code=202)
    async def resume_history_run(run_id: int) -> dict:
        _get_history_run(run_id)
        try:
            await manager.resume_cancelled(
                run_id,
                repos_dir=settings.repos_dir,
                results_dir=settings.results_dir,
                wikis_dir=settings.wikis_dir,
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return manager.status()

    @app.get("/api/target/{target_key:path}")
    def target_merged(target_key: str) -> dict:
        if re.fullmatch(_DEDUPE_KEY_PATTERN, target_key) is None:
            raise HTTPException(status_code=400, detail="Invalid target key.")
        merged = store.get_target_merged(target_key)
        if merged is None:
            raise HTTPException(status_code=404, detail="Target not found.")
        return merged

    @app.get("/api/history/{run_id}/results")
    def history_run_results(run_id: int) -> dict:
        """Artifact file listing for a recorded run (History detail page)."""
        run = _get_history_run(run_id)
        return _scan_results(run["output_dir"])

    @app.get("/api/history/{run_id}/file")
    def history_run_file(
        run_id: int,
        path: str = Query(min_length=1, max_length=4096),
        download: bool = Query(default=False),
    ):
        run = _get_history_run(run_id)
        full = _resolve_output_file(run["output_dir"], path)
        if download:
            return FileResponse(
                full,
                media_type="application/octet-stream",
                filename=Path(full).name,
            )
        try:
            content = Path(full).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        return PlainTextResponse(content)

    @app.post("/api/history/import", status_code=201)
    def import_history(request: ImportRequest) -> dict:
        path = _resolve_managed_import_path(
            request.output_dir, settings.results_dir
        )
        try:
            if _looks_like_output_dir(path):
                run_ids = [store.import_output_dir(path)]
            else:
                run_ids = store.import_results_tree(path)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        runs = [run for run in (store.get_run(i) for i in run_ids) if run is not None]
        return {"imported": len(runs), "runs": runs}

    # ── Database-backed Disclosure catalogue ────────────────────────────

    @app.get("/api/disclosures")
    def list_disclosures(
        status: DisclosureStatus | None = Query(default=None),
        project: str | None = Query(
            default=None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9._-]+$",
        ),
        q: str | None = Query(default=None, max_length=256),
    ) -> dict:
        entries = store.list_disclosed(status=status, project=project, search=q)
        return {
            "entries": entries,
            "matches": len(entries),
            "query": (q or "").strip(),
            **store.disclosed_summary(),
        }

    @app.get("/api/disclosures/artifact")
    def disclosure_artifact(
        project: str = Query(
            min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
        ),
        dedupe_key: str = Query(
            min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
        ),
        artifact: int = Query(ge=0, le=32),
    ) -> FileResponse:
        resolved = store.get_disclosed_artifact(project, dedupe_key, artifact)
        if resolved is None:
            raise HTTPException(status_code=404, detail="Disclosure artifact not found.")
        path = resolved["path"]
        if not _is_managed_path(path, settings.results_dir) or not os.path.isfile(path):
            raise HTTPException(status_code=404, detail="Disclosure artifact not found.")
        return FileResponse(path, filename=os.path.basename(path))

    @app.post("/api/disclosures/status")
    def set_disclosure_status(request: DisclosureStatusRequest) -> dict:
        if not store.set_disclosed_status(
            request.project, request.dedupe_key, request.status
        ):
            raise HTTPException(status_code=404, detail="Disclosed bug not found.")
        return {"ok": True, **store.disclosed_summary()}

    @app.get("/api/disclosures/trash")
    def list_disclosure_trash(
        project: str | None = Query(
            default=None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9._-]+$",
        ),
        q: str | None = Query(default=None, max_length=256),
    ) -> dict:
        entries = store.list_disclosure_trash(project=project, search=q)
        all_entries = (
            store.list_disclosure_trash()
            if project is not None or (q or "").strip()
            else entries
        )
        return {
            "entries": entries,
            "matches": len(entries),
            "total": len(all_entries),
            "projects": sorted({entry["project"] for entry in all_entries}),
            "retention_days": DISCLOSURE_TRASH_RETENTION_DAYS,
        }

    @app.post("/api/disclosures/trash")
    def trash_disclosure(request: DisclosureIdentityRequest) -> dict:
        moved = store.trash_disclosure(request.project, request.dedupe_key)
        if not moved:
            raise HTTPException(status_code=404, detail="Disclosure not found.")
        return {
            "ok": True,
            "retention_days": DISCLOSURE_TRASH_RETENTION_DAYS,
            **store.disclosed_summary(),
        }

    @app.post("/api/disclosures/restore")
    def restore_disclosure(request: DisclosureIdentityRequest) -> dict:
        if not store.restore_disclosure(request.project, request.dedupe_key):
            raise HTTPException(
                status_code=404, detail="Disclosure trash record not found."
            )
        return {"ok": True, **store.disclosed_summary()}

    @app.post("/api/disclosures/trash/purge")
    def purge_all_disclosure_trash() -> dict:
        removed = store.purge_all_trashed_disclosures()
        return {"ok": True, "removed": removed, **store.disclosed_summary()}

    @app.put("/api/disclosures")
    def update_disclosure(request: DisclosureUpdateRequest) -> dict:
        metadata = request.model_dump(exclude={"project", "dedupe_key", "cve_ids"})
        try:
            updated = store.update_disclosed_entry(
                request.project,
                request.dedupe_key,
                metadata,
                cve_ids=request.cve_ids,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        if not updated:
            raise HTTPException(status_code=404, detail="Disclosed bug not found.")
        entry = next(
            (
                item
                for item in store.list_disclosed(project=request.project)
                if item["dedupe_key"] == request.dedupe_key
            ),
            None,
        )
        return {"entry": entry}

    return app


_OUTPUT_STAGE_DIRS = ("stage3-findings", "stage4-vulnerabilities", "stage5-pocs")


def _looks_like_output_dir(path: str) -> bool:
    if os.path.basename(path).startswith("audit-output"):
        return True
    return any(os.path.isdir(os.path.join(path, d)) for d in _OUTPUT_STAGE_DIRS)


def run_web_server(host: str, port: int, defaults: dict | None = None) -> None:
    """Blocking entry point for ``code-auditor --web``."""
    import uvicorn

    defaults = defaults or {}
    settings = load_web_settings()
    configure_logging(settings.log_level)
    app = create_app(defaults, web_settings=settings)

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    logger.info("Web UI available at http://%s:%d", display_host, port)
    asyncio.run(server.serve())
