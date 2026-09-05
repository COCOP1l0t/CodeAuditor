"""FastAPI application for the CodeAuditor web UI."""
from __future__ import annotations

import asyncio
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager, suppress
from datetime import date
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Query, Request, Response, WebSocket
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..db import (
    DEFAULT_DB_PATH,
    DISCLOSURE_TRASH_RETENTION_DAYS,
    RUN_KIND_MAINTENANCE,
    RUN_RUNNING,
    AuditStore,
)
from ..logger import configure_logging, get_logger
from ..repos import RepoError, list_cloned_repos, validate_remote_repo_url
from ..sandbox import inspect_docker_sandbox_environment
from ..wikis import list_local_wikis
from .job import (
    JOB_AUDIT,
    JOB_REPRODUCTION,
    AuditJob,
    AuditJobManager,
    AuditStartParams,
    JobConflictError,
    JobValidationError,
    ReproductionStartParams,
)
from .auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    hash_password,
    new_session_token,
    normalize_username,
    session_token_digest,
    verify_password,
)
from .local_directories import (
    LocalDirectoryPickerError,
    LocalDirectoryPickerUnavailable,
    choose_local_directory,
    validate_local_audit_target,
)
from .progress import install_web_log_handler
from .settings import (
    DEFAULT_SETTINGS_PATH,
    WebSettings,
    WebSettingsError,
    load_web_settings,
    update_agent_settings,
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
_LOCAL_DIRECTORY_TOKEN_PATTERN = r"^[A-Za-z0-9_-]{20,128}$"
_LOCAL_DIRECTORY_TOKEN_TTL_SECONDS = 10 * 60
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
RunStatus = Literal[
    "running", "done", "failed", "cancelled", "imported", "superseded"
]
RunKind = Literal["audit", "maintenance"]


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AuthCredentialsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$",
    )
    password: str = Field(min_length=12, max_length=512)


class AuditStartRequest(StrictRequest):
    repository: str | None = Field(
        default=None, min_length=1, max_length=512, pattern=_REPOSITORY_NAME_PATTERN
    )
    git_url: str | None = Field(default=None, min_length=1, max_length=2048)
    local_directory: str | None = Field(
        default=None,
        min_length=20,
        max_length=128,
        pattern=_LOCAL_DIRECTORY_TOKEN_PATTERN,
    )
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


class AgentSettingsRequest(StrictRequest):
    backend: Literal["claude", "codex"]
    mode: Literal["local", "custom"]
    base_url: str = Field(default="", max_length=2048)
    model: str = Field(default="", max_length=256)
    api_key: str | None = Field(default=None, max_length=8192)
    clear_api_key: bool = False
    sandbox_mode: Literal[
        "docker-networked", "docker-isolated", "local-worktree"
    ] | None = None


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event, ensure_ascii=False)}\n\n"


def _sse_stream(bus) -> StreamingResponse:
    """Replay the bus backlog, then stream live events until disconnect."""
    queue = bus.subscribe()

    async def stream():
        try:
            for event in bus.backlog():
                yield _sse(event)
            while True:
                event = await queue.get()
                yield _sse(event)
        except asyncio.CancelledError:
            pass
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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
    disclosures_total = int(run.get("disclosures_count") or 0)
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
    s6_done, s6_count = marked("stage6-", disclosures_total, disclosures_exist)

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
        entry(6, s6_done, min(s6_count, disclosures_total), disclosures_total),
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


def _validate_http_url(value: str) -> str:
    if not value:
        return value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must use http or https")
    return value


class ImportRequest(StrictRequest):
    output_dir: str = Field(min_length=1, max_length=4096)


class DisclosureIdentityRequest(StrictRequest):
    project: str = Field(
        min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
    )
    dedupe_key: str = Field(
        min_length=71, max_length=71, pattern=_DEDUPE_KEY_PATTERN
    )


class DisclosureStatusRequest(DisclosureIdentityRequest):
    status: DisclosureStatus


class DisclosureUpdateRequest(DisclosureIdentityRequest):
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
        return _validate_http_url(value)

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
        return _validate_http_url(value)


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
        return _validate_http_url(value)


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
    db_path: str | None = None,
    *,
    web_settings: WebSettings | None = None,
    config_path: str = DEFAULT_SETTINGS_PATH,
) -> FastAPI:
    settings = web_settings or load_web_settings(config_path)
    store = AuditStore(
        db_path or DEFAULT_DB_PATH,
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
    manager = AuditJobManager(
        store=store, max_concurrent_jobs=settings.max_concurrent_jobs
    )
    app.state.manager = manager
    app.state.terminal_token = secrets.token_urlsafe(32)
    app.state.local_directory_selections = {}
    app.state.active_terminals = 0
    # One process-wide log handler routes records to the owning job's bus.
    install_web_log_handler(manager.bus_for_job)

    _AUTH_PUBLIC_PATHS = {
        "/api/auth/status",
        "/api/auth/setup",
        "/api/auth/register",
        "/api/auth/login",
        "/api/auth/logout",
    }

    def _session_user(request) -> dict[str, object] | None:
        token = request.cookies.get(SESSION_COOKIE_NAME, "")
        if not token:
            return None
        return store.get_auth_user_by_session(session_token_digest(token))

    def _session_cookie(response: Response, token: str) -> None:
        response.set_cookie(
            SESSION_COOKIE_NAME,
            token,
            max_age=SESSION_TTL_SECONDS,
            httponly=True,
            samesite="lax",
            secure=False,
            path="/",
        )

    def _clear_session_cookie(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE_NAME, path="/")

    def _issue_session(user: dict[str, object]) -> str:
        token = new_session_token()
        now = time.time()
        store.create_auth_session(
            int(user["id"]),
            session_token_digest(token),
            created_at=now,
            expires_at=now + SESSION_TTL_SECONDS,
        )
        return token

    @app.middleware("http")
    async def require_authentication(request, call_next):
        """Require a session after first-run setup has created an account.

        Existing installations remain usable until setup is completed; this
        compatibility mode lets an operator reach ``/api/auth/setup`` without
        a migration-time lockout.  Once any account exists, every API except
        the explicit auth endpoints requires a valid session cookie.
        """
        path = request.url.path
        if path.startswith("/api/") and path not in _AUTH_PUBLIC_PATHS:
            if store.auth_user_count() > 0:
                user = _session_user(request)
                if user is None:
                    return JSONResponse(
                        {"detail": "Authentication required."},
                        status_code=401,
                        headers={"WWW-Authenticate": "Session"},
                    )
                request.state.user = user
        return await call_next(request)

    def jobs_snapshot() -> list[dict]:
        """Combine Web-owned jobs with externally owned maintenance runs."""
        jobs = [
            {**status, "controllable": True, "source": "web"}
            for status in manager.list_jobs()
        ]
        known_run_ids = {
            int(job["run_id"])
            for job in jobs
            if job.get("kind") == JOB_AUDIT and job.get("run_id") is not None
        }

        def json_value(value: object, fallback: object) -> object:
            if not isinstance(value, str):
                return value if value is not None else fallback
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError):
                return fallback
            return decoded

        for run in store.list_running_maintenance_runs():
            run_id = int(run["id"])
            if run_id in known_run_ids:
                continue
            jobs.append(
                {
                    "job_key": str(run_id),
                    "kind": RUN_KIND_MAINTENANCE,
                    "state": RUN_RUNNING,
                    "error": str(run.get("error") or ""),
                    "target": str(run.get("target") or ""),
                    "output_dir": str(run.get("output_dir") or ""),
                    "started_at": float(run.get("started_at") or 0),
                    "ended_at": float(run.get("ended_at") or 0),
                    "duration_seconds": float(run.get("duration_seconds") or 0),
                    "active_started_at": float(run.get("active_started_at") or 0),
                    "duration_known": bool(run.get("duration_known", True)),
                    "history_persist_pending": False,
                    "run_id": run_id,
                    "backend": str(run.get("backend") or ""),
                    "model": run.get("model"),
                    "backends_used": json_value(run.get("backends_used"), []),
                    "models_used": json_value(run.get("models_used"), []),
                    "usage_stats": json_value(run.get("usage_stats"), {}),
                    "stages": [],
                    "reproduction_candidate": None,
                    "reproduction_reports": [],
                    "controllable": False,
                    "source": "database",
                }
            )
        return jobs

    async def require_sandbox_environment(backend: str, sandbox_mode: str) -> None:
        if sandbox_mode == "local-worktree":
            return
        capability = await asyncio.to_thread(
            inspect_docker_sandbox_environment, backend
        )
        if not capability.available:
            raise HTTPException(
                status_code=400,
                detail=(
                    "The selected Docker sandbox is unavailable on this server: "
                    f"{capability.reason}"
                ),
            )

    @app.middleware("http")
    async def require_web_asset_revalidation(request, call_next):
        """Prevent an old app.js from being paired with a newer index page."""
        response = await call_next(request)
        if request.url.path == "/":
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        elif request.url.path.startswith("/api/auth/") or request.url.path in {
            "/api/dashboard",
            "/api/settings",
            "/api/sandbox/capability",
        } or re.fullmatch(r"/api/audit/\d+/processes", request.url.path):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/api/auth/status")
    def auth_status(request: Request) -> dict[str, object]:
        user = _session_user(request)
        return {
            "setup_required": store.auth_user_count() == 0,
            "authenticated": user is not None,
            "user": user,
        }

    @app.post("/api/auth/setup", status_code=201)
    def auth_setup(
        credentials: AuthCredentialsRequest, response: Response
    ) -> dict[str, object]:
        if store.auth_user_count() > 0:
            raise HTTPException(
                status_code=409,
                detail="Administrator setup has already been completed.",
            )
        username = normalize_username(credentials.username)
        try:
            user = store.create_initial_auth_admin(
                username, hash_password(credentials.password)
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=409,
                detail="Administrator setup has already been completed.",
            ) from exc
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail="That username is already registered."
            ) from exc
        # A pre-setup /api/config response may have exposed the old process
        # token. Rotate it as soon as authentication is initialized.
        app.state.terminal_token = secrets.token_urlsafe(32)
        _session_cookie(response, _issue_session(user))
        return {"user": user, "setup_required": False}

    @app.post("/api/auth/register", status_code=201)
    def auth_register(credentials: AuthCredentialsRequest) -> dict[str, object]:
        if store.auth_user_count() == 0:
            raise HTTPException(
                status_code=409,
                detail="Complete administrator setup before registering users.",
            )
        username = normalize_username(credentials.username)
        try:
            user = store.create_auth_user(
                username, hash_password(credentials.password), role="user"
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409, detail="That username is already registered."
            ) from exc
        return {"user": user}

    @app.post("/api/auth/login")
    def auth_login(
        credentials: AuthCredentialsRequest, response: Response
    ) -> dict[str, object]:
        username = normalize_username(credentials.username)
        record = store.get_auth_user_by_username(username)
        if (
            record is None
            or not bool(record.get("is_active"))
            or not verify_password(credentials.password, str(record["password_hash"]))
        ):
            raise HTTPException(status_code=401, detail="Invalid username or password.")
        user = {key: value for key, value in record.items() if key != "password_hash"}
        store.mark_auth_login(int(user["id"]))
        user = store.get_auth_user_by_username(username) or record
        user.pop("password_hash", None)
        _session_cookie(response, _issue_session(user))
        return {"user": AuditStore._public_user(user)}

    @app.post("/api/auth/logout")
    def auth_logout(request: Request, response: Response) -> dict[str, bool]:
        token = request.cookies.get(SESSION_COOKIE_NAME, "")
        if token:
            store.revoke_auth_session(session_token_digest(token))
        _clear_session_cookie(response)
        return {"logged_out": True}

    @app.get("/api/config")
    async def get_config() -> dict:
        return {
            "defaults": {
                "max_parallel": settings.max_parallel,
            },
            "config_path": settings.config_path,
            "repos_dir": settings.repos_dir,
            "wikis_dir": settings.wikis_dir,
            "results_dir": settings.results_dir,
            "max_concurrent_jobs": settings.max_concurrent_jobs,
            "capabilities": {"dashboard_summary": True},
            "terminal_enabled": True,
            "terminal_token": app.state.terminal_token,
        }

    @app.get("/api/settings")
    async def get_agent_settings() -> dict:
        return settings.public_agent_settings()

    @app.get("/api/dashboard")
    def get_dashboard() -> dict:
        """Compact operational summary for the Web landing page."""
        recent_runs, _total = store.list_runs(limit=6)
        return {
            **store.dashboard_summary(),
            "recent_runs": recent_runs,
            "jobs": jobs_snapshot(),
            "repositories": {
                "total": len(list_cloned_repos(settings.repos_dir)),
            },
            "runtime": {
                "backend": settings.backend,
                "sandbox_mode": settings.sandbox_mode,
            },
        }

    @app.get("/api/sandbox/capability")
    async def get_sandbox_capability(
        backend: Literal["claude", "codex"] = Query(...),
    ) -> dict:
        capability = await asyncio.to_thread(
            inspect_docker_sandbox_environment, backend
        )
        return {
            "backend": backend,
            "server_environment": True,
            "docker": capability.public(),
            "local_worktree": {
                "available": True,
                "reason": (
                    "Runs Stage 5 and 6 in a detached worktree on the server host "
                    "without Docker isolation."
                ),
            },
        }

    @app.put("/api/settings")
    async def put_agent_settings(request: AgentSettingsRequest) -> dict:
        nonlocal settings
        sandbox_mode = request.sandbox_mode or settings.sandbox_mode
        await require_sandbox_environment(request.backend, sandbox_mode)
        try:
            settings = update_agent_settings(
                settings,
                backend=request.backend,
                mode=request.mode,
                base_url=request.base_url,
                model=request.model,
                sandbox_mode=sandbox_mode,
                api_key=request.api_key,
                clear_api_key=request.clear_api_key,
            )
        except (OSError, WebSettingsError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        app.state.web_settings = settings
        provider = settings.provider()
        switched_jobs = manager.hot_switch_agent_settings(
            backend=settings.backend,  # type: ignore[arg-type]
            model=provider.model if provider.mode == "custom" else None,
            provider_mode=provider.mode,
            provider_base_url=provider.base_url or None,
            provider_api_key=provider.api_key or None,
        )
        response = settings.public_agent_settings()
        response["active_jobs_updated"] = len(switched_jobs)
        return response

    @app.post("/api/audit", status_code=202)
    async def start_audit(request: AuditStartRequest) -> dict:
        target_choices = sum(
            bool(value)
            for value in (
                request.repository,
                request.git_url,
                request.local_directory,
            )
        )
        if target_choices != 1:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Select exactly one managed repository, Git repository URL, "
                    "or local code folder."
                ),
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
        elif request.local_directory:
            selection = app.state.local_directory_selections.pop(
                request.local_directory, None
            )
            if selection is None or selection[1] < time.monotonic():
                raise HTTPException(
                    status_code=400,
                    detail="The local folder selection is missing or expired; choose it again.",
                )
            try:
                target = validate_local_audit_target(selection[0])
            except LocalDirectoryPickerError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            try:
                git_url = validate_remote_repo_url(request.git_url or "")
            except RepoError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        await require_sandbox_environment(settings.backend, settings.sandbox_mode)
        provider = settings.provider()
        try:
            job = await manager.start(
                AuditStartParams(
                    target=target,
                    git_url=git_url,
                    update_repo=not bool(request.local_directory),
                    wiki=wiki_path,
                    max_parallel=request.max_parallel,
                    backend=settings.backend,
                    model=provider.model if provider.mode == "custom" else None,
                    provider_mode=provider.mode,
                    provider_base_url=provider.base_url or None,
                    provider_api_key=provider.api_key or None,
                    target_au_count=-1,
                    log_level=settings.log_level,
                    repos_dir=settings.repos_dir,
                    results_dir=settings.results_dir,
                    sandbox_mode=settings.sandbox_mode,
                )
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return job.status()

    def _audit_job_or_404(run_id: int) -> AuditJob:
        job = manager.get_job(str(run_id))
        if job is None or job.kind != JOB_AUDIT:
            raise HTTPException(
                status_code=404,
                detail=f"No active or recent audit job for run {run_id}.",
            )
        return job

    @app.post("/api/audit/{run_id}/stop")
    async def stop_audit(run_id: int) -> dict:
        job = _audit_job_or_404(run_id)
        if not job.stop():
            raise HTTPException(status_code=409, detail="That audit is not running.")
        return job.status()

    @app.get("/api/audit/{run_id}/status")
    async def audit_status(run_id: int) -> dict:
        return _audit_job_or_404(run_id).status()

    @app.get("/api/audit/{run_id}/processes")
    async def audit_processes(run_id: int) -> dict:
        try:
            return _audit_job_or_404(run_id).process_tree()
        except JobConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/audit/{run_id}/events")
    async def audit_events(run_id: int) -> StreamingResponse:
        return _sse_stream(_audit_job_or_404(run_id).bus)

    @app.get("/api/jobs")
    async def list_jobs() -> dict:
        """Active and recently finished jobs (sidebar + History live badges)."""
        return {
            "jobs": jobs_snapshot(),
            "external_maintenance_supported": True,
        }

    @app.get("/api/jobs/events")
    async def job_events() -> StreamingResponse:
        """Run-tagged lifecycle events for every job."""
        return _sse_stream(manager.bus)

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
        await require_sandbox_environment(settings.backend, settings.sandbox_mode)
        provider = settings.provider()
        try:
            job = await manager.start_reproduction(
                ReproductionStartParams(
                    run_id=request.run_id,
                    vuln_id=request.vuln_id,
                    backend=settings.backend,
                    model=provider.model if provider.mode == "custom" else None,
                    provider_mode=provider.mode,
                    provider_base_url=provider.base_url or None,
                    provider_api_key=provider.api_key or None,
                    log_level=settings.log_level,
                    reproductions_dir=settings.reproductions_dir,
                    wikis_dir=settings.wikis_dir,
                    sandbox_mode=settings.sandbox_mode,
                )
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return job.status()

    def _reproduction_job_or_404(job_key: str) -> AuditJob:
        if re.fullmatch(r"repro-[0-9a-f]{12}", job_key) is None:
            raise HTTPException(status_code=404, detail="Reproduction job not found.")
        job = manager.get_job(job_key)
        if job is None or job.kind != JOB_REPRODUCTION:
            raise HTTPException(
                status_code=404,
                detail="No active or recent reproduction job with that id.",
            )
        return job

    @app.post("/api/reproduction/{job_key}/stop")
    async def stop_reproduction(job_key: str) -> dict:
        job = _reproduction_job_or_404(job_key)
        if not job.stop():
            raise HTTPException(
                status_code=409, detail="That reproduction is not running."
            )
        return job.status()

    @app.get("/api/reproduction/{job_key}/status")
    async def reproduction_status(job_key: str) -> dict:
        return _reproduction_job_or_404(job_key).status()

    @app.get("/api/reproduction/{job_key}/events")
    async def reproduction_events(job_key: str) -> StreamingResponse:
        return _sse_stream(_reproduction_job_or_404(job_key).bus)

    @app.get("/api/reproduction/{job_key}/results")
    async def reproduction_results(job_key: str) -> dict:
        job = _reproduction_job_or_404(job_key)
        if job.config is None:
            raise HTTPException(
                status_code=404, detail="The reproduction has no output yet."
            )
        return _scan_results(job.config.output_dir)

    @app.get("/api/reproduction/{job_key}/agent-log")
    async def reproduction_agent_log(
        job_key: str,
        download: bool = Query(default=False),
    ):
        job = _reproduction_job_or_404(job_key)
        if job.config is None:
            raise HTTPException(
                status_code=404, detail="The reproduction has no output yet."
            )
        latest = _latest_agent_log(job.config.output_dir)
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

    @app.get("/api/reproduction/{job_key}/results/file")
    async def reproduction_result_file(
        job_key: str,
        path: str = Query(min_length=1, max_length=4096),
    ) -> PlainTextResponse:
        job = _reproduction_job_or_404(job_key)
        if job.config is None:
            raise HTTPException(
                status_code=404, detail="The reproduction has no output yet."
            )
        full = _resolve_output_file(job.config.output_dir, path)
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

    @app.post("/api/local-directories/select")
    async def select_local_directory(
        selection_token: str = Header(
            default="", max_length=128, alias="X-CodeAuditor-Token"
        ),
    ) -> dict:
        """Open a native chooser and issue a short-lived opaque target token."""
        if not hmac.compare_digest(selection_token, app.state.terminal_token):
            raise HTTPException(
                status_code=403,
                detail="Local folder selection authorization failed.",
            )
        try:
            selected = await asyncio.to_thread(choose_local_directory)
            if selected is not None:
                selected = validate_local_audit_target(selected)
        except LocalDirectoryPickerUnavailable as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        except LocalDirectoryPickerError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if selected is None:
            return {"cancelled": True}

        now = time.monotonic()
        selections = app.state.local_directory_selections
        for token, (_path, expires_at) in list(selections.items()):
            if expires_at < now:
                selections.pop(token, None)
        token = secrets.token_urlsafe(32)
        selections[token] = (
            selected,
            now + _LOCAL_DIRECTORY_TOKEN_TTL_SECONDS,
        )
        return {"cancelled": False, "path": selected, "token": token}

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
        status: RunStatus | None = Query(default=None),
        run_kind: RunKind | None = Query(default=None),
        q: str | None = Query(default=None, max_length=256),
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
            limit=limit,
            offset=offset,
            target=target,
            target_key=target_key,
            status=status,
            run_kind=run_kind,
            query=q,
        )
        return {
            "runs": runs,
            "total": total,
            "limit": limit,
            "offset": offset,
            "filters": {
                "status": status or "",
                "run_kind": run_kind or "",
                "q": q or "",
            },
            "capabilities": {"server_filtering": True},
            "db_path": store.db_path,
        }

    @app.get("/api/history/{run_id}")
    def history_run(run_id: int) -> dict:
        return _get_history_run(run_id)

    @app.post("/api/history/{run_id}/resume", status_code=202)
    async def resume_history_run(run_id: int) -> dict:
        _get_history_run(run_id)
        await require_sandbox_environment(settings.backend, settings.sandbox_mode)
        provider = settings.provider()
        try:
            job = await manager.resume_cancelled(
                run_id,
                repos_dir=settings.repos_dir,
                results_dir=settings.results_dir,
                wikis_dir=settings.wikis_dir,
                backend=settings.backend,  # type: ignore[arg-type]
                provider_mode=provider.mode,
                provider_base_url=provider.base_url or None,
                provider_api_key=provider.api_key or None,
                model=provider.model if provider.mode == "custom" else None,
                sandbox_mode=settings.sandbox_mode,
            )
        except JobValidationError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except JobConflictError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        return job.status()

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

    @app.get("/api/history/{run_id}/agent-log")
    def history_run_agent_log(
        run_id: int,
        download: bool = Query(default=False),
    ):
        """Latest agent log of a run; works for both live and finished runs."""
        run = _get_history_run(run_id)
        latest = _latest_agent_log(run["output_dir"])
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


def run_web_server(host: str, port: int) -> None:
    """Blocking entry point for the CodeAuditor Web application."""
    import uvicorn

    settings = load_web_settings()
    configure_logging(settings.log_level)
    app = create_app(web_settings=settings)

    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)

    logger.info("Web UI available at http://%s:%d", host, port)
    asyncio.run(server.serve())
