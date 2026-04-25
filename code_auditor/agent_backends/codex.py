from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from ..config import AuditConfig
from ..logger import get_logger

logger = get_logger("agent.codex")

CODEX_MAX_RETRIES = 3
CODEX_RETRY_BASE_DELAY = 10  # seconds


class CodexTurnFailedError(RuntimeError):
    pass


class CodexBackend:
    async def run(
        self,
        prompt: str,
        config: AuditConfig,
        cwd: str,
        allowed_tools: list[str] | None = None,
        max_turns: int = 30,
        model: str | None = None,
        effort: str | None = None,
        log_file: str | None = None,
    ) -> str:
        if allowed_tools is not None:
            logger.debug("Codex backend ignores Claude-style allowed_tools: %s", allowed_tools)

        _prepare_local_sdk_path(config.codex_sdk_path)

        try:
            from codex_app_server import (  # type: ignore[import-not-found]
                AppServerConfig,
                AskForApproval,
                AsyncCodex,
                ReasoningEffort,
                SandboxMode,
                SandboxPolicy,
                TextInput,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Codex backend requires the Codex app-server Python SDK. "
                "Install codex-app-server-sdk, or pass --codex-sdk-path pointing "
                "to codex-main/sdk/python."
            ) from exc

        approval_policy = AskForApproval.model_validate(config.codex_approval_policy)
        sandbox_mode = SandboxMode(config.codex_sandbox)
        sandbox_policy = SandboxPolicy.model_validate(
            _sandbox_policy_payload(config, cwd),
        )
        reasoning_effort = ReasoningEffort(effort) if effort else None

        app_config = AppServerConfig(
            codex_bin=config.codex_bin,
            cwd=cwd,
        )

        last_exc: Exception | None = None
        for attempt in range(CODEX_MAX_RETRIES):
            try:
                return await self._run_once(
                    prompt=prompt,
                    config=config,
                    cwd=cwd,
                    model=model,
                    app_config=app_config,
                    approval_policy=approval_policy,
                    sandbox_mode=sandbox_mode,
                    sandbox_policy=sandbox_policy,
                    reasoning_effort=reasoning_effort,
                    text_input_cls=TextInput,
                    async_codex_cls=AsyncCodex,
                    log_file=log_file,
                )
            except Exception as exc:
                last_exc = exc
                if attempt < CODEX_MAX_RETRIES - 1 and _is_retryable_codex_error(exc):
                    delay = CODEX_RETRY_BASE_DELAY * (2 ** attempt)
                    logger.warning(
                        "Codex agent call failed (attempt %d/%d), retrying in %ds: %s",
                        attempt + 1, CODEX_MAX_RETRIES, delay, exc,
                    )
                    await asyncio.sleep(delay)
                    continue
                logger.error("Codex agent call failed after %d attempt(s): %s", attempt + 1, exc)
                raise

        raise last_exc  # type: ignore[misc]

    async def _run_once(
        self,
        *,
        prompt: str,
        config: AuditConfig,
        cwd: str,
        model: str | None,
        app_config: object,
        approval_policy: object,
        sandbox_mode: object,
        sandbox_policy: object,
        reasoning_effort: object | None,
        text_input_cls: type,
        async_codex_cls: type,
        log_file: str | None,
    ) -> str:
        text_parts: list[str] = []
        completed = False
        completed_status: str | None = None
        completed_error: str | None = None

        async with async_codex_cls(config=app_config) as codex:
            thread = await codex.thread_start(
                approval_policy=approval_policy,
                cwd=cwd,
                model=model or config.model,
                sandbox=sandbox_mode,
            )
            turn = await thread.turn(
                text_input_cls(prompt),
                approval_policy=approval_policy,
                cwd=cwd,
                effort=reasoning_effort,
                model=model or config.model,
                sandbox_policy=sandbox_policy,
            )

            log_fh = _open_log(log_file)
            try:
                async for event in turn.stream():
                    text_parts.extend(_text_from_event(event))
                    _write_event_log(log_fh, event)
                    state = _turn_completed_state(event)
                    if state is not None:
                        completed = True
                        completed_status, completed_error = state
            finally:
                if log_fh and not log_fh.closed:
                    log_fh.close()

        if not completed:
            raise CodexTurnFailedError("Codex turn stream ended before turn/completed.")
        if completed_status != "completed":
            detail = f": {completed_error}" if completed_error else ""
            raise CodexTurnFailedError(f"Codex turn ended with status {completed_status}{detail}")

        return "".join(text_parts)


def _prepare_local_sdk_path(sdk_path: str | None) -> None:
    if not sdk_path:
        return

    root = Path(sdk_path)
    src = root / "src"
    candidate = src if (src / "codex_app_server").is_dir() else root
    candidate_text = str(candidate)
    if candidate_text not in sys.path:
        sys.path.insert(0, candidate_text)


def _sandbox_policy_payload(config: AuditConfig, cwd: str) -> dict[str, Any]:
    if config.codex_sandbox == "danger-full-access":
        return {"type": "dangerFullAccess"}

    if config.codex_sandbox == "read-only":
        return {
            "type": "readOnly",
            "access": {"type": "fullAccess"},
            "networkAccess": config.codex_network_access,
        }

    roots = _dedupe_paths([
        cwd,
        config.output_dir,
        *config.codex_extra_writable_roots,
    ])
    return {
        "type": "workspaceWrite",
        "networkAccess": config.codex_network_access,
        "readOnlyAccess": {"type": "fullAccess"},
        "writableRoots": roots,
    }


def _dedupe_paths(paths: list[str]) -> list[str]:
    result: list[str] = []
    for path in paths:
        resolved = os.path.realpath(path)
        if resolved not in result:
            result.append(resolved)
    return result


def _open_log(log_file: str | None):
    if not log_file:
        return None
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    fh = open(log_file, "a")  # noqa: SIM115
    if fh.tell() > 0:
        fh.write("\n--- new agent invocation ---\n\n")
        fh.flush()
    return fh


def _text_from_event(event: object) -> list[str]:
    if getattr(event, "method", "") != "item/agentMessage/delta":
        return []
    payload = getattr(event, "payload", None)
    delta = getattr(payload, "delta", "")
    return [delta] if isinstance(delta, str) and delta else []


def _write_event_log(log_fh, event: object) -> None:
    if not log_fh:
        return

    method = getattr(event, "method", "unknown")
    payload = getattr(event, "payload", None)

    if method == "item/agentMessage/delta":
        delta = getattr(payload, "delta", "")
        if delta:
            log_fh.write(delta)
            log_fh.flush()
        return

    if method in {"turn/started", "turn/completed", "error"}:
        log_fh.write(f"\n[{method}] {_payload_summary(payload)}\n")
        log_fh.flush()


def _payload_summary(payload: object) -> str:
    if payload is None:
        return ""
    if hasattr(payload, "model_dump_json"):
        try:
            return payload.model_dump_json()
        except Exception:
            pass
    return str(payload)


def _turn_completed_state(event: object) -> tuple[str | None, str | None] | None:
    if getattr(event, "method", "") != "turn/completed":
        return None

    payload = getattr(event, "payload", None)
    turn = getattr(payload, "turn", None)
    raw_status = getattr(turn, "status", None)
    status = _enum_or_string_value(raw_status)
    error = getattr(turn, "error", None)
    return status, _payload_summary(error) if error is not None else None


def _enum_or_string_value(value: object) -> str | None:
    if value is None:
        return None
    enum_value = getattr(value, "value", None)
    if isinstance(enum_value, str):
        return enum_value
    return str(value)


def _is_retryable_codex_error(exc: Exception) -> bool:
    text = str(exc).lower()
    retryable_fragments = [
        "stream disconnected",
        "tls handshake",
        "network error",
        "error sending request",
        "timeout",
        "temporarily",
        "connection",
        "ended before turn/completed",
    ]
    return any(fragment in text for fragment in retryable_fragments)
