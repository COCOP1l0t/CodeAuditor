"""ConPTY-to-WebSocket bridge for server-owned PoC working directories (Windows)."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect
from winpty import PtyProcess

from ...process_supervisor import ProcessJob


def _terminal_shell() -> str:
    # cmd.exe accepts the CR/LF command stream emitted by the xterm client
    # without PowerShell's interactive line editor repainting partial input.
    return os.environ.get("ComSpec") or shutil.which("cmd.exe") or "cmd.exe"


def _clamp_cols_rows(cols: Any, rows: Any) -> tuple[int, int] | None:
    if (
        not isinstance(cols, int)
        or isinstance(cols, bool)
        or not isinstance(rows, int)
        or isinstance(rows, bool)
    ):
        return None
    return min(max(cols, 20), 400), min(max(rows, 5), 200)


async def serve_poc_terminal(websocket: WebSocket, candidate: dict) -> None:
    """Run an interactive shell rooted at one validated Stage 5 PoC directory."""
    await websocket.accept()
    env = os.environ.copy()
    env.update(
        {
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            "CODE_AUDITOR_RUN_ID": str(candidate["run_id"]),
            "CODE_AUDITOR_VULN_ID": candidate["vuln_id"],
        }
    )
    dimensions = _clamp_cols_rows(100, 30)
    if dimensions is None:  # pragma: no cover - constants are always valid
        dimensions = (100, 30)
    cols, rows = dimensions

    output: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=128)
    bridge_tasks: set[asyncio.Task[None]] = set()
    proc: PtyProcess | None = None
    process_job: ProcessJob | None = None

    async def read_loop() -> None:
        """Poll the ConPTY on worker threads; bounded queue applies backpressure.

        The queue cap mirrors the POSIX bridge: a paste or scrollback flood
        must never block the event loop or stall concurrent SSE streams.
        """
        while True:
            try:
                data = await asyncio.to_thread(proc.read, 65536)
            except (EOFError, OSError):
                data = ""
            if data:
                while True:
                    if not output.full():
                        output.put_nowait(data.encode("utf-8", "replace"))
                        break
                    # Drain before retrying so a slow browser client cannot
                    # wedge the reader thread forever.
                    await asyncio.sleep(0.02)
            else:
                if proc.isalive():
                    await asyncio.sleep(0.01)
                    continue
                if not output.full():
                    output.put_nowait(None)
                return

    async def send_output() -> None:
        while True:
            data = await output.get()
            if data is None:
                return
            await websocket.send_bytes(data)

    async def receive_input() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("bytes") is not None:
                await asyncio.to_thread(proc.write, message["bytes"].decode("utf-8", "replace"))
                continue
            text = message.get("text")
            if text is None:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if payload.get("type") == "input" and isinstance(
                payload.get("data"), str
            ):
                await asyncio.to_thread(proc.write, payload["data"])
            elif payload.get("type") == "resize":
                sized = _clamp_cols_rows(payload.get("cols"), payload.get("rows"))
                if sized:
                    rows, cols = sized[1], sized[0]
                    await asyncio.to_thread(proc.setwinsize, rows, cols)

    try:
        proc = PtyProcess.spawn(
            _terminal_shell(),
            cwd=candidate["poc_dir"],
            env=env,
            dimensions=(rows, cols),
        )
        process_job = ProcessJob()
        try:
            process_job.assign_pid(proc.pid)
        except Exception:
            process_job.close()
            process_job = None
            proc.close(force=True)
            raise
        await websocket.send_json(
            {
                "type": "ready",
                "run_id": candidate["run_id"],
                "vuln_id": candidate["vuln_id"],
                "title": candidate.get("title") or "",
                "cwd": candidate["poc_dir"],
            }
        )
        reader = asyncio.create_task(read_loop())
        sender = asyncio.create_task(send_output())
        receiver = asyncio.create_task(receive_input())
        bridge_tasks.update({reader, sender, receiver})
        done, pending = await asyncio.wait(
            bridge_tasks, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            try:
                task.result()
            except WebSocketDisconnect:
                pass
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.send_json(
                {"type": "error", "detail": "Terminal session failed."}
            )
        except Exception:
            pass
    finally:
        # Closing ConPTY first unblocks a read running in a worker thread before
        # the asyncio bridge tasks are cancelled and awaited.
        if proc is not None:
            with contextlib.suppress(Exception):
                proc.close(force=True)
        for task in list(bridge_tasks):
            if not task.done():
                task.cancel()
        if bridge_tasks:
            await asyncio.gather(*bridge_tasks, return_exceptions=True)
        if process_job is not None:
            with contextlib.suppress(Exception):
                process_job.terminate()
            process_job.close()
        if proc is not None and proc.isalive():
            # PtyProcess.terminate escalates through its own signal logic;
            # give it a moment before forcing closure.
            with contextlib.suppress(Exception):
                await asyncio.to_thread(proc.terminate, force=True)
        with contextlib.suppress(Exception):
            if proc is not None:
                proc.close()
        try:
            await websocket.close()
        except Exception:
            pass
