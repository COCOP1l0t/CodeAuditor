"""PTY-to-WebSocket bridge for server-owned PoC working directories."""
from __future__ import annotations

import asyncio
import errno
import fcntl
import json
import os
import pty
import signal
import struct
import termios
from typing import Any

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect


def _terminal_shell() -> str:
    configured = os.environ.get("SHELL") or ""
    if os.path.isabs(configured) and os.access(configured, os.X_OK):
        return configured
    return "/bin/bash" if os.access("/bin/bash", os.X_OK) else "/bin/sh"


def _resize(fd: int, cols: Any, rows: Any) -> None:
    if (
        not isinstance(cols, int)
        or isinstance(cols, bool)
        or not isinstance(rows, int)
        or isinstance(rows, bool)
    ):
        return
    cols = min(max(cols, 20), 400)
    rows = min(max(rows, 5), 200)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


async def serve_poc_terminal(websocket: WebSocket, candidate: dict) -> None:
    """Run an interactive shell rooted at one validated Stage 5 PoC directory."""
    await websocket.accept()
    master_fd, slave_fd = pty.openpty()
    _resize(master_fd, 100, 30)
    shell = _terminal_shell()
    env = os.environ.copy()
    env.update(
        {
            "TERM": "xterm-256color",
            "COLORTERM": "truecolor",
            "CODE_AUDITOR_RUN_ID": str(candidate["run_id"]),
            "CODE_AUDITOR_VULN_ID": candidate["vuln_id"],
        }
    )
    process = None
    loop = asyncio.get_running_loop()
    output: asyncio.Queue[bytes | None] = asyncio.Queue(maxsize=128)
    reader_state = {"active": False, "paused": False}

    def remove_reader() -> None:
        if reader_state["active"]:
            loop.remove_reader(master_fd)
            reader_state["active"] = False

    def read_master() -> None:
        if output.full():
            reader_state["paused"] = True
            remove_reader()
            return
        try:
            data = os.read(master_fd, 65536)
        except OSError as exc:
            if exc.errno not in {errno.EAGAIN, errno.EIO, errno.EBADF}:
                output.put_nowait(
                    f"\r\n[terminal read error: {exc}]\r\n".encode()
                )
            data = b""
        if not data:
            remove_reader()
            if not output.full():
                output.put_nowait(None)
            return
        output.put_nowait(data)

    def add_reader() -> None:
        if not reader_state["active"]:
            loop.add_reader(master_fd, read_master)
            reader_state["active"] = True
            reader_state["paused"] = False

    async def send_output() -> None:
        while True:
            data = await output.get()
            if reader_state["paused"] and output.qsize() < 64:
                add_reader()
            if data is None:
                return
            await websocket.send_bytes(data)

    async def receive_input() -> None:
        while True:
            message = await websocket.receive()
            if message["type"] == "websocket.disconnect":
                return
            if message.get("bytes") is not None:
                os.write(master_fd, message["bytes"])
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
                os.write(master_fd, payload["data"].encode("utf-8"))
            elif payload.get("type") == "resize":
                _resize(master_fd, payload.get("cols"), payload.get("rows"))

    try:
        process = await asyncio.create_subprocess_exec(
            shell,
            "-i",
            cwd=candidate["poc_dir"],
            env=env,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            start_new_session=True,
        )
        os.close(slave_fd)
        slave_fd = -1
        await websocket.send_json(
            {
                "type": "ready",
                "run_id": candidate["run_id"],
                "vuln_id": candidate["vuln_id"],
                "title": candidate.get("title") or "",
                "cwd": candidate["poc_dir"],
            }
        )
        add_reader()
        sender = asyncio.create_task(send_output())
        receiver = asyncio.create_task(receive_input())
        done, pending = await asyncio.wait(
            {sender, receiver}, return_when=asyncio.FIRST_COMPLETED
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
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "detail": str(exc)})
        except Exception:
            pass
    finally:
        remove_reader()
        if slave_fd >= 0:
            os.close(slave_fd)
        try:
            os.close(master_fd)
        except OSError:
            pass
        if process is not None and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGHUP)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=1.0)
            except TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        try:
            await websocket.close()
        except Exception:
            pass
