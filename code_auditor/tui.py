"""Terminal User Interface for CodeAuditor using Textual and Rich.

Provides a beautiful dashboard that shows:
- Audit configuration summary
- Stage-by-stage progress with spinners
- Live log output
- Final results summary
"""
from __future__ import annotations

import asyncio
import logging
import select
import sys
import termios
import threading
import time
import tty
from _thread import interrupt_main
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from textual.app import App, ComposeResult
from textual.css.query import NoMatches
from textual.widgets import Footer, Header, RichLog, Static

from .logger import configure_logging as _configure_logging
from .logger import format_log_record

TUI_BACKEND = "textual"

# ── Colour palette ──────────────────────────────────────────────────────────
ACCENT = "cyan"
ACCENT2 = "magenta"
SUCCESS = "green"
WARN = "yellow"
ERROR = "red"
DIM = "dim"
BOLD = "bold"

# ── Fixed layout sizes used by both rendering and mouse hit-testing ─────────
HEADER_HEIGHT = 3
CONFIG_HEIGHT = 7
STAGES_HEIGHT = 13
SUMMARY_HEIGHT = 8
PROGRESS_BAR_LEN = 8
MIN_PROGRESS_COUNT_WIDTH = 5

# ── Stage metadata ──────────────────────────────────────────────────────────
STAGE_INFO: dict[int, tuple[str, str]] = {
    0: ("Init", "Git clone + output directory setup"),
    1: ("Context", "Security context research"),
    2: ("Decompose", "Decompose codebase into analysis units"),
    3: ("Discover", "Bug discovery per analysis unit"),
    4: ("Evaluate", "Evaluate findings as vulnerabilities"),
    5: ("PoC", "Proof-of-concept reproduction"),
    6: ("Disclose", "Disclosure package preparation"),
}


@dataclass
class _StageState:
    """Mutable state for a single stage."""
    status: str = "pending"  # pending | running | done | skipped | failed
    detail: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    items_done: int = 0
    items_total: int = 0


@dataclass
class TUIState:
    """Shared state consumed by the live dashboard render function."""
    target: str = ""
    output_dir: str = ""
    discovered_path: str = ""
    wiki_path: str = ""
    backend: str = ""
    model: str = ""
    max_parallel: int = 1
    stages: dict[int, _StageState] = field(default_factory=dict)
    log_lines: list[Text] = field(default_factory=list)
    max_log_lines: int = 40
    max_log_history: int = 1000
    log_scroll_offset: int = 0
    finished: bool = False
    error: str = ""
    start_time: float = 0.0


# ── Logging handler that feeds the TUI ─────────────────────────────────────

class _TUILogHandler(logging.Handler):
    """Captures log records and appends formatted lines to TUIState."""

    def __init__(self, state: TUIState) -> None:
        super().__init__()
        self._state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            was_scrolled = self._state.log_scroll_offset > 0
            new_lines = list(format_log_record(record).split("\n", allow_blank=True))
            self._state.log_lines.extend(new_lines)
            if was_scrolled:
                self._state.log_scroll_offset += len(new_lines)

            history_limit = max(self._state.max_log_lines, self._state.max_log_history)
            if len(self._state.log_lines) > history_limit:
                self._state.log_lines = self._state.log_lines[-history_limit:]
            _clamp_log_scroll_offset(self._state)
        except Exception:
            self.handleError(record)


# ── Dashboard renderer ──────────────────────────────────────────────────────

def _make_header() -> Panel:
    title = Text()
    title.append("⚡ ", style=SUCCESS)
    title.append("Code", style=f"{BOLD} {ACCENT}")
    title.append("Auditor", style=f"{BOLD} {ACCENT2}")
    title.append(" ⚡", style=SUCCESS)
    return Panel(title, style=f"bold {ACCENT}", border_style=ACCENT, padding=(0, 2))


def _make_config_table(state: TUIState) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table.add_column("Key", style=DIM, width=16)
    table.add_column("Value", style=BOLD)
    table.add_row("Target", state.target)
    table.add_row("Output", state.output_dir)
    table.add_row("Discovered", state.discovered_path)
    table.add_row("Wiki", state.wiki_path or "—")
    table.add_row("Backend", f"{state.backend}  ({state.model or 'default'})")
    table.add_row("Parallel", str(state.max_parallel))
    elapsed = time.time() - state.start_time if state.start_time else 0
    table.add_row("Elapsed", _fmt_duration(elapsed))
    return table


def _fmt_duration(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _progress_count_width(state: TUIState) -> int:
    count_width = MIN_PROGRESS_COUNT_WIDTH
    for stage in state.stages.values():
        if stage.items_total > 0:
            count_width = max(count_width, len(f"{stage.items_done}/{stage.items_total}"))
    return count_width


def _fmt_progress(stage: _StageState, count_width: int) -> str:
    if stage.items_total <= 0:
        return ""

    pct = max(0.0, min(1.0, stage.items_done / stage.items_total))
    filled = int(pct * PROGRESS_BAR_LEN)
    bar = "█" * filled + "░" * (PROGRESS_BAR_LEN - filled)
    count = f"{stage.items_done}/{stage.items_total}"
    return f"{bar} {count:>{count_width}}"


def _make_stage_panel(state: TUIState) -> Panel:
    table = Table(show_header=True, header_style=f"bold {ACCENT}", box=None, padding=(0, 1), expand=True)
    table.add_column("#", width=3, justify="center")
    table.add_column("Stage", width=12)
    table.add_column("Description", ratio=3)
    table.add_column("Status", width=14, justify="left")
    progress_count_width = _progress_count_width(state)
    table.add_column("Progress", width=PROGRESS_BAR_LEN + 1 + progress_count_width, justify="right")
    table.add_column("Time", width=14, justify="right")

    for stage_num in sorted(STAGE_INFO.keys()):
        name, desc = STAGE_INFO[stage_num]
        st = state.stages.get(stage_num, _StageState())

        # Status display
        if st.status == "pending":
            status_text = Text("⏳ pending", style=DIM)
        elif st.status == "running":
            status_text = Text("▶ running", style=f"{BOLD} {WARN}")
        elif st.status == "done":
            status_text = Text("✔ done", style=SUCCESS)
        elif st.status == "skipped":
            status_text = Text("⏭ skipped", style=DIM)
        elif st.status == "failed":
            status_text = Text("✘ failed", style=ERROR)
        else:
            status_text = Text(st.status)

        # Progress
        progress_text = _fmt_progress(st, progress_count_width)

        # Time
        if st.start_time and st.end_time:
            time_text = _fmt_duration(st.end_time - st.start_time)
        elif st.start_time and st.status == "running":
            time_text = _fmt_duration(time.time() - st.start_time)
        else:
            time_text = ""

        detail = st.detail or desc
        table.add_row(str(stage_num), name, detail, status_text, progress_text, time_text)

    return Panel(table, title="[bold]Pipeline Stages[/bold]", border_style=ACCENT, padding=(1, 1))


def _visible_log_lines(state: TUIState) -> list[Text]:
    total = len(state.log_lines)
    if total == 0:
        return []

    visible = min(total, max(1, state.max_log_lines))
    offset = _clamped_log_scroll_offset(state)
    start = max(0, total - visible - offset)
    return state.log_lines[start : start + visible]


def _max_log_scroll_offset(state: TUIState) -> int:
    if not state.log_lines:
        return 0
    visible = min(len(state.log_lines), max(1, state.max_log_lines))
    return max(0, len(state.log_lines) - visible)


def _clamped_log_scroll_offset(state: TUIState) -> int:
    return max(0, min(state.log_scroll_offset, _max_log_scroll_offset(state)))


def _clamp_log_scroll_offset(state: TUIState) -> None:
    state.log_scroll_offset = _clamped_log_scroll_offset(state)


def _build_scrollbar(visible: int, total: int, height: int, offset: int = 0) -> Text:
    """Build a vertical scrollbar showing position within the log buffer.

    The scrollbar is ``height`` rows tall.  The thumb size and position are
    proportional to the ratio of *visible* lines to *total* lines.
    """
    if total <= visible or height <= 0:
        return Text("")

    thumb_h = min(height, max(1, int(height * (visible / total))))
    max_offset = max(0, total - visible)
    offset = max(0, min(offset, max_offset))
    track_space = height - thumb_h
    if max_offset == 0:
        thumb_top = 0
    else:
        first_visible = max_offset - offset
        thumb_top = round(track_space * (first_visible / max_offset))

    bars: list[str] = []
    for i in range(height):
        if thumb_top <= i < thumb_top + thumb_h:
            bars.append("█")
        else:
            bars.append("│")
    return Text("\n".join(bars), style=DIM)


def _make_log_panel(state: TUIState) -> Panel:
    content: Text | Table
    if not state.log_lines:
        content = Text("Waiting for logs...", style=DIM)
    else:
        visible_lines = _visible_log_lines(state)
        visible = len(visible_lines)
        total = len(state.log_lines)
        offset = _clamped_log_scroll_offset(state)

        log_text = Text("\n", style="").join(visible_lines)
        scrollbar = _build_scrollbar(visible, total, visible, offset=offset)

        if scrollbar.plain:
            table = Table(show_header=False, box=None, padding=0, expand=True)
            table.add_column(ratio=1)
            table.add_column(width=1, justify="center")
            table.add_row(log_text, scrollbar)
            content = table
        else:
            content = log_text

    return Panel(
        content,
        title="[bold]Live Log[/bold]",
        border_style=DIM,
        padding=(0, 1),
    )


def _make_summary(state: TUIState) -> Panel:
    elapsed = _fmt_duration(time.time() - state.start_time) if state.start_time else "—"
    done = sum(1 for s in state.stages.values() if s.status == "done")
    failed = sum(1 for s in state.stages.values() if s.status == "failed")
    skipped = sum(1 for s in state.stages.values() if s.status == "skipped")

    tree = Tree("[bold]Audit Summary[/bold]")
    tree.add(f"Elapsed: [cyan]{elapsed}[/cyan]")
    tree.add(f"Stages completed: [green]{done}[/green]")
    if failed:
        tree.add(f"Stages failed: [red]{failed}[/red]")
    if skipped:
        tree.add(f"Stages skipped: [dim]{skipped}[/dim]")
    if state.error:
        tree.add(f"Error: [red]{state.error}[/red]")
    return Panel(tree, border_style=SUCCESS if not state.error else ERROR, padding=(1, 2))


def _render_dashboard(state: TUIState) -> Layout:
    """Build the full dashboard layout."""
    layout = Layout()
    layout.split_column(
        Layout(_make_header(), size=HEADER_HEIGHT, name="header"),
        Layout(name="body"),
    )

    body_children = [
        Layout(_make_config_table(state), size=CONFIG_HEIGHT, name="config"),
        Layout(_make_stage_panel(state), size=STAGES_HEIGHT, name="stages"),
        Layout(_make_log_panel(state), name="logs"),
    ]

    if state.finished:
        body_children.append(Layout(_make_summary(state), size=SUMMARY_HEIGHT, name="summary"))

    layout["body"].split_column(*body_children)
    return layout


class CodeAuditorApp(App[None]):
    """Textual app that renders CodeAuditor state with Rich widgets."""

    TITLE = "CodeAuditor"

    CSS = """
    Screen {
        layout: vertical;
    }

    #config {
        height: 7;
    }

    #stages {
        height: 15;
    }

    #logs {
        height: 1fr;
        border: solid $surface;
    }

    #summary {
        height: 8;
        display: none;
    }
    """

    BINDINGS = [
        ("q", "request_exit", "Quit"),
        ("ctrl+c", "interrupt", "Interrupt"),
        ("j", "scroll_log_down", "Scroll down"),
        ("k", "scroll_log_up", "Scroll up"),
        ("pagedown", "scroll_log_page_down", "Page down"),
        ("pageup", "scroll_log_page_up", "Page up"),
        ("end", "scroll_log_latest", "Latest"),
        ("home", "scroll_log_oldest", "Oldest"),
    ]

    def __init__(
        self,
        state: TUIState,
        *,
        exit_callback: Callable[[], None] | None = None,
        interrupt_callback: Callable[[], None] | None = None,
        audit_coro_factory: Callable[[], Awaitable[None]] | None = None,
        audit_done_callback: Callable[[BaseException | None], None] | None = None,
    ) -> None:
        super().__init__()
        self._state = state
        self._exit_callback = exit_callback
        self._interrupt_callback = interrupt_callback
        self._audit_coro_factory = audit_coro_factory
        self._audit_done_callback = audit_done_callback
        self._audit_task: asyncio.Task[None] | None = None
        self._rendered_log_signature: tuple[int, int, int] | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(id="config")
        yield Static(id="stages")
        yield RichLog(id="logs", wrap=True, highlight=False, markup=False)
        yield Static(id="summary")
        yield Footer()

    def on_mount(self) -> None:
        self.refresh_from_state()
        self.set_interval(0.25, self.refresh_from_state)
        if self._audit_coro_factory:
            self._audit_task = asyncio.create_task(self._run_audit())

    async def _run_audit(self) -> None:
        error: BaseException | None = None
        assert self._audit_coro_factory is not None
        try:
            await self._audit_coro_factory()
        except BaseException as exc:
            error = exc
        finally:
            self._state.finished = True
            if self._audit_done_callback:
                self._audit_done_callback(error)
            self.refresh_from_state()

    def refresh_from_state(self) -> None:
        if not self.is_mounted:
            return

        try:
            config = self.query_one("#config", Static)
            stages = self.query_one("#stages", Static)
            summary = self.query_one("#summary", Static)
        except NoMatches:
            return

        config.update(_make_config_table(self._state))
        stages.update(_make_stage_panel(self._state))

        summary.display = self._state.finished
        if self._state.finished:
            summary.update(_make_summary(self._state))

        self._refresh_log()

    def _refresh_log(self) -> None:
        visible_lines = _visible_log_lines(self._state)
        signature = (
            len(self._state.log_lines),
            self._state.log_scroll_offset,
            self._state.max_log_lines,
        )
        if signature == self._rendered_log_signature:
            return

        try:
            log = self.query_one("#logs", RichLog)
        except NoMatches:
            return
        log.clear()
        if visible_lines:
            for line in visible_lines:
                log.write(line, scroll_end=self._state.log_scroll_offset == 0)
        else:
            log.write(Text("Waiting for logs...", style=DIM), scroll_end=True)
        self._rendered_log_signature = signature

    def action_request_exit(self) -> None:
        if self._audit_task and not self._audit_task.done():
            self._audit_task.cancel()
            if self._interrupt_callback:
                self._interrupt_callback()
        elif self._exit_callback:
            self._exit_callback()
        self.exit()

    def action_interrupt(self) -> None:
        if self._audit_task and not self._audit_task.done():
            self._audit_task.cancel()
        if self._interrupt_callback:
            self._interrupt_callback()
        self.exit()

    def action_scroll_log_down(self) -> None:
        self._state.log_scroll_offset -= 1
        _clamp_log_scroll_offset(self._state)
        self.refresh_from_state()

    def action_scroll_log_up(self) -> None:
        self._state.log_scroll_offset += 1
        _clamp_log_scroll_offset(self._state)
        self.refresh_from_state()

    def action_scroll_log_page_down(self) -> None:
        self._state.log_scroll_offset -= max(1, self._state.max_log_lines)
        _clamp_log_scroll_offset(self._state)
        self.refresh_from_state()

    def action_scroll_log_page_up(self) -> None:
        self._state.log_scroll_offset += max(1, self._state.max_log_lines)
        _clamp_log_scroll_offset(self._state)
        self.refresh_from_state()

    def action_scroll_log_latest(self) -> None:
        self._state.log_scroll_offset = 0
        self.refresh_from_state()

    def action_scroll_log_oldest(self) -> None:
        self._state.log_scroll_offset = _max_log_scroll_offset(self._state)
        self.refresh_from_state()


# ── Public API ──────────────────────────────────────────────────────────────

class TUIManager:
    """Manages the Textual live dashboard for CodeAuditor.

    Usage::

        tui = TUIManager()
        tui.configure(target="/path", output_dir="...", discovered_path="...", wiki_path="...", backend="claude", ...)
        tui.start()

        # Inside orchestrator:
        tui.begin_stage(1)
        tui.stage_progress(1, items_done=3, items_total=10)
        tui.end_stage(1)

        tui.stop()
    """

    _CTRL_C = 0x03
    _ESC = "\x1b"
    _SGR_MOUSE_PREFIX = f"{_ESC}[<"
    _MOUSE_REPORTING_ON = f"{_ESC}[?1000h{_ESC}[?1002h{_ESC}[?1006h"
    _MOUSE_REPORTING_OFF = f"{_ESC}[?1000l{_ESC}[?1002l{_ESC}[?1006l"

    def __init__(self) -> None:
        self._state = TUIState()
        self._console = Console()
        self._app: CodeAuditorApp | None = None
        self._app_thread: threading.Thread | None = None
        self._app_thread_id: int | None = None
        self._audit_thread: threading.Thread | None = None
        self._audit_loop: asyncio.AbstractEventLoop | None = None
        self._audit_task: asyncio.Task[None] | None = None
        self._log_handler: _TUILogHandler | None = None
        self._refresh_thread: threading.Thread | None = None
        self._stop_refresh = threading.Event()
        self._keyboard_thread: threading.Thread | None = None
        self._stop_keyboard = threading.Event()
        self._keyboard_enabled = False
        self._mouse_reporting_enabled = False
        self._exit_requested = False
        self._interrupt_main = interrupt_main
        self._audit_failed = False
        self._audit_interrupted = False

    # ── Configuration ───────────────────────────────────────────────────

    def configure(
        self,
        *,
        target: str,
        output_dir: str,
        discovered_path: str,
        wiki_path: str | None,
        backend: str,
        model: str | None,
        max_parallel: int,
    ) -> None:
        self._state.target = target
        self._state.output_dir = output_dir
        self._state.discovered_path = discovered_path
        self._state.wiki_path = wiki_path or ""
        self._state.backend = backend
        self._state.model = model or "default"
        self._state.max_parallel = max_parallel

    # ── Lifecycle ───────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the live dashboard and install the log handler."""
        self._state.start_time = time.time()

        self._install_log_handler()

        # Start live display
        self._start_live()

        # Background thread to keep elapsed/progress updated while stage is running
        def _bg_refresh() -> None:
            while not self._stop_refresh.is_set():
                self._refresh()
                self._stop_refresh.wait(0.25)

        self._stop_refresh.clear()
        self._refresh_thread = threading.Thread(target=_bg_refresh, daemon=True)
        self._refresh_thread.start()

    def run_audit(self, audit_coro_factory: Callable[[], Awaitable[None]]) -> tuple[bool, bool]:
        """Run Textual on the main thread and audit work in a background loop."""
        self._state.start_time = time.time()
        self._audit_failed = False
        self._audit_interrupted = False
        self._exit_requested = False
        self._install_log_handler()
        self._app = CodeAuditorApp(
            self._state,
            exit_callback=self._mark_exit_requested,
            interrupt_callback=self._interrupt_from_tui,
            audit_done_callback=self._audit_done,
        )
        self._app_thread_id = threading.get_ident()
        self._start_audit_thread(audit_coro_factory)
        try:
            self._app.run()
        finally:
            if self._audit_thread and self._audit_thread.is_alive():
                self._cancel_audit()
                self._audit_thread.join(timeout=2.0)
            self._remove_log_handler()
            self._app = None
            self._app_thread = None
            self._app_thread_id = None
            self._audit_thread = None
        return self._audit_failed, self._audit_interrupted

    def _start_audit_thread(self, audit_coro_factory: Callable[[], Awaitable[None]]) -> None:
        def _run() -> None:
            loop = asyncio.new_event_loop()
            self._audit_loop = loop
            asyncio.set_event_loop(loop)
            error: BaseException | None = None
            try:
                task = loop.create_task(audit_coro_factory())
                self._audit_task = task
                loop.run_until_complete(task)
            except BaseException as exc:
                error = exc
            finally:
                self._state.finished = True
                self._audit_done(error)
                self._refresh()
                self._audit_task = None
                self._audit_loop = None
                loop.close()

        self._audit_thread = threading.Thread(target=_run, daemon=True)
        self._audit_thread.start()

    def _cancel_audit(self) -> None:
        loop = self._audit_loop
        task = self._audit_task
        if loop and task and not task.done():
            loop.call_soon_threadsafe(task.cancel)

    def _install_log_handler(self) -> None:
        self._log_handler = _TUILogHandler(self._state)
        self._log_handler.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s", datefmt="%H:%M:%S")
        self._log_handler.setFormatter(fmt)

        root_logger = logging.getLogger("code_auditor")
        root_logger.handlers.clear()
        root_logger.addHandler(self._log_handler)

    def _remove_log_handler(self) -> None:
        if self._log_handler:
            root_logger = logging.getLogger("code_auditor")
            root_logger.removeHandler(self._log_handler)
            self._log_handler = None

    def _audit_done(self, error: BaseException | None) -> None:
        if error is None:
            return
        if isinstance(error, (asyncio.CancelledError, KeyboardInterrupt)):
            self._audit_interrupted = True
            self._state.error = "Interrupted by user."
            return
        self._audit_failed = True
        self._state.error = str(error)

    def stop(self) -> None:
        """Stop the live display and remove the log handler."""
        self._state.finished = True
        self._stop_keyboard.set()
        self._stop_refresh.set()
        if self._keyboard_thread:
            self._keyboard_thread.join(timeout=1.0)
            self._keyboard_thread = None
        self._set_mouse_reporting(False)
        self._keyboard_enabled = False
        if self._refresh_thread:
            self._refresh_thread.join(timeout=1.0)
            self._refresh_thread = None
        self._refresh()
        self._stop_textual_app()

        if self._log_handler:
            root_logger = logging.getLogger("code_auditor")
            root_logger.removeHandler(self._log_handler)
            self._log_handler = None

        # Print final summary to console
        self._console.print()
        self._console.print(_make_summary(self._state))
        self._console.print()

    def wait_for_exit(self) -> None:
        """Show final dashboard and wait for user to press q to exit.

        Keeps the TUI dashboard visible so the user can inspect the final
        state (including any error summary) before pressing *q* to exit.
        """
        self._state.finished = True
        self._stop_refresh.set()
        if self._refresh_thread:
            self._refresh_thread.join(timeout=1.0)
            self._refresh_thread = None

        # One final update so the summary panel appears in the dashboard.
        self._refresh()

        if self._app_thread and self._app_thread.is_alive():
            self._exit_requested = False
            while not self._exit_requested and self._app_thread.is_alive():
                time.sleep(0.1)

        self._stop_keyboard.set()
        if self._keyboard_thread:
            self._keyboard_thread.join(timeout=1.0)
            self._keyboard_thread = None
        self._set_mouse_reporting(False)
        self._keyboard_enabled = False

        self._stop_textual_app()

        if self._log_handler:
            root_logger = logging.getLogger("code_auditor")
            root_logger.removeHandler(self._log_handler)
            self._log_handler = None

        self._console.print("[cyan]Goodbye![/cyan]")

    def request_exit(self) -> None:
        """Request TUI shutdown from keyboard input or signal handling."""
        self._exit_requested = True
        self._stop_keyboard.set()
        self._stop_refresh.set()
        self._exit_textual_app()

    def _mark_exit_requested(self) -> None:
        self._exit_requested = True
        self._stop_keyboard.set()
        self._stop_refresh.set()

    def _interrupt_from_tui(self) -> None:
        self._mark_exit_requested()
        self._audit_interrupted = True
        self._state.error = "Interrupted by user."
        if self._app_thread_id != threading.get_ident():
            self._interrupt_main()

    # ── Keyboard listener ───────────────────────────────────────────────

    def _start_keyboard_listener(self) -> None:
        """Start a background thread that reads stdin in raw mode.

        Detects Ctrl+C to interrupt the audit, and q to exit when the audit
        is finished.
        """
        self._stop_keyboard.clear()
        self._exit_requested = False
        self._keyboard_enabled = False

        if self._keyboard_thread and self._keyboard_thread.is_alive():
            self._keyboard_enabled = True
            return

        if not getattr(sys.stdin, "isatty", lambda: False)():
            return

        try:
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
        except (OSError, termios.error):
            return

        self._keyboard_enabled = True

        def _listen() -> None:
            tty.setcbreak(fd)
            self._set_mouse_reporting(True)
            try:
                prefix: bool | str = False
                while not self._stop_keyboard.is_set():
                    ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                    if not ready:
                        continue
                    try:
                        ch = sys.stdin.read(1)
                    except OSError:
                        # EINTR from signal delivery — retry.
                        continue
                    if not ch:
                        break
                    prefix = self._handle_keyboard_char(ch, prefix=prefix)
            except Exception:
                pass
            finally:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                except (OSError, termios.error):
                    pass
                self._set_mouse_reporting(False)
                self._keyboard_enabled = False

        self._keyboard_thread = threading.Thread(target=_listen, daemon=True)
        self._keyboard_thread.start()

    def _set_mouse_reporting(self, enabled: bool) -> None:
        if self._mouse_reporting_enabled == enabled:
            return

        sequence = self._MOUSE_REPORTING_ON if enabled else self._MOUSE_REPORTING_OFF
        try:
            self._console.file.write(sequence)
            self._console.file.flush()
        except Exception:
            return
        self._mouse_reporting_enabled = enabled

    def _handle_keyboard_char(self, ch: str, *, prefix: bool | str) -> bool | str:
        if not ch:
            return prefix

        if prefix:
            return self._handle_escape_key(ch, prefix=prefix)

        b = ord(ch)

        if b == self._CTRL_C:
            self.request_exit()
            self._interrupt_main()
            return False

        if ch.lower() == "q":
            self.request_exit()
            return False

        if ch == self._ESC:
            return self._ESC

        if ch == "k":
            self._scroll_log(1)
            return False
        if ch == "j":
            self._scroll_log(-1)
            return False

        return False

    def _handle_escape_key(self, ch: str, *, prefix: bool | str) -> bool | str:
        if prefix is True:
            return False

        sequence = f"{prefix}{ch}"
        if sequence == f"{self._ESC}[":
            return sequence

        if sequence.startswith(self._SGR_MOUSE_PREFIX):
            if sequence == self._SGR_MOUSE_PREFIX:
                return sequence
            if ch in ("M", "m"):
                self._handle_sgr_mouse_sequence(sequence)
                return False
            body = sequence[len(self._SGR_MOUSE_PREFIX):]
            if body and body.count(";") <= 2 and all(char.isdigit() or char == ";" for char in body):
                return sequence
            return False

        if sequence in (f"{self._ESC}[A", f"{self._ESC}[D"):
            self._scroll_log(1)
            return False
        if sequence in (f"{self._ESC}[B", f"{self._ESC}[C"):
            self._scroll_log(-1)
            return False
        if sequence == f"{self._ESC}[H":
            self._scroll_log_to_oldest()
            return False
        if sequence == f"{self._ESC}[F":
            self._scroll_log_to_latest()
            return False
        if sequence in (f"{self._ESC}[5", f"{self._ESC}[6", f"{self._ESC}[1", f"{self._ESC}[4"):
            return sequence
        if sequence == f"{self._ESC}[5~":
            self._scroll_log(self._log_page_size())
            return False
        if sequence == f"{self._ESC}[6~":
            self._scroll_log(-self._log_page_size())
            return False
        if sequence == f"{self._ESC}[1~":
            self._scroll_log_to_oldest()
            return False
        if sequence == f"{self._ESC}[4~":
            self._scroll_log_to_latest()
            return False

        return False

    def _handle_sgr_mouse_sequence(self, sequence: str) -> None:
        parsed = self._parse_sgr_mouse_sequence(sequence)
        if parsed is None:
            return

        button, x, y, released = parsed
        button_base = button & 0b11000011
        if button_base == 64:
            if self._point_in_log_panel(x, y):
                self._scroll_log(1)
            return
        if button_base == 65:
            if self._point_in_log_panel(x, y):
                self._scroll_log(-1)
            return

        is_primary_click_or_drag = (button & 0b11) == 0 and button < 64
        if not released and is_primary_click_or_drag and self._point_on_log_scrollbar(x, y):
            self._scroll_log_to_mouse_position(y)

    def _parse_sgr_mouse_sequence(self, sequence: str) -> tuple[int, int, int, bool] | None:
        if not sequence.startswith(self._SGR_MOUSE_PREFIX) or sequence[-1] not in ("M", "m"):
            return None

        parts = sequence[len(self._SGR_MOUSE_PREFIX):-1].split(";")
        if len(parts) != 3:
            return None

        try:
            button, x, y = (int(part) for part in parts)
        except ValueError:
            return None

        return button, x, y, sequence[-1] == "m"

    def _point_in_log_panel(self, x: int, y: int) -> bool:
        left, top, right, bottom = self._log_panel_content_bounds()
        return left <= x <= right and top <= y <= bottom

    def _point_on_log_scrollbar(self, x: int, y: int) -> bool:
        left, top, right, bottom = self._log_panel_content_bounds()
        if not (left <= x <= right and top <= y <= bottom):
            return False
        return x == right and self._log_scrollbar_height() > 0

    def _log_panel_content_bounds(self) -> tuple[int, int, int, int]:
        width, height = self._console.size
        panel_top = HEADER_HEIGHT + CONFIG_HEIGHT + STAGES_HEIGHT + 1
        panel_bottom = height - (SUMMARY_HEIGHT if self._state.finished else 0)
        content_top = panel_top + 1
        content_bottom = panel_bottom - 1
        content_left = 3
        content_right = max(content_left, width - 2)
        return content_left, content_top, content_right, content_bottom

    def _log_scrollbar_height(self) -> int:
        if len(self._state.log_lines) <= max(1, self._state.max_log_lines):
            return 0

        _, top, _, bottom = self._log_panel_content_bounds()
        content_height = max(0, bottom - top + 1)
        visible = min(len(self._state.log_lines), max(1, self._state.max_log_lines))
        return min(content_height, visible)

    def _scroll_log_to_mouse_position(self, y: int) -> None:
        total = len(self._state.log_lines)
        visible = min(total, max(1, self._state.max_log_lines))
        max_offset = max(0, total - visible)
        height = self._log_scrollbar_height()
        if max_offset == 0 or height <= 0:
            return

        _, top, _, _ = self._log_panel_content_bounds()
        thumb_h = min(height, max(1, int(height * (visible / total))))
        track_space = max(0, height - thumb_h)
        if track_space == 0:
            self._state.log_scroll_offset = 0
        else:
            row = max(0, min(y - top, track_space))
            first_visible = round(max_offset * (row / track_space))
            self._state.log_scroll_offset = max_offset - first_visible
        _clamp_log_scroll_offset(self._state)
        self._refresh()

    def _log_page_size(self) -> int:
        return max(1, self._state.max_log_lines)

    def _scroll_log(self, delta: int) -> None:
        self._state.log_scroll_offset += delta
        _clamp_log_scroll_offset(self._state)
        self._refresh()

    def _scroll_log_to_oldest(self) -> None:
        self._state.log_scroll_offset = _max_log_scroll_offset(self._state)
        self._refresh()

    def _scroll_log_to_latest(self) -> None:
        self._state.log_scroll_offset = 0
        self._refresh()

    def _start_live(self) -> None:
        self._sync_log_viewport_size()
        self._app = CodeAuditorApp(
            self._state,
            exit_callback=self._mark_exit_requested,
            interrupt_callback=self._interrupt_from_tui,
        )

        def _run_app() -> None:
            assert self._app is not None
            self._app_thread_id = threading.get_ident()
            self._app.run(headless=True)

        self._app_thread = threading.Thread(target=_run_app, daemon=True)
        self._app_thread.start()

    # ── Refresh ─────────────────────────────────────────────────────────

    def _sync_log_viewport_size(self) -> None:
        _, top, _, bottom = self._log_panel_content_bounds()
        self._state.max_log_lines = max(1, bottom - top + 1)
        _clamp_log_scroll_offset(self._state)

    def _refresh(self) -> None:
        self._sync_log_viewport_size()
        app = self._app
        if app is None:
            return
        if self._app_thread_id == threading.get_ident():
            app.refresh_from_state()
            return
        if self._app_thread is not None and not self._app_thread.is_alive():
            return
        call_from_thread = getattr(app, "call_from_thread", None)
        if call_from_thread is None:
            return
        try:
            call_from_thread(app.refresh_from_state)
        except RuntimeError:
            pass

    def _exit_textual_app(self) -> None:
        app = self._app
        if app is None:
            return
        if self._app_thread_id == threading.get_ident():
            app.exit()
            return
        if self._app_thread is not None and not self._app_thread.is_alive():
            return
        call_from_thread = getattr(app, "call_from_thread", None)
        if call_from_thread is None:
            return
        try:
            call_from_thread(app.exit)
        except RuntimeError:
            pass

    def _stop_textual_app(self) -> None:
        self._exit_textual_app()
        if self._app_thread:
            self._app_thread.join(timeout=1.0)
            if not self._app_thread.is_alive():
                self._app_thread = None
                self._app = None
                self._app_thread_id = None

    # ── Stage events ────────────────────────────────────────────────────

    def begin_stage(self, stage_num: int, detail: str = "") -> None:
        st = _StageState(status="running", detail=detail, start_time=time.time())
        self._state.stages[stage_num] = st
        self._refresh()

    def end_stage(self, stage_num: int, *, success: bool = True) -> None:
        st = self._state.stages.get(stage_num)
        if st:
            st.status = "done" if success else "failed"
            st.end_time = time.time()
            self._refresh()

    def stage_progress(
        self,
        stage_num: int,
        *,
        items_done: int = 0,
        items_total: int = 0,
        detail: str = "",
    ) -> None:
        st = self._state.stages.get(stage_num)
        if st:
            st.items_done = items_done
            st.items_total = items_total
            if detail:
                st.detail = detail
            self._refresh()

    def set_error(self, message: str) -> None:
        self._state.error = message
        self._refresh()


# ── Convenience: configure Rich logging for non-TUI mode ────────────────────

def configure_rich_logging(level: str) -> None:
    """Configure non-TUI logging with the same line format used by the TUI."""
    _configure_logging(level)
