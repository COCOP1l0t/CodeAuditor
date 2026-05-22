from __future__ import annotations

import logging

from rich.console import Console
from rich.text import Text

_configured = False
_FORMATTER = logging.Formatter()

LEVEL_STYLES = {
    logging.DEBUG: "dim",
    logging.INFO: "cyan",
    logging.WARNING: "yellow",
    logging.ERROR: "red",
    logging.CRITICAL: "red bold",
}


def format_log_record(record: logging.LogRecord) -> Text:
    ts = logging.Formatter.formatTime(
        _FORMATTER,
        record,
        datefmt="[%x %X]",
    )
    style = LEVEL_STYLES.get(record.levelno, LEVEL_STYLES[logging.ERROR])
    message = record.getMessage()
    if record.exc_info:
        message = f"{message}\n{_FORMATTER.formatException(record.exc_info)}"
    elif record.exc_text:
        message = f"{message}\n{record.exc_text}"
    if record.stack_info:
        message = f"{message}\n{record.stack_info}"

    text = Text()
    text.append(f"{ts} ", style="dim")
    text.append(f"{record.levelname:<8}", style=style)
    text.append(f" {message}", style="")
    return text


class _ConsoleLogHandler(logging.Handler):
    def __init__(self, console: Console | None = None) -> None:
        super().__init__()
        self._console = console or Console(stderr=True)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._console.print(format_log_record(record))
        except Exception:
            self.handleError(record)


def configure_logging(level: str) -> None:
    global _configured
    root = logging.getLogger("code_auditor")
    root.handlers.clear()
    handler = _ConsoleLogHandler()
    handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    _configured = True


def get_logger(name: str) -> logging.Logger:
    if not _configured:
        configure_logging("INFO")
    return logging.getLogger(f"code_auditor.{name}")
