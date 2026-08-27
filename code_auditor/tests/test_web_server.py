"""Tests for the blocking Web server entry point."""
from __future__ import annotations

from types import SimpleNamespace

from code_auditor.web import server as server_module


def test_run_web_server_logs_configured_bind_host(monkeypatch) -> None:
    observed: dict[str, object] = {}

    class FakeConfig:
        def __init__(self, app, *, host: str, port: int, log_level: str) -> None:
            observed["config"] = (app, host, port, log_level)

    class FakeServer:
        def __init__(self, config: FakeConfig) -> None:
            observed["server_config"] = config

        async def serve(self) -> None:
            observed["served"] = True

    app = object()
    monkeypatch.setattr(
        server_module,
        "load_web_settings",
        lambda: SimpleNamespace(log_level="INFO"),
    )
    monkeypatch.setattr(server_module, "configure_logging", lambda level: None)
    monkeypatch.setattr(server_module, "create_app", lambda *, web_settings: app)
    monkeypatch.setattr(server_module.logger, "info", lambda *args: observed.setdefault("log", args))
    monkeypatch.setattr("uvicorn.Config", FakeConfig)
    monkeypatch.setattr("uvicorn.Server", FakeServer)

    server_module.run_web_server("0.0.0.0", 8000)

    assert observed["config"] == (app, "0.0.0.0", 8000, "warning")
    assert observed["log"] == ("Web UI available at http://%s:%d", "0.0.0.0", 8000)
    assert observed["served"] is True
