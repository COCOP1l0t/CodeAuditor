from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from code_auditor.web.auth import hash_password, verify_password
from code_auditor.web import create_app
from code_auditor.web.settings import WebSettings


PASSWORD = "correct horse battery staple"


def test_verify_password_rejects_unbounded_scrypt_parameters() -> None:
    encoded = hash_password(PASSWORD)
    parts = encoded.split("$")
    parts[1] = str(2**30)
    assert verify_password(PASSWORD, "$".join(parts)) is False


def _client(tmp_path: Path) -> TestClient:
    app = create_app(
        db_path=str(tmp_path / "history.db"),
        web_settings=WebSettings.for_state_dir(
            str(tmp_path), sandbox_mode="local-worktree"
        ),
    )
    return TestClient(app)


def test_first_run_setup_registers_admin_and_gates_api(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        assert client.get("/api/auth/status").json() == {
            "setup_required": True,
            "authenticated": False,
            "user": None,
        }

        setup = client.post(
            "/api/auth/setup",
            json={"username": "Admin", "password": PASSWORD},
        )
        assert setup.status_code == 201
        assert setup.json()["user"]["role"] == "admin"
        assert setup.json()["user"]["username"] == "admin"
        assert client.get("/api/config").status_code == 200

        assert client.post(
            "/api/auth/setup",
            json={"username": "second", "password": PASSWORD},
        ).status_code == 409

        client.post("/api/auth/logout")
        unauthorized = client.get("/api/config")
        assert unauthorized.status_code == 401
        assert unauthorized.headers["www-authenticate"] == "Session"


def test_register_login_logout_and_duplicate_username(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        client.post(
            "/api/auth/setup",
            json={"username": "admin", "password": PASSWORD},
        )
        client.post("/api/auth/logout")

        registered = client.post(
            "/api/auth/register",
            json={"username": "Reviewer", "password": PASSWORD},
        )
        assert registered.status_code == 201
        assert registered.json()["user"]["role"] == "user"

        duplicate = client.post(
            "/api/auth/register",
            json={"username": "reviewer", "password": PASSWORD},
        )
        assert duplicate.status_code == 409

        assert client.post(
            "/api/auth/login",
            json={"username": "reviewer", "password": "wrong password"},
        ).status_code == 401
        login = client.post(
            "/api/auth/login",
            json={"username": "REVIEWER", "password": PASSWORD},
        )
        assert login.status_code == 200
        assert login.json()["user"]["username"] == "reviewer"
        assert client.get("/api/auth/status").json()["authenticated"] is True

        assert client.post("/api/auth/logout").json() == {"logged_out": True}
        assert client.get("/api/auth/status").json()["authenticated"] is False


def test_register_requires_completed_setup(tmp_path: Path) -> None:
    with _client(tmp_path) as client:
        response = client.post(
            "/api/auth/register",
            json={"username": "reviewer", "password": PASSWORD},
        )
        assert response.status_code == 409
