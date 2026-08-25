from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from code_auditor.repos import (
    RepoError,
    ensure_repo,
    ensure_repo_sync,
    repo_local_path,
    validate_remote_repo_url,
)


# ── repo_local_path ──────────────────────────────────────────────────────────


def test_https_url_maps_to_host_owner_repo(tmp_path) -> None:
    dest = repo_local_path("https://github.com/user/repo.git", str(tmp_path))
    assert dest == str(tmp_path / "github.com" / "user" / "repo")


def test_https_url_without_git_suffix(tmp_path) -> None:
    dest = repo_local_path("https://gitlab.com/group/sub/repo", str(tmp_path))
    assert dest == str(tmp_path / "gitlab.com" / "group" / "sub" / "repo")


def test_scp_like_ssh_url(tmp_path) -> None:
    dest = repo_local_path("git@github.com:user/repo.git", str(tmp_path))
    assert dest == str(tmp_path / "github.com" / "user" / "repo")


def test_ssh_scheme_url_maps_to_host_owner_repo(tmp_path) -> None:
    dest = repo_local_path(
        "ssh://git@github.com/user/repo.git", str(tmp_path)
    )
    assert dest == str(tmp_path / "github.com" / "user" / "repo")


def test_url_without_scheme(tmp_path) -> None:
    dest = repo_local_path("github.com/user/repo", str(tmp_path))
    assert dest == str(tmp_path / "github.com" / "user" / "repo")


def test_empty_url_raises(tmp_path) -> None:
    with pytest.raises(RepoError):
        repo_local_path("   ", str(tmp_path))


def test_missing_repo_name_raises(tmp_path) -> None:
    with pytest.raises(RepoError):
        repo_local_path("https://github.com/", str(tmp_path))


def test_dotdot_segment_rejected(tmp_path) -> None:
    with pytest.raises(RepoError):
        repo_local_path("https://github.com/../evil", str(tmp_path))


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/user/repo.git",
        "git@github.com:user/repo.git",
        "ssh://git@gitlab.com/group/repo.git",
    ],
)
def test_validate_remote_repo_url_accepts_safe_remotes(url) -> None:
    assert validate_remote_repo_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "/tmp/local-repo",
        "file:///tmp/local-repo",
        "http://github.com/user/repo.git",
        "https://user:secret@github.com/user/repo.git",
        "https://127.0.0.1/user/repo.git",
        "https://10.0.0.1/user/repo.git",
        "https://localhost/user/repo.git",
        "https://github.com/user/repo.git?upload-pack=evil",
        "root@example.com:user/repo.git",
        "https://github.com/user/repo git",
        "ext::sh -c evil",
    ],
)
def test_validate_remote_repo_url_rejects_unsafe_inputs(url) -> None:
    with pytest.raises(RepoError):
        validate_remote_repo_url(url)


# ── ensure_repo / ensure_repo_sync ───────────────────────────────────────────


def _make_source_repo(base: Path) -> Path:
    src = base / "src-repo"
    src.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=src, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=src, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=src, check=True)
    (src / "README.md").write_text("hello", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=src, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=src, check=True)
    return src


async def test_ensure_repo_clones_and_reuses(tmp_path) -> None:
    src = _make_source_repo(tmp_path)
    repos_dir = str(tmp_path / "repos")

    dest = await ensure_repo(str(src), repos_dir)
    assert os.path.isdir(os.path.join(dest, ".git"))
    assert (Path(dest) / "README.md").is_file()

    # Second call reuses the existing checkout (no re-clone).
    again = await ensure_repo(str(src), repos_dir)
    assert again == dest


async def test_ensure_repo_rejects_non_git_existing_path(tmp_path) -> None:
    src = _make_source_repo(tmp_path)
    repos_dir = tmp_path / "repos"
    dest = repo_local_path(str(src), str(repos_dir))
    Path(dest).mkdir(parents=True)  # exists but no .git

    with pytest.raises(RepoError, match="not a git repository"):
        await ensure_repo(str(src), str(repos_dir))


async def test_ensure_repo_clone_failure_raises(tmp_path) -> None:
    with pytest.raises(RepoError, match="git clone failed"):
        await ensure_repo(str(tmp_path / "missing-repo"), str(tmp_path / "repos"))


def test_ensure_repo_sync_clones(tmp_path) -> None:
    src = _make_source_repo(tmp_path)
    dest = ensure_repo_sync(str(src), str(tmp_path / "repos"))
    assert os.path.isdir(os.path.join(dest, ".git"))


# ── list_cloned_repos ────────────────────────────────────────────────────────


def test_list_cloned_repos_finds_git_dirs(tmp_path) -> None:
    from code_auditor.repos import list_cloned_repos

    repo_a = tmp_path / "github.com" / "user" / "repo-a"
    repo_b = tmp_path / "gitlab.com" / "grp" / "repo-b"
    for repo in (repo_a, repo_b):
        (repo / ".git").mkdir(parents=True)
    # Non-repo directories must be ignored.
    (tmp_path / "github.com" / "user" / "not-a-repo").mkdir(parents=True)

    repos = list_cloned_repos(str(tmp_path))

    assert [r["name"] for r in repos] == [
        "github.com/user/repo-a",
        "gitlab.com/grp/repo-b",
    ]
    assert repos[0]["path"] == str(repo_a)


def test_list_cloned_repos_missing_dir_returns_empty(tmp_path) -> None:
    from code_auditor.repos import list_cloned_repos

    assert list_cloned_repos(str(tmp_path / "missing")) == []


# ── capture_repo_identity ────────────────────────────────────────────────────


def _head(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_capture_identity_basic(tmp_path) -> None:
    from code_auditor.repos import capture_repo_identity

    repo = _make_source_repo(tmp_path)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/user/src-repo.git"],
        cwd=repo,
        check=True,
    )

    identity = capture_repo_identity(str(repo))

    assert identity["commit"] == _head(repo)
    assert identity["branch"] in ("master", "main")
    assert identity["repo_name"] == "src-repo"
    assert identity["repo_url"] == "https://github.com/user/src-repo.git"
    assert identity["dirty"] is False
    assert identity["submodules"] == []

    (repo / "dirty.txt").write_text("x", encoding="utf-8")
    assert capture_repo_identity(str(repo))["dirty"] is True


def test_capture_identity_with_submodule(tmp_path) -> None:
    from code_auditor.repos import capture_repo_identity

    sub = _make_source_repo(tmp_path / "subsrc")
    main = _make_source_repo(tmp_path / "mainsrc")
    subprocess.run(
        ["git", "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub), "libs/sub"],
        cwd=main,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "add submodule"], cwd=main, check=True)

    identity = capture_repo_identity(str(main))

    assert identity["commit"] == _head(main)
    assert identity["repo_name"] == "src-repo"  # falls back to dir basename
    assert identity["submodules"] == [{"path": "libs/sub", "commit": _head(sub)}]


def test_capture_identity_uses_stable_superproject_gitlinks(tmp_path) -> None:
    from code_auditor.db import compute_target_key
    from code_auditor.repos import capture_repo_identity

    nested = _make_source_repo(tmp_path / "nested-src")
    sub = _make_source_repo(tmp_path / "sub-src")
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(nested),
            "deps/nested",
        ],
        cwd=sub,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "add nested"], cwd=sub, check=True)

    main = _make_source_repo(tmp_path / "main-src")
    subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(sub),
            "libs/sub",
        ],
        cwd=main,
        check=True,
    )
    subprocess.run(["git", "commit", "-qm", "add submodule"], cwd=main, check=True)

    initialized = capture_repo_identity(str(main))
    subprocess.run(
        ["git", "submodule", "deinit", "-f", "--all"], cwd=main, check=True
    )
    uninitialized = capture_repo_identity(str(main))

    expected = [{"path": "libs/sub", "commit": _head(sub)}]
    assert initialized["submodules"] == expected
    assert uninitialized["submodules"] == expected
    assert compute_target_key(initialized) == compute_target_key(uninitialized)


def test_capture_identity_non_git_dir(tmp_path) -> None:
    from code_auditor.repos import capture_repo_identity

    identity = capture_repo_identity(str(tmp_path))
    assert identity["commit"] == ""
    assert identity["repo_name"] == ""
    assert identity["submodules"] == []


def test_capture_identity_missing_dir(tmp_path) -> None:
    from code_auditor.repos import capture_repo_identity

    assert capture_repo_identity(str(tmp_path / "nope"))["commit"] == ""


# ── default_audit_output_dir ───────────────────────────────────────────────────


def test_default_audit_output_dir_uses_repo_and_commit(tmp_path) -> None:
    from code_auditor.repos import default_audit_output_dir

    repo = _make_source_repo(tmp_path)
    out = default_audit_output_dir(str(repo), str(tmp_path / "results"))
    expected = str(tmp_path / "results" / "src-repo" / f"audit-output-{_head(repo)[:12]}")
    assert out == expected


def test_default_audit_output_dir_non_git_falls_back_to_date(tmp_path) -> None:
    from datetime import datetime

    from code_auditor.repos import default_audit_output_dir

    out = default_audit_output_dir(str(tmp_path), str(tmp_path / "results"))
    stamp = datetime.now().strftime("%Y%m%d")
    assert out == str(tmp_path / "results" / tmp_path.name / f"audit-output-{stamp}")


def test_default_audit_output_dir_skips_full_worktree_identity(
    tmp_path, monkeypatch
) -> None:
    from code_auditor import repos

    target = str(tmp_path / "checkout")
    calls = []

    def fake_git(_target, *args):  # type: ignore[no-untyped-def]
        calls.append(args)
        return {
            ("rev-parse", "--show-toplevel"): target,
            ("rev-parse", "HEAD"): "a" * 40,
            ("remote", "get-url", "origin"): "https://example.test/org/project.git",
        }.get(args)

    monkeypatch.setattr(repos, "_git", fake_git)

    out = repos.default_audit_output_dir(target, str(tmp_path / "results"))

    assert out == str(tmp_path / "results" / "project" / f"audit-output-{'a' * 12}")
    assert ("status", "--porcelain") not in calls
    assert ("ls-tree", "-r", "HEAD") not in calls


# ── PoC worktree isolation ────────────────────────────────────────────────


async def test_ensure_poc_worktree_creates_and_reuses(tmp_path) -> None:
    from code_auditor.repos import ensure_poc_worktree

    src = _make_source_repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()

    worktree = await ensure_poc_worktree(str(src), str(out))
    assert worktree == str(out / ".poc-worktree")
    assert (Path(worktree) / "README.md").is_file()
    assert _head(Path(worktree)) == _head(src)
    # The shared checkout is not modified, and resume reuses the worktree.
    assert (src / ".git").is_dir()
    assert await ensure_poc_worktree(str(src), str(out)) == worktree


async def test_ensure_poc_worktree_non_git_target_returns_none(tmp_path) -> None:
    from code_auditor.repos import ensure_poc_worktree

    out = tmp_path / "out"
    out.mkdir()
    assert await ensure_poc_worktree(str(tmp_path), str(out)) is None
    assert not (out / ".poc-worktree").exists()
