from code_auditor.runtime_capabilities import (
    require_stage56_execution,
    stage56_execution_capability,
)


def test_windows_enables_only_local_worktree() -> None:
    for mode in ("docker-networked", "docker-isolated"):
        capability = stage56_execution_capability(
            mode, "docker-default", platform_name="nt"
        )
        assert capability.available is False
        assert "WSL2/Linux" in capability.reason

    local = stage56_execution_capability(
        "local-worktree", "docker-default", platform_name="nt"
    )
    assert local.available is True
    assert "Job Object" in local.reason


def test_posix_keeps_stage56_modes_available() -> None:
    for mode in ("docker-networked", "docker-isolated", "local-worktree"):
        capability = stage56_execution_capability(
            mode, "docker-default", platform_name="linux"
        )
        assert capability.available is True


def test_macos_blocks_docker_but_keeps_local_worktree() -> None:
    for mode in ("docker-networked", "docker-isolated"):
        capability = stage56_execution_capability(
            mode, "docker-default", platform_name="darwin"
        )
        assert capability.available is False
        assert "Linux VM/container" in capability.reason

    local = stage56_execution_capability(
        "local-worktree", "docker-default", platform_name="macos"
    )
    assert local.available is True
    assert "macOS worktree" in local.reason


def test_windows_docker_requirement_raises_actionable_error() -> None:
    try:
        require_stage56_execution(
            "docker-networked", "docker-default", platform_name="nt"
        )
    except RuntimeError as exc:
        assert "local-worktree" in str(exc)
    else:
        raise AssertionError("native Windows Docker Stage 5/6 was accepted")


def test_windows_local_worktree_requirement_succeeds() -> None:
    require_stage56_execution(
        "local-worktree", "docker-default", platform_name="nt"
    )
