"""Offline checks for the host setup helpers; never modify host configuration."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts/sandbox"


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = load_script("install-gvisor")
configuration = load_script("configure-gvisor")
controller = load_script("sandboxctl")


def bundle(path, *, sidecars=True, extra=None):
    with tarfile.open(path, "w:bz2") as archive:
        names = ["runsc", "containerd-shim-runsc-v1"]
        if sidecars:
            names.append("gvisor-bin/test-sidecar")
        for name in names:
            entry = tarfile.TarInfo(name)
            entry.size = 4
            entry.mode = 0o777
            archive.addfile(entry, io.BytesIO(b"test"))
        if extra:
            archive.addfile(extra, io.BytesIO(b""))


def test_complete_bundle_and_checksum(tmp_path):
    archive = tmp_path / "gvisor.tar.bz2"
    bundle(archive)
    digest = hashlib.sha512(archive.read_bytes()).hexdigest()
    checksum = tmp_path / "checksum"
    checksum.write_text(f"{digest}  gvisor.tar.bz2\n")
    assert installer.verify_checksum(archive, checksum) == digest
    destination = tmp_path / "installed"
    installer.install_bundle(archive, destination, {"sha512": digest})
    assert (destination / "gvisor-bin/test-sidecar").read_bytes() == b"test"
    assert (destination / "runsc").stat().st_mode & 0o777 == 0o755
    assert destination.stat().st_mode & 0o777 == 0o755
    assert json.loads((destination / "code-auditor-install.json").read_text())["sha512"] == digest
    with pytest.raises(ValueError, match="already exists"):
        installer.install_bundle(archive, destination, {})
    checksum.write_text("0" * 128 + "  gvisor.tar.bz2\n")
    with pytest.raises(ValueError, match="mismatch"):
        installer.verify_checksum(archive, checksum)


@pytest.mark.parametrize("kind", ["missing-sidecars", "parent-path", "symlink", "duplicate"])
def test_invalid_bundle_leaves_no_installation(tmp_path, kind):
    archive = tmp_path / "invalid.tar.bz2"
    extra = None
    if kind != "missing-sidecars":
        extra = tarfile.TarInfo("../outside" if kind == "parent-path" else "runsc")
        if kind == "symlink":
            extra.type = tarfile.SYMTYPE
            extra.linkname = "../outside"
    bundle(archive, sidecars=kind != "missing-sidecars", extra=extra)
    destination = tmp_path / "installed"
    with pytest.raises(ValueError):
        installer.install_bundle(archive, destination, {})
    assert not destination.exists()
    assert not (tmp_path / "outside").exists()
    assert not list(tmp_path.glob(".gvisor-stage-*"))


def test_runtime_merge_preserves_existing_settings():
    original = {"default-runtime": "runc", "data-root": "/data/docker",
                "runtimes": {"other": {"path": "/opt/other", "runtimeArgs": ["--flag"]}},
                "log-opts": {"max-size": "10m"}}
    updated = configuration.merge_runtime(json.dumps(original).encode(), Path("/opt/gvisor/runsc"))
    assert updated.pop("runtimes").pop("runsc") == {"path": "/opt/gvisor/runsc"}
    assert updated == {key: value for key, value in original.items() if key != "runtimes"}
    assert configuration.merge_runtime(json.dumps(original).encode(), Path("/bin/runsc"))["runtimes"]["other"] == original["runtimes"]["other"]
    changed = json.dumps({"runtimes": {"runsc": {"path": "/old", "runtimeArgs": ["--debug"]}}}).encode()
    with pytest.raises(ValueError, match="different settings"):
        configuration.merge_runtime(changed, Path("/new"))
    assert configuration.merge_runtime(changed, Path("/new"), True)["runtimes"]["runsc"] == {"path": "/new"}


@pytest.mark.parametrize("raw", [b"[]", b'{"runtimes": null}', b'{"runtimes": {}, "runtimes": {}}', b"bad-json"])
def test_invalid_daemon_config_is_rejected(raw):
    with pytest.raises(ValueError):
        configuration.merge_runtime(raw, Path("/bin/runsc"))


def test_apply_validates_backs_up_and_is_idempotent(tmp_path, monkeypatch):
    config = tmp_path / "daemon.json"
    before = b'{"default-runtime":"runc","log-driver":"local"}\n'
    config.write_bytes(before)
    calls = []

    def validate(command, **kwargs):
        assert command[:3] == ["dockerd", "--validate", "--config-file"]
        assert json.loads(Path(command[3]).read_text())["log-driver"] == "local"
        calls.append(command)

    monkeypatch.setattr(configuration.subprocess, "run", validate)
    backup = configuration.apply_config(config, Path("/opt/gvisor/runsc"), False, "dockerd")
    assert backup.read_bytes() == before
    assert backup.stat().st_mode & 0o777 == 0o600
    assert json.loads(config.read_bytes())["default-runtime"] == "runc"
    assert configuration.apply_config(config, Path("/opt/gvisor/runsc"), False, "dockerd") is None
    assert len(calls) == 1


@pytest.mark.parametrize("outcome", ["invalid", "concurrent-edit"])
def test_validation_failure_or_concurrent_edit_does_not_overwrite(tmp_path, monkeypatch, outcome):
    config = tmp_path / "daemon.json"
    config.write_bytes(b"{}")

    def validate(command, **kwargs):
        if outcome == "invalid":
            raise subprocess.CalledProcessError(1, command)
        config.write_bytes(b'{"debug": true}')

    monkeypatch.setattr(configuration.subprocess, "run", validate)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        configuration.apply_config(config, Path("/opt/runsc"), False, "dockerd")
    assert config.read_bytes() == (b"{}" if outcome == "invalid" else b'{"debug": true}')
    assert not list(tmp_path.glob("*.bak"))
    assert not list(tmp_path.glob(".daemon-candidate-*"))


def test_installer_and_configuration_default_to_preview(tmp_path):
    destination = tmp_path / "gvisor"
    result = subprocess.run([sys.executable, str(SCRIPTS / "install-gvisor.py"),
                             "--destination", str(destination)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Preview only" in result.stdout
    assert not destination.exists()
    runsc = tmp_path / "runsc"
    runsc.write_text("#!/bin/sh\nexit 99\n")
    runsc.chmod(0o755)
    config = tmp_path / "new/daemon.json"
    result = subprocess.run([sys.executable, str(SCRIPTS / "configure-gvisor.py"),
                             "--runsc", str(runsc), "--config", str(config)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "Preview only" in result.stdout
    assert not config.parent.exists()


def test_explicit_verification_rejects_skips(monkeypatch):
    from code_auditor.sandbox import DockerScratch

    monkeypatch.setattr(DockerScratch, "_verify_runtime", lambda self: None)

    def skipped(command, **kwargs):
        report = next(arg.split("=", 1)[1] for arg in command if arg.startswith("--junitxml="))
        Path(report).write_text('<testsuites><testsuite><testcase><skipped/></testcase><testcase/></testsuite></testsuites>')
        assert kwargs["env"]["CODE_AUDITOR_RUN_SANDBOX_TESTS"] == "1"
        assert all("[runsc]" in arg for arg in command[-2:])
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(controller.subprocess, "run", skipped)
    with pytest.raises(ValueError, match="skipped tests are not success"):
        controller.verify("runsc")
