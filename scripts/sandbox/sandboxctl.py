#!/usr/bin/env python3
"""Check the CodeAuditor environment, build its image, or run benign container tests."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))


def verify(runtime: str) -> int:
    from code_auditor.config import AuditConfig
    from code_auditor.sandbox import DockerScratch

    # Unlike the optional pytest entry point, this explicit command must fail
    # when the requested runtime/image is unavailable, rather than pass via skips.
    config = AuditConfig(target=".", output_dir=".", sandbox_runtime=runtime)
    scratch = DockerScratch(config, "verification-preflight")
    scratch._verify_runtime()
    if importlib.util.find_spec("pytest") is None:
        raise ValueError("install test dependencies first: python -m pip install -e '.[test]'")
    test_file = REPOSITORY / "code_auditor/tests/test_sandbox_integration.py"
    tests = [
        f"{test_file}::test_runtime_write_boundary_and_durable_record[{runtime}]",
        f"{test_file}::test_killed_supervisor_is_cleaned_by_invocation_label[{runtime}]",
    ]
    with tempfile.TemporaryDirectory(prefix="sandbox-test-report-") as directory:
        report = Path(directory) / "results.xml"
        result = subprocess.run([
            sys.executable, "-m", "pytest", "-q", "-rs", "--tb=short",
            f"--junitxml={report}", *tests,
        ], cwd=REPOSITORY, env={**os.environ, "CODE_AUDITOR_RUN_SANDBOX_TESTS": "1"})
        if result.returncode:
            return result.returncode
        cases = ET.parse(report).getroot().findall(".//testcase")
        if len(cases) != 2 or any(case.find(tag) is not None for case in cases
                                  for tag in ("skipped", "failure", "error")):
            raise ValueError("verification requires both tests to pass; skipped tests are not success")
    print(f"Verified {runtime}: write boundary, execution records, and killed-supervisor cleanup.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="read-only application preflight; does not launch a container")
    check.add_argument("--runtime", choices=("docker-default", "runc", "runsc"), default="docker-default")
    check.add_argument("--backend", choices=("claude", "codex"), default="claude")
    build = commands.add_parser("build-image", help="build the repository Dockerfile; may download dependencies")
    build.add_argument("--pull", action="store_true", help="refresh the base image")
    smoke = commands.add_parser("verify", help="run two real, benign container checks without model calls")
    smoke.add_argument("--runtime", choices=("runc", "runsc"), required=True)
    args = parser.parse_args()
    try:
        from code_auditor.config import AuditConfig
        from code_auditor.sandbox import DockerSandboxError, inspect_docker_sandbox_environment
    except ImportError:
        parser.exit(1, "Use the CodeAuditor Python environment: python -m pip install -e '.[test]'\n")
    try:
        if args.command == "check":
            capability = inspect_docker_sandbox_environment(args.backend, args.runtime)
            print(json.dumps(capability.public(), indent=2))
            return 0 if capability.available else 1
        if args.command == "verify":
            return verify(args.runtime)
        config = AuditConfig(target=".", output_dir=".")
        command = [config.sandbox_docker_bin, "build"]
        if args.pull:
            command.append("--pull")
        command.extend([
            "--file", str(REPOSITORY / "docker/code-auditor-sandbox.Dockerfile"),
            "--tag", config.sandbox_image, str(REPOSITORY / "docker"),
        ])
        return subprocess.run(command, check=False).returncode
    except (DockerSandboxError, OSError, ValueError, ET.ParseError) as exc:
        parser.exit(1, f"Sandbox {args.command} failed: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
