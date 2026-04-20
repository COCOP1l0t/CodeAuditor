from __future__ import annotations

import json
import os
import tempfile

from code_auditor.__main__ import _build_parser
from code_auditor.config import AuditConfig
from code_auditor.parsing.stage3 import parse_au_files, parse_auditing_focus
from code_auditor.validation.stage3 import (
    DEFAULT_MAX_ANALYSIS_UNITS,
    validate_stage3_au_file,
    validate_stage3_dir,
    validate_triage_file,
)
from code_auditor.validation.stage2 import (
    validate_stage2_phase_a,
    validate_stage2_phase_b_entry,
    validate_stage2_manifest_final,
)
from code_auditor.validation.stage5 import validate_stage5_file


def _write_au(path: str, desc: str, files: list[str], focus: str) -> None:
    with open(path, "w") as f:
        json.dump({"description": desc, "files": files, "focus": focus}, f)


def _write_triage(result_dir: str, entries: list[dict]) -> None:
    with open(os.path.join(result_dir, "triage.json"), "w") as f:
        json.dump(entries, f)


def _make_triage_entry(area: str, files: list[str], selected: bool) -> dict:
    return {
        "area": area,
        "files": files,
        "loc": 100,
        "rationale": f"{'Selected' if selected else 'Excluded'} for testing.",
        "selected": selected,
    }


def test_stage2_parser_reads_au_files():
    with tempfile.TemporaryDirectory() as tmp:
        _write_au(os.path.join(tmp, "AU-1.json"), "Parses raw DHCP packets", ["src/parser/parse.c", "src/parser/options.c"], "Trace len field through parse_options().")
        _write_au(os.path.join(tmp, "AU-2.json"), "Session management", ["src/session.c"], "Check state transitions.")

        units = parse_au_files(tmp)
        assert len(units) == 2
        assert units[0].id == "AU-1"
        assert units[1].id == "AU-2"


def test_stage2_validator_accepts_valid_au_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        _write_au(path, "Parses raw DHCP packets from the network", ["src/parser/parse.c", "src/parser/options.c"], "Trace the len field from the packet header through parse_options().")

        assert validate_stage3_au_file(path) == []


def test_stage2_validator_rejects_empty_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({"description": "", "files": [], "focus": ""}, f)

        issues = validate_stage3_au_file(path)
        assert len(issues) == 3  # description, files, focus all blank


def test_stage2_dir_validator_checks_sequential_ids():
    with tempfile.TemporaryDirectory() as tmp:
        _write_triage(tmp, [_make_triage_entry("area1", ["a.c"], True)])
        # Write AU-1 and AU-3 (skipping AU-2)
        for n in (1, 3):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage3_dir(tmp)
        seq_issues = [i for i in issues if "Non-sequential" in i.description]
        assert len(seq_issues) == 1


def test_stage2_dir_validator_rejects_too_many_aus():
    # Use max_aus=4 so hard limit is 6; create 7 to exceed it
    max_aus = 4
    count = max_aus + max_aus // 2 + 1  # 7, exceeds hard limit of 6
    with tempfile.TemporaryDirectory() as tmp:
        entries = [_make_triage_entry(f"area{n}", ["a.c"], True) for n in range(1, count + 1)]
        _write_triage(tmp, entries)
        for n in range(1, count + 1):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage3_dir(tmp, max_aus=max_aus)
        too_many_au = [i for i in issues if "Too many analysis units" in i.description]
        too_many_triage = [i for i in issues if "too many areas selected" in i.description]
        assert len(too_many_au) == 1
        assert len(too_many_triage) == 1


def test_stage2_dir_validator_checks_triage_json():
    with tempfile.TemporaryDirectory() as tmp:
        _write_au(os.path.join(tmp, "AU-1.json"), "d", ["a.c"], "f")
        # No triage.json — should produce a validation issue
        issues = validate_stage3_dir(tmp)
        triage_issues = [i for i in issues if "triage.json" in i.description]
        assert len(triage_issues) == 1


def test_triage_validator_accepts_valid():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "triage.json")
        with open(path, "w") as f:
            json.dump([
                _make_triage_entry("Parsing", ["src/parse.c"], True),
                _make_triage_entry("Config", ["src/config.c"], False),
            ], f)

        assert validate_triage_file(path) == []


def test_triage_validator_rejects_missing_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "triage.json")
        with open(path, "w") as f:
            json.dump([{"area": "Parsing"}], f)  # missing files, rationale, selected

        issues = validate_triage_file(path)
        assert len(issues) == 3  # files, rationale, selected


def test_parse_auditing_focus_extracts_sections():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "auditing-focus.md")
        with open(path, "w") as f:
            f.write(
                "# Auditing Focus\n\n"
                "## Explicit In-Scope and Out-of-Scope Modules\n\n"
                "In scope: parser, network\nOut of scope: tests\n\n"
                "## Historical Hot Spots\n\n"
                "- CVE-2024-1234 in parser\n"
            )

        scope, hot_spots = parse_auditing_focus(path)
        assert "parser" in scope
        assert "Out of scope" in scope
        assert "CVE-2024-1234" in hot_spots


def test_parse_auditing_focus_handles_missing_file():
    scope, hot_spots = parse_auditing_focus("/nonexistent/path.md")
    assert scope == ""
    assert hot_spots == ""


def test_stage4_validator_accepts_valid_finding():
    with tempfile.TemporaryDirectory() as tmp:
        finding_path = os.path.join(tmp, "H-01.json")
        with open(finding_path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Length underflow reaches memcpy",
                "location": "src/parser.c:parse_packet (lines 10-24)",
                "data_flow_trace": {
                    "entry_point": "net/recv() in src/net.c:read_packet()",
                    "propagation_chain": [
                        "read_packet() passes raw bytes to parse_packet() as buf param",
                        "parse_packet() reads 2-byte length field from buf into uint16_t len",
                        "len is subtracted by header_size without underflow check, result passed to memcpy as size",
                    ],
                    "neutralizing_checks": "none",
                    "sink": "memcpy(out, buf + offset, len - header_size) in parse_packet():L22",
                },
                "cwe_id": ["CWE-191"],
                "vulnerability_class": ["integer underflow"],
                "cvss_score": "8.1",
                "severity": "High",
                "trigger": "Send a crafted packet with a 2-byte length field smaller than header_size, causing an integer underflow in the memcpy size argument",
                "prerequisites": "Default configuration",
                "impact": "DoS",
                "code_snippet": "memcpy(...)",
            }, f)

        assert validate_stage5_file(finding_path) == []


def test_stage4_validator_rejects_missing_data_flow_trace():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage5_file(path)
        missing = [i for i in issues if "data_flow_trace" in i.description]
        assert len(missing) == 1


def test_stage4_validator_rejects_malformed_data_flow_trace():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        # data_flow_trace is a string instead of an object
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": "not an object",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage5_file(path)
        type_issues = [i for i in issues if "must be a JSON object" in i.description]
        assert len(type_issues) == 1


def test_stage4_validator_rejects_missing_trace_subfields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        # data_flow_trace is an object but missing all subfields
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": {},
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage5_file(path)
        subfield_issues = [i for i in issues if "data_flow_trace" in i.description and "missing" in i.description]
        assert len(subfield_issues) == 4  # entry_point, propagation_chain, neutralizing_checks, sink


def test_stage4_validator_rejects_non_array_propagation_chain():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "H-01.json")
        with open(path, "w") as f:
            json.dump({
                "id": "H-01",
                "title": "Test finding",
                "location": "src/foo.c:bar()",
                "data_flow_trace": {
                    "entry_point": "input",
                    "propagation_chain": "not an array",
                    "neutralizing_checks": "none",
                    "sink": "output",
                },
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "7.5",
            }, f)

        issues = validate_stage5_file(path)
        chain_issues = [i for i in issues if "propagation_chain" in i.description and "array" in i.description]
        assert len(chain_issues) == 1


def test_cli_deployment_build_parallel_default_is_one():
    parser = _build_parser()
    args = parser.parse_args(["--target", "/tmp"])
    assert args.deployment_build_parallel == 1


def test_cli_deployment_build_parallel_can_be_overridden():
    parser = _build_parser()
    args = parser.parse_args(["--target", "/tmp", "--deployment-build-parallel", "4"])
    assert args.deployment_build_parallel == 4


def test_audit_config_has_deployment_build_fields():
    config = AuditConfig(target="/tmp", output_dir="/tmp/out")
    assert config.deployment_build_parallel == 1
    assert config.deployment_build_timeout_sec == 1800


def _make_phase_a_layout(tmp: str, configs: list[dict]) -> None:
    """Create a deployments_dir layout matching what Phase A would produce."""
    os.makedirs(os.path.join(tmp, "configs"), exist_ok=True)
    with open(os.path.join(tmp, "deployment-summary.md"), "w") as f:
        f.write("# Deployment Summary\n\nA non-empty summary.\n")
    for cfg in configs:
        cfg_dir = os.path.join(tmp, "configs", cfg["id"])
        os.makedirs(cfg_dir, exist_ok=True)
        with open(os.path.join(cfg_dir, "deployment-mode.md"), "w") as f:
            f.write(f"# {cfg['name']}\n\nNon-empty deployment-mode body.\n")
    manifest = {"configs": configs}
    with open(os.path.join(tmp, "manifest.json"), "w") as f:
        json.dump(manifest, f)


def _phase_a_config(cfg_id: str = "httpd-static-tls") -> dict:
    return {
        "id": cfg_id,
        "name": "Static web server with TLS",
        "deployment_mode_path": f"configs/{cfg_id}/deployment-mode.md",
        "exposed_surface": ["http parser", "tls handshake"],
        "modules_exercised": ["server/", "modules/ssl/"],
        "build_status": None,
        "artifact_path": None,
        "launch_cmd": None,
        "build_failure_reason": None,
        "attempts_summary": None,
    }


def test_validate_stage2_phase_a_accepts_valid_layout():
    with tempfile.TemporaryDirectory() as tmp:
        _make_phase_a_layout(tmp, [_phase_a_config()])
        assert validate_stage2_phase_a(tmp) == []


def test_validate_stage2_phase_a_rejects_missing_manifest():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "deployment-summary.md"), "w") as f:
            f.write("x\n")
        issues = validate_stage2_phase_a(tmp)
        assert any("manifest.json" in i.description for i in issues)


def test_validate_stage2_phase_a_rejects_empty_configs():
    with tempfile.TemporaryDirectory() as tmp:
        os.makedirs(os.path.join(tmp, "configs"), exist_ok=True)
        with open(os.path.join(tmp, "deployment-summary.md"), "w") as f:
            f.write("x\n")
        with open(os.path.join(tmp, "manifest.json"), "w") as f:
            json.dump({"configs": []}, f)
        issues = validate_stage2_phase_a(tmp)
        assert any("at least one" in i.description.lower() for i in issues)


def test_validate_stage2_phase_a_rejects_non_kebab_id():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _phase_a_config("HttpdStaticTLS")  # camel/pascal case, not kebab
        cfg["deployment_mode_path"] = "configs/HttpdStaticTLS/deployment-mode.md"
        _make_phase_a_layout(tmp, [cfg])
        issues = validate_stage2_phase_a(tmp)
        assert any("kebab" in i.description.lower() for i in issues)


def test_validate_stage2_phase_a_rejects_duplicate_ids():
    with tempfile.TemporaryDirectory() as tmp:
        a = _phase_a_config("dup")
        b = _phase_a_config("dup")
        _make_phase_a_layout(tmp, [a, b])
        issues = validate_stage2_phase_a(tmp)
        assert any("duplicate" in i.description.lower() for i in issues)


def test_validate_stage2_phase_a_rejects_empty_exposed_surface():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _phase_a_config()
        cfg["exposed_surface"] = []
        _make_phase_a_layout(tmp, [cfg])
        issues = validate_stage2_phase_a(tmp)
        assert any("exposed_surface" in i.description for i in issues)


def test_validate_stage2_phase_a_rejects_empty_modules_exercised():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _phase_a_config()
        cfg["modules_exercised"] = []
        _make_phase_a_layout(tmp, [cfg])
        issues = validate_stage2_phase_a(tmp)
        assert any("modules_exercised" in i.description for i in issues)


def test_validate_stage2_phase_a_rejects_missing_deployment_mode_file():
    with tempfile.TemporaryDirectory() as tmp:
        _make_phase_a_layout(tmp, [_phase_a_config()])
        os.remove(os.path.join(tmp, "configs", "httpd-static-tls", "deployment-mode.md"))
        issues = validate_stage2_phase_a(tmp)
        assert any("deployment-mode.md" in i.description for i in issues)


def test_validate_stage2_phase_a_rejects_empty_deployment_mode_file():
    with tempfile.TemporaryDirectory() as tmp:
        _make_phase_a_layout(tmp, [_phase_a_config()])
        with open(os.path.join(tmp, "configs", "httpd-static-tls", "deployment-mode.md"), "w") as f:
            f.write("")
        issues = validate_stage2_phase_a(tmp)
        assert any("deployment-mode.md" in i.description and "empty" in i.description.lower() for i in issues)


def test_validate_stage2_phase_a_rejects_missing_summary():
    with tempfile.TemporaryDirectory() as tmp:
        _make_phase_a_layout(tmp, [_phase_a_config()])
        os.remove(os.path.join(tmp, "deployment-summary.md"))
        issues = validate_stage2_phase_a(tmp)
        assert any("deployment-summary.md" in i.description for i in issues)


def test_validate_stage2_phase_a_rejects_prematurely_set_build_fields():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = _phase_a_config()
        cfg["build_status"] = "ok"
        _make_phase_a_layout(tmp, [cfg])
        issues = validate_stage2_phase_a(tmp)
        assert any("build_status" in i.description and "null" in i.description.lower() for i in issues)


def _make_phase_b_layout(cfg_dir: str, result: dict, scripts: bool = True, artifact: bool = True) -> None:
    os.makedirs(cfg_dir, exist_ok=True)
    with open(os.path.join(cfg_dir, "result.json"), "w") as f:
        json.dump(result, f)
    if scripts:
        for name in ("build.sh", "launch.sh", "smoke-test.sh"):
            path = os.path.join(cfg_dir, name)
            with open(path, "w") as f:
                f.write("#!/bin/sh\n")
            os.chmod(path, 0o755)
    if artifact and result.get("artifact_path"):
        artifact_path = result["artifact_path"]
        os.makedirs(os.path.dirname(artifact_path), exist_ok=True)
        with open(artifact_path, "w") as f:
            f.write("binary")


def test_validate_stage2_phase_b_entry_accepts_ok():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "httpd-static-tls")
        artifact = os.path.join(cfg_dir, "build", "httpd")
        _make_phase_b_layout(cfg_dir, {
            "id": "httpd-static-tls",
            "build_status": "ok",
            "artifact_path": artifact,
            "launch_cmd": f"{cfg_dir}/launch.sh",
            "build_failure_reason": None,
            "attempts_summary": None,
        })
        assert validate_stage2_phase_b_entry(cfg_dir) == []


def test_validate_stage2_phase_b_entry_accepts_infeasible():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "exotic")
        _make_phase_b_layout(cfg_dir, {
            "id": "exotic",
            "build_status": "infeasible",
            "artifact_path": None,
            "launch_cmd": None,
            "build_failure_reason": "requires RDMA hardware not present in this environment",
            "attempts_summary": "tried installing libibverbs; kernel module missing.",
        }, scripts=False, artifact=False)
        assert validate_stage2_phase_b_entry(cfg_dir) == []


def test_validate_stage2_phase_b_entry_rejects_id_mismatch():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "expected-id")
        artifact = os.path.join(cfg_dir, "build", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "different-id",
            "build_status": "ok",
            "artifact_path": artifact,
            "launch_cmd": "x",
            "build_failure_reason": None,
            "attempts_summary": None,
        })
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("id" in i.description and "match" in i.description for i in issues)


def test_validate_stage2_phase_b_entry_rejects_unknown_status():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "x",
            "build_status": "weird",
            "artifact_path": None,
            "launch_cmd": None,
            "build_failure_reason": None,
            "attempts_summary": None,
        }, scripts=False, artifact=False)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("build_status" in i.description for i in issues)


def test_validate_stage2_phase_b_entry_ok_requires_artifact_on_disk():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "x",
            "build_status": "ok",
            "artifact_path": "/nonexistent/path/binary",
            "launch_cmd": "x",
            "build_failure_reason": None,
            "attempts_summary": None,
        }, artifact=False)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("artifact_path" in i.description for i in issues)


def test_validate_stage2_phase_b_entry_ok_requires_executable_scripts():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        artifact = os.path.join(cfg_dir, "build", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "x",
            "build_status": "ok",
            "artifact_path": artifact,
            "launch_cmd": "x",
            "build_failure_reason": None,
            "attempts_summary": None,
        })
        # Strip exec bit on launch.sh
        os.chmod(os.path.join(cfg_dir, "launch.sh"), 0o644)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("launch.sh" in i.description and "executable" in i.description for i in issues)


def test_validate_stage2_phase_b_entry_infeasible_rejects_vacuous_reason():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "x",
            "build_status": "infeasible",
            "artifact_path": None,
            "launch_cmd": None,
            "build_failure_reason": "build failed",
            "attempts_summary": "tried.",
        }, scripts=False, artifact=False)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("build_failure_reason" in i.description and "vacuous" in i.description.lower() for i in issues)


def test_validate_stage2_phase_b_entry_infeasible_requires_attempts_summary():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        _make_phase_b_layout(cfg_dir, {
            "id": "x",
            "build_status": "infeasible",
            "artifact_path": None,
            "launch_cmd": None,
            "build_failure_reason": "missing libfoo, no apt package available",
            "attempts_summary": "",
        }, scripts=False, artifact=False)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("attempts_summary" in i.description for i in issues)


def test_validate_stage2_phase_b_entry_missing_result_json():
    with tempfile.TemporaryDirectory() as tmp:
        cfg_dir = os.path.join(tmp, "configs", "x")
        os.makedirs(cfg_dir, exist_ok=True)
        issues = validate_stage2_phase_b_entry(cfg_dir)
        assert any("result.json" in i.description for i in issues)


def test_validate_stage2_manifest_final_accepts_one_ok():
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = os.path.join(tmp, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump({"configs": [
                {"id": "a", "build_status": "ok"},
                {"id": "b", "build_status": "infeasible"},
            ]}, f)
        assert validate_stage2_manifest_final(manifest_path) == []


def test_validate_stage2_manifest_final_warns_on_zero_ok():
    with tempfile.TemporaryDirectory() as tmp:
        manifest_path = os.path.join(tmp, "manifest.json")
        with open(manifest_path, "w") as f:
            json.dump({"configs": [
                {"id": "a", "build_status": "infeasible"},
                {"id": "b", "build_status": "timeout"},
            ]}, f)
        issues = validate_stage2_manifest_final(manifest_path)
        assert any("no entries" in i.description.lower() and "ok" in i.description.lower() for i in issues)


def test_validate_stage2_manifest_final_missing_file():
    issues = validate_stage2_manifest_final("/nonexistent/manifest.json")
    assert any("manifest.json" in i.description.lower() for i in issues)

