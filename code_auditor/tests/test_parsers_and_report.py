from __future__ import annotations

import json
import os
import tempfile

from code_auditor.parsing.stage2 import parse_au_files, parse_auditing_focus
from code_auditor.report.generate import generate_report
from code_auditor.validation.stage2 import (
    MAX_ANALYSIS_UNITS,
    validate_stage2_au_file,
    validate_stage2_dir,
    validate_triage_file,
)
from code_auditor.validation.stage4 import validate_stage4_file


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

        assert validate_stage2_au_file(path) == []


def test_stage2_validator_rejects_empty_fields():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "AU-1.json")
        with open(path, "w") as f:
            json.dump({"description": "", "files": [], "focus": ""}, f)

        issues = validate_stage2_au_file(path)
        assert len(issues) == 3  # description, files, focus all blank


def test_stage2_dir_validator_checks_sequential_ids():
    with tempfile.TemporaryDirectory() as tmp:
        _write_triage(tmp, [_make_triage_entry("area1", ["a.c"], True)])
        # Write AU-1 and AU-3 (skipping AU-2)
        for n in (1, 3):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage2_dir(tmp)
        seq_issues = [i for i in issues if "Non-sequential" in i.description]
        assert len(seq_issues) == 1


def test_stage2_dir_validator_rejects_too_many_aus():
    with tempfile.TemporaryDirectory() as tmp:
        entries = [_make_triage_entry(f"area{n}", ["a.c"], True) for n in range(1, MAX_ANALYSIS_UNITS + 3)]
        _write_triage(tmp, entries)
        for n in range(1, MAX_ANALYSIS_UNITS + 3):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage2_dir(tmp)
        too_many_au = [i for i in issues if "Too many analysis units" in i.description]
        too_many_triage = [i for i in issues if "too many areas selected" in i.description]
        assert len(too_many_au) == 1
        assert len(too_many_triage) == 1


def test_stage2_dir_validator_checks_triage_json():
    with tempfile.TemporaryDirectory() as tmp:
        _write_au(os.path.join(tmp, "AU-1.json"), "d", ["a.c"], "f")
        # No triage.json — should produce a validation issue
        issues = validate_stage2_dir(tmp)
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


def test_stage4_validator_and_report_generator_accept_json():
    with tempfile.TemporaryDirectory() as tmp:
        stage1_dir = os.path.join(tmp, "stage-1-details")
        os.makedirs(stage1_dir)
        research_record_path = os.path.join(stage1_dir, "stage-1-security-context.json")
        findings_dir = os.path.join(tmp, "stage-4-details")
        report_path = os.path.join(tmp, "report.md")
        finding_path = os.path.join(findings_dir, "H-01.json")

        os.makedirs(findings_dir)
        with open(research_record_path, "w") as f:
            json.dump({
                "project": {
                    "name": "Example Protocol",
                    "path": "/tmp/example",
                    "language": "C",
                    "description": "Example protocol implementation.",
                    "deployment_model": "Network daemon",
                },
                "sources_consulted": [],
                "scope_announcements": {
                    "in_scope_modules": [],
                    "out_of_scope_modules": [],
                    "in_scope_issue_types": ["memory corruption"],
                    "out_of_scope_issue_types": ["test code"],
                },
                "historical_vulnerabilities": [
                    {
                        "cve_id": "CVE-2024-1234",
                        "date": "2024-01-15",
                        "affected_component": "parser",
                        "vulnerability_class": "buffer overflow",
                        "root_cause": "Missing bounds check",
                        "impact": "RCE",
                        "severity": "Critical",
                        "attacker_profile": "Network attacker",
                        "summary": "Heap buffer overflow in protocol parser.",
                    },
                ],
                "severity_guidance": {
                    "source": "SECURITY.md",
                    "raw_quotes": [],
                    "notes": "Memory corruption in parsers is Critical.",
                },
                "fuzzing_targets": [],
                "notes": "",
            }, f)
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
                "prerequisites": "Default configuration",
                "impact": "DoS",
                "code_snippet": "memcpy(...)",
            }, f)

        assert validate_stage4_file(finding_path) == []

        summary = generate_report(research_record_path, findings_dir, report_path)
        report_content = open(report_path).read()

        assert summary.total_findings == 1
        assert "H-01: Length underflow reaches memcpy" in report_content
        assert "Example Protocol" in report_content
        assert "CVE-2024-1234" in report_content
        assert "Data Flow" in report_content
        assert "net/recv()" in report_content
        assert "parse_packet() reads 2-byte length field" in report_content
        assert "Sink" in report_content


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

        issues = validate_stage4_file(path)
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

        issues = validate_stage4_file(path)
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

        issues = validate_stage4_file(path)
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

        issues = validate_stage4_file(path)
        chain_issues = [i for i in issues if "propagation_chain" in i.description and "array" in i.description]
        assert len(chain_issues) == 1


def test_report_graceful_without_data_flow_trace():
    """Report generator should not crash when data_flow_trace is absent (old findings)."""
    with tempfile.TemporaryDirectory() as tmp:
        stage1_dir = os.path.join(tmp, "stage-1-details")
        os.makedirs(stage1_dir)
        research_path = os.path.join(stage1_dir, "stage-1-security-context.json")
        findings_dir = os.path.join(tmp, "stage-4-details")
        os.makedirs(findings_dir)
        report_path = os.path.join(tmp, "report.md")

        with open(research_path, "w") as f:
            json.dump({"project": {"name": "Test"}, "historical_vulnerabilities": []}, f)

        with open(os.path.join(findings_dir, "M-01.json"), "w") as f:
            json.dump({
                "id": "M-01",
                "title": "Old finding without trace",
                "location": "src/foo.c:bar()",
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer overflow"],
                "cvss_score": "5.0",
                "severity": "Medium",
                "impact": "DoS",
                "code_snippet": "foo()",
            }, f)

        summary = generate_report(research_path, findings_dir, report_path)
        report_content = open(report_path).read()

        assert summary.total_findings == 1
        assert "M-01: Old finding without trace" in report_content
        assert "Data Flow" not in report_content
