from __future__ import annotations

import json
import os
import tempfile

from code_auditor.parsing.stage2 import parse_au_files, parse_auditing_focus
from code_auditor.validation.stage2 import (
    DEFAULT_MAX_ANALYSIS_UNITS,
    validate_stage2_au_file,
    validate_stage2_dir,
    validate_triage_file,
)
from code_auditor.validation.stage4 import validate_stage4_file
from code_auditor.validation.stage6 import validate_stage6_verdict


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
    # Use max_aus=4 so hard limit is 6; create 7 to exceed it
    max_aus = 4
    count = max_aus + max_aus // 2 + 1  # 7, exceeds hard limit of 6
    with tempfile.TemporaryDirectory() as tmp:
        entries = [_make_triage_entry(f"area{n}", ["a.c"], True) for n in range(1, count + 1)]
        _write_triage(tmp, entries)
        for n in range(1, count + 1):
            _write_au(os.path.join(tmp, f"AU-{n}.json"), "d", ["a.c"], "f")

        issues = validate_stage2_dir(tmp, max_aus=max_aus)
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

        assert validate_stage4_file(finding_path) == []


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


_STAGE6_GOOD_VERDICT = """# Verdict: H-01

## Verdict

real-vulnerability

## Summary

Test summary.

## PoC Behavior

Test.

## Documentation References

- Source: README.md
- Quote: Silent on this topic.

## Analysis

Test.

## Justification

Test.
"""


def test_stage6_verdict_validator_accepts_valid():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "verdict.md")
        with open(path, "w") as f:
            f.write(_STAGE6_GOOD_VERDICT)

        assert validate_stage6_verdict(path) == []


def test_stage6_verdict_validator_rejects_missing_section():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "verdict.md")
        with open(path, "w") as f:
            f.write(_STAGE6_GOOD_VERDICT.replace("## Justification", "## NotJustification"))

        issues = validate_stage6_verdict(path)
        missing = [i for i in issues if "Justification" in i.description]
        assert len(missing) == 1


def test_stage6_verdict_validator_rejects_invalid_verdict_value():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "verdict.md")
        with open(path, "w") as f:
            f.write(_STAGE6_GOOD_VERDICT.replace("real-vulnerability", "totally-fine"))

        issues = validate_stage6_verdict(path)
        verdict_issues = [i for i in issues if "verdict value" in i.description.lower()]
        assert len(verdict_issues) == 1


def test_stage6_verdict_validator_accepts_api_misuse_and_uncertain():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "verdict.md")
        for value in ("api-misuse", "uncertain"):
            with open(path, "w") as f:
                f.write(_STAGE6_GOOD_VERDICT.replace("real-vulnerability", value))
            assert validate_stage6_verdict(path) == []


def test_stage6_verdict_validator_reports_missing_file():
    with tempfile.TemporaryDirectory() as tmp:
        issues = validate_stage6_verdict(os.path.join(tmp, "nope.md"))
        assert len(issues) == 1


