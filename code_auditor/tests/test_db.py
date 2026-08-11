from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from code_auditor import __main__ as main_module
from code_auditor.config import AuditConfig
from code_auditor.db import (
    DISCLOSURE_TRASH_RETENTION_SECONDS,
    RUN_CANCELLED,
    RUN_DONE,
    RUN_FAILED,
    RUN_IMPORTED,
    RUN_RUNNING,
    AuditStore,
    scan_output_dir,
)
from code_auditor.disclosures import build_dedupe_key


def _make_output_dir(base: Path) -> Path:
    """Create a synthetic stage 3-6 output layout."""
    out = base / "audit-output-20260101"

    findings = out / "stage3-findings"
    findings.mkdir(parents=True)
    (findings / "AU-1-F-1.json").write_text(
        json.dumps(
            {
                "finding_id": "F-01",
                "title": "Buffer overflow in parser",
                "location": "src/parser.c:parse (lines 10-20)",
                "vulnerability_class": "buffer-overflow",
                "root_cause": "Missing bounds check",
                "preliminary_severity": "High",
            }
        ),
        encoding="utf-8",
    )

    vulns = out / "stage4-vulnerabilities"
    vulns.mkdir(parents=True)
    (vulns / "H-01.json").write_text(
        json.dumps(
            {
                "id": "H-01",
                "title": "Buffer overflow in parser",
                "location": "src/parser.c:parse (lines 10-20)",
                "trigger": "Crafted input packet",
                "data_flow_trace": {
                    "entry_point": "handle_packet",
                    "propagation_chain": ["handle_packet", "parse"],
                    "neutralizing_checks": "none",
                    "sink": "memcpy",
                },
                "cwe_id": ["CWE-120"],
                "vulnerability_class": ["buffer-overflow"],
                "cvss_score": "8.1",
                "severity": "High",
                "impact": "Remote code execution",
            }
        ),
        encoding="utf-8",
    )

    poc = out / "stage5-pocs" / "H-01"
    poc.mkdir(parents=True)
    (poc / "report.md").write_text(
        "# PoC Report\n\nReproduction Status: reproduced\n",
        encoding="utf-8",
    )

    fp_poc = out / "stage5-pocs" / "L-02_fp"
    fp_poc.mkdir(parents=True)
    (fp_poc / "report.md").write_text(
        "# PoC Report\n\nReproduction Status: false-positive\n",
        encoding="utf-8",
    )

    disclosure = out / "stage6-disclosures" / "H-01" / "disclosure"
    disclosure.mkdir(parents=True)
    (disclosure / "report.md").write_text("# Disclosure", encoding="utf-8")
    (disclosure / "email.txt").write_text("Subject: Vuln", encoding="utf-8")
    (disclosure / "disclosure.zip").write_bytes(b"PK\x05\x06")

    return out


def _make_config(base: Path, out: Path) -> AuditConfig:
    return AuditConfig(target=str(base), output_dir=str(out))


def _write_stage5_evidence(out: Path, vuln_id: str = "H-01") -> None:
    poc = out / "stage5-pocs" / vuln_id
    graph = {
        "schema_version": 1,
        "finding_id": vuln_id,
        "title": "Buffer overflow in parser",
        "trigger": "Crafted input packet",
        "evidence_basis": "ASan run and debugger backtrace from the real target",
        "nodes": [
            {
                "id": "source",
                "function": "handle_packet",
                "location": "src/net.c:40",
                "role": "source",
                "description": "Receives attacker-controlled bytes",
                "evidence": "Observed debugger frame",
                "key_parameters": [],
            },
            {
                "id": "sink",
                "function": "parse",
                "location": "src/parser.c:20",
                "role": "sink",
                "description": "Performs the unsafe copy",
                "evidence": "ASan faulting frame",
                "key_parameters": [],
            },
        ],
        "edges": [
            {
                "from": "source",
                "to": "sink",
                "label": "calls",
                "condition": "packet length exceeds buffer capacity",
                "attacker_controlled": True,
            }
        ],
    }
    (poc / "trigger-graph.json").write_text(
        json.dumps(graph), encoding="utf-8"
    )
    (poc / "asan-report.txt").write_text(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
        encoding="utf-8",
    )


# ── scan_output_dir ──────────────────────────────────────────────────────────


def test_scan_output_dir_parses_all_stages(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    artifacts = scan_output_dir(str(out))

    assert len(artifacts["findings"]) == 1
    finding = artifacts["findings"][0]
    assert finding["finding_key"] == "AU-1-F-1"
    assert finding["au_id"] == "AU-1"
    assert finding["preliminary_severity"] == "high"
    assert json.loads(finding["vulnerability_class"]) == ["buffer-overflow"]

    assert len(artifacts["vulnerabilities"]) == 1
    vuln = artifacts["vulnerabilities"][0]
    assert vuln["vuln_id"] == "H-01"
    assert vuln["severity"] == "high"
    assert vuln["cvss_score"] == 8.1
    assert vuln["cvss_score"] != "8.1"  # coerced to REAL
    assert vuln["dedupe_key"].startswith("sha256:")
    assert vuln["entry_point"] == "handle_packet"
    assert vuln["sink"] == "memcpy"
    assert json.loads(vuln["propagation_chain"]) == ["handle_packet", "parse"]

    statuses = {p["vuln_id"]: p["status"] for p in artifacts["pocs"]}
    assert statuses == {"H-01": "reproduced", "L-02": "false-positive"}

    assert len(artifacts["disclosures"]) == 1
    disclosure = artifacts["disclosures"][0]
    assert disclosure["vuln_id"] == "H-01"
    assert disclosure["report_path"].endswith("report.md")
    assert disclosure["zip_path"].endswith("disclosure.zip")


def test_scan_output_dir_indexes_standardized_stage5_evidence(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    _write_stage5_evidence(out)

    artifacts = scan_output_dir(str(out))
    poc = next(item for item in artifacts["pocs"] if item["vuln_id"] == "H-01")

    assert poc["trigger_graph_path"].endswith("stage5-pocs/H-01/trigger-graph.json")
    assert poc["asan_report_path"].endswith("stage5-pocs/H-01/asan-report.txt")


def test_scan_output_dir_ignores_invalid_trigger_graph(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    graph_path = out / "stage5-pocs" / "H-01" / "trigger-graph.json"
    graph_path.write_text('{"schema_version": 1}', encoding="utf-8")

    artifacts = scan_output_dir(str(out))
    poc = next(item for item in artifacts["pocs"] if item["vuln_id"] == "H-01")

    assert poc["trigger_graph_path"] == ""


def test_scan_output_dir_records_poc_dirs_without_report_as_errors(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    dead = out / "stage5-pocs" / "H-03"
    dead.mkdir()
    (dead / "agent.log").write_text("API Error: 429\n", encoding="utf-8")

    artifacts = scan_output_dir(str(out))

    statuses = {p["vuln_id"]: p["status"] for p in artifacts["pocs"]}
    assert statuses == {
        "H-01": "reproduced",
        "L-02": "false-positive",
        "H-03": "error",
    }
    error_poc = next(p for p in artifacts["pocs"] if p["vuln_id"] == "H-03")
    assert error_poc["report_path"] == ""
    assert error_poc["trigger_graph_path"] == ""
    assert error_poc["asan_report_path"] == ""


def test_record_run_counts_only_completed_disclosures(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    # A disclosure whose agent died before producing any artifact.
    (out / "stage6-disclosures" / "C-02" / "disclosure").mkdir(parents=True)

    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    assert run["disclosures_count"] == 1  # only H-01 has a report


def test_get_run_includes_non_reproduced_poc_issues(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    (out / "stage4-vulnerabilities" / "H-03.json").write_text(
        json.dumps(
            {
                "id": "H-03",
                "title": "Vuln whose PoC agent died",
                "location": "src/net.c:f",
                "trigger": "input",
                "data_flow_trace": {},
                "severity": "High",
            }
        ),
        encoding="utf-8",
    )
    dead = out / "stage5-pocs" / "H-03"
    dead.mkdir()
    (dead / "agent.log").write_text("API Error: 429\n", encoding="utf-8")

    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    assert [v["vuln_id"] for v in run["vulnerabilities"]] == ["H-01"]
    assert run["reproduced_vulns_count"] == 1
    issues = {p["vuln_id"]: p["poc_status"] for p in run["poc_issues"]}
    assert issues == {"H-03": "error"}


def test_resume_cancelled_run_accepts_done_with_errors(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        _make_config(tmp_path, out),
        status=RUN_DONE,
        error="3 agent task(s) failed: stage5:H-03",
    )

    assert store.resume_cancelled_run(run_id)
    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_RUNNING
    assert run["error"] == ""


def test_resume_cancelled_run_rejects_clean_done_run(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    assert not store.resume_cancelled_run(run_id)
    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_DONE


def test_resume_cancelled_run_accepts_failed_run(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        _make_config(tmp_path, out),
        status=RUN_FAILED,
        error="18 agent task(s) failed: stage5:H-03",
    )

    assert store.resume_cancelled_run(run_id)
    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_RUNNING


def test_record_run_stores_models_used(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    config = _make_config(tmp_path, out)
    config.models_used.extend(["model-a", "model-b"])
    store = AuditStore(str(tmp_path / "history.db"))

    run_id = store.record_run(config, status=RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    assert json.loads(run["models_used"]) == ["model-a", "model-b"]


def test_finish_run_updates_models_used(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(_make_config(tmp_path, out), started_at=100.0)

    store.finish_run(run_id, RUN_DONE, models_used=["model-a"])

    run = store.get_run(run_id)
    assert run is not None
    assert json.loads(run["models_used"]) == ["model-a"]


def test_record_run_stores_usage_stats(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    config = _make_config(tmp_path, out)
    config.usage_stats.update(
        {"agent_calls": 3, "input_tokens": 1500, "output_tokens": 250, "cost_usd": 0.05}
    )
    store = AuditStore(str(tmp_path / "history.db"))

    run_id = store.record_run(config, status=RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    stats = json.loads(run["usage_stats"])
    assert stats["agent_calls"] == 3
    assert stats["input_tokens"] == 1500
    assert stats["output_tokens"] == 250
    assert stats["cost_usd"] == 0.05


def test_finish_run_updates_usage_stats(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(_make_config(tmp_path, out), started_at=100.0)

    store.finish_run(run_id, RUN_DONE, usage_stats={"agent_calls": 1, "cost_usd": 0.01})

    run = store.get_run(run_id)
    assert run is not None
    assert json.loads(run["usage_stats"]) == {"agent_calls": 1, "cost_usd": 0.01}


def test_scan_output_dir_missing_dir_returns_empty(tmp_path) -> None:
    artifacts = scan_output_dir(str(tmp_path / "nope"))
    assert artifacts == {
        "analysis_units": [],
        "findings": [],
        "vulnerabilities": [],
        "pocs": [],
        "disclosures": [],
    }


def test_scan_output_dir_uses_repo_url_for_vulnerability_dedupe(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    repo_url = "https://example.com/project.git"
    artifacts = scan_output_dir(str(out), repo_url=repo_url)
    raw = json.loads(
        (out / "stage4-vulnerabilities" / "H-01.json").read_text(
            encoding="utf-8"
        )
    )

    assert artifacts["vulnerabilities"][0]["dedupe_key"] == build_dedupe_key(
        raw, repo_url
    )
    assert artifacts["vulnerabilities"][0]["dedupe_key"] != build_dedupe_key(
        raw, ""
    )


# ── AuditStore ───────────────────────────────────────────────────────────────


def test_schema_init_is_idempotent(tmp_path) -> None:
    db = str(tmp_path / "history.db")
    store = AuditStore(db)
    AuditStore(db)  # second init must not raise
    with store._connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(pocs)")}
    assert {"trigger_graph_path", "asan_report_path"} <= columns


def test_record_run_persists_run_and_artifacts(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    started = time.time() - 60

    run_id = store.record_run(
        _make_config(tmp_path, out), status=RUN_DONE, started_at=started
    )

    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_DONE
    assert run["target"] == str(tmp_path)
    assert run["findings_count"] == 1
    assert run["vulns_count"] == 1
    assert run["pocs_reproduced_count"] == 1
    assert run["reproduced_vulns_count"] == 1
    assert run["disclosures_count"] == 1
    assert run["ended_at"] >= started

    assert "findings" not in run
    assert len(run["vulnerabilities"]) == 1
    vuln = run["vulnerabilities"][0]
    assert vuln["poc_status"] == "reproduced"
    assert vuln["poc_report_path"].endswith("stage5-pocs/H-01/report.md")
    assert vuln["disclosure_report_path"].endswith("disclosure/report.md")
    assert vuln["disclosure_email_path"].endswith("email.txt")


def test_persist_artifacts_is_idempotent(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    store.persist_artifacts(run_id, str(out))
    store.persist_artifacts(run_id, str(out))

    run = store.get_run(run_id)
    assert run is not None
    assert len(run["vulnerabilities"]) == 1


def test_get_run_only_returns_reproduced_vulnerabilities(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    (out / "stage4-vulnerabilities" / "M-02.json").write_text(
        json.dumps(
            {
                "id": "M-02",
                "title": "Unconfirmed issue",
                "location": "src/other.c:f",
                "trigger": "input",
                "data_flow_trace": {},
                "severity": "Medium",
            }
        ),
        encoding="utf-8",
    )
    failed_poc = out / "stage5-pocs" / "M-02"
    failed_poc.mkdir()
    (failed_poc / "report.md").write_text(
        "# PoC\n\nReproduction Status: not-reproduced\n", encoding="utf-8"
    )
    (out / "stage4-vulnerabilities" / "M-03.json").write_text(
        json.dumps(
            {
                "id": "M-03",
                "title": "Partial issue",
                "location": "src/partial.c:f",
                "trigger": "input",
                "data_flow_trace": {},
                "severity": "Medium",
            }
        ),
        encoding="utf-8",
    )
    partial_poc = out / "stage5-pocs" / "M-03"
    partial_poc.mkdir()
    (partial_poc / "report.md").write_text(
        "# PoC\n\nReproduction Status: partially-reproduced\n", encoding="utf-8"
    )
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    assert run["vulns_count"] == 3
    assert run["pocs_reproduced_count"] == 1
    assert [v["vuln_id"] for v in run["vulnerabilities"]] == ["H-01"]

    runs, total = store.list_runs()
    assert total == 1
    assert runs[0]["reproduced_vulns_count"] == 1
    assert [item["vuln_id"] for item in store.list_reproduction_candidates()] == [
        "H-01"
    ]
    assert store.get_reproduction_candidate(run_id, "H-01") is not None
    assert store.get_reproduction_candidate(run_id, "M-03") is None


def test_finish_run_updates_status_and_scans(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(_make_config(tmp_path, out))

    store.finish_run(run_id, RUN_DONE)

    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_DONE
    assert run["vulns_count"] == 1
    assert run["ended_at"] is not None


def test_resume_cancelled_run_reuses_same_history_row(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.create_run(
        _make_config(tmp_path, out), started_at=123.0
    )
    store.finish_run(run_id, RUN_CANCELLED, "cancelled", ended_at=456.0)

    assert store.resume_cancelled_run(run_id) is True
    run = store.get_run(run_id)
    assert run is not None
    assert run["id"] == run_id
    assert run["status"] == RUN_RUNNING
    assert run["started_at"] == 123.0
    assert run["ended_at"] is None
    assert run["error"] == ""
    assert store.resume_cancelled_run(run_id) is False

    runs, total = store.list_runs()
    assert total == 1
    assert runs[0]["id"] == run_id


def test_cancel_running_runs_only_recovers_active_rows(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    interrupted_id = store.create_run(
        _make_config(tmp_path, out), started_at=100.0
    )
    done_id = store.create_run(_make_config(tmp_path, out), started_at=200.0)
    store.finish_run(done_id, RUN_DONE, ended_at=250.0)

    recovered = store.cancel_running_runs("worker exited", ended_at=300.0)

    assert recovered == [interrupted_id]
    interrupted = store.get_run(interrupted_id)
    assert interrupted is not None
    assert interrupted["status"] == RUN_CANCELLED
    assert interrupted["error"] == "worker exited"
    assert interrupted["ended_at"] == 300.0
    assert store.get_run(done_id)["status"] == RUN_DONE
    assert store.cancel_running_runs("again") == []
    assert store.resume_cancelled_run(interrupted_id)


def test_import_output_dir(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))

    run_id = store.import_output_dir(str(out))

    run = store.get_run(run_id)
    assert run is not None
    assert run["status"] == RUN_IMPORTED
    assert run["target"] == str(tmp_path)  # defaults to dirname(output_dir)
    assert run["vulns_count"] == 1
    assert run["ended_at"] is not None  # latest artifact mtime

    with pytest.raises(ValueError):
        store.import_output_dir(str(tmp_path / "missing"))


def test_list_runs_pagination(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    for _ in range(3):
        store.record_run(_make_config(tmp_path, out), status=RUN_DONE)

    runs, total = store.list_runs(limit=2, offset=0)
    assert total == 3
    assert len(runs) == 2
    runs, total = store.list_runs(limit=2, offset=2)
    assert len(runs) == 1


def test_get_run_unknown_returns_none(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "history.db"))
    assert store.get_run(999) is None


# ── CLI persistence hook ─────────────────────────────────────────────────────


def test_persist_run_safely_writes_row(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    db_path = str(tmp_path / "history.db")
    config = _make_config(tmp_path, out)

    main_module._persist_run_safely(db_path, config, RUN_DONE, "", time.time())

    store = AuditStore(db_path)
    runs, total = store.list_runs()
    assert total == 1
    assert runs[0]["status"] == RUN_DONE
    assert runs[0]["vulns_count"] == 1


def test_persist_run_safely_swallows_errors(tmp_path) -> None:
    config = AuditConfig(target=str(tmp_path), output_dir=str(tmp_path))
    # Unwritable db path must not raise.
    main_module._persist_run_safely(
        str(tmp_path / "no-such-dir" / "sub" / "\0bad.db"), config, RUN_DONE, "", time.time()
    )


def test_list_runs_filter_by_target(tmp_path) -> None:
    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(_make_config(tmp_path, out), status=RUN_DONE)
    other = tmp_path / "other"
    other.mkdir()
    store.record_run(
        AuditConfig(target=str(other), output_dir=str(out)), status=RUN_DONE
    )

    runs, total = store.list_runs(target=str(tmp_path))
    assert total == 1
    assert runs[0]["target"] == str(tmp_path)

    runs, total = store.list_runs()
    assert total == 2


def test_import_results_tree_maps_targets_and_dates(tmp_path, monkeypatch) -> None:
    import code_auditor.db as db_module
    from datetime import datetime

    root = tmp_path / "results"
    for project, day in (("qemu", "20260102"), ("other", "20260304")):
        vulns = root / project / f"audit-output-{day}" / "stage4-vulnerabilities"
        vulns.mkdir(parents=True)
        (vulns / "H-01.json").write_text(
            json.dumps(
                {
                    "id": "H-01",
                    "title": "v",
                    "location": "l",
                    "trigger": "t",
                    "data_flow_trace": {},
                    "cwe_id": [],
                    "vulnerability_class": [],
                    "cvss_score": 5.0,
                    "severity": "Medium",
                }
            ),
            encoding="utf-8",
        )

    monkeypatch.setattr(
        db_module,
        "list_cloned_repos",
        lambda repos_dir=None: [{"name": "qemu", "path": "/repos/qemu"}],
    )

    store = AuditStore(str(tmp_path / "history.db"))
    run_ids = store.import_results_tree(str(root))
    assert len(run_ids) == 2

    runs = [store.get_run(i) for i in run_ids]
    by_target = {r["target"]: r for r in runs}
    assert "/repos/qemu" in by_target  # matched cloned repo
    assert by_target["/repos/qemu"]["started_at"] == datetime(2026, 1, 2).timestamp()
    other = [r for r in runs if r["target"] != "/repos/qemu"][0]
    assert other["target"] == str(root / "other")
    assert other["started_at"] == datetime(2026, 3, 4).timestamp()


def test_import_results_tree_without_outputs_raises(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "history.db"))
    with pytest.raises(ValueError, match="No audit-output"):
        store.import_results_tree(str(tmp_path))


# ── Repo identity & target_key ───────────────────────────────────────────────


def test_compute_target_key_stable_and_sensitive() -> None:
    from code_auditor.db import compute_target_key

    base = {
        "repo_name": "qemu",
        "commit": "abc123",
        "submodules": [{"path": "slirp", "commit": "s1"}],
    }
    assert compute_target_key(base) == compute_target_key(dict(base))
    assert compute_target_key(base).startswith("sha256:")
    assert compute_target_key({**base, "commit": "def456"}) != compute_target_key(base)
    changed_sub = {
        **base,
        "submodules": [{"path": "slirp", "commit": "s2"}],
    }
    assert compute_target_key(changed_sub) != compute_target_key(base)
    assert compute_target_key({"repo_name": "qemu", "commit": ""}) == ""


def test_schema_migration_adds_identity_columns(tmp_path) -> None:
    import sqlite3

    db = str(tmp_path / "old.db")
    # Pre-migration database: runs table without identity columns.
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE runs (id INTEGER PRIMARY KEY, target TEXT NOT NULL,"
            " output_dir TEXT NOT NULL, status TEXT NOT NULL,"
            " created_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO runs (target, output_dir, status, created_at)"
            " VALUES ('/x', '/x/out', 'done', 1.0)"
        )

    store = AuditStore(db)  # must migrate without error
    with store._connect() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
    for col in ("repo_name", "commit", "submodules", "target_key", "dirty"):
        assert col in columns
    runs, total = store.list_runs()
    assert total == 1  # existing row preserved


def test_record_run_captures_repo_identity(tmp_path) -> None:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "a.txt").write_text("a", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

    out = _make_output_dir(tmp_path)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        AuditConfig(target=str(repo), output_dir=str(out)), status=RUN_DONE
    )

    run = store.get_run(run_id)
    assert run is not None
    assert run["repo_name"] == "repo"
    assert len(run["commit"]) == 40
    assert run["branch"] in ("master", "main")
    assert run["target_key"].startswith("sha256:")
    assert run["dirty"] in (0, 1)

    # target_key filter finds exactly this run.
    runs, total = store.list_runs(target_key=run["target_key"])
    assert total == 1
    assert runs[0]["id"] == run_id


def test_backfill_identities_on_open(tmp_path) -> None:
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    (repo / "a.txt").write_text("a", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)

    db = str(tmp_path / "history.db")
    store = AuditStore(db)
    # Simulate a pre-identity row.
    with store._connect() as conn:
        conn.execute(
            "INSERT INTO runs (target, output_dir, status, created_at, target_key)"
            " VALUES (?, ?, 'imported', 1.0, '')",
            (str(repo), str(tmp_path / "out")),
        )

    # Reopening the store backfills the identity.
    store2 = AuditStore(db)
    runs, _ = store2.list_runs()
    backfilled = [r for r in runs if r["target"] == str(repo)]
    assert backfilled and backfilled[0]["target_key"].startswith("sha256:")


# ── Database-backed Disclosures ──────────────────────────────────────────────


def _make_disclosure_output(
    project_dir: Path,
    *,
    finding_override: dict | None = None,
) -> Path:
    project_dir.mkdir(parents=True, exist_ok=True)
    out = _make_output_dir(project_dir)
    if finding_override is not None:
        (out / "stage4-vulnerabilities" / "H-01.json").write_text(
            json.dumps(finding_override), encoding="utf-8"
        )
    (out / "stage6-disclosures" / "H-01" / "disclosure" / "email.txt").write_text(
        "Subject: Some vuln\n", encoding="utf-8"
    )
    return out


def test_record_run_populates_disclosure_catalogue_and_summary(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )

    entries = store.list_disclosed()
    assert len(entries) == 1
    entry = entries[0]
    assert entry["project"] == "qemu"
    assert entry["review_status"] == "unreviewed"
    assert entry["title"] == "Some vuln"
    assert entry["has_disclosure_report"] is True
    assert {artifact["label"] for artifact in entry["artifacts"]} == {
        "Stage 4 Finding",
        "Stage 5 Report",
        "Stage 6 Report",
        "Stage 6 Email",
        "Stage 6 Zip",
    }
    assert store.disclosed_summary() == {
        "counts": {"unreviewed": 1},
        "projects": ["qemu"],
    }
    assert store.list_disclosed(search="some VULN qemu CWE-120")
    assert store.list_disclosed(search="not-present") == []

    candidate = store.get_disclosed_terminal_candidate(
        "qemu", entry["dedupe_key"]
    )
    assert candidate is not None
    assert candidate["run_id"] == run_id
    assert candidate["poc_dir"].endswith("stage5-pocs/H-01")


def test_record_run_registers_stage5_evidence_for_disclosure(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    _write_stage5_evidence(out)
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )

    labels = {artifact["label"] for artifact in store.list_disclosed()[0]["artifacts"]}
    assert "Stage 5 Trigger Graph" in labels
    assert "Stage 5 ASan Report" in labels


def test_database_disclosures_dedupe_and_preserve_review_status(tmp_path) -> None:
    first = _make_disclosure_output(tmp_path / "one" / "qemu")
    second = _make_disclosure_output(tmp_path / "two" / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(first.parent), output_dir=str(first)),
        status=RUN_DONE,
    )
    entry = store.list_disclosed()[0]
    assert store.set_disclosed_status("qemu", entry["dedupe_key"], "reported")

    store.record_run(
        AuditConfig(target=str(second.parent), output_dir=str(second)),
        status=RUN_DONE,
    )

    assert len(store.list_disclosed()) == 1
    assert store.list_disclosed(status="reported")[0]["dedupe_key"] == entry["dedupe_key"]
    assert store.set_disclosed_status("qemu", entry["dedupe_key"], "fixed") is False
    assert store.set_disclosed_status(
        "qemu", "sha256:" + "0" * 64, "reported"
    ) is False


def test_database_updates_disclosure_metadata_without_changing_identity(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    original = store.list_disclosed()[0]
    assert store.set_disclosed_status("qemu", original["dedupe_key"], "reported")

    metadata = {
        "title": "Reviewed title",
        "location": "hw/net/device.c:handle_packet",
        "cwe": "CWE-787",
        "vulnerability_class": "out-of-bounds-write",
        "trigger": "A crafted packet reaches the unchecked copy.",
        "summary": "Reviewed summary",
        "repo_url": "https://example.com/qemu",
        "audited_commit": "deadbeef",
        "audit_finished_date": "2026-08-04",
        "model_backend": "manual-review",
    }
    assert store.update_disclosed_entry("qemu", original["dedupe_key"], metadata)

    updated = store.list_disclosed()[0]
    assert updated["dedupe_key"] == original["dedupe_key"]
    assert updated["project"] == "qemu"
    assert updated["review_status"] == "reported"
    for field, value in metadata.items():
        assert updated[field] == value
    assert store.update_disclosed_entry(
        "qemu", "sha256:" + "0" * 64, metadata
    ) is False


def test_legacy_file_backed_rows_migrate_to_unique_database_records(tmp_path) -> None:
    db_path = tmp_path / "history.db"
    key = "sha256:" + "a" * 64
    other_key = "sha256:" + "b" * 64
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE disclosed_bugs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                title TEXT,
                location TEXT,
                cwe TEXT,
                vulnerability_class TEXT,
                trigger TEXT,
                summary TEXT,
                repo_url TEXT,
                audited_commit TEXT,
                audit_finished_date TEXT,
                model_backend TEXT,
                review_status TEXT,
                source_html TEXT NOT NULL,
                artifact_links TEXT NOT NULL DEFAULT '[]',
                updated_at REAL,
                UNIQUE(source_html, dedupe_key)
            )
            """
        )
        values = (
            "qemu", key, "Vuln", "loc", "CWE-120", "overflow", "input",
            "summary", "", "abc", "2026-01-01", "claude", "confirmed",
            "[]",
        )
        conn.execute(
            """
            INSERT INTO disclosed_bugs (
                project, dedupe_key, title, location, cwe,
                vulnerability_class, trigger, summary, repo_url,
                audited_commit, audit_finished_date, model_backend,
                review_status, source_html, artifact_links, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'one', ?, 1)
            """,
            values,
        )
        conn.execute(
            """
            INSERT INTO disclosed_bugs (
                project, dedupe_key, title, location, cwe,
                vulnerability_class, trigger, summary, repo_url,
                audited_commit, audit_finished_date, model_backend,
                review_status, source_html, artifact_links, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'two', ?, 2)
            """,
            values,
        )
        conn.execute(
            """
            INSERT INTO disclosed_bugs (
                project, dedupe_key, title, review_status,
                source_html, artifact_links, updated_at
            ) VALUES ('virtualbox', ?, 'Old fixed status', 'fixed', 'old', '[]', 1)
            """,
            (other_key,),
        )

    store = AuditStore(str(db_path))

    with store._connect() as conn:
        columns = {
            row[1] for row in conn.execute("PRAGMA table_info(disclosed_bugs)")
        }
        assert "source_html" not in columns
        assert conn.execute("SELECT COUNT(*) FROM disclosed_bugs").fetchone()[0] == 2
    assert store.list_disclosed(project="qemu")[0]["review_status"] == "confirmed"
    assert store.list_disclosed(project="virtualbox")[0]["review_status"] == "unreviewed"


def test_manual_cve_import_links_local_disclosure_and_reproduced_poc(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    _write_stage5_evidence(out)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    poc_key = store.get_run(run_id)["vulnerabilities"][0]["dedupe_key"]
    assert store.list_disclosed()[0]["dedupe_key"] == poc_key
    assert store.set_disclosed_status("qemu", poc_key, "confirmed")

    imported = store.import_cve(
        {
            "cve_id": "CVE-2026-12345",
            "cvss_score": 8.1,
            "severity": "high",
            "project_url": "https://example.com/qemu",
            "cve_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
            "references": [
                {"label": "Upstream", "url": "https://example.com/advisory"}
            ],
            "dedupe_keys": [poc_key],
        }
    )
    assert imported["project"] == "qemu"

    cve = store.list_cves()[0]
    assert cve["cve_id"] == "CVE-2026-12345"
    assert cve["references"][0]["label"] == "Upstream"
    assert cve["confirmed_disclosures"][0]["review_status"] == "confirmed"
    assert cve["pocs"][0]["run_id"] == run_id
    assert cve["pocs"][0]["vuln_id"] == "H-01"
    assert {
        artifact["label"]
        for artifact in cve["local_disclosures"][0]["artifacts"]
    } >= {"Stage 5 Trigger Graph", "Stage 5 ASan Report"}

    disclosure = store.list_disclosed()[0]
    assert disclosure["cves"] == [
        {
            "cve_id": "CVE-2026-12345",
            "cve_url": "https://www.cve.org/CVERecord?id=CVE-2026-12345",
        }
    ]
    assert store.list_disclosed(search="cve-2026-12345")
    assert store.list_disclosed(search="H-01 Buffer overflow")

    updated_cve = store.update_cve(
        "CVE-2026-12345",
        {
            "cvss_score": 9.1,
            "severity": "critical",
            "project_url": "https://example.com/qemu/security",
            "cve_url": "https://example.com/cve/CVE-2026-12345",
            "references": [
                {"label": "Updated advisory", "url": "https://example.com/new"}
            ],
            "dedupe_keys": [poc_key],
        },
    )
    assert updated_cve is not None
    assert updated_cve["cve_id"] == "CVE-2026-12345"
    assert updated_cve["cvss_score"] == 9.1
    assert updated_cve["severity"] == "critical"
    assert updated_cve["references"] == [
        {"label": "Updated advisory", "url": "https://example.com/new"}
    ]
    assert store.update_cve("CVE-2026-99999", {"dedupe_keys": [poc_key]}) is None

    terminal = store.get_poc_terminal_candidate(run_id, "H-01")
    assert terminal is not None
    assert terminal["poc_dir"] == str(out / "stage5-pocs" / "H-01")
    assert store.get_poc_terminal_candidate(run_id, "L-02") is None


def test_confirmed_disclosure_reassigns_cve_links_atomically(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    assert store.set_disclosed_status("qemu", key, "confirmed")

    for cve_id in ("CVE-2026-61405", "CVE-2026-8348"):
        store.import_cve(
            {
                "cve_id": cve_id,
                "cve_url": f"https://www.cve.org/CVERecord?id={cve_id}",
                "dedupe_keys": [key],
            }
        )

    editable_fields = (
        "title",
        "location",
        "cwe",
        "vulnerability_class",
        "trigger",
        "summary",
        "repo_url",
        "audited_commit",
        "audit_finished_date",
        "model_backend",
    )
    metadata = {field: disclosure.get(field) or "" for field in editable_fields}
    metadata["summary"] = "Association reviewed"
    assert store.update_disclosed_entry(
        "qemu", key, metadata, cve_ids=["CVE-2026-8348"]
    )

    updated = store.list_disclosed()[0]
    assert updated["summary"] == "Association reviewed"
    assert [cve["cve_id"] for cve in updated["cves"]] == ["CVE-2026-8348"]
    assert [cve["cve_id"] for cve in store.list_cves()] == ["CVE-2026-8348"]

    with pytest.raises(ValueError, match="Unknown CVE"):
        store.update_disclosed_entry(
            "qemu", key, {**metadata, "summary": "must roll back"},
            cve_ids=["CVE-2026-99999"],
        )
    rolled_back = store.list_disclosed()[0]
    assert rolled_back["summary"] == "Association reviewed"
    assert [cve["cve_id"] for cve in rolled_back["cves"]] == ["CVE-2026-8348"]

    assert store.set_disclosed_status("qemu", key, "reported")
    assert store.list_disclosed()[0]["cves"] == []
    assert store.list_cves() == []
    with pytest.raises(ValueError, match="only be edited for confirmed"):
        store.update_disclosed_entry("qemu", key, metadata, cve_ids=[])


def test_store_startup_removes_cve_links_from_nonconfirmed_disclosures(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    db_path = tmp_path / "history.db"
    store = AuditStore(str(db_path))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    assert store.set_disclosed_status("qemu", key, "confirmed")
    store.import_cve(
        {
            "cve_id": "CVE-2026-8348",
            "cve_url": "https://www.cve.org/CVERecord?id=CVE-2026-8348",
            "dedupe_keys": [key],
        }
    )

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE disclosed_bugs SET review_status = 'rejected' "
            "WHERE project = 'qemu' AND dedupe_key = ?",
            (key,),
        )

    reopened = AuditStore(str(db_path))
    assert reopened.list_disclosed()[0]["cves"] == []
    assert reopened.list_cves() == []


def test_cve_import_candidates_only_include_confirmed_disclosures(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    assert store.list_cve_import_candidates() == []

    assert store.set_disclosed_status("qemu", key, "confirmed")
    assert [item["dedupe_key"] for item in store.list_cve_import_candidates()] == [
        key
    ]


def test_disclosure_trash_restore_and_expiry(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    db_path = tmp_path / "history.db"
    store = AuditStore(str(db_path))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    disclosure_dir = out / "stage6-disclosures" / "H-01" / "disclosure"
    stage6_vuln_dir = disclosure_dir.parent
    stage6_log = stage6_vuln_dir / "agent.log"
    stage6_log.write_text("keep the non-disclosure Stage 6 log", encoding="utf-8")
    stage5_report = out / "stage5-pocs" / "H-01" / "report.md"

    deleted_at = time.time()
    assert store.trash_disclosure("qemu", key, deleted_at=deleted_at)
    assert store.list_disclosed() == []
    trashed = store.list_disclosure_trash()
    assert len(trashed) == 1
    assert trashed[0]["review_status"] == "unreviewed"
    assert trashed[0]["deleted_at"] == deleted_at
    assert trashed[0]["purge_at"] == deleted_at + DISCLOSURE_TRASH_RETENTION_SECONDS
    assert store.get_disclosed_artifact("qemu", key, 0) is None
    assert store.get_disclosed_terminal_candidate("qemu", key) is None

    assert store.restore_disclosure("qemu", key)
    assert store.list_disclosure_trash() == []
    assert store.list_disclosed()[0]["review_status"] == "unreviewed"

    assert store.trash_disclosure("qemu", key)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE disclosed_bugs SET deleted_at = ? WHERE dedupe_key = ?",
            (time.time() - DISCLOSURE_TRASH_RETENTION_SECONDS - 1, key),
        )
    reopened = AuditStore(str(db_path))
    assert reopened.list_disclosure_trash() == []
    assert not disclosure_dir.exists()
    assert stage6_log.is_file()
    assert stage5_report.is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM disclosed_bugs WHERE dedupe_key = ?", (key,)
        ).fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM disclosures").fetchone()[0] == 0
        assert conn.execute(
            "SELECT disclosures_count FROM runs"
        ).fetchone()[0] == 0


def test_purge_all_trashed_disclosures(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    db_path = tmp_path / "history.db"
    store = AuditStore(str(db_path))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    disclosure_dir = out / "stage6-disclosures" / "H-01" / "disclosure"
    stage5_report = out / "stage5-pocs" / "H-01" / "report.md"

    assert store.purge_all_trashed_disclosures() == 0
    assert store.list_disclosed()[0]["dedupe_key"] == key

    assert store.trash_disclosure("qemu", key)
    assert store.purge_all_trashed_disclosures() == 1
    assert store.list_disclosure_trash() == []
    assert store.list_disclosed() == []
    assert not disclosure_dir.exists()
    assert stage5_report.is_file()
    with sqlite3.connect(db_path) as conn:
        assert conn.execute(
            "SELECT COUNT(*) FROM disclosed_bugs WHERE dedupe_key = ?", (key,)
        ).fetchone()[0] == 0


def test_confirmed_disclosure_trash_preserves_cve_link_for_restore(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    disclosure = store.list_disclosed()[0]
    key = disclosure["dedupe_key"]
    assert store.set_disclosed_status("qemu", key, "confirmed")
    store.import_cve(
        {
            "cve_id": "CVE-2026-8348",
            "cve_url": "https://www.cve.org/CVERecord?id=CVE-2026-8348",
            "dedupe_keys": [key],
        }
    )

    assert store.trash_disclosure("qemu", key)
    assert store.list_disclosed() == []
    assert store.list_cves() == []
    assert store.list_disclosure_trash()[0]["cves"] == [
        {
            "cve_id": "CVE-2026-8348",
            "cve_url": "https://www.cve.org/CVERecord?id=CVE-2026-8348",
        }
    ]

    assert store.restore_disclosure("qemu", key)
    restored = store.list_disclosed()[0]
    assert restored["review_status"] == "confirmed"
    assert [cve["cve_id"] for cve in restored["cves"]] == ["CVE-2026-8348"]
    assert [cve["cve_id"] for cve in store.list_cves()] == ["CVE-2026-8348"]


def test_expired_disclosure_never_deletes_unregistered_stage6_path(tmp_path) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    db_path = tmp_path / "history.db"
    store = AuditStore(str(db_path))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    entry = store.list_disclosed()[0]
    key = entry["dedupe_key"]

    outside = tmp_path / "outside" / "stage6-disclosures" / "H-99" / "disclosure"
    outside.mkdir(parents=True)
    outside_report = outside / "report.md"
    outside_report.write_text("do not delete", encoding="utf-8")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE disclosed_bugs SET review_status = 'slop', artifact_links = ? "
            "WHERE dedupe_key = ?",
            (
                json.dumps([{"label": "Stage 6 Report", "path": str(outside_report)}]),
                key,
            ),
        )

    assert store.trash_disclosure(
        "qemu",
        key,
        deleted_at=time.time() - DISCLOSURE_TRASH_RETENTION_SECONDS - 1,
    )
    assert store.purge_expired_disclosures() == 1
    assert outside_report.is_file()


def test_expired_disclosure_keeps_stage6_directory_referenced_by_active_row(
    tmp_path,
) -> None:
    out = _make_disclosure_output(tmp_path / "qemu")
    db_path = tmp_path / "history.db"
    store = AuditStore(str(db_path))
    store.record_run(
        AuditConfig(target=str(tmp_path / "qemu"), output_dir=str(out)),
        status=RUN_DONE,
    )
    entry = store.list_disclosed()[0]
    key = entry["dedupe_key"]
    disclosure_dir = out / "stage6-disclosures" / "H-01" / "disclosure"

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM disclosed_bugs WHERE dedupe_key = ?", (key,)
        ).fetchone()
        columns = [
            item[1] for item in conn.execute("PRAGMA table_info(disclosed_bugs)")
        ]
        values = dict(zip(columns, row, strict=True))
        values.pop("id")
        values["project"] = "shared-project"
        values["dedupe_key"] = "sha256:" + "b" * 64
        placeholders = ", ".join("?" for _ in values)
        conn.execute(
            f"INSERT INTO disclosed_bugs ({', '.join(values)}) VALUES ({placeholders})",
            tuple(values.values()),
        )

    assert store.set_disclosed_status("qemu", key, "slop")
    assert store.trash_disclosure(
        "qemu",
        key,
        deleted_at=time.time() - DISCLOSURE_TRASH_RETENTION_SECONDS - 1,
    )
    assert store.purge_expired_disclosures() == 1
    assert disclosure_dir.is_dir()
    assert len(store.list_disclosed()) == 1
    assert store.list_disclosed()[0]["project"] == "shared-project"


# ── Analysis units persistence & reuse ───────────────────────────────────────


def _write_au_files(out: Path, count: int = 2) -> None:
    aus_dir = out / "stage2-analysis-units"
    aus_dir.mkdir(parents=True, exist_ok=True)
    for i in range(1, count + 1):
        (aus_dir / f"AU-{i}.json").write_text(
            json.dumps(
                {
                    "description": f"Analyze module {i}",
                    "files": [f"src/mod{i}.c"],
                    "focus": f"parser {i}",
                }
            ),
            encoding="utf-8",
        )


def _git_repo(path: Path) -> None:
    import subprocess

    path.mkdir(exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=path, check=True)
    (path / "a.txt").write_text("a", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=path, check=True)


def test_analysis_units_persisted_with_target_key(tmp_path) -> None:
    from code_auditor.db import compute_target_key
    from code_auditor.repos import capture_repo_identity

    repo = tmp_path / "repo"
    _git_repo(repo)
    out = tmp_path / "out"
    _write_au_files(out)

    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.record_run(
        AuditConfig(target=str(repo), output_dir=str(out)), status=RUN_DONE
    )

    run = store.get_run(run_id)
    assert run is not None
    assert len(run["analysis_units"]) == 2
    au = run["analysis_units"][0]
    assert au["au_id"] == "AU-1"
    assert au["focus"] == "parser 1"
    assert json.loads(au["files"]) == ["src/mod1.c"]
    assert au["target_key"] == compute_target_key(capture_repo_identity(str(repo)))


def test_set_run_identity_updates_analysis_unit_target_key(tmp_path) -> None:
    from code_auditor.db import compute_target_key

    out = tmp_path / "out"
    _write_au_files(out, count=1)
    store = AuditStore(str(tmp_path / "history.db"))
    run_id = store.import_output_dir(str(out), target=str(tmp_path))
    identity = {
        "repo_name": "repo",
        "repo_url": "https://example.com/repo.git",
        "branch": "main",
        "commit": "abc123",
        "dirty": False,
        "submodules": [],
    }

    store.set_run_identity(run_id, identity)

    run = store.get_run(run_id)
    assert run is not None
    assert run["analysis_units"][0]["target_key"] == compute_target_key(identity)


def test_seed_analysis_units_reuses_previous_run(tmp_path) -> None:
    from code_auditor.db import compute_target_key
    from code_auditor.repos import capture_repo_identity

    repo = tmp_path / "repo"
    _git_repo(repo)
    out = tmp_path / "out"
    _write_au_files(out, count=3)

    store = AuditStore(str(tmp_path / "history.db"))
    store.record_run(AuditConfig(target=str(repo), output_dir=str(out)), status=RUN_DONE)
    target_key = compute_target_key(capture_repo_identity(str(repo)))

    aus = store.latest_analysis_units(target_key)
    assert len(aus) == 3

    fresh_out = tmp_path / "fresh-out"
    seeded = store.seed_analysis_units(target_key, str(fresh_out))
    assert seeded == 3
    seeded_files = sorted((fresh_out / "stage2-analysis-units").glob("AU-*.json"))
    assert [p.name for p in seeded_files] == ["AU-1.json", "AU-2.json", "AU-3.json"]
    assert json.loads(seeded_files[0].read_text())["focus"] == "parser 1"

    # Second seed is a no-op (files already exist).
    assert store.seed_analysis_units(target_key, str(fresh_out)) == 0
    # Unknown target key seeds nothing.
    assert store.seed_analysis_units("sha256:unknown", str(tmp_path / "x")) == 0


def test_get_run_related_runs_share_target_key(tmp_path) -> None:
    repo = tmp_path / "repo"
    _git_repo(repo)
    out = tmp_path / "out"
    store = AuditStore(str(tmp_path / "history.db"))
    config = AuditConfig(target=str(repo), output_dir=str(out))
    first = store.record_run(config, status=RUN_DONE)
    second = store.record_run(config, status=RUN_DONE)

    run = store.get_run(second)
    assert run is not None
    assert run["related_run_ids"] == [first]


def test_get_target_merged_unions_vulns_across_runs(tmp_path) -> None:
    from code_auditor.db import compute_target_key
    from code_auditor.repos import capture_repo_identity

    repo = tmp_path / "repo"
    _git_repo(repo)
    out = _make_output_dir(tmp_path)
    (out / "stage4-vulnerabilities" / "L-02.json").write_text(
        json.dumps(
            {
                "id": "L-02",
                "title": "False positive",
                "location": "src/nope.c:f",
                "trigger": "input",
                "data_flow_trace": {},
                "severity": "Low",
            }
        ),
        encoding="utf-8",
    )
    store = AuditStore(str(tmp_path / "history.db"))
    config = AuditConfig(target=str(repo), output_dir=str(out))
    first = store.record_run(config, status=RUN_DONE)
    second = store.record_run(config, status=RUN_DONE)

    target_key = compute_target_key(capture_repo_identity(str(repo)))
    merged = store.get_target_merged(target_key)
    assert merged is not None
    assert {r["id"] for r in merged["runs"]} == {first, second}
    # Both runs contributed H-01. L-02 is excluded because its PoC is a
    # false-positive.
    assert len(merged["vulnerabilities"]) == 2
    assert {v["vuln_id"] for v in merged["vulnerabilities"]} == {"H-01"}
    assert {v["run_id"] for v in merged["vulnerabilities"]} == {first, second}
    assert merged["vulnerabilities"][0]["severity"] == "high"

    assert store.get_target_merged("sha256:unknown") is None


def test_merged_analysis_units_unions_runs_and_collapses_identical(tmp_path) -> None:
    from code_auditor.db import compute_target_key
    from code_auditor.repos import capture_repo_identity

    repo = tmp_path / "repo"
    _git_repo(repo)
    first_out = tmp_path / "first"
    second_out = tmp_path / "second"
    _write_au_files(first_out, count=2)
    _write_au_files(second_out, count=2)
    (second_out / "stage2-analysis-units" / "AU-2.json").write_text(
        json.dumps(
            {
                "description": "Analyze a different module",
                "files": ["src/different.c"],
                "focus": "different parser",
            }
        ),
        encoding="utf-8",
    )

    store = AuditStore(str(tmp_path / "history.db"))
    first = store.record_run(
        AuditConfig(target=str(repo), output_dir=str(first_out)), status=RUN_DONE
    )
    second = store.record_run(
        AuditConfig(target=str(repo), output_dir=str(second_out)), status=RUN_DONE
    )
    target_key = compute_target_key(capture_repo_identity(str(repo)))

    merged = store.merged_analysis_units(target_key)

    assert [au["au_id"] for au in merged] == ["AU-1", "AU-2", "AU-3"]
    assert merged[0]["source_units"] == [
        {"run_id": second, "au_id": "AU-1"},
        {"run_id": first, "au_id": "AU-1"},
    ]
    assert {au["original_au_id"] for au in merged} == {"AU-1", "AU-2"}
    assert store.merged_analysis_units("sha256:unknown") == []

    seeded_out = tmp_path / "seeded"
    assert store.seed_analysis_units(target_key, str(seeded_out)) == 3
    assert sorted(p.name for p in (seeded_out / "stage2-analysis-units").glob("AU-*.json")) == [
        "AU-1.json",
        "AU-2.json",
        "AU-3.json",
    ]
