from pathlib import Path

from code_auditor.contracts import (
    STAGE3_REQUIRED_FIELDS,
    STAGE4_DATA_FLOW_TRACE_FIELDS,
    STAGE4_REQUIRED_FIELDS,
)


def test_stage_prompts_document_the_shared_contract_fields() -> None:
    root = Path(__file__).resolve().parents[2] / "code_auditor" / "prompts"
    stage3 = (root / "stage3.md").read_text(encoding="utf-8")
    stage4 = (root / "stage4.md").read_text(encoding="utf-8")

    assert all(field in stage3 for field in STAGE3_REQUIRED_FIELDS)
    assert all(field in stage4 for field in STAGE4_REQUIRED_FIELDS)
    assert all(field in stage4 for field in STAGE4_DATA_FLOW_TRACE_FIELDS)
