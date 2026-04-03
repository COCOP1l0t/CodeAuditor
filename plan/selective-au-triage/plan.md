# Plan: Selective AU Triage for Stage 2

## Motivation

Stage 2 decomposes a codebase into analysis units (AUs), each analyzed by an independent sub-agent in stage 3. The current prompt tells the agent "no more than 50 units should have `analyze` set to `true`." In practice, the agent always produces exactly 50 AUs with `analyze: true` regardless of codebase size or security relevance — it treats the ceiling as a target.

The root cause is structural: the prompt asks the agent to create all AUs first (Step 3–4), then retroactively select which ones to analyze (Step 5). By the time the agent reaches the selection step, it has already committed to the AUs it created and has no incentive to exclude any.

## Design

Restructure the prompt into a **triage-first** workflow:

1. **Enumerate and understand** the codebase (same as today).
2. **Triage**: group code into functional areas, assess each area's bug-hunting value using stage 1 research (hot spots, scope boundaries), and write a triage manifest recording all areas with selection rationale. At most **30** areas may be selected.
3. **Create AUs** only for selected areas from the triage. Every AU file written will be analyzed — no `analyze` field needed.

This forces the agent to make exclusion decisions *before* creating any AU files.

### Additional cleanup

- **Drop `analyze` field** from the AU JSON schema. The triage manifest replaces it as the selection/exclusion record. Every AU file that exists goes to stage 3.
- **Drop `project-summary.json`**. No code reads it — the report's project summary comes from the stage 1 research record.

## Current data flow

```
Step 1-2: Enumerate + Understand
        ↓
Step 3: Group ALL code into AUs
        ↓
Step 4: Write ALL AU files (AU-1.json ... AU-N.json) + project-summary.json
        ↓
Step 5: Retroactively set analyze=true/false on each AU
        ↓
Parser filters to only analyze=true AUs → stage 3
```

## Proposed data flow

```
Step 1: Enumerate + Understand
        ↓
Step 2: Triage — assess all code areas, write triage.json (selected + excluded with rationale)
        ↓
Step 3: Create AU files ONLY for selected areas → stage 3 (all AUs analyzed)
```

---

## Changes required

### 1. Prompt rewrite: `prompts/stage2.md`

Replace the current 5-step workflow with 3 steps. Full draft in [stage2.md](stage2.md).

Key changes from current prompt:
- **Step 2 (Triage)** is entirely new. The agent groups code into functional areas, assesses each one using the Auditing Focus, and writes `triage.json` to the result directory. The manifest is an array of objects:
  ```json
  [
    {
      "area": "DHCP packet parsing",
      "files": ["src/parser/parse.c", "src/parser/options.c"],
      "loc": 1200,
      "rationale": "Parses untrusted network input; historical CVE-2024-1234 in this component.",
      "selected": true
    },
    {
      "area": "Configuration file loading",
      "files": ["src/config.c"],
      "loc": 300,
      "rationale": "Reads local config only, no external input handling.",
      "selected": false
    }
  ]
  ```
- **Step 3 (Create AUs)** only creates AUs for selected areas. The AU JSON schema drops the `analyze` field:
  ```json
  {
    "description": "Short description of what this unit covers",
    "files": ["relative/path/to/file1.c", "relative/path/to/file2.c"],
    "focus": "Concrete analysis guidance..."
  }
  ```
- **Step 5 (Select Units)** is deleted — selection happens in the triage step.
- **`project-summary.json`** is removed from the output instructions.
- Hard cap changes from 50 to **30**.

### 2. Parser: `code_auditor/parsing/stage2.py`

**`parse_au_files()`** — remove the `only_analyze` parameter and all `analyze`-field filtering logic. Every AU file found is returned.

Current:
```python
def parse_au_files(result_dir: str, only_analyze: bool = True) -> list[AnalysisUnit]:
    ...
    if only_analyze and not data.get("analyze", True):
        continue
    ...
```

New:
```python
def parse_au_files(result_dir: str) -> list[AnalysisUnit]:
    ...
    # No filtering — every AU file is returned
    ...
```

`parse_auditing_focus()` is unchanged.

### 3. Validator: `code_auditor/validation/stage2.py`

**`validate_stage2_au_file()`** — remove the `analyze` field check (lines 130–135).

**`validate_stage2_dir()`**:
- Remove the `analyze_count` tracking and the "Too many units selected" check (lines 56–76).
- Add a check that the total number of AU files does not exceed 30.
- Add a check that `triage.json` exists and is valid JSON (array of objects, each with `area`, `files`, `rationale`, `selected` fields).

### 4. Stage runner: `code_auditor/stages/stage2.py`

No structural changes. The runner already calls the agent, validates, and parses AU files. The only change is that `parse_au_files()` no longer takes `only_analyze`.

### 5. Orchestrator: `code_auditor/orchestrator.py`

Line 61 calls `parse_au_files(stage2_dir)` — this already works without the `only_analyze` parameter since it defaulted to `True`. After removing the parameter, this call is unchanged.

### 6. Tests: `code_auditor/tests/test_parsers_and_report.py`

| Test | Action |
|------|--------|
| `test_stage2_parser_reads_au_files` | Rewrite: remove `analyze` field from test data, remove `only_analyze=True/False` assertions. Test that all AU files are returned. |
| `test_stage2_validator_accepts_valid_au_file` | Update: remove `analyze` field from test JSON. |
| `test_stage2_validator_rejects_empty_fields` | Update: expected issue count changes from 3 to 3 (description, files, focus — `analyze` no longer checked). No change needed. |
| `test_stage2_validator_rejects_missing_analyze` | **Delete** — `analyze` field no longer exists. |
| `test_stage2_dir_validator_checks_sequential_ids` | Update: remove `analyze` field from test JSON. |
| `test_stage2_dir_validator_rejects_too_many_analyze` | **Replace** with `test_stage2_dir_validator_rejects_too_many_aus` — create 32 AU files and assert the validator rejects (cap is 30). |
| (new) `test_stage2_dir_validator_checks_triage_json` | Add: validate that missing or malformed `triage.json` produces validation issues. |

---

## Files to modify

| File | Action |
|------|--------|
| `prompts/stage2.md` | Rewrite — triage-first workflow, drop `analyze`, drop `project-summary.json` |
| `code_auditor/parsing/stage2.py` | Remove `only_analyze` parameter and filtering |
| `code_auditor/validation/stage2.py` | Remove `analyze` checks, add triage.json validation, change cap to 30 |
| `code_auditor/stages/stage2.py` | No structural changes |
| `code_auditor/orchestrator.py` | No changes needed |
| `code_auditor/tests/test_parsers_and_report.py` | Update/delete/add tests per table above |
