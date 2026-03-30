# Plan: Observation Memory System

## Goal

Add a mirrored observation directory that accumulates security-relevant insights as sub-agents analyze each AU and finding. Later agents read prior observations to avoid redundant work and make better-informed judgments.

## Observation Directory Structure

```
audit-output/
├── observations/
│   ├── _index.md                    # project-wide cross-cutting insights
│   ├── src/
│   │   ├── _module.md               # module-level observations
│   │   ├── net/
│   │   │   ├── _module.md
│   │   │   ├── http_parser.c.md     # per-file, with function-level sections inside
│   │   │   └── tcp_conn.c.md
│   │   └── auth/
│   │       ├── _module.md
│   │       └── session.c.md
```

- Each source file `path/to/foo.c` maps to `observations/path/to/foo.c.md`.
- Each directory gets a `_module.md` for module/directory-level observations.
- `_index.md` holds project-wide cross-cutting insights.
- Observations are stored at **file granularity**, with **function-level sections** inside the file (not separate files per function).

### Observation File Format

```markdown
## File Summary
One-paragraph security-relevant summary of the file's role and trust level.

## function_name (lines X-Y)
- Security-relevant contracts, invariants, guarantees
- Data flow notes: where input comes from, where output goes
- Already-investigated patterns and conclusions

## another_function (lines X-Y)
- ...
```

### What To Store (non-obvious conclusions only)

- Security-relevant contracts: "this function guarantees sanitized output"
- Trust boundaries: "untrusted data enters this module via X"
- Dead code / conditional compilation: "path only reachable with FEATURE_X"
- Data flow conclusions: "user input reaches db_query() via 3 hops, sanitized at hop 2"
- Already-investigated patterns: "checked all callsites of malloc — all have overflow guards"

Do NOT store simple summaries of what code does — the agent can read the code itself. Only store conclusions that required reasoning.

## Sequential Execution

Remove all parallelism from Stage 3 and Stage 5. Process AUs and findings one by one so each agent benefits from all prior observations without concurrency hazards.

### Changes to orchestrator/stages

- **Stage 3**: iterate AUs sequentially (no `run_parallel_limited`), each agent reads existing observations and emits new ones.
- **Stage 5**: iterate findings sequentially (no `run_parallel_limited`), each agent reads existing observations and may add verification-level insights.

## Workflow Per Stage 3 AU

1. **Orchestrator** computes relevant observation file paths from the AU's file list.
2. **Orchestrator** injects observation file paths into the Stage 3 prompt (alongside AU file path).
3. **Agent** reads existing observation files before analyzing code — skips re-deriving known conclusions.
4. **Agent** performs audit, emits findings as usual.
5. **Agent** also emits a structured observations block in its output (JSON array of per-file observations).
6. **Orchestrator** (deterministic code) merges new observations into the mirrored tree — appends new function sections, updates existing ones.

## Workflow Per Stage 5 Finding

1. **Orchestrator** reads the finding's `location` field to determine relevant observation files.
2. **Orchestrator** injects observation file paths into the Stage 5 prompt.
3. **Agent** reads observations for additional context when verifying the finding.
4. **Agent** may emit additional observations (e.g., "confirmed this function is safe" or "discovered additional callers").
5. **Orchestrator** merges any new observations back into the tree.

## Implementation Steps

### Step 1: Create observation directory infrastructure

- **File**: `code_auditor/observations.py` (new)
- Functions:
  - `init_observation_dir(config)` — create `observations/` in output dir.
  - `source_to_obs_path(source_path, config)` — map a source file path to its observation file path.
  - `get_relevant_obs_paths(au_file_list, config)` — given an AU's file list, return paths to existing observation files + their parent `_module.md` files.
  - `merge_observations(agent_output_observations, config)` — parse the agent's structured observations block and write/update the corresponding observation files.
  - `read_observations(obs_paths)` — read and concatenate observation file contents for prompt injection.

### Step 2: Define agent observation output format

The agent emits observations as a JSON block in its output (separate from findings):

```json
{
  "observations": [
    {
      "file": "src/net/http_parser.c",
      "content": "## File Summary\n...\n\n## parse_header (lines 45-120)\n- Bounds-checked...\n"
    },
    {
      "file": "src/net/tcp_conn.c",
      "content": "## File Summary\n...\n"
    }
  ],
  "module_observations": [
    {
      "directory": "src/net",
      "content": "All network input treated as untrusted. Sanitization happens at parse layer."
    }
  ],
  "project_observations": "Optional project-wide insight to append to _index.md"
}
```

### Step 3: Update Stage 3 prompt (`prompts/stage3.md`)

Add to the prompt template:

- `__OBSERVATION_PATHS__` — list of existing observation file paths to read before analysis.
- Instruction: "Before analyzing code, read the observation files listed below for prior insights about these files. Use them to skip re-analyzing known-safe patterns and to inform your analysis of data flows."
- Instruction: "After analysis, emit an observations JSON block (format specified) capturing security-relevant conclusions for every file and function you analyzed deeply."
- Include the observation output JSON schema in the prompt.

### Step 4: Update Stage 3 runner (`code_auditor/stages/stage3.py`)

- Remove `run_parallel_limited` — replace with sequential `for` loop over AUs.
- Before each AU:
  - Call `get_relevant_obs_paths()` to find existing observations.
  - Call `read_observations()` to build the observations context string.
  - Inject into prompt via new `__OBSERVATION_PATHS__` / `__EXISTING_OBSERVATIONS__` placeholder.
- After each AU:
  - Parse the agent's observations block from its output.
  - Call `merge_observations()` to update the observation tree.

### Step 5: Update Stage 5 prompt (`prompts/stage5.md`)

- Add `__EXISTING_OBSERVATIONS__` placeholder — relevant observations for the finding's file(s).
- Instruction: "Use the prior observations below as additional context when verifying this finding. If you discover new security-relevant insights during verification, include them in an observations block."

### Step 6: Update Stage 5 runner (`code_auditor/stages/stage5.py`)

- Remove `run_parallel_limited` — replace with sequential `for` loop over findings.
- Before each finding:
  - Extract file path from finding JSON's `location` field.
  - Look up and inject relevant observations.
- After each finding:
  - If agent emitted observations, merge them.

### Step 7: Update Stage 0 (`code_auditor/stages/stage0.py`)

- Add `init_observation_dir(config)` call to create the `observations/` directory during setup.

### Step 8: Parse agent observation output

- **File**: `code_auditor/parsing/observations.py` (new)
- Function: `extract_observations(agent_text)` — find and parse the observations JSON block from agent output. Return structured data for `merge_observations()`.
- Handle cases where agent doesn't emit observations (graceful fallback).

### Step 9: Validation (optional, low priority)

- Validate observation JSON structure (file paths exist, content is non-empty).
- Not critical — malformed observations are low-risk (they just won't help future agents).
