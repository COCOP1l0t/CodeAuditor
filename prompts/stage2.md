# Stage 2: Codebase Decomposition into Analysis Units

You are performing **Stage 2** of an orchestrated software security audit. Write your output to disk; do not print it in your response.

## Your Task

Analyze the project at **__TARGET_PATH__** and decompose it into **analysis units** — self-contained work packages that will each be assigned to an independent sub-agent for security analysis.

- **Result directory**: `__RESULT_DIR__`

## User Instructions

__USER_INSTRUCTIONS__

## Auditing Focus

### Explicit In-Scope and Out-of-Scope Modules

__SCOPE_MODULES__

### Historical Hot Spots

__HISTORICAL_HOT_SPOTS__

## Workflow

### Step 1: Enumerate Source Files

List all source files in **__TARGET_PATH__**. Focus on implementation files (`.c`, `.cpp`, `.go`, `.rs`, `.py`, `.java`, `.ts`, etc.). Exclude: build artifacts, test files (`*_test.*`, `*.test.*`, `test/`, `tests/`), generated code, and third-party vendored dependencies.

### Step 2: Understand the Project

Read key project files to understand the project's purpose and architecture:
- `README*`, build files (`Makefile`, `CMakeLists.txt`, `go.mod`, `Cargo.toml`, `package.json`, etc.)
- Directory structure and naming conventions
- Top-level source files that define the main entry points or architecture

### Step 3: Measure and Decompose

Group related source files into analysis units based on what the code **does**, not where it lives. Each unit must have proper code size for a single sub-agent to analyze with sufficient depth. Count the lines of code in the files you are grouping to inform your sizing decisions.

**Good split boundaries:**
- Protocol parsing vs. protocol handling vs. session/state management
- Different protocol versions or message types
- Core logic vs. I/O vs. configuration vs. utility code
- Independent subsystems with minimal coupling
- Top-level dispatch branches or distinct functional layers

Do not split purely by directory — group by functionality. Do not merge unrelated subsystems into one unit just because they share a directory.

Use the **Auditing Focus** section above to guide decomposition, and:
- **Respect scope boundaries.** Code that is explicitly out of scope according to the Auditing Focus does not need to be included in any analysis unit. In-scope modules should get tighter, more focused units.
- **Reflect hot spots in the `focus` field.** When writing an AU that covers a historical hot spot, mention the relevant vulnerability classes and patterns in the `focus` so the downstream analysis agent knows what to prioritize.

If the Auditing Focus section is empty or states that no historical data is available, decompose based purely on code structure and sizing.

### Step 4: Write Output

Write **one JSON file per analysis unit** to the result directory:
- `__RESULT_DIR__/AU-1.json`
- `__RESULT_DIR__/AU-2.json`
- etc.

Each file is a self-contained work package:

```json
{
  "description": "Short description of what this unit covers",
  "files": ["relative/path/to/file1.c", "relative/path/to/file2.c"],
  "focus": "Concrete analysis guidance: which functions or subsystems are most complex, which code paths handle external input, what data structures are central, which operations are dangerous (memory copies, size arithmetic, state transitions). Be specific enough that a sub-agent can start analysis immediately.",
  "analyze": true
}
```

Also write a project summary to `__RESULT_DIR__/project-summary.json`:

```json
{
  "project_summary": {
    "path": "__TARGET_PATH__",
    "name": "project name",
    "language": "primary language",
    "description": "Brief description of what the project does"
  },
  "au_count": 5
}
```

### Step 5: Select Units for Analysis

Review all the analysis units you produced. Select the units that should be included in subsequent deep analysis, based on their security relevance and the Auditing Focus. Set the `analyze` field to `true` for selected units and `false` for units that can be skipped.

No more than **50** units should have `analyze` set to `true`. If you produced more than 50 units, prioritize those covering in-scope modules, historical hot spots, code that handles external input, and security-critical functionality.

**Rules:**

1. **Actionable focus.** Name concrete functions, data flows, or code patterns — not generic phrases like "look for bugs" or "check for vulnerabilities".
2. **Sequential IDs.** Units must be numbered `AU-1`, `AU-2`, `AU-3`, ... matching their filenames.
3. **Valid JSON.** No trailing commas, no comments, properly quoted strings. The `files` field must be a JSON array of relative file path strings.

## Completion Checklist

- [ ] All source files enumerated (excluding tests, generated code, third-party deps)
- [ ] Lines of code counted for each file or file group
- [ ] Files grouped into analysis units guided by auditing focus and code structure
- [ ] Each unit has a clear description and specific, actionable focus
- [ ] `analyze` field set for each unit; no more than 50 units selected
- [ ] One JSON file per unit written to `__RESULT_DIR__/` as `AU-{N}.json`
- [ ] Project summary written to `__RESULT_DIR__/project-summary.json`
- [ ] `au_count` in project summary matches the number of AU files written
