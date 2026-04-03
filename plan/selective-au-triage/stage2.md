# Stage 2: Codebase Decomposition into Analysis Units

You are performing **Stage 2** of an orchestrated software security audit. Write your output to disk; do not print it in your response.

## Your Task

Analyze the project at **__TARGET_PATH__** and decompose it into **analysis units** — self-contained work packages that will each be assigned to an independent sub-agent for in-depth security analysis.

This is a targeted vulnerability hunt, not a comprehensive audit. Your goal is to identify the code areas most likely to contain impactful vulnerabilities and create analysis units only for those areas. Code that is unlikely to be bug-productive should be excluded entirely.

- **Result directory**: `__RESULT_DIR__`

## User Instructions

__USER_INSTRUCTIONS__

## Auditing Focus

### Explicit In-Scope and Out-of-Scope Modules

__SCOPE_MODULES__

### Historical Hot Spots

__HISTORICAL_HOT_SPOTS__

## Workflow

### Step 1: Enumerate and Understand

List all source files in **__TARGET_PATH__**. Focus on implementation files (`.c`, `.cpp`, `.go`, `.rs`, `.py`, `.java`, `.ts`, etc.). Exclude: build artifacts, test files (`*_test.*`, `*.test.*`, `test/`, `tests/`), generated code, and third-party vendored dependencies.

Read key project files to understand the project's purpose and architecture:
- `README*`, build files (`Makefile`, `CMakeLists.txt`, `go.mod`, `Cargo.toml`, `package.json`, etc.)
- Directory structure and naming conventions
- Top-level source files that define the main entry points or architecture

### Step 2: Triage

Group the source files into **functional areas** — coarse groupings based on what the code does (e.g. "protocol parsing", "session management", "authentication", "configuration loading"). Count the approximate lines of code in each area.

For each functional area, assess its value for bug hunting. Use the **Auditing Focus** section above as your primary guide:
- **Respect scope boundaries.** Code explicitly marked out of scope should be excluded. In-scope modules should be prioritized.
- **Reflect hot spots.** Areas with historical vulnerabilities or known vulnerability patterns are high-priority targets.
- When the Auditing Focus is empty or states no data is available, use your own judgment based on the code's exposure to untrusted input, complexity, and security sensitivity.

Write a triage manifest to `__RESULT_DIR__/triage.json` — a JSON array where each entry represents one functional area:

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

**Selection rules:**
- At most **30** areas may have `selected` set to `true`.
- 30 is a hard ceiling, not a target. Select only as many areas as genuinely warrant deep security analysis — this could be 5, 15, or 30 depending on the project.
- Every selected area will consume one or more sub-agent slots for deep analysis. Be selective: prefer fewer, well-targeted areas over broad but shallow coverage.
- Every area must have a `rationale` explaining why it was selected or excluded.

### Step 3: Create Analysis Units

For each **selected** area in the triage, create one or more analysis units. If a selected area is too large for a single sub-agent to analyze with sufficient depth, split it into multiple units along natural code boundaries. If it is small enough, one AU per area is fine.

Write **one JSON file per analysis unit** to the result directory:
- `__RESULT_DIR__/AU-1.json`
- `__RESULT_DIR__/AU-2.json`
- etc.

Each file is a self-contained work package:

```json
{
  "description": "Short description of what this unit covers",
  "files": ["relative/path/to/file1.c", "relative/path/to/file2.c"],
  "focus": "Concrete analysis guidance: which functions or subsystems are most complex, which code paths handle external input, what data structures are central, which operations are dangerous (memory copies, size arithmetic, state transitions). Be specific enough that a sub-agent can start analysis immediately."
}
```

Do not create analysis units for areas that were not selected in the triage.

**Rules:**

1. **Actionable focus.** Name concrete functions, data flows, or code patterns — not generic phrases like "look for bugs" or "check for vulnerabilities".
2. **Sequential IDs.** Units must be numbered `AU-1`, `AU-2`, `AU-3`, ... matching their filenames.
3. **Valid JSON.** No trailing commas, no comments, properly quoted strings. The `files` field must be a JSON array of relative file path strings.

## Completion Checklist

- [ ] All source files enumerated (excluding tests, generated code, third-party deps)
- [ ] Code grouped into functional areas with approximate LOC counts
- [ ] Each area assessed for bug-hunting value using the Auditing Focus
- [ ] Triage manifest written to `__RESULT_DIR__/triage.json` with rationale for each area
- [ ] No more than 30 areas selected; only areas that genuinely warrant deep analysis
- [ ] AU files created only for selected areas, written as `AU-{N}.json`
- [ ] Each AU has a clear description and specific, actionable focus
