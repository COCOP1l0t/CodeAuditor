# Stage 3: Vulnerability Analysis — Single Entry Point

You are performing **Stage 3** of an orchestrated network protocol security audit. Write your findings to disk; do not print them in your response.

## Your Task

Perform deep security analysis of **one specific entry point** (`__EP_ID__` in module `__MODULE_ID__`).

- **Target project**: `__TARGET_PATH__`
- **Stage 1 scope**: `__STAGE1_OUTPUT_PATH__`
- **Result directory**: `__RESULT_DIR__`
- **Finding file prefix**: `__FINDING_PREFIX__` (e.g., files will be named `__FINDING_PREFIX__-F-01.md`, `__FINDING_PREFIX__-F-02.md`, etc.)
- **Security checklist**: `__CHECKLIST_PATH__`

## Entry Point to Analyze

```
__EP_BLOCK__
```

## Core Methodology

Use **data-flow-driven analysis**: starting from the entry point function, trace how attacker-controlled values propagate through local variables, struct fields, function arguments, loop bounds, buffer offsets, allocation sizes, and into dangerous sinks (memory operations, system calls, response construction, state updates).

### Type-Specific Strategy

- **Type P (Parser)**: Prioritize memory safety — buffer overflows, OOB access, integer overflows in length/offset calculations, malformed input handling, truncation errors.
- **Type H (Handler)**: Prioritize logic and validation — improper field validation, injection into response construction, incorrect error handling, resource allocation from attacker-controlled values, access control.
- **Type S (Session)**: Prioritize protocol correctness — state machine transitions, auth bypass via state confusion, session fixation, incomplete cleanup, cross-handler race conditions.

## Workflow

### Step 1: Read Stage 1 Scope

Read `__STAGE1_OUTPUT_PATH__` for the project threat model. Let the threat model guide your analysis priorities.

### Step 2: Read the Security Checklist

Read `__CHECKLIST_PATH__` for a comprehensive list of vulnerability classes relevant to this project's language. Use it as your analysis guide — work through the checklist categories systematically.

### Step 3: Analyze the Entry Point

Perform in-depth analysis of the entry point defined above. Read the relevant source files (use `__TARGET_PATH__` as the project root). Trace attacker-controlled data through all code paths.

For each security issue found, write a separate finding file. **Each file contains exactly one finding.**

### Step 4: Write Finding Files

For each confirmed finding, write one file to `__RESULT_DIR__/` named `__FINDING_PREFIX__-F-{NN}.md` (where `{NN}` is a zero-padded two-digit number: F-01, F-02, etc.).

**Each finding file must have this exact format:**

```markdown
<!-- Source context: Module __MODULE_ID__, Entry Point __EP_ID__ (__EP_TYPE__) -->
<!-- Location: __LOCATION__ -->
<!-- Target: __TARGET_PATH__ -->

### F-01: {Short Title}
- **Location**: `{file}:{function}` (lines {X}-{Y})
- **Vulnerability class**: {class}
- **Root cause**: {description in 1-3 sentences}
- **Preliminary severity**: {Critical|High|Medium|Low}
- **Key code snippet**:
```{lang}
{5-30 lines of annotated code showing the vulnerability}
```
- **Reachability notes**: {how an attacker reaches this, prerequisites}
```

**Format rules (strictly enforced by the validation script):**
1. Heading must be exactly `### F-01:` followed by a space and the title.
2. Required fields (each on its own `- **{name}**:` line): `Location`, `Vulnerability class`, `Root cause`, `Preliminary severity`.
3. Severity must be exactly one of: `Critical`, `High`, `Medium`, `Low`.
4. Nothing outside the source context comment and finding block — no intro paragraphs, extra headings, or closing remarks.

**If no findings for this entry point:** write no files. It is valid to produce zero finding files.

## Completion Checklist

- [ ] Threat model read from Stage 1 output
- [ ] Security checklist reviewed
- [ ] Entry point source code read and analyzed
- [ ] All attacker-controlled data paths traced to dangerous sinks
- [ ] One finding file written per confirmed security issue (or zero files if no findings)
- [ ] Each file passes the `validate_stage3.py` format requirements
