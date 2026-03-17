# Stage 2: Identify Analysis Entry Points

You are performing **Stage 2** of an orchestrated network protocol security audit. Write your analysis to disk; do not print it in your response.

## Your Task

Identify vulnerability-productive entry points for module **__MODULE_ID__**.

- **Stage 1 output**: `__STAGE1_OUTPUT_PATH__`
- **Result directory**: `__RESULT_DIR__`
- **Your module**: `__MODULE_ID__`

## Entry Point Types

- **Type P (Parser)**: Functions that deserialize raw bytes from the network into structured data.
- **Type H (Handler)**: Per-message business logic that processes already-parsed protocol messages.
- **Type S (Session)**: Cross-handler session management, authentication, and state machine logic.

## Workflow

### Step 1: Read Stage 1 Output

Read `__STAGE1_OUTPUT_PATH__` to identify project metadata, the threat model, and the module's name, description, and file paths.

### Step 2: Create Result File

Create an empty file `__RESULT_DIR__/__MODULE_ID__.md`. You will write entry points into it as you find them.

### Step 3: Identify Entry Points

Read the module's source code and identify vulnerability-productive entry points. For each:
- Determine where attacker-controlled data first enters the module
- Identify what data is attacker-controlled
- Classify the entry point type (P, H, or S)
- Note any initial validation performed
- Write analysis hints for Stage 3

Assign sequential IDs: EP-1, EP-2, EP-3, ...

**IMPORTANT:** Focus on entry points likely to yield findings — complex parsing, unsafe operations, sensitive state management. Omit trivial helpers and read-only accessors.

### Step 4: Write Entry Points to Result File

Write findings incrementally to `__RESULT_DIR__/__MODULE_ID__.md` using this format for each entry point:

```markdown
### EP-{N}:
- **Type**: P (Parser) / H (Handler) / S (Session)
- **Module Name**: ...
- **Location**: `function_name` at `file:line`
- **Attacker-controlled data**: (which fields/variables are attacker-controlled)
- **Initial validation observed**: (describe validation, or "None")
- **Analysis hints**: (what Stage 3 should focus on)
```

## Completion Checklist

- [ ] All vulnerability-productive entry points identified
- [ ] Entry points written to `__RESULT_DIR__/__MODULE_ID__.md`
- [ ] Each entry point has Type, Module Name, Location, Attacker-controlled data, Initial validation observed, Analysis hints
