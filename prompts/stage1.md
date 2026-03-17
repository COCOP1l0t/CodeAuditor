# Stage 1: Orient and Scope

You are performing **Stage 1** of an orchestrated network protocol security audit. Write your analysis to disk; do not print it in your response.

## Your Task

Analyze the project at **__TARGET_PATH__** and produce a scope document at **__OUTPUT_PATH__**.

## Threat Model

__THREAT_MODEL__

## User Instructions

__USER_INSTRUCTIONS__

## Workflow

### Step 1: Understand the Protocol (if needed)

This step is only necessary if the protocol(s) implemented by the project is a custom or uncommon protocol. For well-known protocols (HTTP, DNS, FTP, etc.), skip to Step 2.

Gather information about the protocol from:
- The project's documentation, README, or design documents.
- Source files that define message structures, parsing code, or state machines.

### Step 2: Determine Implementation Role

Determine whether the project implements the **client side**, **server side**, or **both sides** of the protocol:

- **Server-side**: The attacker is a malicious client sending crafted requests.
- **Client-side**: The attacker is a malicious server (or MITM) replying with crafted messages.
- **Both**: Both sides must be audited independently.

### Step 3: Clarify Threat Model

Review the project for any defined security policy (`SECURITY.md`, `security.txt`, etc.). Combine the threat model above with the user instructions and the project's own security policy to determine the final threat model.

### Step 4: Enumerate Modules and Protocol Implementations

Identify the project's structure and group related source files into **modules** that implement a cohesive protocol or subsystem. For each module, decide whether it falls within the audit scope and is vulnerability-productive enough for deeper analysis.

**IMPORTANT:** Each module will be processed independently. Ensure modules are self-contained and cohesive.

### Step 5: Write Output

Write your output to **__OUTPUT_PATH__** using the available file editing tools. The file must have this exact structure:

```markdown
# Orient and Scope

## Project Summary
(project path, name, language, brief description of functionality and protocols, client/server role)

## Threat Model
(final threat model)

## Module Structure

| ID | Module | Description | Files / Directory | Analyze in Stage 2 |
|----|--------|-------------|-------------------|-------------------|
| M-1 | [name] | [short description] | [files or dir] | Yes / No |
| M-2 | ... | ... | ... | ... |
```

**IMPORTANT**: Write the output to **__OUTPUT_PATH__** using the available file editing tools. Do not return the content in your response.

## Completion Checklist

- [ ] Protocol(s) understood or confirmed well-known
- [ ] Client/server role identified
- [ ] Threat model finalized
- [ ] Modules enumerated with analysis verdicts
- [ ] Output written to **__OUTPUT_PATH__**
