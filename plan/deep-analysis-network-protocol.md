---
name: deep-analysis-network-protocol
description: >
  Performs deep verification and proof-of-concept development for findings from a
  security-audit-network-protocol audit report. Trigger this skill when ALL of the following
  conditions are met: (1) a completed audit report from security-audit-network-protocol exists with
  findings marked "Worth Further Analysis: Yes"; (2) the user selects specific finding(s) for
  in-depth verification (e.g., "analyze H-01 in depth", "verify C-01 and develop a PoC"); and
  (3) source code is available for building and runtime testing. The skill guides vulnerability
  confirmation, reproduction strategy design, PoC development with iterative refinement, and
  technical report generation.
---

# Deep Analysis Skill — Network Protocol Vulnerability Verification

A structured methodology for verifying vulnerabilities identified by the
security-audit-network-protocol skill. Takes individual findings from the audit report, confirms
them through code analysis and runtime testing, develops proof-of-concept exploits, and produces
detailed technical reports.

**Prerequisites**: A completed security-audit-network-protocol audit report. This skill operates on
findings marked "Worth Further Analysis: Yes" in that report. It can also be invoked directly if the
user provides a known vulnerability to verify.

---

## Workflow

### Step 1: Confirm the Vulnerability

**Goal**: Determine whether the finding is a true vulnerability worth further investigation —
filter out false positives, unreachable code paths, and low-value issues before investing effort in
reproduction.

Re-read the relevant code paths carefully. Verify that:

- Verify the finding against the project's security policy (if one exists, as identified in the
  audit's Step 1c). Confirm that the issue qualifies as a security vulnerability according to the
  project's own security model and threat boundaries. If the project explicitly considers this class
  of issue out of scope, note this in the assessment.
- The attacker-controlled data genuinely reaches the dangerous sink without sufficient validation.
- The conditions and pre-requisites identified in the audit report are actually achievable by a
  remote attacker.
- No subtle guards (assertions, earlier bounds checks, compiler mitigations) prevent triggering.
- **Fallback — Git history analysis**: Only perform this sub-step if you cannot confidently confirm
  the vulnerability's existence through code analysis alone, or if the vulnerability pattern is
  ambiguous and it is unclear whether the maintainer would consider it a security risk. In those
  cases, check the git history of the relevant code (`git log -p --follow <file>`) to determine
  whether the vulnerable code was recently introduced or is long-standing, or whether a bounds check
  was intentionally added or removed. This context can help resolve ambiguity and inform severity
  assessment. Skip this sub-step in all other cases — it consumes significant context and rarely
  aids reproduction.

If the finding does not hold up, report that it is a false positive and explain why.

**Step 1 checkpoint** — before proceeding, verify:

- [ ] Finding re-examined against actual code paths; false positives filtered out
- [ ] Finding verified against the project's security policy, if one exists
- [ ] Git history reviewed only if needed to resolve confirmation ambiguity; otherwise skipped

### Step 2: Design the Reproduction Strategy

**Goal**: Determine the strategy to manifest the vulnerability with strong, observable, and solid
proof. Always perform runtime verification against the actual project unless technically impossible.

Design the strategy carefully — it determines how to build the project and how the PoC is
structured. This strategy must be clearly recorded and included in the final technical report.

#### 2.1 Determine Verification Approach

Determine the project type to decide how to set up the verification target:

1. **Executable projects** (e.g., pure-FTPD, httpd, dnsmasq): Build the project directly. The
   resulting binary is the target — run it and send crafted input against it.

2. **Library projects** (e.g., libssh, libcurl, libtls): The library itself is not directly
   executable, so a target binary is needed:
   - First, check if the project ships example programs or test binaries that exercise the relevant
     code path. If a suitable one exists, use it as the target.
   - If no suitable example exists, design a minimal **harness** — a small program that calls the
     library's API to set up the vulnerable code path (e.g., initialize a server context, start
     listening, accept connections). Define what API calls the harness must make, what state it must
     establish, and how it exposes the vulnerable code path to network input. The harness design
     may influence PoC design (and vice versa), so both should be considered together. The actual
     harness implementation is deferred to Step 3.

**Critical principle**: Always verify against the real project code. Never reimplement the
vulnerable logic in a standalone program — that would only prove the *pattern* is dangerous, not
that the *actual project* is affected.

#### 2.2 Build Configuration

The guiding principle is to **ensure the vulnerable code path is compiled in, reachable by the PoC,
and instrumented to produce clear observable evidence** when triggered. Tailor the build
configuration to the project's language and runtime:

**C / C++**:
- Enable `-fsanitize=address,undefined` for memory errors and undefined behavior detection.
- Enable `-fsanitize=leak` (LeakSanitizer) when investigating resource exhaustion bugs.
- Build with `-O0 -g` for clear stack traces and debuggability. However, note that some bugs are
  optimization-dependent (e.g., use-after-free may only manifest with `-O2` because the compiler
  reuses stack slots). If a PoC fails at `-O0`, retry at `-O2`.
- When sanitizers are not available (e.g., cross-compiled targets, or when ASAN is incompatible with
  the target's memory allocator), use Valgrind as an alternative.

**Go**:
- Build with `-race` to enable the race detector for concurrency bugs.
- Use `-gcflags='all=-N -l'` to disable optimizations and inlining for clearer stack traces.
- Ensure CGo code paths (if relevant) are also compiled with ASAN/MSAN via `CGO_CFLAGS`.

**Rust**:
- Build in debug mode (`cargo build` without `--release`) to retain bounds checks, overflow checks,
  and debug symbols.
- For unsafe code, use Miri (`cargo +nightly miri run`) for undefined behavior detection, or
  compile with `-Zsanitizer=address` on nightly.

**Java / JVM**:
- Enable verbose runtime diagnostics: `-ea` (assertions), `-XX:+HeapDumpOnOutOfMemoryError`.
- For deserialization or injection vulnerabilities, ensure the vulnerable classpath and any gadget
  libraries are included.
- Use debug builds or set logging to verbose/trace level to observe internal behavior.

**Python / JavaScript / other interpreted languages**:
- Enable debug or verbose modes (e.g., `python -X dev`, `node --trace-warnings`).
- Ensure the vulnerable module version and all dependencies are exactly matched.
- For Python C extensions, build with `CFLAGS="-fsanitize=address -g"` to instrument the native
  layer.

**General**:
- Disable features or compile-time flags that would exclude the vulnerable code path (e.g., do not
  disable optional protocol extensions that contain the bug).
- If the project has conditional compilation (e.g., `#ifdef`, feature flags, build profiles), ensure
  the vulnerable path is included.
- Record the exact build commands, compiler/runtime versions, and all flags in the reproduction
  strategy.

#### 2.3 PoC Design

Design the PoC to be **minimal and self-contained**. The final PoC should contain only the core
functionality needed to trigger the issue and produce clear evidence. Avoid unnecessary
dependencies — a single-file script or program (e.g., Python with raw sockets, C with POSIX
sockets, or Go with `net`) is ideal. Choose whichever language is most convenient for the protocol
and vulnerability at hand. This makes it easy for maintainers to reproduce.

If the bug requires specific conditions (e.g., winning a race, specific heap layout), document the
conditions and design the PoC to maximize reliability. The reproduction strategy should address how
to make triggering deterministic or near-deterministic. For race conditions, consider the entire
reproduction setup holistically — the harness and build configuration can be as important as the PoC
itself. For example, a harness that introduces a deliberate delay between critical operations (e.g.,
via `sleep`, `usleep`, or a debug hook) can widen the race window. Similarly, building with
sanitizers or debug flags may slow execution enough to change timing. Design the harness, build
flags, and PoC together to create favorable conditions for reliable reproduction.

**Step 2 checkpoint** — before proceeding, verify:

- [ ] Project type identified (executable vs. library) and verification approach determined
- [ ] Build configuration specified — language-appropriate instrumentation, optimization level, and
      fallback tools if needed
- [ ] PoC design is minimal, self-contained, and addresses reliability concerns

### Step 3: Environment Setup

**Goal**: Build the project and prepare artifacts for testing.

#### 3.1 Create the Artifact Directory

Create a directory `PoC/{ID}` under the current working directory, where `{ID}` is the finding ID
from the audit report (e.g., `PoC/H-01`). All artifacts — built executables, harness source, PoC
scripts, and output logs — are placed in this directory.

#### 3.2 Build the Project

Build the project (and harness, if applicable) with the build configuration determined in Step 2.2.
Handle dependencies as needed. When the project's build system supports specifying an output
directory, place build artifacts in the `PoC/{ID}` directory. When the build system does not support
redirecting output, build in-place within the project source tree. Never install build artifacts to
system directories (e.g., `/usr/bin`, `/usr/local/bin`, `/etc`) — use local paths or staging
directories only.

#### 3.3 Assess Local System Impact

Before running the PoC, assess whether the target or PoC could cause damage to the local system
(e.g., a DHCP client that reconfigures network interfaces, a service that modifies system files, or
a target that requires root privileges with system-wide side effects).

If the target could harm the local system:

- **Stop and inform the user** of the specific risks.
- **Abort the reproduction step** unless the user explicitly acknowledges the risks and authorizes
  proceeding.
- Provide exact commands the user would need to run manually if they choose to proceed.

If the target can be safely run without system impact, proceed directly.

**Manual intervention**: Some targets require elevated privileges or special setup (e.g., a server
that must run as root, or a network namespace). When this is the case:

- Stop and ask the user to perform the required manual step.
- Provide exact commands to run (copy-pasteable).
- Wait for the user to confirm completion.
- Verify the intervention succeeded (e.g., confirm the target process is running, the port is open)
  before proceeding.

**Step 3 checkpoint** — before proceeding, verify:

- [ ] Artifact directory `PoC/{ID}` created with all build outputs, harness source, and PoC scripts
- [ ] Project (and harness, if applicable) built successfully with appropriate instrumentation
      enabled
- [ ] Local system impact assessed; user informed and authorized if risks exist

### Step 4: Develop and Run the PoC

**Goal**: Develop a proof-of-concept that triggers the vulnerability and produces clear, observable
evidence. Iterate through multiple rounds of testing and refinement until the evidence is solid.

Write a PoC that sends crafted protocol messages to trigger the vulnerability. The PoC must produce
**clear, concrete, and observable evidence** that the vulnerability exists. Examples of good
evidence:

- AddressSanitizer (ASAN) report showing the exact out-of-bounds access or use-after-free
- Crash with a core dump or signal (SIGSEGV, SIGABRT)
- Leaked memory contents visible in a response packet (hex dump showing heap/stack data)
- Server becomes unresponsive (demonstrable hang or resource exhaustion)
- Unexpected command execution (e.g., a DNS lookup or file creation triggered by injected input)

Run the PoC against the target and capture the output. If it does not trigger as expected,
investigate and iterate:

- Examine the target's actual behavior (debug output, strace, logs).
- Adjust the PoC based on observed behavior.
- Continue iterating until the vulnerability is triggered with clear evidence, or until
  investigation concludes it is a false positive.

Once reproduction succeeds, create a **clean copy** of the PoC in a separate file (e.g.,
`poc.py` alongside the working `poc_debug.py`). The clean copy should contain only the core
triggering logic — remove debugging scaffolding, diagnostic prints, and dead code paths so it is
concise enough for a maintainer to review and reproduce. Keep the original development PoC with its
debugging instrumentation intact, as it is valuable for further investigation or re-testing.

After creating the clean copy, **re-execute it** against the target to verify that it triggers the
vulnerability and produces the same evidence as the development PoC. Capture the output from this
clean-copy run — this is the authoritative output that must be used in the technical report and
referenced in the disclosure email. All subsequent steps must reference the clean PoC (`poc.py`),
not the development PoC (`poc_debug.py`). The clean PoC is the artifact that will be packaged and
sent to the maintainer, so the observations included in the report must match its output exactly.

**Step 4 checkpoint** — before proceeding, verify:

- [ ] PoC triggers the vulnerability with clear, observable evidence
- [ ] Clean PoC copy created in a separate file; development PoC with debug instrumentation
      preserved
- [ ] Clean PoC re-executed against the target; output captured and confirmed to match expected
      evidence

### Step 5: Write the Technical Report

**Goal**: Produce a detailed technical report documenting the confirmed vulnerability, the evidence,
and complete reproduction instructions.

Generate a technical report and store it as `PoC/{ID}/report.md`. The report should be
professional, detailed, and concise. Use the following structure:

#### 1. Title

Clear, descriptive title (e.g., "Heap Buffer Overflow in DHCP Option Parsing").

#### 2. Summary

One-paragraph description of the vulnerability and its impact.

#### 3. Severity Assessment

- **CWE Classification**: The CWE identifier and name (e.g., CWE-122: Heap-based Buffer Overflow).
  This is standard practice and aids CVE assignment.
- **CVSS Score**: CVSS v3.1 vector string, numeric score, and severity label with justification.

#### 4. Security Impact

Describe the concrete security impact this vulnerability poses. Explain what an attacker could
achieve by exploiting it (e.g., remote code execution, information disclosure, denial of service,
privilege escalation). Discuss the realistic threat scenario — who is affected, under what
conditions, and what the blast radius would be in a typical deployment.

#### 5. Vulnerability Details

##### 5.1 Affected Component

The specific library, binary, or module name containing the vulnerability.

##### 5.2 Affected Versions

Which versions or commit ranges are affected, informed by the git history analysis from Step 1
(if performed). If the git history analysis was skipped, state what is known (e.g., "confirmed in
version X; introduction point not determined").

##### 5.3 Pre-requisites

What an attacker needs to exploit the vulnerability (network access, specific configuration,
authentication level, etc.).

##### 5.4 Root Cause Analysis

Detailed explanation of why the vulnerability exists — trace from attacker-controlled input to the
dangerous operation, including annotated code snippets that walk through the control flow, highlight
attacker-controlled data, and point out where validation is missing or insufficient.

#### 6. Reproduction

##### 6.1 Reproduction Strategy

The strategy designed in Step 2 — project type, build configuration, instrumentation flags, and PoC
design rationale. Write a narrative paragraph describing how the project is configured and built
(e.g., which configure flags were used and why, what sanitizers are enabled, whether a harness was
needed), how the target is set up for testing, and how the PoC is designed to trigger the
vulnerability. This should give the reader a clear mental model of the overall reproduction approach
before diving into the step-by-step commands.

##### 6.2 Steps to Reproduce

Exact, step-by-step instructions to trigger the vulnerability. This section must be detailed enough
for an independent party to reproduce from scratch:

- How to obtain the vulnerable version of the code (commit hash or version tag).
- How to build the project (exact configure/make commands, compiler flags, dependencies to install).
- How to build and compile the harness, if applicable, with full source code included.
- How to start the target (exact commands, required configuration, listening ports).
- How to run the PoC (exact commands, expected timing, any required arguments).

##### 6.3 Observed Result

The concrete evidence captured during reproduction — paste the full ASAN output, crash log, hex
dump, or other diagnostic output. Include enough context to show that the evidence corresponds to
the claimed vulnerability. **Important**: the output included here must be from a run of the final
clean PoC script (`poc.py`) — not from an intermediate development run. The maintainer must be able
to execute the provided PoC and observe the same output.

#### 7. Suggested Fix

Provide a brief description of the recommended remediation direction (e.g., "add a bounds check
before the memcpy on line N", "validate the length field against the remaining packet size").
Do not invest effort in developing or testing a full patch. Only include an actual diff if the fix
is trivially simple to construct (e.g., a one-line bounds check). The purpose of this section is to
point the maintainer in the right direction, not to provide a ready-made solution.

**Step 5 checkpoint** — verify:

- [ ] Technical report written to `PoC/{ID}/report.md`
- [ ] Report includes all sections with appropriate detail
- [ ] Reproduction steps are detailed enough for independent reproduction from scratch

### Step 6: Write the Disclosure Email and Package Artifacts

**Goal**: Produce a ready-to-send email and a concise attachment package for reporting the
vulnerability to the project maintainers or relevant security contacts.

#### 6.1 Package PoC Artifacts

Create a zip file named `PoC/{ID}/PoC.zip` containing the artifacts a maintainer needs to
understand and reproduce the issue. At minimum, include:

- The technical report (`report.md`)
- The clean PoC script (e.g., `poc.py`)

Optionally include other artifacts if they would help the maintainer understand, reproduce, or fix
the issue (e.g., harness source code, sample captures). Keep the contents concise — do not burden
the maintainer with unnecessary files or verbose debug artifacts.

**Important**: Do not include internal audit identifiers (e.g., `C-01`, `H-02`) in the packaged
artifacts. The email, PoC script, technical report, and all other artifacts must be standalone and
self-explanatory to a maintainer who has no knowledge of the internal audit numbering scheme.

#### 6.2 Write the Disclosure Email

Generate the email and store it as `PoC/{ID}/email.txt`. The email serves as a high-level summary
of the technical report, focusing on the security impact to notify maintainers that a security issue
requires attention. Reference the attached `PoC.zip` as containing the full technical report and
reproduction materials.

Format requirements:

- First write the email without line wrapping, then use `fold -s -w 72` to wrap lines at word
  boundaries. Store the wrapped result as the final `email.txt`.
- Use plain text only (no HTML or markdown formatting).

Use the following structure:

```
Subject: [Security] <concise description of the vulnerability>

Hi,

<Opening paragraph: identify yourself/your role, state that you
are reporting a security vulnerability in [project name], and
briefly describe the affected component.>

<Impact paragraph: describe the security impact — what an attacker
could achieve, the severity (reference the CVSS score), and the
conditions required for exploitation. Keep this focused on why
the maintainer should prioritize this.>

<Summary paragraph: brief technical summary of the root cause —
just enough for the maintainer to understand the class of bug
and where it lives, without reproducing the full analysis.>

<Reproduction note: state that a detailed technical report with
full reproduction steps and a proof-of-concept is attached as
PoC.zip. Mention the key evidence (e.g., "ASAN confirms
a heap buffer overflow").>

<Affected versions paragraph: state which versions are known to
be affected.>

<Suggested fix paragraph: briefly describe the recommended
remediation direction to give the maintainer a starting point.>

<Closing: offer to provide further details, coordinate on
disclosure timeline, and provide contact information.>

Regards,
<name / handle>
```

**Step 6 checkpoint** — verify:

- [ ] `PoC/{ID}/PoC.zip` created with technical report and clean PoC script (plus any other helpful
      artifacts)
- [ ] Email written to `PoC/{ID}/email.txt`
- [ ] Email follows plain-text format with lines wrapped at 72 characters
- [ ] Email clearly communicates the security impact and references the attached `PoC.zip`
- [ ] Report, email, and packaged artifacts are consistent with each other — no internal audit
      identifiers (e.g., `C-01`, `H-02`) appear in any artifact, and all referenced output and
      observations originate from the clean PoC (`poc.py`), not the development PoC