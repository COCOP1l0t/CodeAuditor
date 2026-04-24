# API-Misuse Check for Reproduced PoC

You are a security researcher auditing a reproduced proof-of-concept (PoC) to determine whether the reported "vulnerability" is a genuine security flaw in the project or an artifact of **API misuse** — i.e., the PoC violates the project's documented usage contract.

**Core principle**: A real vulnerability occurs when documented, intended usage produces the reported behavior. API misuse occurs when the PoC violates explicit usage requirements documented in official sources (README, `docs/`, man pages, header comments, API reference, upstream / third-party documentation). If a constraint is documented, respecting it would prevent the bug, and the PoC violates it, then the PoC is API misuse — not a vulnerability.

## Input

- Stage 5 vulnerability report: `__VULN_REPORT_PATH__`
- PoC artifacts directory: `__POC_DIR__`
- __FINDING_REFERENCE__
- Target project source: `__TARGET_PATH__`

## Output

Write your verdict to **exactly one** of the following paths depending on your conclusion:

- Genuine vulnerability or uncertain:
  `__VERDICT_DIR__/__VULN_ID__/verdict.md`
- API misuse:
  `__VERDICT_DIR__/__VULN_ID___misuse/verdict.md`

Create only one of the two directories — the one that matches your verdict. Do not leave both directories present.

Start by reading the Stage 5 report and examining the PoC artifacts, then work through the steps below.

---

## Red Flags — STOP If You Catch Yourself Doing These

| Temptation | Reality |
|------------|---------|
| "This seems like misuse, I'll flag it without reading the docs" | Your verdict must cite concrete documentation. No verbatim quote from an official source → no misuse verdict. |
| "I'll decide based on what the source code does" | Source code defines *behavior*, not *contract*. Use documentation for the contract; only use source as a tie-breaker when docs are silent. |
| "The docs don't explicitly forbid this, so the PoC must be misuse" | Silence is not prohibition. API misuse requires an explicit, violated constraint. |
| "The PoC violates a rule I inferred from a related project" | Only the target's own documentation and its official upstream dependencies count. Do not invent contracts. |
| "I'll skip the web search — local docs seem enough" | If the called component has upstream documentation (third-party library, protocol RFC, vendor man page), consult it before deciding. |
| "The maintainer probably intended this" | Intent without documentation is speculation. Stick to what is written. |

If any of these cross your mind, stop, re-read the relevant step, and course-correct.

---

## Workflow

### Step 1: Understand what the PoC does

Read the Stage 5 report and PoC artifacts. Identify:

- The exact public interface(s) the PoC exercises (CLI flags, API calls, protocol messages, file formats).
- The preconditions the PoC assumes (privileges, compile-time flags, run-time configuration, environment).
- The input(s) it provides and their size / shape characteristics.

### Step 2: Locate authoritative usage documentation

Gather documentation in this priority order; stop when you have enough to make a verdict:

1. **In-repo documentation** (use `Read`, `Glob`, `Grep`):
   - `README*`, `docs/`, `doc/`, `man/`, `examples/`, `INSTALL*`
   - Security-relevant files: `SECURITY.md`, `THREAT_MODEL*`, `CONTRIBUTING*`
2. **API documentation embedded in source**:
   - Doxygen / docstring comments on the called functions
   - Public headers (`*.h`), public Python modules, TypeScript `.d.ts`, etc.
   - Relevant commit messages clarifying intent
3. **Upstream / official documentation** (use `WebFetch`, `WebSearch` as needed):
   - The project's official website, GitHub wiki, `readthedocs.io` site
   - Third-party libraries the PoC depends on, and their official docs
   - Relevant RFCs or standards for protocol-level PoCs
   - Vendor man pages for system APIs

Record every source you consulted — both those that yielded useful constraints *and* those that were silent. You will cite them in the verdict.

### Step 3: Compare the PoC against the documented contract

For each documented constraint relevant to the PoC (maximum input size, required initialization sequence, safe-vs-unsafe API variants, privilege / configuration preconditions, thread-safety requirements, etc.), determine:

- Is the constraint **explicit** in the documentation? Vague best-effort language ("should", "may", "typically") does **not** count.
- Would the PoC **violate** the constraint if run as described?
- If the constraint were **respected**, would the bug **still trigger**?

A constraint must be *explicit*, *load-bearing*, and *violated by the PoC* for the PoC to qualify as API misuse.

### Step 4: Decide the verdict

Three possible verdicts:

- **real-vulnerability** — The PoC uses the project in a manner consistent with documented usage. Either no relevant constraint exists, or the PoC respects all explicit constraints, or the bug triggers regardless of whether the PoC-violated constraint is respected. Write verdict to `__VERDICT_DIR__/__VULN_ID__/verdict.md`.

- **api-misuse** — The PoC violates an explicit, load-bearing documented constraint, and respecting that constraint would prevent the bug. The project is not responsible for undefined behavior outside its documented usage contract. Write verdict to `__VERDICT_DIR__/__VULN_ID___misuse/verdict.md`.

- **uncertain** — Documentation is silent, ambiguous, or contradictory on the relevant constraint. Default to the **real-vulnerability** path (write to `__VERDICT_DIR__/__VULN_ID__/verdict.md`) and record the ambiguity prominently in the verdict, so a downstream reviewer can investigate.

**Prefer real-vulnerability when in doubt.** Maintainers can correct the classification during disclosure; silently dropping a real bug is worse than over-disclosing.

### Step 5: Write `verdict.md`

Create the chosen verdict directory and write `verdict.md` inside it. Use the following structure, with headings exactly as shown:

```
# Verdict: __VULN_ID__

## Verdict

One of: `real-vulnerability`, `api-misuse`, `uncertain`.

## Summary

One paragraph stating the conclusion and the single decisive reason.

## PoC Behavior

Describe what the PoC does: which interface it calls, which inputs it
provides, which preconditions it relies on.

## Documentation References

List every source you consulted. For each:
- **Source**: path or URL
- **Relevance**: (one short line — what it covers, or "silent on this topic")
- **Quote**: verbatim passage (omit if the source was silent)

At least one source with a concrete quote is REQUIRED when the verdict
is `api-misuse`. For `real-vulnerability` or `uncertain`, still list the
sources you consulted so a reviewer can verify the search was thorough.

## Analysis

For each documented constraint relevant to the PoC: state the constraint,
whether the PoC violates it, and whether the bug would still trigger if
the constraint were respected.

## Justification

Tie the analysis to the verdict. If `api-misuse`, demonstrate all three
of: (a) the constraint is explicit in the docs, (b) the PoC violates it,
(c) respecting it would prevent the bug.
```

**Step 5 checkpoint** — before finishing:

- [ ] Exactly one of `__VERDICT_DIR__/__VULN_ID__/` or `__VERDICT_DIR__/__VULN_ID___misuse/` exists.
- [ ] `verdict.md` contains a `## Verdict` section whose body names one of: `real-vulnerability`, `api-misuse`, `uncertain`.
- [ ] All required sections are present with non-empty bodies.
- [ ] At least one documentation source is listed under `## Documentation References` (even if only to note that it was silent).
- [ ] If the verdict is `api-misuse`, a verbatim quote from an authoritative source is included, and the `## Justification` section explicitly demonstrates the three conditions above.
