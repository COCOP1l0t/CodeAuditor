---
status: WIP — paused during brainstorming; resume by re-opening this file and continuing from "Open questions"
topic: Defer Stage 2 Phase B builds until after Stage 5 selects an archetype
date-paused: 2026-04-20
---

# Lazy Build Refactor (WIP)

## Motivation

Stage 2 Phase B (`prompts/stage2-build.md`) currently builds and deploys every
deployment archetype produced by Phase A, unconditionally, before Stage 3
even starts. When the audit ends up finding zero confirmed vulnerabilities,
all of that build work is wasted — tokens, wall-clock time, disk.

We want builds to happen **on demand**, only for archetypes that a confirmed
vulnerability actually needs.

## Proposed shape

Rename / renumber so the pipeline becomes:

| New # | Old # | What it does |
|-------|-------|--------------|
| 0–4   | 0–4   | unchanged |
| 5     | 5     | Evaluate findings **and** pick the deployment archetype(s) to reproduce on |
| 6     | —     | **NEW:** build + deploy only the archetypes selected in Stage 5 (dedup across vulns) |
| 7     | 6     | PoC reproduction against the pre-built artifact |
| 8     | 7     | Disclosure |

Stage 2 keeps Phase A only (deployment research → `manifest.json` +
per-archetype `deployment-mode.md`). Phase B moves out and becomes the new
build stage.

Stage 5's prompt (`prompts/stage5.md`) gains a new step: read the Phase A
manifest + deployment-mode files, then pick the archetype(s) whose
`modules_exercised` / `exposed_surface` best fit the confirmed finding. The
selection is recorded in the Stage 5 output JSON.

The new build stage:
- Reads all Stage 5 outputs, collects the union of chosen archetype IDs.
- Runs one build agent per unique archetype (reusing `stage2-build.md` and
  the existing `--deployment-build-parallel` / `--deployment-build-timeout-sec`
  knobs + checkpoint markers).
- Merges `result.json` into the manifest the same way
  `merge_results_into_manifest()` does today.

Stage 6 keeps its current logic mostly intact — it already reads the manifest
and picks an `ok` archetype. The only change: it will look up the archetype
that Stage 5 chose for this specific vuln (rather than picking itself).

## Open questions (where we paused)

1. **Build-failure handling.** Stage 5 picks archetype X; the new build stage
   fails on X. What should happen?
   - (a) Stage 6 falls through to its existing source-build fallback (Step 1B).
   - (b) Stage 5 emits a **ranked list** of archetypes; the new stage tries
     them in priority order until one builds. *(tentative lean — confirm
     with user)*
   - (c) Mark the vuln as unreproducible; skip it in Stage 6.
   - (d) Something else.

2. **Stage numbering / rename.** Insert as "5.5" or shift old 6→7 and 7→8?
   (Probably the latter — the codebase uses stageN files/dirs and hardcoded
   output paths like `stage6-pocs/`, `stage7-disclosures/`. Renumbering is a
   mechanical sweep but needs to be planned.)

3. **Stage 5 concerns: single vs. split.** Stage 5 today is "confirm the
   vuln." Adding "pick deployment" mixes concerns. Keep them together in one
   prompt/agent, or split into stage 5a (evaluate) + stage 5b (select)?

4. **Dedup guarantee.** Two vulns picking archetype A must trigger exactly
   one build. Probably obvious but worth stating in the spec.

5. **Checkpoint compatibility.** Existing `stage2:build:<cfg_id>` markers
   should keep working if the new stage uses the same key scheme — so a
   partially-built prior run still resumes cleanly.

6. **CLI knobs.** Do `--deployment-build-parallel` /
   `--deployment-build-timeout-sec` stay as-is (moved to apply to the new
   stage), or do we rename them to match the new stage number?

## Where to resume

Answer Q1 (build-failure handling) first — it's the most consequential for
the data model (single-pick vs. ranked list changes the Stage 5 output
schema). Then Q3 (split vs. unified stage 5), then the rest.

After that, the brainstorming skill's normal flow picks up: propose 2–3
approaches, present design sections, write the real spec (not this WIP
note), then hand off to writing-plans.
