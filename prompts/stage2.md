# Stage 2: Deployment Realization — Phase A (Research)

You are performing **Phase A of Stage 2** of an orchestrated software security audit. Your job is to investigate how the target project is actually deployed in production and to enumerate 1–N **deployment archetypes** that materially differ in attack surface. **Write your output to disk; do not print it in your response.** Phase B (a separate agent invocation) will later realize each archetype as a runnable instrumented build.

## Your Task

Research the project at **__TARGET_PATH__** and produce:

1. A **manifest** at `__MANIFEST_PATH__` listing every archetype.
2. A **deployment summary** at `__SUMMARY_PATH__` — one short paragraph per archetype, suitable for injection into downstream analysis prompts.
3. One **deployment mode** description per archetype at `__CONFIGS_DIR__/<config-id>/deployment-mode.md`.

Prior research is available at:
- Auditing focus: `__AUDITING_FOCUS_PATH__`
- Stage 1 research record: `__RESEARCH_RECORD_PATH__` (the `deployment_model` field is a useful starting point).

## Workflow

### Step 1: Investigate Real-World Deployments

Read the project's documentation, examples, upstream Dockerfiles, distro packaging, and any deployment guides you can find on the project website. Identify the distinct *roles* the target is run in (e.g. for an HTTP server: "static web server with TLS", "reverse proxy", "CGI host"). Each archetype must materially differ in attack surface — different exposed interfaces, different code paths, different configuration footprint.

**Each archetype must be grounded in evidence found during research.** Do not invent archetypes the project does not actually support.

### Step 2: Define Archetypes

For each archetype, decide:
- A short kebab-case `id` (lowercase, hyphenated). Example: `httpd-static-tls`.
- A human-readable `name`.
- The `exposed_surface` — the kinds of interfaces this deployment exposes to attackers (e.g. "http parser", "tls handshake", "mod_ssl").
- The `modules_exercised` — relative source paths (directories or files) that this deployment uses at runtime (e.g. `server/`, `modules/ssl/`).

### Step 3: Write the Deployment Mode Files

For each archetype, write `__CONFIGS_DIR__/<id>/deployment-mode.md` describing:
- The role the target plays.
- The network/IPC surface it exposes (ports, sockets, IPC channels, files watched, etc.).
- The kinds of inputs it processes from the outside world.
- A behavioral contract the smoke test must satisfy: "when this deployment is launched, sending input X to interface Y must produce response Z." Be specific enough that Phase B's smoke test can mechanically verify it.

### Step 4: Write the Manifest

Write `__MANIFEST_PATH__` with this schema:

```json
{
  "configs": [
    {
      "id": "httpd-static-tls",
      "name": "Static web server with TLS",
      "deployment_mode_path": "configs/httpd-static-tls/deployment-mode.md",
      "exposed_surface": ["http parser", "tls handshake", "mod_ssl"],
      "modules_exercised": ["server/", "modules/ssl/", "modules/http/"],
      "build_status": null,
      "artifact_path": null,
      "launch_cmd": null,
      "build_failure_reason": null,
      "attempts_summary": null
    }
  ]
}
```

The `build_*` and `artifact_*` and `launch_cmd` and `attempts_summary` fields **must all be null** after Phase A — Phase B fills them.

### Step 5: Write the Deployment Summary

Write `__SUMMARY_PATH__` — one short paragraph per archetype covering: role, exposed surface, modules exercised. This text is injected into downstream prompts (stages 3, 4, and 6) to bias analysis toward production-reachable code.

## Constraints

- 1 to N archetypes; pick the smallest set that captures distinct attack surfaces.
- All ids are unique kebab-case.
- `exposed_surface` and `modules_exercised` must be non-empty for every archetype.
- Every `deployment_mode_path` must point at a non-empty file you actually wrote.

## Completion Checklist

- [ ] Project documentation, examples, distro packaging consulted
- [ ] At least one archetype defined and grounded in evidence
- [ ] `__MANIFEST_PATH__` written with all build fields null
- [ ] `__SUMMARY_PATH__` written
- [ ] Each archetype has a non-empty `deployment-mode.md`