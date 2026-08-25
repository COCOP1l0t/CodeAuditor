<p align="center">
  <b>🇺🇸 English</b> | <a href="README.zh.md">中文</a>
</p>

# CodeAuditor

A multi-stage, agentic code auditing pipeline that can run on the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) or the [Codex App Server Python SDK](https://github.com/openai/codex/blob/main/sdk/python/README.md). Given a target source tree, CodeAuditor researches project context, decomposes the codebase into analysis units, hunts for bugs, evaluates them as security vulnerabilities, reproduces them with a working PoC, and finally prepares a disclosure-ready report package.

CodeAuditor has discovered several CVEs in widely used open-source projects — see [Vulnerabilities found](#vulnerabilities-found) below.

![TUI Dashboard](docs/images/tui-dashboard.png)

## How it works

The audit runs as seven sequential stages. Each stage is driven by a prompt template in `prompts/` and executed by one or more backend agents. Outputs are validated, and on validation failure a repair prompt is sent (up to `max_retries`). Intermediate artifacts are written under the output directory; a `.markers/` folder tracks completed sub-tasks so runs can be resumed.

| Stage | What it does | Parallelism |
|-------|--------------|-------------|
| 0 | Git pull + create output directories | None |
| 1 | Security context research (git history, web, `SECURITY.md`) | Single agent |
| 2 | Decompose the project into analysis units (AUs) | Single agent |
| 3 | Bug discovery per analysis unit | 1 agent per AU |
| 4 | Evaluate findings: real vulnerability? severity? | 1 agent per finding |
| 5 | PoC reproduction: build, exploit, capture evidence | 1 agent per vulnerability |
| 6 | Disclosure: technical report, email, minimal PoC, zipped package | 1 agent per vulnerability |

Stage 1 produces two directives — an *auditing focus* and *vulnerability criteria* — that are injected into later stages so the whole pipeline stays aligned with the project's actual threat model.

### System Design

```
┌─────────────┐
│ Target Repo │
└──────┬──────┘
       │
       ▼
┌─────────────┐     ┌─────────────────────────────┐
│  Stage 0    │     │      DIRECTIVE INJECTION    │
│    Init     │────►│  ┌─────────┐  ┌─────────┐   │
└─────────────┘     │  │Auditing │  │Vuln     │   │
       │            │  │ Focus   │  │Criteria │   │
       ▼            │  └────┬────┘  └────┬────┘   │
┌─────────────┐     │       │            │        │
│  Stage 1    │────►│       └──────┬─────┘        │
│   Context   │     └──────────────┼──────────────┘
└─────────────┘                    │
       │                           │
       ▼                           ▼
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│  Stage 2    │──►│  Stage 3    │──►│  Stage 4    │──►│  Stage 5    │──►│  Stage 6    │
│  Decompose  │   │   Discover  │   │   Evaluate  │   │     PoC     │   │   Disclose  │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘   └──────┬──────┘
                                                                               │
                                                                               ▼
                                                                        ┌─────────────┐
                                                                        │  Disclosure │
                                                                        │   Package   │
                                                                        └─────────────┘
```

## Requirements

- Python **3.12+**
- A working [Claude Code](https://docs.claude.com/en/docs/claude-code) install for `--backend claude` (the SDK reuses its authentication)
- A working Codex CLI at `/usr/local/bin/codex` with `codex app-server` support and local Codex auth/session for `--backend codex`
- Git and a working Docker Engine. Stage 5/6 build tools live in the sandbox image.

## Installation

```bash
git clone https://github.com/COCOP1l0t/CodeAuditor.git
cd CodeAuditor
pip install -e .
```

This exposes the `code-auditor` CLI entry point.

## Usage

```bash
code-auditor --target /path/to/project [options]
```

### Common options

| Flag | Description |
|------|-------------|
| **`--target`** | **Required** unless `--web` or `--repo-url` is used. Root directory of the project to audit. |
| `--repo-url` | Git repository URL. Cloned into `~/.code_auditor/repo/{host}/{owner}/{repo}` on first use and reused afterwards (Stage 0 keeps it updated with `git pull`); the clone becomes the audit target. |
| `--output-dir` | Output directory (default: `~/.code_auditor/results/{repo}/audit-output-{commit}` — the same repo+commit always reuses one directory, so repeated audits of a commit merge and resume; non-git targets fall back to a date stamp). |
| `--wiki` | LLM wiki knowledge base directory. CodeAuditor treats it as read-only and gives agents stage-specific wiki search guidance. |
| `--max-parallel` | Max concurrent agents (default: `1`). |
| `--backend` | Agent backend: `claude` or `codex` (default: `claude`). |
| `--model` | Backend model override. Claude defaults to `claude-sonnet-4-6`; Codex uses the local Codex config default unless specified. |
| `--target-au-count` | Target number of analysis units for Stage 2 (default: `-1` = no ceiling, explore as many units as genuinely warrant deep analysis). |
| `--log-level` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` (default: `INFO`). |
| `--tui` | Launch the interactive TUI dashboard instead of plain log output. |
| `--web` | Launch the web UI; audit parameters are entered in the browser (see below). |
| `--host` | Web UI bind host (default: `127.0.0.1`; use `0.0.0.0` to expose on the network). |
| `--port` | Web UI bind port (default: `8000`). |
| `--db` | Audit history SQLite database path (default: `~/.code_auditor/audits.db`). |
| `--sandbox-image` | Docker image for Stage 5/6 builds (default: `code-auditor-sandbox:latest`). |
| `--sandbox-root` | Dedicated disposable root below `/tmp` (default: `/tmp/code-auditor`). |
| `--no-docker-sandbox` | Disable Docker isolation for controlled debugging. This restores persistent build behavior and is unsafe for normal audits. |
| `--retention-migration-dry-run [ROOT]` | Print a read-only historical retain-manifest migration plan as JSON; defaults to `~/.code_auditor/results`. |
| `--retention-manifest-apply [ROOT]` | Atomically create or repair only manifests accepted by a fresh migration plan; never deletes artifacts. |
| `--retention-entrypoint-repair-dry-run [ROOT]` | Report safe canonical-entrypoint repairs and the exact manual blocker queue; never writes files. |
| `--retention-entrypoint-repair-apply [ROOT]` | Create only unambiguous `reproduce.sh` wrappers and their validated manifests; never runs PoCs or deletes artifacts. |
| `--reviewed-cleanup-dry-run [ROOT]` | Plan compilation/cache deletion only for reproduced bugs whose SQLite review status is not `unreviewed`. |
| `--reviewed-cleanup-apply [ROOT]` | Recheck the database and delete only the compilation/cache directories accepted by the reviewed cleanup plan. |

**Bold** options are required.

### Disposable Stage 5/6 builds and retained artifacts

Build the default sandbox image once before an audit can enter Stage 5:

```bash
docker build -f docker/code-auditor-sandbox.Dockerfile \
  -t code-auditor-sandbox:latest docker
```

Every Stage 5/6 task then receives a fresh source checkout and writable workspace
under `/tmp/code-auditor/`. The agent CLI and every build/reproduction command it
starts run in Docker with a read-only root filesystem, dropped capabilities,
`no-new-privileges`, and CPU, memory, and PID limits. The audited Git object store is
mounted read-only; only that task's `/tmp` scratch tree is writable. The scratch tree
and any labelled container are removed when the task finishes.

Before cleanup, CodeAuditor validates `retain-manifest.json` and atomically exports
only its bounded, regular files. `reproduce.sh` is mandatory, executable, UTF-8, and
must not reference disposable worktrees, build trees, toolchains, or CodeAuditor
paths. A custom sandbox image can add project-specific SDKs without weakening this
runtime boundary.

Historical results are never changed automatically. Inspect a deterministic dry-run
plan with:

```bash
code-auditor --retention-migration-dry-run \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db > retention-plan.json
```

The report contains proposed manifests, per-artifact blockers, exact disposable
paths, allocated-byte estimates, and `mutations: []`. Running outputs and all outputs
whose database state cannot be verified are marked blocked. `_merged-leftovers`
always requires manual review. After reviewing the plan, write only the accepted
manifests with:

```bash
code-auditor --retention-manifest-apply \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db > manifest-apply.json
```

This command rechecks every artifact immediately before an atomic manifest write,
is idempotent, and still does not delete or compact historical artifacts.

Missing canonical entrypoints can be repaired in two gated passes:

```bash
code-auditor --retention-entrypoint-repair-dry-run \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db > entrypoint-plan.json
code-auditor --retention-entrypoint-repair-apply \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db > entrypoint-apply.json
```

Automatic repair is limited to one regular executable legacy script with a shebang
and no other migration blockers, or one such reproduction-named script explicitly
invoked by `report.md`. The generated wrapper only delegates and forwards arguments;
it does not claim that the PoC was re-executed. `blocked_artifacts` preserves exact
file/marker evidence and recommended fixes for worktree references, missing reports,
incomplete disclosures, ambiguous entries, and invalid manifests.

Historical compilation results have a separate review-status gate:

```bash
code-auditor --reviewed-cleanup-dry-run \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db
code-auditor --reviewed-cleanup-apply \
  ~/.code_auditor/results --db ~/.code_auditor/audits.db
```

The apply command requires a `reproduced` PoC and a known review status other than
`unreviewed`, refuses active outputs, and preserves database-registered files, valid
manifest files, retained files, source worktrees, reports, disclosure bundles, and
reproduction entrypoints. Unknown, unmapped, non-reproduced, and mixed-status rows
fail closed.

### Audit history database

Every audit run — classic CLI, TUI, or web mode — is recorded in a local SQLite database (default `~/.code_auditor/audits.db`, override with `--db`). Each run is pinned to the exact code that was audited by a **target identity**: repository name, HEAD commit, and submodule commits (plus branch, origin URL, and a dirty flag for context), captured at the end of the audit (i.e. after stage 0's `git pull`). The identity is hashed into a `target_key`, so multiple audits of the same code state can be grouped, and audits of different commits never mix. Runs also store the configuration snapshot, status, timestamps, accumulated active duration, analysis units, evaluated vulnerabilities (severity, CVSS, CWE, data-flow trace, cross-run dedupe key), PoC reproduction statuses, and disclosure package paths. A resumed run adds the new active session to its previous duration without counting the cancelled or failed interval between sessions. Runs created before active-session accounting was available are conservatively marked with an unknown duration and shown as `N/A`, even after resume, because their earlier active intervals cannot be reconstructed. Persistence failures never affect the audit itself (a warning is logged instead).

The web UI's **History** tab lists all recorded runs across projects. Run and merged-target detail pages show only vulnerabilities whose PoC status is exactly `reproduced`, together with severity badges and links into the original report files. `partially-reproduced` is treated as an unsuccessful reproduction. Stage 3 findings are intermediate artifacts and are not displayed. Existing output directories from before this feature can be backfilled from the History tab via *Import output directory* (or `POST /api/history/import`): point it at a single `audit-output-*` directory, or at a directory under the configured managed results root to batch-import every output directory it contains. Imports outside that root are rejected; projects whose name matches a cloned repo under `~/.code_auditor/repo/` are linked automatically.

The **Disclosures** tab is fully backed by `~/.code_auditor/audits.db`. Recording or importing a run automatically upserts every local Stage 6 report into `disclosed_bugs`, keyed by its stable project and vulnerability identity; no separate HTML registry or manual file sync is involved. Each row shows its review status (`unreviewed` / `reported` / `confirmed` / `rejected` / `duplicated` / `triage` / `bug` / `slop`), project, CWE, audited commit, and date. Confirmed rows are joined to public CVE records by the same stable identity, and a registered Stage 5 artifact provides an interactive PoC terminal. Review status and artifact indexes stay in SQLite, while the report, email draft, ZIP, and PoC evidence remain ordinary files under the run's Stage 5/6 output directories rather than database BLOBs.

Analysis units (stage 2 decompositions) are also persisted in the database, keyed by the run's target identity. When a new audit starts on a repo+commit that was audited before — in any mode — distinct analysis units from all matching runs are merged and seeded into the output directory, so stage 2 can reuse the combined coverage instead of re-running decomposition. Only completely equivalent AU definitions are folded together; overlapping units with different files or audit guidance remain distinct, and their source runs are retained. Run detail pages show each run's analysis units and link to other runs of the same target. The merged target view (`#/target/…`) shows both the merged AUs and reproduced vulnerabilities from every matching run, sorted by severity and attributed to their source run.

### Web UI

```bash
code-auditor --web [--host 127.0.0.1] [--port 8000]
```

Then open `http://127.0.0.1:8000` in a browser. **New Audit** offers only managed repositories already cloned under `~/.code_auditor/repo/`, or a new HTTPS/Git-over-SSH URL to clone there; arbitrary local target directories are not accepted by the Web API. Web audits write to `~/.code_auditor/results/<repo>/audit-output-<commit>/` by default, so the same repo+commit always resumes in the same output directory. You can start and stop the audit, watch stage progress and live logs (streamed over SSE), and browse vulnerabilities, PoC reports, and disclosure files. The **CVE** sidebar lists the curated public CVE record, project, CVSS, upstream disclosure links, matching confirmed local Disclosure, and matching local PoCs. A **Terminal** action on a CVE, confirmed Disclosure, run, or merged-target vulnerability opens an interactive xterm window backed by a server PTY whose initial directory is that vulnerability's `stage5-pocs/<id>/` directory. Multiple terminals can be open at once. The **Reproduction** sidebar narrows exactly reproduced History vulnerabilities through target-project, commit, and vulnerability selectors, then displays the selected vulnerability's current PoC status. Starting the retest reruns only Stage 5 at the recorded source commit in an isolated Git worktree under `~/.code_auditor/reproductions/`; it does not modify the original audit output.

The top-right **LLM Settings** dialog selects Claude or Codex for new jobs, resumed runs, and subsequent agent calls in active jobs. An agent call already in flight keeps an immutable snapshot of the backend/provider settings with which it started; the next call uses the newly saved selection. History records the backends actually invoked in first-use order, without duplicates, just like its model-usage list. Each backend can either reuse its local CLI login and configuration (`~/.claude/` or `~/.codex/config.toml`) through the corresponding Agent SDK, or use a custom base URL, API key, and model name. Custom Codex providers must implement the OpenAI Responses protocol. Audit and reproduction request bodies cannot override this selection.

On first Web startup CodeAuditor creates `~/.code_auditor/settings.json` with mode `0600`; logging defaults to `DEBUG`. The settings API never returns a stored API key, and submitting an empty key preserves the current value. Keys are still stored as plaintext in this server-side file, so protect the host account and do not expose the UI over untrusted, unencrypted networks. An existing `~/.code_auditor/web-config.json` is validated and migrated to the new filename. The dialog is the preferred editor; the underlying shape is:

```json
{
  "backend": "claude",
  "log_level": "DEBUG",
  "max_parallel": 1,
  "repos_dir": "~/.code_auditor/repo",
  "results_dir": "~/.code_auditor/results",
  "reproductions_dir": "~/.code_auditor/reproductions",
  "providers": {
    "claude": {"mode": "local", "base_url": "", "api_key": "", "model": ""},
    "codex": {"mode": "local", "base_url": "", "api_key": "", "model": ""}
  }
}
```

Wiki paths are intentionally absent from this configuration. The Web UI scans `~/.code_auditor/wiki/` directly and offers an optional local Wiki dropdown; a Git checkout or a directory containing `index.md` is treated as one Wiki. If the directory or matching Wiki does not exist, the audit runs without Wiki context. Reproduction reuses a recorded Wiki only while it remains in this managed local list.

Managed paths are validated to remain inside `~/.code_auditor`. Browser request bodies reject unknown fields, repository and Wiki selections are resolved against server-managed lists, clone URLs are restricted to validated HTTPS or Git-over-SSH remotes, and artifact paths are confined to their corresponding output directories. PoC terminals accept only database-backed, exactly reproduced vulnerabilities below the managed results root; their WebSockets require a random per-server token and a same-origin browser connection. Only one audit or standalone reproduction can run at a time. Keep the default `127.0.0.1` bind unless you intentionally want to expose the UI — the web UI can launch agent runs, Stage 0 executes `git pull`, and PoC terminal windows provide an interactive shell in vulnerability artifact directories.

Agent runs use a 20-minute semantic timeout cycle by default. If an agent is still running after 20 minutes, CodeAuditor starts a status-checking subagent to inspect that agent's `agent.log`; when the checker determines the analysis is already finished, CodeAuditor kills the original backend process. Otherwise, it waits another 20 minutes and repeats the check.

Before Stage 6 starts, a Web audit receives the existing SQLite Disclosure index for exact and semantic duplicate detection. Stage 6 itself creates only the report package; once the run finishes, the output scanner records it directly in SQLite without a registry-path option in CLI, TUI, Web settings, or browser requests.

Runs resume from checkpoint markers automatically — delete the output directory (or its `.markers/` subdirectory) to start a fresh audit.

### Wiki knowledge base

`--wiki /path/to/wiki` lets CodeAuditor use an existing LLM wiki knowledge base during the audit. CodeAuditor treats the wiki as read-only and instructs agents not to create, edit, or update wiki files. Enforce filesystem permissions externally if write prevention is required.

Recommended structure:

```text
wiki/
|-- index.md
|-- overview.md
|-- attack-surface.md
|-- auditing-guide.md
|-- exploit-patterns.md
|-- reproduction-workflow.md
|-- vulnerability-timeline.md
|-- entities/
|   `-- <component>.md
|-- concepts/
|   `-- <vulnerability-class>.md
`-- sources/
    `-- <cve-or-case-study>.md
```

`index.md` is recommended as the navigation entry point. Partial wikis are supported; stages skip absent files and use the pages that exist.

> A real-world example is the [QEMU-Security-Wiki](https://github.com/qianfei11/QEMU-Security-Wiki) — a community-maintained knowledge base for auditing QEMU.

### Example

```bash
code-auditor \
  --target ~/projects/libfoo \
  --output-dir ~/audits/libfoo \
  --wiki ~/knowledge/libfoo-wiki \
  --max-parallel 4 \
  --tui \
  --log-level DEBUG
```

## Output layout

```
{output-dir}/
├── stage1-security-context/  # context research + auditing focus + vuln criteria
├── stage2-analysis-units/    # codebase decomposition
├── stage3-findings/          # per-AU bug findings
├── stage4-vulnerabilities/   # evaluated, confirmed vulnerabilities
├── stage5-pocs/              # PoCs + evidence
├── stage6-disclosures/       # disclosure reports, emails, zipped PoCs
└── .markers/          # checkpoint markers for --resume
```

Completed and imported runs index their Stage 6 packages directly in SQLite. All modes write the same Stage 6 filesystem artifacts shown above.

## Project layout

```
code_auditor/
├── __main__.py          # CLI entry point
├── config.py            # AuditConfig and dataclasses
├── cves.py              # Public CVE catalogue and disclosure identity links
├── disclosures.py       # Stable Disclosure identities and metadata helpers
├── db.py                # SQLite audit history and Disclosure catalogue
├── orchestrator.py      # Sequential stage runner
├── agent.py             # Backend wrappers + validation retry loop
├── prompts.py           # Prompt loader with __KEY__ substitution
├── checkpoint.py        # Marker-based checkpoint/resume
├── repos.py             # Git URL → ~/.code_auditor/repo/ clone/reuse helpers
├── logger.py            # Logging helper
├── utils.py             # Parallelism + file helpers
├── stages/              # stage0 – stage6
├── parsing/             # Structured extraction from agent output
├── validation/          # Per-stage output validators
├── web/                 # FastAPI web UI (--web): server, job manager, SSE, static page
└── tests/
prompts/                 # stage1.md – stage6.md prompt templates
```

## Development

```bash
pytest                       # run all tests
pytest code_auditor/tests    # same thing
pytest -k stage2             # filter by name
```

Tests cover parsers and validators; they do not make real agent calls.

## Vulnerabilities Found

Vulnerabilities CodeAuditor has helped discover and disclose:

| CVE ID | Project | Year | CVSS Base Score | Severity | Reference |
|--------|---------|------|-----------------|----------|-----------|
| CVE-2026-28780 | [httpd](https://github.com/apache/httpd) | 2026 | 9.8 | Critical | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-34032 | [httpd](https://github.com/apache/httpd) | 2026 | 5.3 | Medium | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-40312 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | 2026 | 5.5 | Medium | [GitHub](https://github.com/ImageMagick/ImageMagick) |
| CVE-2026-40385 | [libexif](https://github.com/libexif/libexif) | 2026 | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-40386 | [libexif](https://github.com/libexif/libexif) | 2026 | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-7180 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | / | / | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-8341 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 6.5 | Medium | [#3750](https://gitlab.com/qemu-project/qemu/-/work_items/3750) |
| CVE-2026-8343 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 5.3 | Medium | [#3791](https://gitlab.com/qemu-project/qemu/-/work_items/3791) [#3807](https://gitlab.com/qemu-project/qemu/-/work_items/3807) [#3827](https://gitlab.com/qemu-project/qemu/-/work_items/3827) |
| CVE-2026-8348 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 4.4 | Medium | [#3810](https://gitlab.com/qemu-project/qemu/-/work_items/3810) |
| CVE-2026-9238 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 5.5 | Medium | [#3820](https://gitlab.com/qemu-project/qemu/-/work_items/3820) |
| CVE-2026-15705 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 5.3 | Medium | [#3808](https://gitlab.com/qemu-project/qemu/-/work_items/3808) |
| CVE-2026-41437 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | / | / | [#3711](https://gitlab.com/qemu-project/qemu/-/work_items/3711) |
| CVE-2026-41439 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | / | / | [#3714](https://gitlab.com/qemu-project/qemu/-/work_items/3714) |
| CVE-2026-48914 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 6.7 | Medium | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-48915 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 6.1 | Medium | [#3857](https://gitlab.com/qemu-project/qemu/-/work_items/3857) |
| CVE-2026-61405 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 6.0 | Medium | [#3890](https://gitlab.com/qemu-project/qemu/-/work_items/3890) |
| CVE-2026-61406 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 6.5 | Medium | [#3899](https://gitlab.com/qemu-project/qemu/-/work_items/3899) |
| CVE-2026-61476 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | 4.4 | Medium | [#3875](https://gitlab.com/qemu-project/qemu/-/work_items/3875) |
| CVE-2026-63324 | [QEMU](https://gitlab.com/qemu-project/qemu) | 2026 | / | / | [#3984](https://gitlab.com/qemu-project/qemu/-/work_items/3984) |
| CVE-2026-53701 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 2026 | 6.5 | Medium | [#5035](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5035) |
| CVE-2026-53702 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 2026 | 6.5 | Medium | [#5036](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5036) |
| CVE-2026-53703 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 2026 | 7.1 | High | [#5038](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5038) |
| CVE-2026-53704 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 2026 | 7.1 | High | [#5039](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5039) |

## Responsible use

CodeAuditor is intended for auditing code you own or have explicit permission to test, and for coordinated disclosure to upstream maintainers. Do not use it to target systems or projects without authorization.

**Important:** Before sending any vulnerability report to project maintainers, manually review the generated disclosure materials. Verify that the vulnerability is real, the severity assessment is accurate, and the proof-of-concept actually reproduces the issue. Automated findings may contain false positives or inaccuracies that could waste maintainers' time or damage your credibility.


## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

This software is provided for educational, research, and experimental purposes only. See the disclaimer at the top of the LICENSE file.
