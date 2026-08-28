<p align="center">
  <b>🇺🇸 English</b> | <a href="README.zh.md">中文</a>
</p>

# CodeAuditor

CodeAuditor is a multi-stage, agentic code-auditing pipeline powered by the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) or the [Codex App Server Python SDK](https://github.com/openai/codex/blob/main/sdk/python/README.md). It researches a target project, finds and evaluates security bugs, reproduces confirmed vulnerabilities, and prepares disclosure-ready reports.

It has helped discover CVEs in widely used open-source projects; see [Vulnerabilities found](#vulnerabilities-found).

## How it works

An audit runs through seven stages:

| Stage | Purpose |
|-------|---------|
| 0 | Update the target repository and prepare the output directory |
| 1 | Research security context and define the audit focus |
| 2 | Decompose the codebase into analysis units (AUs) |
| 3 | Find bugs in each analysis unit |
| 4 | Evaluate reachability, impact, and severity |
| 5 | Reproduce confirmed vulnerabilities and capture evidence |
| 6 | Prepare a report, email, minimal PoC, and disclosure package |

Outputs are validated and checkpointed between stages. Stage 1's project-specific audit focus and vulnerability criteria guide the later analysis.

## Requirements

- Python **3.12+**
- Git; Docker Engine is required only for Docker sandbox modes
- [Claude Code](https://docs.claude.com/en/docs/claude-code), or a Codex CLI with `codex app-server` support; select the backend in Web settings

## Installation

```bash
git clone https://github.com/COCOP1l0t/CodeAuditor.git
cd CodeAuditor
pip install -e .
```

## Quick start

Start the Web UI and open `http://127.0.0.1:8000`:

```bash
code-auditor
```

Web server options:

| Flag | Description |
|------|-------------|
| `--host` | Bind address; default `0.0.0.0` |
| `--port` | Listen port; default `8000` |

Audit parameters such as repository, Wiki, backend, model, sandbox mode, parallelism, and output paths are managed in the Web UI and `~/.code_auditor/settings.json`. Run `code-auditor --help` for maintenance commands.

Stage 5 and 6 can use a networked Docker sandbox, a network-isolated Docker sandbox, or a local detached worktree. The Web settings enable Docker choices only after the server passes its Docker, image, disk-space, and Agent runtime checks. Docker is the default; build its image once before an audit reaches reproduction:

```bash
docker build -f docker/code-auditor-sandbox.Dockerfile \
  -t code-auditor-sandbox:latest docker
```

## Web UI

Use the Web UI to start and monitor audits, review history and disclosures, inspect PoC results, and rerun reproductions. Report and PoC artifacts remain under the results directory, while audit metadata is stored in SQLite.

The default `0.0.0.0` bind exposes the UI on every network interface. Use `--host 127.0.0.1` when remote access is not required. The UI can start agents and provide interactive shells for reproduced PoCs, and its settings file may contain API keys.

## Wiki knowledge base

The Web UI discovers knowledge bases under `~/.code_auditor/wiki/`. CodeAuditor treats the selected Wiki as read-only and uses available pages as supporting context rather than vulnerability evidence.

See [QEMU-Security-Wiki](https://github.com/qianfei11/QEMU-Security-Wiki) for an example.

## Output layout

```text
{output-dir}/
├── stage1-security-context/
├── stage2-analysis-units/
├── stage3-findings/
├── stage4-vulnerabilities/
├── stage5-pocs/
├── stage6-disclosures/
└── .markers/
```

The same repository commit reuses its output directory and resumes from checkpoints. Delete the output directory, or its `.markers/` directory, to start over.

## Development

```bash
pip install -e '.[test]'
pytest -q
```

Tests do not make real agent calls.

## Vulnerabilities found

Vulnerabilities CodeAuditor has helped discover and disclose:

| CVE ID | Project | CVSS Base Score | Severity | Reference |
|--------|---------|-----------------|----------|-----------|
| CVE-2026-28780 | [httpd](https://github.com/apache/httpd) | 9.8 | Critical | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-34032 | [httpd](https://github.com/apache/httpd) | 5.3 | Medium | [GitHub](https://github.com/apache/httpd) |
| CVE-2026-40312 | [ImageMagick](https://github.com/ImageMagick/ImageMagick) | 5.5 | Medium | [GitHub](https://github.com/ImageMagick/ImageMagick) |
| CVE-2026-40385 | [libexif](https://github.com/libexif/libexif) | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-40386 | [libexif](https://github.com/libexif/libexif) | 7.1 | High | [GitHub](https://github.com/libexif/libexif) |
| CVE-2026-7180 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-8341 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.5 | Medium | [#3750](https://gitlab.com/qemu-project/qemu/-/work_items/3750) |
| CVE-2026-8343 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.3 | Medium | [#3791](https://gitlab.com/qemu-project/qemu/-/work_items/3791) [#3807](https://gitlab.com/qemu-project/qemu/-/work_items/3807) [#3827](https://gitlab.com/qemu-project/qemu/-/work_items/3827) |
| CVE-2026-8348 | [QEMU](https://gitlab.com/qemu-project/qemu) | 4.4 | Medium | [#3810](https://gitlab.com/qemu-project/qemu/-/work_items/3810) |
| CVE-2026-9238 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.5 | Medium | [#3820](https://gitlab.com/qemu-project/qemu/-/work_items/3820) |
| CVE-2026-15705 | [QEMU](https://gitlab.com/qemu-project/qemu) | 5.3 | Medium | [#3808](https://gitlab.com/qemu-project/qemu/-/work_items/3808) |
| CVE-2026-41437 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3711](https://gitlab.com/qemu-project/qemu/-/work_items/3711) |
| CVE-2026-41439 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3714](https://gitlab.com/qemu-project/qemu/-/work_items/3714) |
| CVE-2026-48914 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.7 | Medium | [GitLab](https://gitlab.com/qemu-project/qemu) |
| CVE-2026-48915 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.1 | Medium | [#3857](https://gitlab.com/qemu-project/qemu/-/work_items/3857) |
| CVE-2026-61405 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.0 | Medium | [#3890](https://gitlab.com/qemu-project/qemu/-/work_items/3890) |
| CVE-2026-61406 | [QEMU](https://gitlab.com/qemu-project/qemu) | 6.5 | Medium | [#3899](https://gitlab.com/qemu-project/qemu/-/work_items/3899) |
| CVE-2026-61476 | [QEMU](https://gitlab.com/qemu-project/qemu) | 4.4 | Medium | [#3875](https://gitlab.com/qemu-project/qemu/-/work_items/3875) |
| CVE-2026-63324 | [QEMU](https://gitlab.com/qemu-project/qemu) | / | / | [#3984](https://gitlab.com/qemu-project/qemu/-/work_items/3984) |
| CVE-2026-53701 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 6.5 | Medium | [#5035](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5035) |
| CVE-2026-53702 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 6.5 | Medium | [#5036](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5036) |
| CVE-2026-53703 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 7.1 | High | [#5038](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5038) |
| CVE-2026-53704 | [GStreamer](https://gitlab.freedesktop.org/gstreamer/gstreamer) | 7.1 | High | [#5039](https://gitlab.freedesktop.org/gstreamer/gstreamer/-/work_items/5039) |

## Responsible use

CodeAuditor is intended for auditing code you own or have explicit permission to test, and for coordinated disclosure to upstream maintainers. Do not use it to target systems or projects without authorization.

**Important:** Before sending any vulnerability report to project maintainers, manually review the generated disclosure materials. Verify that the vulnerability is real, the severity assessment is accurate, and the proof-of-concept actually reproduces the issue. Automated findings may contain false positives or inaccuracies that could waste maintainers' time or damage your credibility.


## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

This software is provided for educational, research, and experimental purposes only. See the disclaimer at the top of the LICENSE file.
