from __future__ import annotations

import hashlib
import html
import json
import os
import re
import subprocess
import tomllib
from datetime import date
from pathlib import Path
from typing import Any


_HEADER = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reproduced Bugs</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.5; }
body { margin: 0; background: Canvas; color: CanvasText; }
main { max-width: 1100px; margin: 0 auto; padding: 32px 20px 56px; }
h1 { margin: 0 0 8px; font-size: 2rem; }
h2 { margin: 0 0 12px; font-size: 1.35rem; }
h3 { margin: 24px 0 8px; font-size: 1.05rem; }
a { color: LinkText; }
code { font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace; overflow-wrap: anywhere; }
.intro { margin: 0 0 24px; color: color-mix(in srgb, CanvasText 72%, Canvas 28%); }
details.reproduced-bug { border-top: 1px solid color-mix(in srgb, CanvasText 22%, Canvas 78%); padding: 0; }
details.reproduced-bug[open] { padding-bottom: 30px; }
summary { align-items: center; cursor: pointer; display: flex; gap: 12px; justify-content: space-between; padding: 18px 0; }
.bug-title { font-size: 1.35rem; font-weight: 700; }
.review-tag { border: 1px solid color-mix(in srgb, CanvasText 24%, Canvas 76%); border-radius: 999px; font-size: 0.82rem; font-weight: 700; padding: 2px 10px; text-transform: uppercase; white-space: nowrap; }
.review-tag-unreviewed { background: color-mix(in srgb, CanvasText 8%, Canvas 92%); }
.review-tag-reported { background: color-mix(in srgb, LinkText 16%, Canvas 84%); }
.review-tag-confirmed { background: color-mix(in srgb, green 18%, Canvas 82%); }
.review-tag-rejected { background: color-mix(in srgb, red 16%, Canvas 84%); }
.review-tag-duplicated { background: color-mix(in srgb, orange 18%, Canvas 82%); }
.review-status { border: 1px solid color-mix(in srgb, CanvasText 20%, Canvas 80%); margin: 0 0 18px; padding: 12px; }
.review-status legend { font-weight: 700; padding: 0 6px; }
.review-options { display: flex; flex-wrap: wrap; gap: 8px; }
.review-option { align-items: center; border: 1px solid color-mix(in srgb, CanvasText 18%, Canvas 82%); display: inline-flex; gap: 6px; padding: 4px 9px; }
.status-filter { border: 1px solid color-mix(in srgb, CanvasText 20%, Canvas 80%); margin: 22px 0 10px; padding: 12px; }
.status-filter legend { font-weight: 700; padding: 0 6px; }
.status-filter-options { display: flex; flex-wrap: wrap; gap: 8px; }
.status-filter button { background: Canvas; border: 1px solid color-mix(in srgb, CanvasText 22%, Canvas 78%); color: CanvasText; cursor: pointer; font: inherit; padding: 5px 10px; }
.status-filter button[aria-pressed="true"] { background: color-mix(in srgb, LinkText 16%, Canvas 84%); border-color: LinkText; }
.status-actions { align-items: center; display: flex; flex-wrap: wrap; gap: 10px; margin-top: 10px; }
.save-status { color: color-mix(in srgb, CanvasText 64%, Canvas 36%); }
.filter-count { color: color-mix(in srgb, CanvasText 64%, Canvas 36%); font-variant-numeric: tabular-nums; }
.metadata { display: grid; gap: 8px 16px; margin: 0; }
.metadata div { display: grid; grid-template-columns: minmax(150px, 220px) 1fr; gap: 12px; }
.metadata dt { font-weight: 700; }
.metadata dd { margin: 0; overflow-wrap: anywhere; }
ul { padding-left: 1.4rem; }
</style>
<script>
(function () {
  const statuses = new Set(["unreviewed", "reported", "confirmed", "rejected", "duplicated"]);
  const statusJsonFileName = "reproduced-bugs-status.json";
  const reviewStatusStoragePrefix = "code-auditor:review-status:";
  let activeStatusFilter = "all";

  function reviewStatusStorageKey(details) {
    return details.dataset.dedupeKey ? reviewStatusStoragePrefix + location.pathname + ":" + details.dataset.dedupeKey : "";
  }

  function storedReviewStatus(details) {
    const key = reviewStatusStorageKey(details);
    if (!key) {
      return "";
    }
    try {
      const status = localStorage.getItem(key) || "";
      return statuses.has(status) ? status : "";
    } catch (_error) {
      return "";
    }
  }

  function storeReviewStatus(details, status) {
    const key = reviewStatusStorageKey(details);
    if (!key) {
      return;
    }
    try {
      localStorage.setItem(key, status);
    } catch (_error) {
    }
  }

  function updateMetadataComment(details, status) {
    for (const node of details.childNodes) {
      if (node.nodeType !== Node.COMMENT_NODE) {
        continue;
      }
      const match = node.data.trim().match(/^code-auditor:discovered\\s+(.+)$/s);
      if (!match) {
        continue;
      }
      try {
        const metadata = JSON.parse(match[1]);
        metadata.review_status = status;
        node.data = " code-auditor:discovered " + JSON.stringify(metadata).replace(/>/g, "\\u003e") + " ";
      } catch (_error) {
      }
      return;
    }
  }

  function applyReviewStatus(details, status, options = {}) {
    if (!statuses.has(status)) {
      return;
    }
    if (options.persist !== false) {
      storeReviewStatus(details, status);
    }
    details.dataset.reviewStatus = status;
    const tag = details.querySelector(":scope > summary .review-tag");
    if (tag) {
      tag.className = "review-tag review-tag-" + status;
      tag.textContent = status;
    }
    const fieldset = details.querySelector(":scope > .review-status");
    if (fieldset) {
      fieldset.dataset.reviewStatus = status;
      fieldset.querySelectorAll('input[type="radio"]').forEach((input) => {
        const selected = input.value === status;
        input.checked = selected;
        if (selected) {
          input.setAttribute("checked", "");
        } else {
          input.removeAttribute("checked");
        }
      });
    }
    updateMetadataComment(details, status);
    if (options.persist !== false) {
      setSaveStatus("Saved locally.");
    }
    updateStatusFilterCounts();
    applyStatusFilter(activeStatusFilter);
  }

  function restoreStoredReviewStatuses() {
    let restored = 0;
    reproducedBugs().forEach((details) => {
      const status = storedReviewStatus(details);
      if (status) {
        applyReviewStatus(details, status, { persist: false });
        restored += 1;
      }
    });
    if (restored > 0) {
      setSaveStatus("Restored local statuses.");
    }
    return restored;
  }

  function statusFilterButtons() {
    return document.querySelectorAll(".status-filter button[data-status-filter]");
  }

  function reproducedBugs() {
    return document.querySelectorAll("details.reproduced-bug");
  }

  function updateStatusFilterCounts() {
    const counts = { all: 0, unreviewed: 0, reported: 0, confirmed: 0, rejected: 0, duplicated: 0 };
    reproducedBugs().forEach((details) => {
      const status = details.dataset.reviewStatus || "unreviewed";
      counts.all += 1;
      if (Object.prototype.hasOwnProperty.call(counts, status)) {
        counts[status] += 1;
      }
    });
    statusFilterButtons().forEach((button) => {
      const status = button.dataset.statusFilter || "all";
      const count = button.querySelector(".filter-count");
      if (count) {
        count.textContent = String(counts[status] || 0);
      }
    });
  }

  function applyStatusFilter(status) {
    activeStatusFilter = status === "all" || statuses.has(status) ? status : "all";
    reproducedBugs().forEach((details) => {
      const bugStatus = details.dataset.reviewStatus || "unreviewed";
      details.hidden = activeStatusFilter !== "all" && bugStatus !== activeStatusFilter;
    });
    statusFilterButtons().forEach((button) => {
      button.setAttribute("aria-pressed", String(button.dataset.statusFilter === activeStatusFilter));
    });
  }

  function setSaveStatus(message) {
    const output = document.querySelector(".save-status");
    if (output) {
      output.textContent = message;
    }
  }

  function currentStatusMap() {
    const statusMap = {};
    reproducedBugs().forEach((details) => {
      const dedupeKey = details.dataset.dedupeKey || "";
      const status = details.dataset.reviewStatus || "unreviewed";
      if (dedupeKey && statuses.has(status)) {
        statusMap[dedupeKey] = status;
      }
    });
    return statusMap;
  }

  function statusJsonText() {
    const sortedStatusMap = {};
    Object.entries(currentStatusMap()).sort(([leftKey], [rightKey]) => {
      return leftKey.localeCompare(rightKey);
    }).forEach(([dedupeKey, status]) => {
      sortedStatusMap[dedupeKey] = status;
    });
    return JSON.stringify(sortedStatusMap, null, 2) + "\\n";
  }

  function downloadStatusJson(text) {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = statusJsonFileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 0);
    setSaveStatus("Exported " + statusJsonFileName + ".");
  }

  async function exportStatusJson() {
    const text = statusJsonText();
    if (typeof window.showSaveFilePicker !== "function") {
      downloadStatusJson(text);
      return;
    }
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: statusJsonFileName,
        types: [
          {
            description: "JSON files",
            accept: { "application/json": [".json"] },
          },
        ],
      });
      const writable = await handle.createWritable();
      await writable.write(text);
      await writable.close();
      setSaveStatus("Saved " + (handle.name || statusJsonFileName) + ".");
    } catch (_error) {
      if (_error && _error.name === "AbortError") {
        setSaveStatus("Export canceled.");
        return;
      }
      downloadStatusJson(text);
    }
  }

  function normalizeStatusMap(rawStatusMap) {
    const source = rawStatusMap && typeof rawStatusMap === "object" && rawStatusMap.statuses
      ? rawStatusMap.statuses
      : rawStatusMap;
    const normalized = {};
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      return normalized;
    }
    Object.entries(source).forEach(([dedupeKey, status]) => {
      if (typeof dedupeKey === "string" && statuses.has(status)) {
        normalized[dedupeKey] = status;
      }
    });
    return normalized;
  }

  function applyStatusMap(rawStatusMap, options = {}) {
    const statusMap = normalizeStatusMap(rawStatusMap);
    let applied = 0;
    reproducedBugs().forEach((details) => {
      if (options.overwriteStored === false && storedReviewStatus(details)) {
        return;
      }
      const status = statusMap[details.dataset.dedupeKey || ""];
      if (status) {
        applyReviewStatus(details, status, { persist: options.persist !== false });
        applied += 1;
      }
    });
    updateStatusFilterCounts();
    applyStatusFilter(activeStatusFilter);
    return applied;
  }

  async function loadDefaultStatusJson() {
    try {
      const response = await fetch(statusJsonFileName, { cache: "no-store" });
      if (!response.ok) {
        return;
      }
      const statusMap = await response.json();
      const applied = applyStatusMap(statusMap, { persist: false, overwriteStored: false });
      if (applied > 0) {
        setSaveStatus("Loaded " + statusJsonFileName + ".");
      }
    } catch (_error) {
    }
  }

  function loadSelectedStatusJson(file) {
    if (!file) {
      return;
    }
    const reader = new FileReader();
    reader.addEventListener("load", () => {
      try {
        const applied = applyStatusMap(JSON.parse(String(reader.result || "")));
        setSaveStatus("Loaded " + applied + " statuses from " + file.name + ".");
      } catch (_error) {
        setSaveStatus("Could not load status JSON.");
      }
    });
    reader.addEventListener("error", () => {
      setSaveStatus("Could not load status JSON.");
    });
    reader.readAsText(file);
  }

  document.addEventListener("change", (event) => {
    const input = event.target;
    if (!(input instanceof HTMLInputElement)) {
      return;
    }
    if (input.classList.contains("status-json-input")) {
      loadSelectedStatusJson(input.files ? input.files[0] : null);
      input.value = "";
      return;
    }
    if (input.type !== "radio") {
      return;
    }
    if (!input.name.startsWith("review-status-")) {
      return;
    }
    const details = input.closest("details.reproduced-bug");
    if (details) {
      applyReviewStatus(details, input.value);
    }
  });

  document.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
      return;
    }
    const button = event.target.closest(".status-filter button[data-status-filter]");
    if (button) {
      applyStatusFilter(button.dataset.statusFilter || "all");
      return;
    }
    const loadButton = event.target.closest(".load-status-json");
    if (loadButton) {
      const input = document.querySelector(".status-json-input");
      if (input) {
        input.click();
      }
      return;
    }
    if (event.target.closest(".export-status-json")) {
      exportStatusJson();
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    restoreStoredReviewStatuses();
    loadDefaultStatusJson();
    updateStatusFilterCounts();
    applyStatusFilter(activeStatusFilter);
  });
})();
</script>
</head>
<body>
<main>
<h1>Reproduced Bugs</h1>
<p class="intro">Entries below are unique reproduced bugs. Embedded code-auditor metadata comments preserve cross-run dedupe keys for automated Stage 6 reuse.</p>
<fieldset class="status-filter">
<legend>Status filter</legend>
<div class="status-filter-options">
<button type="button" data-status-filter="all" aria-pressed="true">All <span class="filter-count">0</span></button>
<button type="button" data-status-filter="unreviewed" aria-pressed="false">Unreviewed <span class="filter-count">0</span></button>
<button type="button" data-status-filter="reported" aria-pressed="false">Reported <span class="filter-count">0</span></button>
<button type="button" data-status-filter="confirmed" aria-pressed="false">Confirmed <span class="filter-count">0</span></button>
<button type="button" data-status-filter="rejected" aria-pressed="false">Rejected <span class="filter-count">0</span></button>
<button type="button" data-status-filter="duplicated" aria-pressed="false">Duplicated <span class="filter-count">0</span></button>
</div>
<div class="status-actions">
<button type="button" class="load-status-json">Load status JSON</button>
<button type="button" class="export-status-json">Export status JSON</button>
<input type="file" class="status-json-input" accept="application/json,.json" hidden>
<output class="save-status" aria-live="polite"></output>
</div>
</fieldset>
"""
_FOOTER = "</main>\n</body>\n</html>\n"
_COMMENT_PREFIX = "code-auditor:discovered"
_COMMENT_RE = re.compile(r"<!--\s*code-auditor:discovered\s+(.+?)\s*-->", re.DOTALL)
_REVIEW_STATUSES = ("unreviewed", "reported", "confirmed", "rejected", "duplicated")
_STATUS_SIDECAR_FILENAME = "reproduced-bugs-status.json"


def read_discovered_keys(path: str) -> set[str]:
    """Read dedupe keys from embedded discovered-bug JSON comments."""
    discovered_path = Path(path)
    if not discovered_path.exists():
        return set()

    try:
        content = discovered_path.read_text(encoding="utf-8")
    except OSError:
        return set()

    keys: set[str] = set()
    for match in _COMMENT_RE.finditer(content):
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue

        if isinstance(payload, dict):
            dedupe_key = payload.get("dedupe_key")
            if isinstance(dedupe_key, str) and dedupe_key:
                keys.add(dedupe_key)
    return keys


def build_dedupe_key(finding: dict[str, Any], repo_url: str | None) -> str:
    """Build a stable cross-run key for the same vulnerability shape."""
    trace = finding.get("data_flow_trace")
    trace_data = trace if isinstance(trace, dict) else {}
    stable_payload = {
        "repo": _normalize_text(repo_url or ""),
        "location": _normalize_path_text(finding.get("location")),
        "cwe": _normalize_list(finding.get("cwe_id") or finding.get("cwe")),
        "vulnerability_class": _normalize_list(finding.get("vulnerability_class")),
        "trigger": _normalize_text(finding.get("trigger")),
        "trace_root": _normalize_path_text(
            trace_data.get("root_path")
            or trace_data.get("root")
            or trace_data.get("source")
            or trace_data.get("entry_point")
        ),
        "trace_sink": _normalize_path_text(trace_data.get("sink")),
    }
    encoded = json.dumps(stable_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def collect_repo_snapshot(target: str, audit_finished_date: str | None = None) -> dict[str, str]:
    """Collect best-effort repository metadata without requiring a git repo."""
    target_path = os.path.realpath(target)
    repo_url = _run_git(target_path, ["config", "--get", "remote.origin.url"])
    audited_commit = _run_git(target_path, ["rev-parse", "HEAD"])
    status = _run_git(target_path, ["status", "--porcelain"])

    version, description = _read_project_metadata(target_path)
    if status is None:
        dirty_status = "unknown"
    else:
        dirty_status = "dirty" if status else "clean"

    return {
        "target_path": target_path,
        "repo_url": repo_url or "",
        "audited_commit": audited_commit or "",
        "version": version,
        "description": description,
        "dirty_status": dirty_status,
        "audit_finished_date": audit_finished_date or date.today().isoformat(),
    }


def build_discovered_entry(
    finding: dict[str, Any],
    repo_snapshot: dict[str, str],
    *,
    discovered_path: str | None = None,
    stage4_finding_path: str | None = None,
    stage5_report_path: str | None = None,
    stage6_report_path: str | None = None,
    stage6_email_path: str | None = None,
    stage6_zip_path: str | None = None,
) -> str:
    """Build one human-readable HTML entry with machine-readable metadata."""
    title = _single_line(finding.get("title")) or "Untitled vulnerability"
    repo_url = repo_snapshot.get("repo_url", "")
    audited_commit = repo_snapshot.get("audited_commit", "")
    audit_finished_date = repo_snapshot.get("audit_finished_date", "")
    dedupe_key = build_dedupe_key(finding, repo_url)
    review_status = _normalize_review_status(finding.get("review_status"))

    metadata = {
        "dedupe_key": dedupe_key,
        "title": title,
        "repo_url": repo_url,
        "audited_commit": audited_commit,
        "audit_finished_date": audit_finished_date,
        "review_status": review_status,
    }
    metadata_json = _comment_safe_json(metadata)

    lines = [
        (
            f'<details class="reproduced-bug" data-dedupe-key="{_html_attr(dedupe_key)}" '
            f'data-review-status="{_html_attr(review_status)}">'
        ),
        (
            f'<summary><span class="bug-title">{_html_text(title)}</span>'
            f'<span class="review-tag review-tag-{_html_attr(review_status)}">'
            f"{_html_text(review_status)}</span></summary>"
        ),
        f"<!-- {_COMMENT_PREFIX} {metadata_json} -->",
        _review_status_box(dedupe_key, review_status),
        '<dl class="metadata">',
        _metadata_row("Repository", repo_url or repo_snapshot.get("target_path")),
        _metadata_row("Version", repo_snapshot.get("version")),
        _metadata_row("Description", repo_snapshot.get("description")),
        _metadata_row("Audited Commit", audited_commit, code=True),
        _metadata_row("Dirty Status", repo_snapshot.get("dirty_status")),
        _metadata_row("Audit Finished", audit_finished_date),
        _metadata_row("Severity", _severity_cvss(finding)),
        _metadata_row("CWE", ", ".join(_display_list(finding.get("cwe_id") or finding.get("cwe")))),
        _metadata_row("Vulnerability Class", ", ".join(_display_list(finding.get("vulnerability_class")))),
        _metadata_row("Location", finding.get("location"), code=True),
        "</dl>",
    ]

    sections = [
        ("Summary", finding.get("summary") or finding.get("description")),
        ("Impact", finding.get("impact")),
        ("Trigger", finding.get("trigger")),
    ]
    for heading, value in sections:
        body = _html_block(value)
        if body:
            lines.extend(
                [
                    f'<section class="{heading.lower()}">',
                    f"<h3>{heading}</h3>",
                    body,
                    "</section>",
                ]
            )

    links = _artifact_links(
        discovered_path=discovered_path,
        stage4_finding_path=stage4_finding_path,
        stage5_report_path=stage5_report_path,
        stage6_report_path=stage6_report_path,
        stage6_email_path=stage6_email_path,
        stage6_zip_path=stage6_zip_path,
    )
    if links:
        lines.extend(['<section class="artifacts">', "<h3>Artifacts</h3>", "<ul>"])
        lines.extend(f"<li>{link}</li>" for link in links)
        lines.extend(["</ul>", "</section>"])

    lines.append("</details>")
    return "\n".join(lines).rstrip() + "\n"


def append_entries(path: str, entries: list[str]) -> None:
    """Append discovered-bug entries, creating the file and header when needed."""
    blocks = [entry.strip() for entry in entries if entry.strip()]
    if not blocks:
        return

    discovered_path = Path(path)
    discovered_path.parent.mkdir(parents=True, exist_ok=True)

    if discovered_path.exists():
        content = discovered_path.read_text(encoding="utf-8")
    else:
        content = ""

    block_text = "\n\n".join(blocks).rstrip()
    if not content.strip():
        content = _HEADER + block_text + "\n" + _FOOTER
    elif _is_html_document(content):
        content = _insert_before_main_close(content, block_text)
    else:
        content = content.rstrip() + "\n\n" + block_text + "\n"
    discovered_path.write_text(content, encoding="utf-8")
    _write_status_sidecar(discovered_path, content)


def _run_git(target_path: str, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", target_path, *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _read_project_metadata(target_path: str) -> tuple[str, str]:
    pyproject_path = Path(target_path) / "pyproject.toml"
    if pyproject_path.exists():
        try:
            with pyproject_path.open("rb") as f:
                data = tomllib.load(f)
            project = data.get("project", {})
            if isinstance(project, dict):
                return str(project.get("version", "") or ""), str(project.get("description", "") or "")
        except (OSError, tomllib.TOMLDecodeError):
            pass

    package_json_path = Path(target_path) / "package.json"
    if package_json_path.exists():
        try:
            data = json.loads(package_json_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return str(data.get("version", "") or ""), str(data.get("description", "") or "")
        except (OSError, json.JSONDecodeError):
            pass

    return "", ""


def _artifact_links(
    *,
    discovered_path: str | None,
    stage4_finding_path: str | None,
    stage5_report_path: str | None,
    stage6_report_path: str | None,
    stage6_email_path: str | None,
    stage6_zip_path: str | None,
) -> list[str]:
    candidates = [
        ("Stage 4 Finding", stage4_finding_path),
        ("Stage 5 Report", stage5_report_path),
        ("Stage 6 Report", stage6_report_path),
        ("Stage 6 Email", stage6_email_path),
        ("Stage 6 Zip", stage6_zip_path),
    ]
    return [
        f'<a href="{_html_attr(_artifact_path(path, discovered_path))}">{_html_text(label)}</a>'
        for label, path in candidates
        if path
    ]


def _artifact_path(path: str, discovered_path: str | None) -> str:
    target = os.path.realpath(path)
    if discovered_path:
        try:
            base_dir = os.path.dirname(os.path.realpath(discovered_path))
            if os.path.commonpath([base_dir, target]) == base_dir:
                return os.path.relpath(target, base_dir).replace(os.sep, "/")
        except ValueError:
            pass
    return target.replace(os.sep, "/")


def _comment_safe_json(metadata: dict[str, str]) -> str:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).replace(
        ">", "\\u003e"
    )


def _is_html_document(content: str) -> bool:
    lowered = content.lower()
    return "<html" in lowered and "</main>" in lowered and "</html>" in lowered


def _insert_before_main_close(content: str, block_text: str) -> str:
    index = content.lower().rfind("</main>")
    if index == -1:
        return content.rstrip() + "\n\n" + block_text + "\n"
    before = content[:index].rstrip()
    after = content[index:].lstrip()
    return before + "\n\n" + block_text + "\n" + after


def _write_status_sidecar(discovered_path: Path, content: str) -> None:
    html_statuses = _status_map_from_content(content)
    if not html_statuses:
        return

    sidecar_path = discovered_path.parent / _STATUS_SIDECAR_FILENAME
    existing_statuses: dict[str, str] = {}
    if sidecar_path.exists():
        try:
            raw_statuses = json.loads(sidecar_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw_statuses = {}
        if isinstance(raw_statuses, dict):
            existing_statuses = {
                key: status
                for key, status in raw_statuses.items()
                if isinstance(key, str) and status in _REVIEW_STATUSES
            }

    merged = {
        key: existing_statuses.get(key, status)
        for key, status in sorted(html_statuses.items())
    }
    sidecar_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")


def _status_map_from_content(content: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for match in _COMMENT_RE.finditer(content):
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        dedupe_key = payload.get("dedupe_key")
        if isinstance(dedupe_key, str) and dedupe_key:
            statuses[dedupe_key] = _normalize_review_status(payload.get("review_status"))
    return statuses


def _metadata_row(label: str, value: Any, *, code: bool = False) -> str:
    visible = _visible_value(value)
    rendered = f"<code>{_html_text(visible)}</code>" if code else _html_text(visible)
    return f"<div><dt>{_html_text(label)}</dt><dd>{rendered}</dd></div>"


def _review_status_box(dedupe_key: str, selected_status: str) -> str:
    input_name = _status_input_name(dedupe_key)
    options = []
    for status in _REVIEW_STATUSES:
        checked = " checked" if status == selected_status else ""
        options.append(
            (
                f'<label class="review-option review-option-{_html_attr(status)}">'
                f'<input type="radio" name="{_html_attr(input_name)}" '
                f'value="{_html_attr(status)}"{checked}> {_html_text(status)}</label>'
            )
        )
    return (
        f'<fieldset class="review-status" data-review-status="{_html_attr(selected_status)}">\n'
        "<legend>Review status</legend>\n"
        '<div class="review-options">\n'
        + "\n".join(options)
        + "\n</div>\n</fieldset>"
    )


def _normalize_review_status(value: Any) -> str:
    status = _normalize_text(value)
    if status in _REVIEW_STATUSES:
        return status
    return "unreviewed"


def _status_input_name(dedupe_key: str) -> str:
    return "review-status-" + re.sub(r"[^a-zA-Z0-9_-]+", "-", dedupe_key).strip("-")


def _html_block(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        items = [_single_line(item) for item in value if _single_line(item)]
        if not items:
            return ""
        return "<ul>\n" + "\n".join(f"<li>{_html_text(item)}</li>" for item in items) + "\n</ul>"

    text = str(value).strip()
    if not text:
        return ""

    paragraphs = [part.strip() for part in re.split(r"\n\s*\n", text) if part.strip()]
    return "\n".join(f"<p>{_html_lines(part)}</p>" for part in paragraphs)


def _html_lines(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "<br>\n".join(_html_text(line) for line in lines)


def _html_text(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _html_attr(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _severity_cvss(finding: dict[str, Any]) -> str:
    severity = _single_line(finding.get("severity"))
    cvss = _single_line(finding.get("cvss_score") or finding.get("cvss"))
    if severity and cvss:
        return f"{severity} / CVSS {cvss}"
    if severity:
        return severity
    if cvss:
        return f"CVSS {cvss}"
    return "unknown"


def _display_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [_single_line(item) for item in value if _single_line(item)]
    text = _single_line(value)
    return [text] if text else []


def _normalize_list(value: Any) -> list[str]:
    return sorted({_normalize_text(item) for item in _display_list(value) if _normalize_text(item)})


def _normalize_text(value: Any) -> str:
    return " ".join(_single_line(value).lower().split())


def _normalize_path_text(value: Any) -> str:
    return " ".join(_single_line(value).replace("\\", "/").split())


def _single_line(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def _paragraph(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "\n".join(f"- {_single_line(item)}" for item in value if _single_line(item))
    return str(value).strip()


def _visible_value(value: Any) -> str:
    return _single_line(value) or "unknown"
