"use strict";

// ── Stage metadata (mirrors code_auditor/tui.py STAGE_INFO) ────────────────
const STAGE_INFO = {
  0: ["Init", "Git clone + output directory setup"],
  1: ["Context", "Security context research"],
  2: ["Decompose", "Decompose codebase into analysis units"],
  3: ["Discover", "Bug discovery per analysis unit"],
  4: ["Evaluate", "Evaluate findings as vulnerabilities"],
  5: ["PoC", "Proof-of-concept reproduction"],
  6: ["Disclose", "Disclosure package preparation"],
};

const STATUS_LABEL = {
  pending: "Pending",
  running: "Running",
  done: "Complete",
  failed: "Failed",
};

// ── DOM handles ─────────────────────────────────────────────────────────────
const $ = (id) => document.getElementById(id);
const form = $("audit-form");
const logPane = $("log-pane");
const jobBadge = $("job-badge");
const jobStatusPanel = $("job-status-panel");
const btnStart = $("btn-start");
const btnStop = $("btn-stop");
const formError = $("form-error");
const stagesTbody = document.querySelector("#stages-table tbody");
const resultsPanel = $("results-panel");
const viewerPanel = $("viewer-panel");
const reproductionForm = $("reproduction-form");
const reproductionLogPane = $("reproduction-log-pane");
const reproductionBtnStart = $("r-btn-start");
const reproductionBtnStop = $("r-btn-stop");
const reproductionFormError = $("r-form-error");
const reproductionResultsPanel = $("reproduction-results-panel");
const reproductionViewerPanel = $("reproduction-viewer-panel");

let jobState = "idle";
let jobKind = "audit";
let reproductionCandidates = [];
let configuredGitUrl = "";
let managedResultsDir = "";
let terminalToken = "";
let terminalEnabled = false;
let terminalSequence = 0;
const terminalSessions = new Map();
let cveImportCandidates = [];
let disclosureEditingEntry = null;
let cveDialogMode = "import";
let cveEditingId = "";
let cveLoadSequence = 0;
let disclosureEditSequence = 0;
let disclosureCvesReady = false;
const BUSY_JOB_STATES = new Set(["restoring", "running"]);

const disclosureSort = { key: "", direction: "ascending" };
const cveSort = { key: "", direction: "ascending" };
const TRIGGER_GRAPH_ARTIFACT = "Stage 5 Trigger Graph";
const ASAN_REPORT_ARTIFACT = "Stage 5 ASan Report";
const SVG_NS = "http://www.w3.org/2000/svg";
const TRIGGER_GRAPH_ROLES = new Set([
  "trigger",
  "source",
  "propagation",
  "guard",
  "sink",
  "source-and-sink",
]);
let triggerGraphLoadSequence = 0;
let asanReportLoadSequence = 0;
let lastAuditLogAt = 0;
let lastAuditHeartbeatAt = 0;
let lastAgentEventAt = 0;
let auditHeartbeatPending = false;
const activeAgentLogOffsets = new Map();
const completedStageNotifications = new Set();
const MAX_LOG_PANE_CHARS = 200000;
const MAX_LOG_PANE_ENTRIES = 2000;
const LOG_RENDER_INTERVAL_MS = 100;
const AGENT_LOG_FALLBACK_CHARS = 20000;
const logBuffers = new Map();
const tableCollator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});

function isJobBusy(state = jobState) {
  return BUSY_JOB_STATES.has(state);
}

// ── Config form ─────────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();
    const d = cfg.defaults || {};
    configuredGitUrl = d.git_url || "";
    managedResultsDir = cfg.results_dir || "";
    terminalToken = cfg.terminal_token || "";
    terminalEnabled = cfg.terminal_enabled === true && terminalToken !== "";
    if (managedResultsDir) {
      $("import-output-dir").placeholder =
        `${managedResultsDir}/project/audit-output-commit`;
    }
    if (d.max_parallel) $("f-max-parallel").value = d.max_parallel;
    $("f-config-path").textContent =
      cfg.config_path || "~/.code_auditor/settings.json";
  } catch (e) {
    formError.textContent = `Failed to load config: ${e}`;
    reproductionFormError.textContent = `Failed to load config: ${e}`;
  }
}

// ── Cloned repositories ─────────────────────────────────────────────────────
async function loadRepos() {
  const select = $("f-repo-select");
  try {
    const res = await fetch("/api/repos");
    const data = await res.json();
    select.innerHTML = `<option value="">— select a repository —</option>`;
    for (const repo of data.repos || []) {
      const opt = document.createElement("option");
      opt.value = repo.name;
      opt.textContent = repo.name;
      select.appendChild(opt);
    }
    const clone = document.createElement("option");
    clone.value = "__clone__";
    clone.textContent = "Clone a new repository URL…";
    select.appendChild(clone);
    if (configuredGitUrl) {
      select.value = "__clone__";
      $("f-git-url").value = configuredGitUrl;
      updateRepositoryChoice();
    }
  } catch {
    // repo list unavailable; the select simply stays empty
  }
}

async function loadWikis() {
  const select = $("f-wiki-select");
  try {
    const res = await fetch("/api/wikis");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    select.innerHTML = `<option value="">— none —</option>`;
    for (const wiki of data.wikis || []) {
      const opt = document.createElement("option");
      opt.value = wiki.name;
      opt.textContent = wiki.name;
      select.appendChild(opt);
    }
  } catch {
    select.innerHTML = `<option value="">— none —</option>`;
  }
}

async function updateRepositoryChoice() {
  const repository = $("f-repo-select").value;
  const cloning = repository === "__clone__";
  $("f-git-url-label").hidden = !cloning;
  $("f-git-url").required = cloning;
  if (!cloning) $("f-git-url").value = "";
  if (!repository || cloning) {
    $("repo-runs").hidden = true;
    return;
  }
  await loadRepoRuns(repository);
}

$("f-repo-select").addEventListener("change", updateRepositoryChoice);

async function loadRepoRuns(repository) {
  const box = $("repo-runs");
  try {
    const res = await fetch(
      `/api/history?limit=5&repository=${encodeURIComponent(repository)}`
    );
    const data = await res.json();
    const runs = data.runs || [];
    if (runs.length === 0) {
      box.innerHTML = `<span class="dim">No previous audits recorded for this repository.</span>`;
      box.hidden = false;
      return;
    }
    const items = runs
      .map(
        (r) =>
          `<li><a href="#/run/${escapeHtml(r.id)}">Run #${escapeHtml(r.id)}</a> ` +
          `<span class="badge badge-${escapeHtml(r.status)}">${escapeHtml(r.status)}</span> ` +
          `${escapeHtml(fmtTime(r.started_at || r.created_at))} — ` +
          `${escapeHtml(r.reproduced_vulns_count)} reproduced vulnerabilities</li>`
      )
      .join("");
    box.innerHTML = `<h3>Previous audits of this repository</h3><ul>${items}</ul>`;
    box.hidden = false;
  } catch {
    box.hidden = true;
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  formError.textContent = "";
  const body = {};
  const repository = $("f-repo-select").value;
  const gitUrl = $("f-git-url").value.trim();
  if (!repository) {
    formError.textContent = "Select an existing repository or clone a new one.";
    return;
  }
  if (repository === "__clone__") {
    if (!gitUrl || gitUrl.length > 2048) {
      formError.textContent = "Provide a valid HTTPS or SSH Git repository URL.";
      return;
    }
    body.git_url = gitUrl;
  } else {
    body.repository = repository;
  }
  const maxParallel = Number($("f-max-parallel").value);
  if (!Number.isInteger(maxParallel) || maxParallel < 1 || maxParallel > 16) {
    formError.textContent = "Max parallel agents must be an integer from 1 to 16.";
    return;
  }
  body.max_parallel = maxParallel;
  const wiki = $("f-wiki-select").value;
  if (wiki) body.wiki = wiki;

  try {
    const res = await fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      formError.textContent = err.detail || `Start failed (HTTP ${res.status})`;
      return;
    }
    const data = await res.json();
    setJobState(data.state || "running", data.error, data.kind || "audit");
  } catch (err) {
    formError.textContent = `Start failed: ${err}`;
  }
});

btnStop.addEventListener("click", async () => {
  try {
    await fetch("/api/audit/stop", { method: "POST" });
  } catch (e) {
    // status stream will reconcile state
  }
});

// ── Standalone reproduction ────────────────────────────────────────────────
async function loadReproductionCandidates() {
  const currentTarget = $("r-target-select").value;
  const currentCommit = $("r-commit-select").value;
  const currentBug = $("r-bug-select").value;
  try {
    const res = await fetch("/api/reproduction/candidates");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    reproductionCandidates = data.candidates || [];
    populateReproductionTargets(currentTarget, currentCommit, currentBug);
  } catch (e) {
    reproductionCandidates = [];
    $("r-target-select").innerHTML =
      `<option value="">— targets unavailable —</option>`;
    $("r-commit-select").innerHTML =
      `<option value="">— commits unavailable —</option>`;
    $("r-bug-select").innerHTML =
      `<option value="">— candidates unavailable —</option>`;
    $("r-target-select").disabled = true;
    $("r-commit-select").disabled = true;
    $("r-bug-select").disabled = true;
    $("r-bug-count").textContent = "Could not load candidates.";
    reproductionFormError.textContent = `Failed to load candidates: ${e}`;
    renderReproductionCandidate();
  }
}

function reproductionTargetKey(candidate) {
  return candidate.target || candidate.repo_name || "";
}

function populateReproductionTargets(
  preferredTarget = "",
  preferredCommit = "",
  preferredBug = ""
) {
  const select = $("r-target-select");
  const targets = new Map();
  for (const candidate of reproductionCandidates) {
    const key = reproductionTargetKey(candidate);
    if (!targets.has(key)) {
      targets.set(
        key,
        candidate.repo_name || baseName(candidate.target) || "Unknown target"
      );
    }
  }
  select.innerHTML = `<option value="">— select a target project —</option>`;
  for (const [value, label] of targets) {
    const opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    opt.title = value;
    select.appendChild(opt);
  }
  select.disabled = targets.size === 0;
  if (preferredTarget && targets.has(preferredTarget)) {
    select.value = preferredTarget;
  }
  populateReproductionCommits(preferredCommit, preferredBug);
}

function populateReproductionCommits(preferredCommit = "", preferredBug = "") {
  const target = $("r-target-select").value;
  const select = $("r-commit-select");
  const candidates = reproductionCandidates.filter(
    (candidate) => reproductionTargetKey(candidate) === target
  );
  const commits = new Map();
  for (const candidate of candidates) {
    const commit = candidate.commit || "";
    commits.set(commit, (commits.get(commit) || 0) + 1);
  }
  select.innerHTML = `<option value="">— select a commit —</option>`;
  for (const [commit, count] of commits) {
    const opt = document.createElement("option");
    opt.value = commit;
    opt.textContent =
      `${commit.slice(0, 12) || "unknown"} · ${count} reproduced bug` +
      (count === 1 ? "" : "s");
    opt.title = commit;
    select.appendChild(opt);
  }
  select.disabled = !target || commits.size === 0;
  if (preferredCommit && commits.has(preferredCommit)) {
    select.value = preferredCommit;
  }
  populateReproductionBugs(preferredBug);
}

function populateReproductionBugs(preferredBug = "") {
  const target = $("r-target-select").value;
  const commit = $("r-commit-select").value;
  const select = $("r-bug-select");
  select.innerHTML = `<option value="">— select a reproduced bug —</option>`;
  reproductionCandidates.forEach((candidate, index) => {
    if (
      reproductionTargetKey(candidate) !== target ||
      candidate.commit !== commit
    ) {
      return;
    }
    const opt = document.createElement("option");
    opt.value = String(index);
    opt.textContent =
      `Run #${candidate.run_id} / ${candidate.vuln_id}: ` +
      `${candidate.title || "Untitled vulnerability"}`;
    select.appendChild(opt);
  });
  select.disabled = !target || !commit || select.options.length === 1;
  if (
    preferredBug &&
    [...select.options].some((option) => option.value === preferredBug)
  ) {
    select.value = preferredBug;
  }
  const count = reproductionCandidates.filter(
    (candidate) =>
      (!target || reproductionTargetKey(candidate) === target) &&
      (!commit || candidate.commit === commit)
  ).length;
  const scope = commit
    ? " at this commit"
    : target
      ? " in this project"
      : " available";
  $("r-bug-count").textContent =
    `${count} exactly reproduced bug${count === 1 ? "" : "s"}${scope}`;
  renderReproductionCandidate();
}

function selectedReproductionCandidate() {
  const value = $("r-bug-select").value;
  if (value === "") return null;
  return reproductionCandidates[Number(value)] || null;
}

function renderReproductionCandidate() {
  const candidate = selectedReproductionCandidate();
  const meta = $("r-bug-meta");
  if (!candidate) {
    meta.hidden = true;
    meta.innerHTML = "";
    updateReproductionStartAvailability();
    return;
  }
  const values = [
    ["Run", `#${candidate.run_id}`],
    ["Vulnerability", candidate.vuln_id],
    ["Current reproduction status", candidate.poc_status || "unknown"],
    ["Severity", candidate.severity || "—"],
    ["CVSS", candidate.cvss_score ?? "—"],
    ["Commit", candidate.commit || "—"],
    ["Location", candidate.location || "—"],
  ];
  meta.innerHTML = values
    .map(
      ([key, value]) =>
        `<span class="meta-key">${escapeHtml(key)}</span>` +
        `<span class="meta-val">${escapeHtml(String(value))}</span>`
    )
    .join("");
  meta.hidden = false;
  updateReproductionStartAvailability();
}

$("r-target-select").addEventListener("change", () => {
  populateReproductionCommits();
});
$("r-commit-select").addEventListener("change", () => {
  populateReproductionBugs();
});
$("r-bug-select").addEventListener("change", renderReproductionCandidate);

function updateReproductionStartAvailability() {
  reproductionBtnStart.disabled =
    isJobBusy() || selectedReproductionCandidate() === null;
}

reproductionForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  reproductionFormError.textContent = "";
  const candidate = selectedReproductionCandidate();
  if (!candidate) {
    reproductionFormError.textContent = "Select a reproduced vulnerability.";
    return;
  }
  const body = {
    run_id: candidate.run_id,
    vuln_id: candidate.vuln_id,
  };
  try {
    const res = await fetch("/api/reproduction", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      reproductionFormError.textContent =
        err.detail || `Start failed (HTTP ${res.status})`;
      return;
    }
    const data = await res.json();
    setJobState(
      data.state || "running",
      data.error,
      data.kind || "reproduction"
    );
  } catch (err) {
    reproductionFormError.textContent = `Start failed: ${err}`;
  }
});

reproductionBtnStop.addEventListener("click", async () => {
  try {
    await fetch("/api/reproduction/stop", { method: "POST" });
  } catch {
    // status stream will reconcile state
  }
});

// ── Job state / stages table ────────────────────────────────────────────────
function setJobState(state, error, kind) {
  const enteringActive = isJobBusy(state) && !isJobBusy(jobState);
  if (kind) jobKind = kind;
  jobState = state;
  jobStatusPanel.dataset.state = state;
  jobBadge.textContent =
    (jobKind ? `${jobKind}: ` : "") + state + (error ? `: ${error}` : "");
  jobBadge.className = `badge badge-${state}`;
  btnStart.disabled = isJobBusy(state);
  reproductionBtnStart.disabled = isJobBusy(state);
  btnStop.disabled = !isJobBusy(state) || jobKind !== "audit";
  reproductionBtnStop.disabled =
    !isJobBusy(state) || jobKind !== "reproduction";
  if (enteringActive) {
    completedStageNotifications.clear();
    lastAgentEventAt = 0;
    activeAgentLogOffsets.clear();
    if (jobKind === "reproduction") {
      resetReproductionStage();
      clearLogBuffer(reproductionLogPane);
      reproductionResultsPanel.hidden = true;
      reproductionViewerPanel.hidden = true;
    } else {
      resetStages();
      clearLogBuffer(logPane);
      resultsPanel.hidden = true;
      viewerPanel.hidden = true;
    }
  }
  if (state === "done" || state === "failed" || state === "cancelled") {
    if (jobKind === "reproduction") loadReproductionResults();
    else loadResults();
  }
  updateReproductionStartAvailability();
  updateResumeButtons();
}

function resetStages() {
  stagesTbody.innerHTML = "";
  for (const n of Object.keys(STAGE_INFO)) {
    const [name, desc] = STAGE_INFO[n];
    const tr = document.createElement("tr");
    tr.id = `stage-row-${n}`;
    tr.innerHTML =
      `<td>${n}</td><td>${name}</td><td class="stage-desc">${desc}</td>` +
      `<td class="stage-status">${STATUS_LABEL.pending}</td><td class="stage-progress"></td>`;
    stagesTbody.appendChild(tr);
  }
}

function updateStage(n, status, detail) {
  const row = $(`stage-row-${n}`);
  if (!row) return;
  row.querySelector(".stage-status").textContent = STATUS_LABEL[status] || status;
  row.className = `stage-${status}`;
  if (detail) row.querySelector(".stage-desc").textContent = detail;
}

function updateProgress(n, done, total, detail) {
  const row = $(`stage-row-${n}`);
  if (!row) return;
  const cell = row.querySelector(".stage-progress");
  cell.textContent = total > 0 ? `${done}/${total}` : "";
  if (detail) row.querySelector(".stage-desc").textContent = detail;
}

function resetReproductionStage() {
  const row = $("reproduction-stage-row");
  row.className = "";
  row.querySelector(".stage-desc").textContent =
    "Retest the selected vulnerability";
  row.querySelector(".stage-status").textContent = STATUS_LABEL.pending;
  row.querySelector(".stage-progress").textContent = "";
}

function updateReproductionStage(status, detail) {
  const row = $("reproduction-stage-row");
  row.querySelector(".stage-status").textContent =
    STATUS_LABEL[status] || status;
  row.className = `stage-${status}`;
  if (detail) row.querySelector(".stage-desc").textContent = detail;
}

function updateReproductionProgress(done, total, detail) {
  const row = $("reproduction-stage-row");
  row.querySelector(".stage-progress").textContent =
    total > 0 ? `${done}/${total}` : "";
  if (detail) row.querySelector(".stage-desc").textContent = detail;
}

function stageNotificationKey(kind, stage) {
  return `${kind || "audit"}:${stage}`;
}

function rememberCompletedStage(kind, stage) {
  completedStageNotifications.add(stageNotificationKey(kind, stage));
}

function dismissNotification(item) {
  if (item?.isConnected) item.remove();
  if ($("notification-list").children.length === 0) {
    $("notification-center").hidden = true;
  }
}

function notifyStageCompleted(kind, stage, detail) {
  const key = stageNotificationKey(kind, stage);
  if (completedStageNotifications.has(key)) return;
  completedStageNotifications.add(key);

  const metadata = STAGE_INFO[stage] || [`Stage ${stage}`, "Stage completed"];
  const item = document.createElement("article");
  item.className = "notification-item";
  item.setAttribute("role", "status");

  const title = document.createElement("strong");
  title.className = "notification-item-title";
  title.textContent = `Stage ${stage} complete · ${metadata[0]}`;
  const description = document.createElement("span");
  description.className = "notification-item-detail";
  description.textContent = detail || metadata[1];
  const timestamp = document.createElement("time");
  timestamp.className = "notification-item-time";
  timestamp.textContent = new Date().toLocaleTimeString();
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "notification-item-dismiss";
  dismiss.setAttribute("aria-label", "Dismiss notification");
  dismiss.textContent = "×";
  dismiss.addEventListener("click", () => dismissNotification(item));

  item.append(title, description, timestamp, dismiss);
  const list = $("notification-list");
  list.prepend(item);
  while (list.children.length > 5) list.lastElementChild.remove();
  $("notification-center").hidden = false;
  window.setTimeout(() => dismissNotification(item), 12000);
}

$("btn-clear-notifications").addEventListener("click", () => {
  $("notification-list").replaceChildren();
  $("notification-center").hidden = true;
});

// ── Logs (SSE) ──────────────────────────────────────────────────────────────
function logBufferFor(pane) {
  let state = logBuffers.get(pane);
  if (!state) {
    state = {
      entries: [],
      head: 0,
      chars: 0,
      trimmed: false,
      renderTimer: 0,
    };
    logBuffers.set(pane, state);
  }
  return state;
}

function renderLogBuffer(pane, state) {
  state.renderTimer = 0;
  const pinnedToBottom =
    pane.scrollHeight - pane.scrollTop - pane.clientHeight < 36;
  const prefix = state.trimmed ? "[older Web logs trimmed — full log remains available]\n" : "";
  pane.textContent = prefix + state.entries.slice(state.head).join("");
  if (pinnedToBottom) pane.scrollTop = pane.scrollHeight;
}

function clearLogBuffer(pane) {
  const state = logBufferFor(pane);
  if (state.renderTimer) window.clearTimeout(state.renderTimer);
  state.entries = [];
  state.head = 0;
  state.chars = 0;
  state.trimmed = false;
  state.renderTimer = 0;
  pane.textContent = "";
}

function appendLogToPane(pane, message) {
  const state = logBufferFor(pane);
  let entry = `${String(message ?? "")}\n`;
  if (entry.length > MAX_LOG_PANE_CHARS) {
    entry = entry.slice(-MAX_LOG_PANE_CHARS);
    state.trimmed = true;
  }
  state.entries.push(entry);
  state.chars += entry.length;
  while (
    state.entries.length - state.head > MAX_LOG_PANE_ENTRIES ||
    state.chars > MAX_LOG_PANE_CHARS
  ) {
    const removed = state.entries[state.head];
    state.head += 1;
    state.chars -= removed.length;
    state.trimmed = true;
  }
  if (state.head > 1024 && state.head > state.entries.length / 2) {
    state.entries = state.entries.slice(state.head);
    state.head = 0;
  }
  if (!state.renderTimer) {
    state.renderTimer = window.setTimeout(
      () => renderLogBuffer(pane, state),
      LOG_RENDER_INTERVAL_MS
    );
  }
  return state;
}

function appendLog(message) {
  const pane = jobKind === "reproduction" ? reproductionLogPane : logPane;
  appendLogToPane(pane, message);
  lastAuditLogAt = Date.now();
}

async function pollActiveAgentLog() {
  if (Date.now() - lastAgentEventAt < 15000) return false;
  const res = await fetch("/api/results/agent-log");
  if (!res.ok) return false;
  const text = await res.text();
  const path = res.headers.get("X-CodeAuditor-Log-Path") || "agent.log";
  const knownPath = activeAgentLogOffsets.has(path);
  const previousLength = knownPath
    ? Math.min(activeAgentLogOffsets.get(path) || 0, text.length)
    : Math.max(0, text.length - AGENT_LOG_FALLBACK_CHARS);
  activeAgentLogOffsets.set(path, text.length);
  if (text.length <= previousLength) return false;
  const addition = text
    .slice(previousLength)
    .slice(-AGENT_LOG_FALLBACK_CHARS)
    .trimEnd();
  if (!addition) return false;
  appendLog(`[${path}] ${addition}`);
  return true;
}

async function pollAuditHeartbeat() {
  if (!isJobBusy() || auditHeartbeatPending) return;
  auditHeartbeatPending = true;
  try {
    const res = await fetch("/api/audit/status");
    if (!res.ok) return;
    const status = await res.json();
    if (!isJobBusy(status.state)) {
      setJobState(status.state, status.error, status.kind || jobKind);
      return;
    }
    if (status.state !== jobState) {
      setJobState(status.state, status.error, status.kind || jobKind);
    }
    const runningStage = (status.stages || []).find(
      (stage) => stage.status === "running"
    );
    const now = Date.now();
    const appendedAgentLog = runningStage
      ? await pollActiveAgentLog()
      : false;
    if (
      runningStage &&
      !appendedAgentLog &&
      now - lastAuditLogAt >= 15000 &&
      now - lastAuditHeartbeatAt >= 15000
    ) {
      const elapsed = Math.max(0, Math.round(runningStage.elapsed || 0));
      appendLog(
        `[live] ${jobKind} is active — Stage ${runningStage.stage}: ` +
        `${runningStage.detail || "running"} (${elapsed}s elapsed)`
      );
      lastAuditHeartbeatAt = now;
    }
  } catch {
    // EventSource reconnection remains authoritative; heartbeat is a fallback.
  } finally {
    auditHeartbeatPending = false;
  }
}

function connectEvents() {
  const source = new EventSource("/api/audit/events");
  source.onmessage = (msg) => {
    let ev;
    try {
      ev = JSON.parse(msg.data);
    } catch {
      return;
    }
    if (ev.type === "log") {
      if (String(ev.message || "").includes(" Agent: ")) {
        lastAgentEventAt = Date.now();
      }
      appendLog(ev.message);
    } else if (ev.type === "stage") {
      if (jobKind === "reproduction" && ev.stage === 5) {
        updateReproductionStage(ev.status, ev.detail);
      } else {
        updateStage(ev.stage, ev.status, ev.detail);
      }
      if (ev.status === "done") {
        notifyStageCompleted(jobKind, ev.stage, ev.detail);
      }
    } else if (ev.type === "progress") {
      if (jobKind === "reproduction" && ev.stage === 5) {
        updateReproductionProgress(
          ev.items_done,
          ev.items_total,
          ev.detail
        );
      } else {
        updateProgress(ev.stage, ev.items_done, ev.items_total, ev.detail);
      }
    } else if (ev.type === "job") {
      setJobState(ev.status, ev.error, ev.kind);
    }
  };
  source.onerror = () => {
    // EventSource auto-reconnects; nothing to do.
  };
}

// ── Results ─────────────────────────────────────────────────────────────────
async function viewLatestAgentLog(preferReproduction = false) {
  const useReproduction = preferReproduction || jobKind === "reproduction";
  const panel = useReproduction ? reproductionViewerPanel : viewerPanel;
  const title = useReproduction
    ? $("reproduction-viewer-title")
    : $("viewer-title");
  const content = useReproduction
    ? $("reproduction-viewer-content")
    : $("viewer-content");
  try {
    const res = await fetch("/api/results/agent-log");
    const text = await res.text();
    const path = res.headers.get("X-CodeAuditor-Log-Path") || "Latest Agent log";
    title.textContent = path;
    content.textContent = res.ok ? text : `Error: ${text}`;
  } catch (error) {
    title.textContent = "Latest Agent log";
    content.textContent = `Error: ${error}`;
  }
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth" });
}

$("btn-full-agent-log").addEventListener("click", () => viewLatestAgentLog(false));
$("r-btn-full-agent-log").addEventListener("click", () => viewLatestAgentLog(true));

async function loadResults() {
  try {
    const res = await fetch("/api/results");
    if (!res.ok) return;
    const data = await res.json();
    $("results-output-dir").textContent = `Output: ${baseName(data.output_dir)}`;
    fillFileList("results-vulnerabilities", data.vulnerabilities);
    fillFileList("results-pocs", data.poc_reports);
    fillFileList("results-disclosures", data.disclosures);
    fillFileList("results-agent-logs", data.agent_logs);
    resultsPanel.hidden = false;
  } catch {
    // no results available
  }
}

function fillFileList(id, files, viewer = viewFile) {
  const ul = $(id);
  ul.innerHTML = "";
  for (const f of files || []) {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "#";
    a.textContent = f;
    a.addEventListener("click", (e) => {
      e.preventDefault();
      viewer(f);
    });
    li.appendChild(a);
    ul.appendChild(li);
  }
  if (!files || files.length === 0) {
    const li = document.createElement("li");
    li.textContent = "—";
    li.className = "dim";
    ul.appendChild(li);
  }
}

async function viewFile(path) {
  try {
    const res = await fetch(`/api/results/file?path=${encodeURIComponent(path)}`);
    const text = await res.text();
    $("viewer-title").textContent = path;
    $("viewer-content").textContent = res.ok ? text : `Error: ${text}`;
    viewerPanel.hidden = false;
    viewerPanel.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    $("viewer-title").textContent = path;
    $("viewer-content").textContent = `Error: ${e}`;
    viewerPanel.hidden = false;
  }
}

async function loadReproductionResults() {
  try {
    const res = await fetch("/api/reproduction/results");
    if (!res.ok) return;
    const data = await res.json();
    $("reproduction-results-output-dir").textContent =
      `Output: ${data.output_dir}`;
    fillFileList(
      "reproduction-vulnerabilities",
      data.vulnerabilities,
      viewReproductionFile
    );
    fillFileList("reproduction-pocs", data.poc_reports, viewReproductionFile);
    fillFileList(
      "reproduction-agent-logs",
      data.agent_logs,
      viewReproductionFile
    );
    reproductionResultsPanel.hidden = false;
  } catch {
    // no reproduction results available
  }
}

async function viewReproductionFile(path) {
  try {
    const res = await fetch(
      `/api/reproduction/results/file?path=${encodeURIComponent(path)}`
    );
    const text = await res.text();
    $("reproduction-viewer-title").textContent = path;
    $("reproduction-viewer-content").textContent =
      res.ok ? text : `Error: ${text}`;
    reproductionViewerPanel.hidden = false;
    reproductionViewerPanel.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    $("reproduction-viewer-title").textContent = path;
    $("reproduction-viewer-content").textContent = `Error: ${e}`;
    reproductionViewerPanel.hidden = false;
  }
}

// ── History view ────────────────────────────────────────────────────────────
const SEVERITIES = ["critical", "high", "medium", "low"];

function baseName(path) {
  if (!path) return "—";
  const parts = String(path).replace(/\/+$/, "").split("/");
  return parts[parts.length - 1] || path;
}

function repoDisplay(run) {
  return run.repo_name || baseName(run.target);
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function fmtDuration(start, end) {
  if (!start) return "—";
  const secs = Math.max(0, Math.round((end || Date.now() / 1000) - start));
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = secs % 60;
  if (h) return `${h}h ${m}m ${s}s`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function severityBadge(sev) {
  sev = (sev || "").toLowerCase();
  if (!sev) return "—";
  const span = document.createElement("span");
  span.className = `sev-badge sev-${sev}`;
  span.textContent = sev;
  return span;
}

function parseJsonList(text) {
  try {
    const v = JSON.parse(text || "[]");
    return Array.isArray(v) ? v : [String(v)];
  } catch {
    return [];
  }
}

function modelsUsedDisplay(run) {
  const models = parseJsonList(run.models_used);
  return models.length ? models.join(", ") : run.model || "";
}

function fmtTokenCount(n) {
  if (!Number.isFinite(n) || n <= 0) return "0";
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}k`;
  return String(Math.round(n));
}

function parseJsonObject(text) {
  try {
    const v = JSON.parse(text || "{}");
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch {
    return {};
  }
}

function usageStatsDisplay(run) {
  const stats = typeof run.usage_stats === "object" && run.usage_stats !== null
    ? run.usage_stats
    : parseJsonObject(run.usage_stats);
  const input = Number(stats.input_tokens || 0);
  const output = Number(stats.output_tokens || 0);
  const cost = Number(stats.cost_usd || 0);
  const parts = [];
  if (input || output) {
    parts.push(`${fmtTokenCount(input)} in / ${fmtTokenCount(output)} out`);
  }
  if (cost > 0) {
    parts.push(`$${cost.toFixed(2)}`);
  }
  return parts.join(" · ");
}

function setResumeMessage(message, isError = false) {
  for (const id of ["history-message", "run-resume-message"]) {
    const node = $(id);
    if (!node) continue;
    node.textContent = message;
    node.classList.toggle("error", isError);
    node.classList.toggle("dim", !isError);
  }
}

function updateResumeButtons() {
  document.querySelectorAll("[data-resume-run]").forEach((button) => {
    button.disabled = isJobBusy();
  });
}

async function resumeCancelledAudit(runId, button) {
  if (isJobBusy()) {
    setResumeMessage("Another audit or reproduction is already running.", true);
    return;
  }
  if (!window.confirm(
    `Continue Run #${runId} using its existing output and checkpoints?`
  )) return;

  setResumeMessage("");
  if (button) button.disabled = true;
  try {
    const res = await fetch(`/api/history/${runId}/resume`, { method: "POST" });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      setResumeMessage(data.detail || `Resume failed (HTTP ${res.status})`, true);
      if (button) button.disabled = false;
      return;
    }
    setJobState(data.state || "running", data.error, data.kind || "audit");
    location.hash = "#/";
    route();
  } catch (error) {
    setResumeMessage(`Resume failed: ${error}`, true);
    if (button) button.disabled = false;
  }
}

async function loadHistory() {
  const tbody = document.querySelector("#history-table tbody");
  tbody.innerHTML = "";
  setResumeMessage("");
  try {
    const res = await fetch("/api/history");
    const data = await res.json();
    for (const run of data.runs || []) {
      const tr = document.createElement("tr");
      tr.className = "run-row";
      const cells = [
        run.id,
        repoDisplay(run),
        { kind: "commit" },
        fmtTime(run.started_at || run.created_at),
        run.status === "running"
          ? "running…"
          : run.status === "imported"
            ? "—"
            : fmtDuration(run.started_at, run.ended_at),
        { kind: "status" },
        run.backend || "—",
        usageStatsDisplay(run) || "—",
        run.reproduced_vulns_count,
      ];
      for (const c of cells) {
        const td = document.createElement("td");
        if (c && c.kind === "commit") {
          if (run.commit) {
            td.textContent = run.commit.slice(0, 7) + (run.dirty ? "*" : "");
            td.title = `${run.repo_name || ""} ${run.commit}${run.dirty ? " (dirty)" : ""}`;
            td.className = "commit-cell";
          } else {
            td.textContent = "—";
          }
        } else if (c && c.kind === "status") {
          const badge = document.createElement("span");
          badge.className = `badge badge-${run.status}`;
          badge.textContent = run.status;
          td.appendChild(badge);
          if (run.status === "done" && run.error) {
            const warn = document.createElement("span");
            warn.textContent = " ⚠";
            warn.title = run.error;
            td.appendChild(warn);
          }
        } else {
          td.textContent = c ?? "—";
        }
        tr.appendChild(td);
      }
      const actionCell = document.createElement("td");
      actionCell.className = "history-action";
      if (
        run.status === "cancelled" ||
        run.status === "failed" ||
        (run.status === "done" && run.error)
      ) {
        const resumeButton = document.createElement("button");
        resumeButton.type = "button";
        resumeButton.className = "btn btn-resume";
        resumeButton.dataset.resumeRun = String(run.id);
        resumeButton.textContent = "Resume";
        resumeButton.title = "Continue from the existing audit checkpoints";
        resumeButton.disabled = isJobBusy();
        resumeButton.addEventListener("click", (event) => {
          event.stopPropagation();
          resumeCancelledAudit(run.id, resumeButton);
        });
        actionCell.appendChild(resumeButton);
      } else {
        actionCell.textContent = "—";
      }
      tr.appendChild(actionCell);
      tr.addEventListener("click", () => {
        location.hash = `#/run/${run.id}`;
      });
      tbody.appendChild(tr);
    }
    if (!data.runs || data.runs.length === 0) {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td colspan="10" class="dim">No audit runs recorded yet.</td>`;
      tbody.appendChild(tr);
    }
  } catch (e) {
    tbody.innerHTML =
      `<tr><td colspan="10" class="error">Failed to load history: ` +
      `${escapeHtml(String(e))}</td></tr>`;
  }
}

$("btn-import").addEventListener("click", async () => {
  $("import-error").textContent = "";
  const outputDir = $("import-output-dir").value.trim();
  if (!outputDir || outputDir.length > 4096) {
    $("import-error").textContent = "A valid managed output directory is required.";
    return;
  }
  if (
    managedResultsDir &&
    outputDir.startsWith("/") &&
    outputDir !== managedResultsDir &&
    !outputDir.startsWith(`${managedResultsDir}/`)
  ) {
    $("import-error").textContent =
      `Import paths must stay under ${managedResultsDir}.`;
    return;
  }
  try {
    const res = await fetch("/api/history/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ output_dir: outputDir }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      $("import-error").textContent = err.detail || `Import failed (HTTP ${res.status})`;
      return;
    }
    const data = await res.json();
    $("import-output-dir").value = "";
    $("import-error").textContent = "";
    const ok = $("import-ok");
    ok.textContent = `Imported ${data.imported} run(s).`;
    setTimeout(() => (ok.textContent = ""), 8000);
    await loadHistory();
  } catch (e) {
    $("import-error").textContent = `Import failed: ${e}`;
  }
});

// ── Run detail view ─────────────────────────────────────────────────────────
async function loadRunDetail(runId) {
  const resumeButton = $("btn-run-resume");
  resumeButton.hidden = true;
  resumeButton.dataset.resumeRun = "";
  resumeButton.onclick = null;
  setResumeMessage("");
  let run;
  try {
    const res = await fetch(`/api/history/${runId}`);
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    run = await res.json();
  } catch (e) {
    $("run-detail-title").textContent = `Run #${runId}`;
    $("run-meta").innerHTML = `<span class="error">Failed to load: ${escapeHtml(String(e))}</span>`;
    return;
  }

  $("run-detail-title").textContent = `Run #${run.id} — ${repoDisplay(run)}`;
  if (run.status === "cancelled") {
    resumeButton.hidden = false;
    resumeButton.dataset.resumeRun = String(run.id);
    resumeButton.disabled = isJobBusy();
    resumeButton.onclick = () => resumeCancelledAudit(run.id, resumeButton);
  }
  let submodules = [];
  try {
    submodules = JSON.parse(run.submodules || "[]");
  } catch {
    submodules = [];
  }
  const meta = [
    ["Status", run.status + (run.error ? `: ${run.error}` : "")],
    ["Target", repoDisplay(run)],
    ["Repo", run.repo_name || "—"],
    ["Branch", run.branch || "—"],
    [
      "Commit",
      run.commit
        ? `${run.commit.slice(0, 10)}${run.dirty ? " (dirty)" : ""}`
        : "—",
    ],
    [
      "Submodules",
      submodules.length
        ? submodules.map((s) => `${s.path}@${(s.commit || "").slice(0, 7)}`).join(", ")
        : "—",
    ],
    ["Output", baseName(run.output_dir)],
    ["Backend", run.backend || "—"],
    ["Models used", modelsUsedDisplay(run) || "—"],
    ["Tokens / Cost", usageStatsDisplay(run) || "—"],
    ["Started", fmtTime(run.started_at)],
    ["Ended", fmtTime(run.ended_at)],
    ["Duration", run.status === "imported" ? "—" : fmtDuration(run.started_at, run.ended_at)],
    ["Reproduced vulnerabilities", String(run.reproduced_vulns_count ?? (run.vulnerabilities || []).length)],
  ];
  $("run-meta").innerHTML = meta
    .map(([k, v]) => `<span class="meta-key">${escapeHtml(k)}</span><span class="meta-val">${escapeHtml(v)}</span>`)
    .join("");
  if ((run.related_run_ids || []).length > 0) {
    const links = run.related_run_ids
      .map(
        (id) =>
          `<a href="#/run/${escapeHtml(id)}" class="related-run-link">` +
          `Run #${escapeHtml(id)}</a>`
      )
      .join(" ");
    const merged = run.target_key
      ? ` · <a href="#/target/${encodeURIComponent(run.target_key)}" class="related-run-link">merged view</a>`
      : "";
    $("run-meta").innerHTML +=
      `<span class="meta-key">Same target</span><span class="meta-val">${links}${merged}</span>`;
  }

  const atbody = document.querySelector("#run-aus-table tbody");
  atbody.innerHTML = "";
  for (const au of run.analysis_units || []) {
    const files = parseJsonList(au.files);
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${escapeHtml(au.au_id)}</td><td>${files.length}</td>` +
      `<td>${escapeHtml(au.focus) || "—"}</td><td>${escapeHtml(au.description) || "—"}</td>`;
    atbody.appendChild(tr);
    const filesRow = document.createElement("tr");
    filesRow.className = "details-row";
    filesRow.innerHTML =
      `<td colspan="4"><details><summary>files</summary>` +
      `<div class="kv">${files.map(escapeHtml).join("<br>") || "—"}</div>` +
      `</details></td>`;
    atbody.appendChild(filesRow);
  }
  const ausPanel = atbody.closest("section");
  if (ausPanel) ausPanel.hidden = (run.analysis_units || []).length === 0;

  const vtbody = document.querySelector("#run-vulns-table tbody");
  vtbody.innerHTML = "";
  for (const v of run.vulnerabilities || []) {
    const tr = document.createElement("tr");
    const cwes = parseJsonList(v.cwe_ids).join(", ");
    const disclosure = v.disclosure_report_path
      ? `<a href="#" class="disclosure-artifact-link" data-file="${escapeHtml(v.disclosure_report_path)}">report</a>` +
        (v.disclosure_zip_path ? ` <a href="#" class="disclosure-artifact-link" data-file="${escapeHtml(v.disclosure_zip_path)}">zip</a>` : "")
      : "—";
    tr.innerHTML =
      `<td>${escapeHtml(v.vuln_id)}</td><td class="sev-cell"></td><td>${escapeHtml(v.cvss_score ?? "—")}</td>` +
      `<td>${escapeHtml(cwes) || "—"}</td><td>${escapeHtml(v.title) || "—"}</td>` +
      `<td>${escapeHtml(v.poc_status) || "—"} ${terminalButtonHtml(run.id, v.vuln_id, v.title)}</td>` +
      `<td>${disclosure}</td>`;
    tr.querySelector(".sev-cell").appendChild(severityBadge(v.severity));
    vtbody.appendChild(tr);
    const details = document.createElement("tr");
    details.className = "details-row";
    details.innerHTML =
      `<td colspan="7"><details><summary>details</summary>` +
      `<div class="kv">Location: ${escapeHtml(v.location) || "—"}</div>` +
      `<div class="kv">Trigger: ${escapeHtml(v.trigger) || "—"}</div>` +
      `<div class="kv">Impact: ${escapeHtml(v.impact) || "—"}</div>` +
      (v.poc_report_path
        ? `<div class="kv">PoC report: <a href="#" data-file="${escapeHtml(v.poc_report_path)}">${escapeHtml(v.poc_report_path)}</a></div>`
        : "") +
      `<pre class="raw-json">${escapeHtml(v.raw_json)}</pre></details></td>`;
    vtbody.appendChild(details);
  }
  if (!run.vulnerabilities || run.vulnerabilities.length === 0) {
    vtbody.innerHTML = `<tr><td colspan="7" class="dim">No vulnerabilities recorded.</td></tr>`;
  }

  // Wire file links to the history file endpoint.
  document.querySelectorAll("#view-run-detail a[data-file]").forEach((a) => {
    a.addEventListener("click", (e) => {
      e.preventDefault();
      viewHistoryFile(runId, a.getAttribute("data-file"));
    });
  });
  wireTerminalButtons($("view-run-detail"));
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = String(text ?? "");
  return div.innerHTML;
}

async function viewHistoryFile(runId, path) {
  const panel = $("history-viewer-panel");
  try {
    const res = await fetch(
      `/api/history/${runId}/file?path=${encodeURIComponent(path)}`
    );
    const text = await res.text();
    $("history-viewer-title").textContent = path;
    $("history-viewer-content").textContent = res.ok ? text : `Error: ${text}`;
    panel.hidden = false;
    panel.scrollIntoView({ behavior: "smooth" });
  } catch (e) {
    $("history-viewer-title").textContent = path;
    $("history-viewer-content").textContent = `Error: ${e}`;
    panel.hidden = false;
  }
}

// ── Target merged view ──────────────────────────────────────────────────────
async function loadTargetView(targetKey) {
  let data;
  try {
    const res = await fetch(`/api/target/${encodeURIComponent(targetKey)}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    data = await res.json();
  } catch (e) {
    $("target-title").textContent = "Target";
    $("target-meta").innerHTML = `<span class="error">Failed to load: ${escapeHtml(String(e))}</span>`;
    return;
  }
  const runs = data.runs || [];
  const first = runs[0] || {};
  $("target-title").textContent =
    `Target: ${repoDisplay(first)} @ ${(first.commit || "").slice(0, 10)}`;
  const totalVulns = (data.vulnerabilities || []).length;
  const totalAus = (data.analysis_units || []).length;
  const meta = [
    ["Repo", first.repo_name || "—"],
    ["Branch", first.branch || "—"],
    ["Commit", first.commit ? first.commit.slice(0, 10) : "—"],
    [
      "Runs",
      runs
        .map(
          (r) =>
            `<a href="#/run/${escapeHtml(r.id)}" class="related-run-link">` +
            `#${escapeHtml(r.id)}</a>`
        )
        .join(" "),
    ],
    ["Reproduced vulnerabilities", String(totalVulns)],
    ["Merged analysis units", String(totalAus)],
  ];
  $("target-meta").innerHTML = meta
    .map(([k, v]) => `<span class="meta-key">${escapeHtml(k)}</span><span class="meta-val">${k === "Runs" ? v : escapeHtml(v)}</span>`)
    .join("");

  $("target-vuln-count").textContent = `(${totalVulns} across ${runs.length} runs)`;
  const tbody = document.querySelector("#target-vulns-table tbody");
  tbody.innerHTML = "";
  for (const v of data.vulnerabilities || []) {
    const tr = document.createElement("tr");
    const cwes = parseJsonList(v.cwe_ids).join(", ");
    tr.innerHTML =
      `<td><a href="#/run/${escapeHtml(v.run_id)}" class="related-run-link">#${escapeHtml(v.run_id)}</a></td>` +
      `<td>${escapeHtml(v.vuln_id)}</td><td class="sev-cell"></td>` +
      `<td>${escapeHtml(v.cvss_score ?? "—")}</td><td>${escapeHtml(cwes) || "—"}</td>` +
      `<td>${escapeHtml(v.title) || "—"}</td>` +
      `<td>${escapeHtml(v.poc_status) || "—"} ${terminalButtonHtml(v.run_id, v.vuln_id, v.title)}</td>`;
    tr.querySelector(".sev-cell").appendChild(severityBadge(v.severity));
    tbody.appendChild(tr);
  }
  if (totalVulns === 0) {
    tbody.innerHTML = `<tr><td colspan="7" class="dim">No reproduced vulnerabilities recorded.</td></tr>`;
  }
  wireTerminalButtons($("view-target"));

  $("target-au-count").textContent = `(${totalAus} distinct units)`;
  const auTbody = document.querySelector("#target-aus-table tbody");
  auTbody.innerHTML = "";
  for (const au of data.analysis_units || []) {
    const files = parseJsonList(au.files);
    const sourceRuns = [
      ...new Set((au.source_units || []).map((source) => source.run_id)),
    ];
    const sourceLinks = sourceRuns
      .map(
        (id) =>
          `<a href="#/run/${escapeHtml(id)}" class="related-run-link">` +
          `#${escapeHtml(id)}</a>`
      )
      .join(" ");
    const tr = document.createElement("tr");
    tr.innerHTML =
      `<td>${escapeHtml(au.au_id)}</td><td>${sourceLinks || "—"}</td><td>${files.length}</td>` +
      `<td>${escapeHtml(au.focus) || "—"}</td><td>${escapeHtml(au.description) || "—"}</td>`;
    auTbody.appendChild(tr);
    const filesRow = document.createElement("tr");
    filesRow.className = "details-row";
    filesRow.innerHTML =
      `<td colspan="5"><details><summary>files</summary>` +
      `<div class="kv">${files.map(escapeHtml).join("<br>") || "—"}</div>` +
      `</details></td>`;
    auTbody.appendChild(filesRow);
  }
  if (totalAus === 0) {
    auTbody.innerHTML = `<tr><td colspan="5" class="dim">No analysis units recorded.</td></tr>`;
  }
}

function sortedTableEntries(entries, state, valueFor) {
  if (!state.key) return [...entries];
  return entries
    .map((entry, index) => ({ entry, index }))
    .sort((left, right) => {
      const a = valueFor(left.entry, state.key);
      const b = valueFor(right.entry, state.key);
      const aEmpty = a === null || a === undefined || a === "";
      const bEmpty = b === null || b === undefined || b === "";
      if (aEmpty !== bEmpty) return aEmpty ? 1 : -1;
      let compared = 0;
      if (typeof a === "number" && typeof b === "number") {
        compared = a - b;
      } else {
        compared = tableCollator.compare(String(a ?? ""), String(b ?? ""));
      }
      if (compared === 0) return left.index - right.index;
      return state.direction === "descending" ? -compared : compared;
    })
    .map(({ entry }) => entry);
}

function updateSortIndicators(tableId, state) {
  const table = $(tableId);
  for (const button of table.querySelectorAll(".sort-button")) {
    const th = button.closest("th");
    th.setAttribute(
      "aria-sort",
      button.dataset.sort === state.key ? state.direction : "none"
    );
  }
}

function wireSortableTable(tableId, state, reload) {
  const table = $(tableId);
  for (const button of table.querySelectorAll(".sort-button")) {
    button.addEventListener("click", () => {
      const key = button.dataset.sort;
      if (state.key === key) {
        state.direction =
          state.direction === "ascending" ? "descending" : "ascending";
      } else {
        state.key = key;
        state.direction = "ascending";
      }
      updateSortIndicators(tableId, state);
      reload();
    });
  }
  updateSortIndicators(tableId, state);
}

function disclosureSortValue(entry, key) {
  const values = {
    status: entry.review_status,
    project: entry.project,
    title: entry.title,
    cve: (entry.cves || []).map((cve) => cve.cve_id).join(" "),
    cwe: entry.cwe,
    commit: entry.audited_commit,
    date: entry.audit_finished_date,
  };
  return values[key] ?? "";
}

function cveSortValue(entry, key) {
  const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
  const values = {
    cve: entry.cve_id,
    project: entry.project,
    score: entry.cvss_score,
    severity: severityRank[entry.severity] || 0,
    public: (entry.references || [])
      .map((reference) => `${reference.label} ${reference.url}`)
      .join(" ") || entry.cve_url,
    local: (entry.local_disclosures || [])
      .map((disclosure) => disclosure.title || disclosure.dedupe_key)
      .join(" "),
  };
  return values[key] ?? "";
}

function disclosureArtifactUrl(entry, artifact) {
  if (!entry || !Number.isInteger(artifact?.index)) return "";
  const params = new URLSearchParams({
    project: entry.project,
    dedupe_key: entry.dedupe_key,
    artifact: String(artifact.index),
  });
  return `/api/disclosures/artifact?${params}`;
}

function evidenceReference(entries, label) {
  for (const entry of entries || []) {
    const artifact = (entry.artifacts || []).find((item) => item.label === label);
    if (artifact) return { entry, artifact };
  }
  return null;
}

function appendEvidenceActionButtons(container, entries, title) {
  const graphReference = evidenceReference(entries, TRIGGER_GRAPH_ARTIFACT);
  const graphButton = document.createElement("button");
  graphButton.type = "button";
  graphButton.className = "btn btn-graph";
  graphButton.textContent = "Graph";
  graphButton.disabled = graphReference === null;
  graphButton.title = graphReference
    ? "Open the interactive PoC trigger graph"
    : "No standardized trigger-graph.json artifact is registered";
  graphButton.setAttribute("aria-label", `Open trigger graph for ${title}`);
  if (graphReference) {
    graphButton.addEventListener("click", () =>
      openTriggerGraph(
        graphReference.entry,
        graphReference.artifact,
        title
      )
    );
  }
  container.appendChild(graphButton);

  const asanReference = evidenceReference(entries, ASAN_REPORT_ARTIFACT);
  const asanButton = document.createElement("button");
  asanButton.type = "button";
  asanButton.className = "btn btn-asan";
  asanButton.textContent = "ASan";
  asanButton.disabled = asanReference === null;
  asanButton.title = asanReference
    ? "Open the captured AddressSanitizer report"
    : "No standardized asan-report.txt artifact is registered";
  asanButton.setAttribute("aria-label", `Open ASan report for ${title}`);
  if (asanReference) {
    asanButton.addEventListener("click", () =>
      openAsanReport(asanReference.entry, asanReference.artifact, title)
    );
  }
  container.appendChild(asanButton);
}

function createSvgElement(tag, attributes = {}) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, String(value));
  }
  return element;
}

function graphText(value, fallback = "—") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function shortenedGraphText(value, length) {
  const text = graphText(value, "");
  return text.length > length ? `${text.slice(0, length - 1)}…` : text;
}

function appendGraphDetail(details, label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = graphText(value);
  details.append(dt, dd);
}

function renderTriggerGraphNodeDetails(graph, node) {
  const details = $("trigger-graph-details");
  details.replaceChildren();
  const heading = document.createElement("h3");
  heading.textContent = graphText(node.function);
  const role = document.createElement("span");
  const roleName = TRIGGER_GRAPH_ROLES.has(node.role) ? node.role : "propagation";
  role.className = `badge graph-role graph-role-${roleName}`;
  role.textContent = roleName;
  const fields = document.createElement("dl");
  appendGraphDetail(fields, "Location", node.location);
  appendGraphDetail(fields, "Function logic", node.description);
  appendGraphDetail(fields, "Runtime evidence", node.evidence);
  appendGraphDetail(fields, "PoC trigger", graph.trigger);
  appendGraphDetail(fields, "Evidence basis", graph.evidence_basis);
  details.append(heading, role, fields);

  const parameterHeading = document.createElement("h4");
  parameterHeading.textContent = "Key parameters";
  details.appendChild(parameterHeading);
  const parameterList = document.createElement("div");
  parameterList.className = "graph-parameter-list";
  for (const parameter of node.key_parameters || []) {
    const item = document.createElement("div");
    item.className = "graph-parameter";
    const name = document.createElement("strong");
    name.textContent = graphText(parameter.name);
    item.appendChild(name);
    for (const [label, value] of [
      ["Value", parameter.value],
      ["Origin", parameter.origin],
      ["Security role", parameter.security_role],
      ["Meaning", parameter.description],
    ]) {
      if (!graphText(value, "")) continue;
      const line = document.createElement("span");
      line.textContent = `${label}: ${value}`;
      item.appendChild(line);
    }
    parameterList.appendChild(item);
  }
  if (!parameterList.childElementCount) {
    const empty = document.createElement("p");
    empty.className = "dim";
    empty.textContent = "No key parameters were recorded for this frame.";
    parameterList.appendChild(empty);
  }
  details.appendChild(parameterList);
}

function triggerGraphLayout(graph) {
  const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
  const outgoing = new Map(graph.nodes.map((node) => [node.id, []]));
  const indegree = new Map(graph.nodes.map((node) => [node.id, 0]));
  for (const edge of graph.edges) {
    if (!nodeById.has(edge.from) || !nodeById.has(edge.to)) continue;
    outgoing.get(edge.from).push(edge.to);
    indegree.set(edge.to, indegree.get(edge.to) + 1);
  }
  const depths = new Map();
  const queue = graph.nodes
    .filter((node) => indegree.get(node.id) === 0)
    .map((node) => node.id);
  for (const nodeId of queue) depths.set(nodeId, 0);
  let cursor = 0;
  while (cursor < queue.length) {
    const nodeId = queue[cursor++];
    for (const target of outgoing.get(nodeId)) {
      depths.set(target, Math.max(depths.get(target) || 0, depths.get(nodeId) + 1));
      indegree.set(target, indegree.get(target) - 1);
      if (indegree.get(target) === 0) queue.push(target);
    }
  }
  let fallbackDepth = Math.max(0, ...depths.values()) + 1;
  for (const node of graph.nodes) {
    if (!depths.has(node.id)) depths.set(node.id, fallbackDepth++);
  }
  const levels = new Map();
  for (const node of graph.nodes) {
    const depth = depths.get(node.id);
    if (!levels.has(depth)) levels.set(depth, []);
    levels.get(depth).push(node);
  }
  return { nodeById, levels };
}

function renderTriggerGraph(graph) {
  if (
    !graph ||
    graph.schema_version !== 1 ||
    !Array.isArray(graph.nodes) ||
    !graph.nodes.length ||
    graph.nodes.length > 128 ||
    !Array.isArray(graph.edges) ||
    graph.edges.length > 256
  ) {
    throw new Error("The trigger graph does not match the supported schema.");
  }
  const ids = new Set();
  for (const node of graph.nodes) {
    if (!node || typeof node.id !== "string" || ids.has(node.id)) {
      throw new Error("The trigger graph contains invalid or duplicate node IDs.");
    }
    ids.add(node.id);
  }

  const svg = $("trigger-graph-svg");
  svg.replaceChildren();
  const { nodeById, levels } = triggerGraphLayout(graph);
  const nodeWidth = 246;
  const nodeHeight = 88;
  const horizontalGap = 54;
  const verticalGap = 76;
  const padding = 40;
  const orderedLevels = [...levels.entries()].sort((a, b) => a[0] - b[0]);
  const maxLevelSize = Math.max(...orderedLevels.map(([, nodes]) => nodes.length));
  const width = Math.max(
    760,
    padding * 2 + maxLevelSize * nodeWidth + (maxLevelSize - 1) * horizontalGap
  );
  const height = Math.max(
    420,
    padding * 2 + orderedLevels.length * nodeHeight +
      (orderedLevels.length - 1) * verticalGap
  );
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("width", String(width));
  svg.setAttribute("height", String(height));

  const definitions = createSvgElement("defs");
  const marker = createSvgElement("marker", {
    id: "trigger-graph-arrow",
    markerWidth: 8,
    markerHeight: 8,
    refX: 7,
    refY: 4,
    orient: "auto",
    markerUnits: "strokeWidth",
  });
  marker.appendChild(createSvgElement("path", { d: "M0,0 L8,4 L0,8 z", fill: "#566474" }));
  definitions.appendChild(marker);
  svg.appendChild(definitions);

  const positions = new Map();
  orderedLevels.forEach(([, nodes], depth) => {
    const levelWidth = nodes.length * nodeWidth + (nodes.length - 1) * horizontalGap;
    const startX = (width - levelWidth) / 2;
    nodes.forEach((node, index) => {
      positions.set(node.id, {
        x: startX + index * (nodeWidth + horizontalGap),
        y: padding + depth * (nodeHeight + verticalGap),
      });
    });
  });

  for (const edge of graph.edges) {
    const source = positions.get(edge.from);
    const target = positions.get(edge.to);
    if (!source || !target) continue;
    const x1 = source.x + nodeWidth / 2;
    const y1 = source.y + nodeHeight;
    const x2 = target.x + nodeWidth / 2;
    const y2 = target.y;
    const middle = (y1 + y2) / 2;
    const path = createSvgElement("path", {
      d: `M${x1},${y1} C${x1},${middle} ${x2},${middle} ${x2},${y2}`,
      class: edge.attacker_controlled
        ? "trigger-graph-edge trigger-graph-edge-attacker"
        : "trigger-graph-edge",
      "marker-end": "url(#trigger-graph-arrow)",
    });
    const title = createSvgElement("title");
    title.textContent = [edge.label, edge.condition].filter(Boolean).join(" — ");
    path.appendChild(title);
    svg.appendChild(path);
    const label = createSvgElement("text", {
      x: (x1 + x2) / 2,
      y: middle - 6,
      class: "trigger-graph-edge-label",
    });
    label.textContent = shortenedGraphText(edge.label, 32);
    svg.appendChild(label);
  }

  let selectedGroup = null;
  const selectNode = (node, group) => {
    selectedGroup?.classList.remove("trigger-graph-node-selected");
    selectedGroup = group;
    group.classList.add("trigger-graph-node-selected");
    renderTriggerGraphNodeDetails(graph, node);
  };
  const groupsByNodeId = new Map();
  for (const node of graph.nodes) {
    const position = positions.get(node.id);
    const role = TRIGGER_GRAPH_ROLES.has(node.role) ? node.role : "propagation";
    const group = createSvgElement("g", {
      class: `trigger-graph-node trigger-graph-node-${role}`,
      transform: `translate(${position.x},${position.y})`,
      role: "button",
      tabindex: 0,
      "aria-label": `${node.function}, ${role}`,
    });
    group.appendChild(createSvgElement("rect", {
      width: nodeWidth,
      height: nodeHeight,
      rx: 4,
    }));
    for (const [textValue, y, className] of [
      [shortenedGraphText(node.function, 35), 25, "trigger-graph-node-function"],
      [role, 48, "trigger-graph-node-role"],
      [shortenedGraphText(node.location, 41), 69, "trigger-graph-node-location"],
    ]) {
      const text = createSvgElement("text", { x: 13, y, class: className });
      text.textContent = textValue;
      group.appendChild(text);
    }
    group.addEventListener("click", () => selectNode(node, group));
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        selectNode(node, group);
        event.preventDefault();
      }
    });
    svg.appendChild(group);
    groupsByNodeId.set(node.id, group);
  }
  const preferred = graph.nodes.find((node) =>
    ["trigger", "source", "source-and-sink"].includes(node.role)
  ) || graph.nodes[0];
  const preferredGroup = groupsByNodeId.get(preferred.id);
  if (preferredGroup) selectNode(nodeById.get(preferred.id), preferredGroup);
}

async function openTriggerGraph(entry, artifact, title) {
  const sequence = ++triggerGraphLoadSequence;
  const dialog = $("trigger-graph-dialog");
  $("trigger-graph-title").textContent = `PoC trigger graph — ${title}`;
  $("trigger-graph-meta").textContent = `${entry.project} · ${entry.dedupe_key}`;
  $("trigger-graph-message").textContent = "Loading trigger graph…";
  $("trigger-graph-layout").hidden = true;
  if (!dialog.open) dialog.showModal();
  try {
    const res = await fetch(disclosureArtifactUrl(entry, artifact));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const contentLength = Number(res.headers.get("content-length") || 0);
    if (contentLength > 2 * 1024 * 1024) throw new Error("Graph artifact is too large.");
    const graph = await res.json();
    if (sequence !== triggerGraphLoadSequence) return;
    renderTriggerGraph(graph);
    $("trigger-graph-message").textContent =
      `${graph.nodes.length} functions · ${graph.edges.length} call edges`;
    $("trigger-graph-layout").hidden = false;
  } catch (error) {
    if (sequence !== triggerGraphLoadSequence) return;
    $("trigger-graph-message").textContent =
      `Unable to display trigger graph: ${error.message || error}`;
  }
}

async function openAsanReport(entry, artifact, title) {
  const sequence = ++asanReportLoadSequence;
  const dialog = $("asan-report-dialog");
  $("asan-report-title").textContent = `AddressSanitizer report — ${title}`;
  $("asan-report-meta").textContent = `${entry.project} · ${entry.dedupe_key}`;
  $("asan-report-message").textContent = "Loading ASan report…";
  $("asan-report-content").hidden = true;
  if (!dialog.open) dialog.showModal();
  try {
    const res = await fetch(disclosureArtifactUrl(entry, artifact));
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const contentLength = Number(res.headers.get("content-length") || 0);
    if (contentLength > 8 * 1024 * 1024) throw new Error("ASan report is too large.");
    const report = await res.text();
    if (sequence !== asanReportLoadSequence) return;
    if (report.length > 8 * 1024 * 1024) throw new Error("ASan report is too large.");
    $("asan-report-content").textContent = report;
    $("asan-report-content").hidden = false;
    $("asan-report-message").textContent =
      `${report.split(/\r?\n/).length} lines · captured Stage 5 evidence`;
  } catch (error) {
    if (sequence !== asanReportLoadSequence) return;
    $("asan-report-message").textContent =
      `Unable to display ASan report: ${error.message || error}`;
  }
}

$("btn-trigger-graph-close").addEventListener("click", () => {
  triggerGraphLoadSequence += 1;
  $("trigger-graph-dialog").close();
});

$("btn-asan-report-close").addEventListener("click", () => {
  asanReportLoadSequence += 1;
  $("asan-report-dialog").close();
});

// ── Disclosures view ────────────────────────────────────────────────────────
const DISCLOSED_STATUSES = [
  "unreviewed",
  "reported",
  "confirmed",
  "rejected",
  "duplicated",
  "triage",
  "bug",
  "slop",
];
let disclosureFilter = "";
let disclosureLoadSequence = 0;
let disclosureSearchTimer = null;
let trashLoadSequence = 0;
let trashSearchTimer = null;

async function loadDisclosures() {
  const sequence = ++disclosureLoadSequence;
  const project = $("disclosure-project").value;
  const search = $("disclosure-search").value.trim();
  const params = new URLSearchParams();
  if (disclosureFilter) params.set("status", disclosureFilter);
  if (project) params.set("project", project);
  if (search) params.set("q", search);
  const tbody = document.querySelector("#disclosures-table tbody");
  tbody.innerHTML = "";
  try {
    const res = await fetch(`/api/disclosures?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (sequence !== disclosureLoadSequence) return;
    renderDisclosureChips(data.counts || {});
    renderProjectOptions(data.projects || []);
    const entries = sortedTableEntries(
      data.entries || [],
      disclosureSort,
      disclosureSortValue
    );
    updateSortIndicators("disclosures-table", disclosureSort);
    $("disclosure-count").textContent = search
      ? `${entries.length} match${entries.length === 1 ? "" : "es"}`
      : `${entries.length} record${entries.length === 1 ? "" : "s"}`;
    for (const e of entries) {
      const cves = (e.cves || [])
        .map((cve) => externalLinkHtml(cve.cve_id, cve.cve_url))
        .join("");
      const poc = e.terminal
        ? disclosureTerminalButtonHtml(e)
        : e.poc
          ? terminalButtonHtml(e.poc.run_id, e.poc.vuln_id, e.poc.title)
          : "—";
      const tr = document.createElement("tr");
      tr.className = "record-row";
      tr.innerHTML =
        `<td class="status-cell"></td><td class="project-cell">${escapeHtml(e.project)}</td>` +
        `<td class="title-cell">${escapeHtml(e.title) || "—"}</td>` +
        `<td class="identity-cell"><span class="table-link-list">${cves || "—"}</span></td>` +
        `<td class="cwe-cell">${escapeHtml(e.cwe) || "—"}</td>` +
        `<td class="commit-cell">${escapeHtml((e.audited_commit || "").slice(0, 7)) || "—"}</td>` +
        `<td class="date-cell">${escapeHtml(e.audit_finished_date) || "—"}</td>` +
        `<td class="action-cell"><div class="row-actions">${poc}</div></td>`;
      const select = document.createElement("select");
      select.className = `status-select badge-disc-${e.review_status}`;
      for (const s of DISCLOSED_STATUSES) {
        const opt = document.createElement("option");
        opt.value = s;
        opt.textContent = s;
        if (s === e.review_status) opt.selected = true;
        select.appendChild(opt);
      }
      select.addEventListener("change", () =>
        changeDisclosureStatus(e.project, e.dedupe_key, select.value)
      );
      const cell = tr.querySelector(".status-cell");
      const statusControl = document.createElement("div");
      statusControl.className = "status-control";
      statusControl.appendChild(select);
      cell.appendChild(statusControl);
      const actionContainer = tr.querySelector(".row-actions");
      appendEvidenceActionButtons(
        actionContainer,
        [e],
        e.title || e.dedupe_key
      );
      const editButton = document.createElement("button");
      editButton.type = "button";
      editButton.className = "btn btn-edit";
      editButton.textContent = "Edit";
      editButton.setAttribute("aria-label", `Edit ${e.title || e.dedupe_key}`);
      editButton.addEventListener("click", () => openDisclosureEditDialog(e));
      actionContainer.appendChild(editButton);
      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className = "btn btn-delete";
      deleteButton.textContent = "Delete";
      deleteButton.setAttribute(
        "aria-label",
        `Move ${e.title || e.dedupe_key} to the recycle bin`
      );
      deleteButton.addEventListener("click", () =>
        moveDisclosureToTrash(e, deleteButton)
      );
      actionContainer.appendChild(deleteButton);
      tbody.appendChild(tr);

      const details = document.createElement("tr");
      details.className = "details-row";
      const artifacts = (e.artifacts || [])
        .map((artifact) => disclosureArtifactLinkHtml(e, artifact))
        .filter(Boolean)
        .join(" · ");
      details.innerHTML =
        `<td colspan="8"><details><summary>details</summary>` +
        `<div class="kv">${escapeHtml(e.summary) || "—"}</div>` +
        `<div class="kv">Location: ${escapeHtml(e.location) || "—"}</div>` +
        `<div class="kv">Trigger: ${escapeHtml(e.trigger) || "—"}</div>` +
        `<div class="kv">Repo: ${externalLinkHtml(e.repo_url, e.repo_url) || "—"} · ` +
        `backend: ${escapeHtml(e.model_backend) || "legacy record (not recorded)"}</div>` +
        `<div class="kv">Artifacts: ${artifacts || "—"}</div>` +
        `</details></td>`;
      tbody.appendChild(details);
    }
    if (entries.length === 0) {
      tbody.innerHTML = search
        ? `<tr><td colspan="8" class="dim">No disclosures match “${escapeHtml(search)}”.</td></tr>`
        : disclosureFilter || project
          ? `<tr><td colspan="8" class="dim">No disclosures match the selected filters.</td></tr>`
          : `<tr><td colspan="8" class="dim">No Disclosure records are available yet.</td></tr>`;
    }
    wireTerminalButtons($("view-disclosures"));
  } catch (err) {
    if (sequence !== disclosureLoadSequence) return;
    $("disclosure-count").textContent = "Unavailable";
    tbody.innerHTML =
      `<tr><td colspan="8" class="error">Failed to load: ` +
      `${escapeHtml(String(err))}</td></tr>`;
  }
}

function disclosureArtifactLinkHtml(entry, artifact) {
  if (!Number.isInteger(artifact.index) || !artifact.label) return "";
  const url = disclosureArtifactUrl(entry, artifact);
  if (!url) return "";
  return (
    `<a href="${escapeHtml(url)}" ` +
    `target="_blank" rel="noopener noreferrer">${escapeHtml(artifact.label)}</a>`
  );
}

function renderDisclosureChips(counts) {
  const box = $("disclosure-chips");
  box.innerHTML = "";
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const all = [["", `all ${total}`], ...DISCLOSED_STATUSES.map((s) => [s, `${s} ${counts[s] || 0}`])];
  for (const [value, label] of all) {
    const btn = document.createElement("button");
    btn.className = "chip" + (disclosureFilter === value ? " chip-active" : "");
    btn.textContent = label;
    btn.addEventListener("click", () => {
      disclosureFilter = value;
      loadDisclosures();
    });
    box.appendChild(btn);
  }
}

function renderProjectOptions(projects) {
  const select = $("disclosure-project");
  const current = select.value;
  select.innerHTML = `<option value="">All projects</option>`;
  for (const p of projects) {
    const opt = document.createElement("option");
    opt.value = p;
    opt.textContent = p;
    if (p === current) opt.selected = true;
    select.appendChild(opt);
  }
}

$("disclosure-project").addEventListener("change", loadDisclosures);

$("disclosure-search").addEventListener("input", () => {
  clearTimeout(disclosureSearchTimer);
  disclosureSearchTimer = setTimeout(loadDisclosures, 220);
});

$("disclosure-search").addEventListener("search", () => {
  clearTimeout(disclosureSearchTimer);
  loadDisclosures();
});

async function changeDisclosureStatus(project, dedupeKey, status) {
  try {
    const res = await fetch("/api/disclosures/status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ project, dedupe_key: dedupeKey, status }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      $("disclosures-msg").textContent = err.detail || `Update failed (HTTP ${res.status})`;
    }
  } catch (e) {
    $("disclosures-msg").textContent = `Update failed: ${e}`;
  }
  await loadDisclosures();
}

async function moveDisclosureToTrash(entry, button) {
  const title = entry.title || entry.dedupe_key;
  if (!window.confirm(
    `Move “${title}” to the recycle bin? After 30 days, the record and its linked Stage 6 disclosure artifacts will be permanently deleted. Stage 5 PoC files will be retained.`
  )) return;
  button.disabled = true;
  try {
    const res = await fetch("/api/disclosures/trash", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project: entry.project,
        dedupe_key: entry.dedupe_key,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    $("disclosures-msg").textContent =
      `Moved “${title}” to the recycle bin for ${data.retention_days || 30} days.`;
    await Promise.all([loadDisclosures(), loadTrash()]);
  } catch (error) {
    $("disclosures-msg").textContent =
      `Delete failed: ${error.message || error}`;
    button.disabled = false;
  }
}

// ── Disclosure recycle bin ────────────────────────────────────────────────
function updateTrashNavigation(total) {
  const count = $("trash-nav-count");
  count.textContent = String(total || 0);
  count.hidden = !total;
}

function renderTrashProjectOptions(projects) {
  const select = $("trash-project");
  const current = select.value;
  select.innerHTML = `<option value="">All projects</option>`;
  for (const project of projects) {
    const option = document.createElement("option");
    option.value = project;
    option.textContent = project;
    option.selected = project === current;
    select.appendChild(option);
  }
}

function trashDeadline(entry) {
  const seconds = Math.max(0, Number(entry.purge_at || 0) - Date.now() / 1000);
  const days = Math.ceil(seconds / 86400);
  return `${fmtTime(entry.purge_at)} · ${days} day${days === 1 ? "" : "s"} left`;
}

async function loadTrash() {
  const sequence = ++trashLoadSequence;
  const project = $("trash-project").value;
  const search = $("trash-search").value.trim();
  const params = new URLSearchParams();
  if (project) params.set("project", project);
  if (search) params.set("q", search);
  const tbody = document.querySelector("#trash-table tbody");
  tbody.innerHTML = "";
  try {
    const res = await fetch(`/api/disclosures/trash?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (sequence !== trashLoadSequence) return;
    const entries = data.entries || [];
    updateTrashNavigation(data.total || 0);
    renderTrashProjectOptions(data.projects || []);
    $("trash-count").textContent = search || project
      ? `${data.matches || 0} of ${data.total || 0} records`
      : `${data.total || 0} record${data.total === 1 ? "" : "s"}`;
    for (const entry of entries) {
      const row = document.createElement("tr");
      row.className = "record-row";
      row.innerHTML =
        `<td class="date-cell">${escapeHtml(fmtTime(entry.deleted_at))}</td>` +
        `<td class="date-cell">${escapeHtml(trashDeadline(entry))}</td>` +
        `<td class="project-cell">${escapeHtml(entry.project)}</td>` +
        `<td class="title-cell">${escapeHtml(entry.title) || "—"}</td>` +
        `<td><span class="badge badge-disc-${escapeHtml(entry.review_status)}">` +
        `${escapeHtml(entry.review_status)}</span></td>` +
        `<td class="action-cell"><div class="row-actions"></div></td>`;
      const restore = document.createElement("button");
      restore.type = "button";
      restore.className = "btn btn-restore";
      restore.textContent = "Restore";
      restore.setAttribute(
        "aria-label",
        `Restore ${entry.title || entry.dedupe_key}`
      );
      restore.addEventListener("click", () => restoreDisclosure(entry, restore));
      row.querySelector(".row-actions").appendChild(restore);
      tbody.appendChild(row);
    }
    if (entries.length === 0) {
      tbody.innerHTML = search || project
        ? `<tr><td colspan="6" class="dim">No deleted disclosures match the selected filters.</td></tr>`
        : `<tr><td colspan="6" class="dim">The recycle bin is empty.</td></tr>`;
    }
  } catch (error) {
    if (sequence !== trashLoadSequence) return;
    $("trash-count").textContent = "Unavailable";
    tbody.innerHTML =
      `<tr><td colspan="6" class="error">Failed to load: ` +
      `${escapeHtml(String(error))}</td></tr>`;
  }
}

async function restoreDisclosure(entry, button) {
  button.disabled = true;
  try {
    const res = await fetch("/api/disclosures/restore", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        project: entry.project,
        dedupe_key: entry.dedupe_key,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    $("trash-msg").textContent = `Restored “${entry.title || entry.dedupe_key}”.`;
    await Promise.all([loadTrash(), loadDisclosures()]);
  } catch (error) {
    $("trash-msg").textContent =
      `Restore failed: ${error.message || error}`;
    button.disabled = false;
  }
}

async function refreshTrashCount() {
  try {
    const res = await fetch("/api/disclosures/trash");
    if (!res.ok) return;
    const data = await res.json();
    updateTrashNavigation(data.total || 0);
  } catch {
    // The full recycle-bin view reports detailed errors when opened.
  }
}

$("trash-project").addEventListener("change", loadTrash);
$("trash-search").addEventListener("input", () => {
  clearTimeout(trashSearchTimer);
  trashSearchTimer = setTimeout(loadTrash, 220);
});
$("trash-search").addEventListener("search", () => {
  clearTimeout(trashSearchTimer);
  loadTrash();
});

async function openDisclosureEditDialog(entry) {
  const sequence = ++disclosureEditSequence;
  disclosureEditingEntry = entry;
  disclosureCvesReady = entry.review_status !== "confirmed";
  $("disclosure-edit-identity").textContent =
    `${entry.project} · ${entry.dedupe_key}`;
  $("disclosure-edit-field-title").value = entry.title || "";
  $("disclosure-edit-field-cwe").value = entry.cwe || "";
  $("disclosure-edit-field-location").value = entry.location || "";
  $("disclosure-edit-field-vulnerability-class").value =
    entry.vulnerability_class || "";
  $("disclosure-edit-field-trigger").value = entry.trigger || "";
  $("disclosure-edit-field-summary").value = entry.summary || "";
  $("disclosure-edit-field-repo-url").value = entry.repo_url || "";
  $("disclosure-edit-field-commit").value = entry.audited_commit || "";
  $("disclosure-edit-field-audit-date").value =
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(entry.audit_finished_date || "")
      ? entry.audit_finished_date
      : "";
  $("disclosure-edit-field-backend").value = entry.model_backend || "";
  $("disclosure-edit-message").textContent = "";
  const cveField = $("disclosure-edit-cves-field");
  const cveSelect = $("disclosure-edit-cves");
  const submit = $("btn-disclosure-edit-submit");
  cveField.hidden = entry.review_status !== "confirmed";
  cveSelect.innerHTML = "";
  submit.disabled = entry.review_status === "confirmed";
  const dialog = $("disclosure-edit-dialog");
  if (!dialog.open) dialog.showModal();
  if (entry.review_status !== "confirmed") return;

  $("disclosure-edit-message").textContent = "Loading project CVEs…";
  try {
    const params = new URLSearchParams({ project: entry.project });
    const res = await fetch(`/api/cves?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (sequence !== disclosureEditSequence || disclosureEditingEntry !== entry) {
      return;
    }
    const selectedIds = new Set((entry.cves || []).map((cve) => cve.cve_id));
    const available = data.entries || [];
    const availableIds = new Set(available.map((cve) => cve.cve_id));
    for (const cve of available) {
      const option = document.createElement("option");
      option.value = cve.cve_id;
      option.textContent =
        `${cve.cve_id} · ${cve.cvss_score ?? "no CVSS"} · ${cve.severity || "unrated"}`;
      option.selected = selectedIds.has(cve.cve_id);
      cveSelect.appendChild(option);
    }
    for (const cve of entry.cves || []) {
      if (availableIds.has(cve.cve_id)) continue;
      const option = document.createElement("option");
      option.value = cve.cve_id;
      option.textContent = `${cve.cve_id} · current association`;
      option.selected = true;
      cveSelect.appendChild(option);
    }
    disclosureCvesReady = true;
    submit.disabled = false;
    $("disclosure-edit-message").textContent =
      `${cveSelect.options.length} project CVEs available.`;
  } catch (error) {
    if (sequence !== disclosureEditSequence) return;
    $("disclosure-edit-message").textContent =
      `Failed to load CVEs: ${error.message || error}`;
    submit.disabled = true;
  }
}

$("btn-disclosure-edit-cancel").addEventListener("click", () => {
  disclosureEditSequence += 1;
  $("disclosure-edit-dialog").close();
  disclosureEditingEntry = null;
  disclosureCvesReady = false;
});

$("disclosure-edit-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!disclosureEditingEntry) return;
  const message = $("disclosure-edit-message");
  if (disclosureEditingEntry.review_status === "confirmed" && !disclosureCvesReady) {
    message.textContent = "Wait for the project CVE list to finish loading.";
    return;
  }
  const payload = {
    project: disclosureEditingEntry.project,
    dedupe_key: disclosureEditingEntry.dedupe_key,
    title: $("disclosure-edit-field-title").value,
    cwe: $("disclosure-edit-field-cwe").value,
    location: $("disclosure-edit-field-location").value,
    vulnerability_class: $("disclosure-edit-field-vulnerability-class").value,
    trigger: $("disclosure-edit-field-trigger").value,
    summary: $("disclosure-edit-field-summary").value,
    repo_url: $("disclosure-edit-field-repo-url").value,
    audited_commit: $("disclosure-edit-field-commit").value,
    audit_finished_date: $("disclosure-edit-field-audit-date").value,
    model_backend: $("disclosure-edit-field-backend").value,
  };
  if (disclosureEditingEntry.review_status === "confirmed") {
    payload.cve_ids = [...$("disclosure-edit-cves").selectedOptions].map(
      (option) => option.value
    );
  }
  message.textContent = "Saving…";
  try {
    const res = await fetch("/api/disclosures", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    $("disclosure-edit-dialog").close();
    disclosureEditingEntry = null;
    disclosureCvesReady = false;
    $("disclosures-msg").textContent = "Disclosure updated.";
    await Promise.all([loadDisclosures(), loadCves()]);
  } catch (error) {
    message.textContent = `Update failed: ${error.message || error}`;
  }
});

// ── CVE catalogue ──────────────────────────────────────────────────────────
async function loadCves() {
  const sequence = ++cveLoadSequence;
  const project = $("cve-project").value;
  const params = new URLSearchParams();
  if (project) params.set("project", project);
  const tbody = document.querySelector("#cves-table tbody");
  tbody.innerHTML = "";
  try {
    const res = await fetch(`/api/cves?${params}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (sequence !== cveLoadSequence) return;
    renderCveProjectOptions(data.projects || []);
    const entries = sortedTableEntries(data.entries || [], cveSort, cveSortValue);
    updateSortIndicators("cves-table", cveSort);
    $("cve-count").textContent =
      `${entries.length} local CVE${entries.length === 1 ? "" : "s"}`;
    for (const cve of entries) {
      const publicLinks = [
        externalLinkHtml("CVE record", cve.cve_url),
        ...(cve.references || []).map((reference) =>
          externalLinkHtml(reference.label, reference.url)
        ),
      ].filter(Boolean);
      const disclosures = (cve.local_disclosures || [])
        .map(
          (entry) =>
            `<a href="#/disclosures" class="related-run-link" ` +
            `title="${escapeHtml(entry.title || "Local Disclosure")}">` +
            `${escapeHtml(entry.review_status || "local")} Disclosure</a>`
        )
        .join("");
      const terminals = (cve.pocs || [])
        .map(
          (poc) =>
            `<span class="cve-poc">Run #${escapeHtml(poc.run_id)} / ` +
            `${escapeHtml(poc.vuln_id)} ${terminalButtonHtml(poc.run_id, poc.vuln_id, poc.title)}</span>`
        )
        .join("");
      const local = [disclosures, terminals].filter(Boolean).join("") || "—";
      const tr = document.createElement("tr");
      tr.className = "record-row";
      tr.innerHTML =
        `<td class="identity-cell">${externalLinkHtml(cve.cve_id, cve.cve_url)}</td>` +
        `<td class="project-cell">${externalLinkHtml(cve.project, cve.project_url) || escapeHtml(cve.project)}</td>` +
        `<td class="numeric-cell">${escapeHtml(cve.cvss_score ?? "/")}</td>` +
        `<td class="identity-cell"><span class="sev-badge sev-${escapeHtml(cve.severity || "unknown")}">` +
        `${escapeHtml(cve.severity || "/")}</span></td>` +
        `<td><div class="table-link-list">${publicLinks.join("") || "—"}</div></td>` +
        `<td><div class="table-link-list table-link-list-local">${local}</div></td>` +
        `<td class="action-cell"><div class="row-actions"></div></td>`;
      const actionContainer = tr.querySelector(".row-actions");
      appendEvidenceActionButtons(
        actionContainer,
        cve.local_disclosures || [],
        cve.cve_id
      );
      const editButton = document.createElement("button");
      editButton.type = "button";
      editButton.className = "btn btn-edit";
      editButton.textContent = "Edit";
      editButton.setAttribute("aria-label", `Edit ${cve.cve_id}`);
      editButton.addEventListener("click", () => openCveDialog(cve));
      actionContainer.appendChild(editButton);
      tbody.appendChild(tr);
    }
    if (entries.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="dim">No CVEs match this project.</td></tr>`;
    }
    wireTerminalButtons($("view-cves"));
  } catch (err) {
    if (sequence !== cveLoadSequence) return;
    tbody.innerHTML =
      `<tr><td colspan="7" class="error">Failed to load CVEs: ` +
      `${escapeHtml(String(err))}</td></tr>`;
  }
}

function renderCveProjectOptions(projects) {
  const select = $("cve-project");
  const current = select.value;
  select.innerHTML = `<option value="">All projects</option>`;
  for (const project of projects) {
    const option = document.createElement("option");
    option.value = project;
    option.textContent = project;
    if (project === current) option.selected = true;
    select.appendChild(option);
  }
}

$("cve-project").addEventListener("change", loadCves);

wireSortableTable("disclosures-table", disclosureSort, loadDisclosures);
wireSortableTable("cves-table", cveSort, loadCves);

function addCveReferenceRow(reference = {}) {
  const row = document.createElement("div");
  row.className = "cve-reference-row";
  row.innerHTML =
    `<label>Label<input class="cve-reference-label" maxlength="256" ` +
    `placeholder="Upstream advisory"></label>` +
    `<label>URL<input class="cve-reference-url" type="url" maxlength="2048" ` +
    `placeholder="https://example.org/advisory"></label>` +
    `<button type="button" class="btn btn-compact cve-reference-remove">Remove</button>`;
  row.querySelector(".cve-reference-label").value = reference.label || "";
  row.querySelector(".cve-reference-url").value = reference.url || "";
  row.querySelector(".cve-reference-remove").addEventListener("click", () =>
    row.remove()
  );
  $("cve-reference-list").appendChild(row);
}

function renderCveReferenceRows(references) {
  $("cve-reference-list").innerHTML = "";
  for (const reference of references.length ? references : [{}]) {
    addCveReferenceRow(reference);
  }
}

function collectCveReferences() {
  const references = [];
  for (const row of $("cve-reference-list").querySelectorAll(".cve-reference-row")) {
    const label = row.querySelector(".cve-reference-label").value.trim();
    const url = row.querySelector(".cve-reference-url").value.trim();
    if (!label && !url) continue;
    if (!label || !url) {
      throw new Error("Each disclosure site needs both a label and URL.");
    }
    references.push({ label, url });
  }
  return references;
}

async function openCveDialog(cve = null) {
  cveDialogMode = cve ? "edit" : "import";
  cveEditingId = cve?.cve_id || "";
  const message = $("cve-import-message");
  const select = $("cve-disclosures");
  const dialog = $("cve-import-dialog");
  const submit = $("btn-cve-import-submit");
  $("cve-import-form").reset();
  $("cve-import-title").textContent = cve ? "Edit CVE" : "Import CVE";
  submit.textContent = cve ? "Save changes" : "Import";
  submit.disabled = true;
  $("cve-id").readOnly = Boolean(cve);
  if (cve) {
    $("cve-id").value = cve.cve_id || "";
    $("cve-score").value = cve.cvss_score ?? "";
    $("cve-severity").value = cve.severity || "";
    $("cve-url").value = cve.cve_url || "";
    $("cve-project-url").value = cve.project_url || "";
  }
  renderCveReferenceRows(cve?.references || []);
  if (!dialog.open) dialog.showModal();
  message.textContent = "Loading local Disclosure reports…";
  select.innerHTML = "";
  try {
    const res = await fetch("/api/cves/candidates");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    cveImportCandidates = data.entries || [];
    for (const entry of cveImportCandidates) {
      const option = document.createElement("option");
      option.value = entry.dedupe_key;
      option.textContent =
        `${entry.project} · ${entry.review_status} · ${entry.title || entry.dedupe_key}`;
      if (cve?.dedupe_keys?.includes(entry.dedupe_key)) option.selected = true;
      select.appendChild(option);
    }
    message.textContent = cveImportCandidates.length
      ? `${cveImportCandidates.length} local reports available.`
      : "No local Stage 6 Disclosure reports are available.";
    submit.disabled = cveImportCandidates.length === 0;
  } catch (error) {
    message.textContent = `Failed to load Disclosure reports: ${error}`;
    submit.disabled = true;
  }
}

function updateCveProjectUrl() {
  const selectedKeys = new Set(
    [...$("cve-disclosures").selectedOptions].map((option) => option.value)
  );
  const selected = cveImportCandidates.filter((entry) =>
    selectedKeys.has(entry.dedupe_key)
  );
  const urls = [...new Set(selected.map((entry) => entry.repo_url).filter(Boolean))];
  if (urls.length === 1 && !$("cve-project-url").value) {
    $("cve-project-url").value = urls[0];
  }
}

$("btn-cve-import").addEventListener("click", () => openCveDialog());
$("btn-cve-import-cancel").addEventListener("click", () => {
  $("cve-import-dialog").close();
  cveDialogMode = "import";
  cveEditingId = "";
});
$("btn-cve-reference-add").addEventListener("click", () => addCveReferenceRow());
$("cve-disclosures").addEventListener("change", updateCveProjectUrl);
$("cve-id").addEventListener("blur", () => {
  const cveId = $("cve-id").value.trim().toUpperCase();
  $("cve-id").value = cveId;
  if (/^CVE-[0-9]{4}-[0-9]{4,}$/.test(cveId) && !$("cve-url").value) {
    $("cve-url").value = `https://www.cve.org/CVERecord?id=${cveId}`;
  }
});

$("cve-import-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const message = $("cve-import-message");
  const dedupeKeys = [...$("cve-disclosures").selectedOptions].map(
    (option) => option.value
  );
  if (!dedupeKeys.length) {
    message.textContent = "Select at least one local Disclosure report.";
    return;
  }
  const scoreText = $("cve-score").value.trim();
  let references;
  try {
    references = collectCveReferences();
  } catch (error) {
    message.textContent = error.message || String(error);
    return;
  }
  const payload = {
    cve_id: $("cve-id").value.trim(),
    dedupe_keys: dedupeKeys,
    cvss_score: scoreText === "" ? null : Number(scoreText),
    severity: $("cve-severity").value,
    cve_url: $("cve-url").value.trim(),
    project_url: $("cve-project-url").value.trim(),
    references,
  };
  const editing = cveDialogMode === "edit";
  message.textContent = editing ? "Saving…" : "Importing…";
  try {
    const endpoint = editing
      ? `/api/cves/${encodeURIComponent(cveEditingId)}`
      : "/api/cves";
    const res = await fetch(endpoint, {
      method: editing ? "PUT" : "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    $("cve-import-dialog").close();
    $("cve-import-form").reset();
    cveDialogMode = "import";
    cveEditingId = "";
    await Promise.all([loadCves(), loadDisclosures()]);
  } catch (error) {
    message.textContent = `${editing ? "Update" : "Import"} failed: ${error.message || error}`;
  }
});

function externalLinkHtml(label, url) {
  try {
    const parsed = new URL(String(url || ""));
    if (!['https:', 'http:'].includes(parsed.protocol)) return "";
    return (
      `<a href="${escapeHtml(parsed.href)}" target="_blank" rel="noopener noreferrer">` +
      `${escapeHtml(label)}</a>`
    );
  } catch {
    return "";
  }
}

// ── Interactive PoC terminal tabs ─────────────────────────────────────────
function terminalButtonHtml(runId, vulnId, title) {
  return (
    `<button type="button" class="btn btn-terminal poc-terminal-button" ` +
    `data-terminal-run="${escapeHtml(runId)}" ` +
    `data-terminal-vuln="${escapeHtml(vulnId)}" ` +
    `data-terminal-title="${escapeHtml(title || vulnId)}">Terminal</button>`
  );
}

function disclosureTerminalButtonHtml(entry) {
  const terminal = entry.terminal || {};
  return (
    `<button type="button" class="btn btn-terminal poc-terminal-button" ` +
    `data-terminal-project="${escapeHtml(entry.project)}" ` +
    `data-terminal-dedupe="${escapeHtml(entry.dedupe_key)}" ` +
    `data-terminal-vuln="${escapeHtml(terminal.vuln_id)}" ` +
    `data-terminal-title="${escapeHtml(terminal.title || entry.title || terminal.vuln_id)}">` +
    `Terminal</button>`
  );
}

function wireTerminalButtons(root) {
  root.querySelectorAll(".poc-terminal-button:not([data-wired])").forEach((button) => {
    button.dataset.wired = "true";
    button.addEventListener("click", () =>
      openPocTerminal(
        Number(button.dataset.terminalRun || 0),
        button.dataset.terminalVuln,
        button.dataset.terminalTitle,
        button.dataset.terminalProject || "",
        button.dataset.terminalDedupe || ""
      )
    );
  });
}

function showTerminalDock() {
  const dock = $("terminal-dock");
  const splitter = $("terminal-splitter");
  dock.hidden = false;
  splitter.hidden = false;
  requestAnimationFrame(() => clampTerminalDockHeight());
}

function hideTerminalDock() {
  $("terminal-dock").hidden = true;
  $("terminal-splitter").hidden = true;
}

function setTerminalDockHeight(requestedHeight) {
  const workspace = $("workspace");
  const dock = $("terminal-dock");
  const splitter = $("terminal-splitter");
  const shortViewport = workspace.clientHeight <= 600;
  const minHeight = matchMedia("(max-width: 760px)").matches ? 180 : 200;
  const minContentHeight = shortViewport
    ? 160
    : (matchMedia("(max-width: 760px)").matches ? 180 : 220);
  const maxHeight = Math.max(
    minHeight,
    workspace.clientHeight - minContentHeight - splitter.offsetHeight
  );
  const height = Math.min(maxHeight, Math.max(minHeight, requestedHeight));
  dock.style.height = `${Math.round(height)}px`;
  splitter.setAttribute("aria-valuemax", String(Math.round(maxHeight)));
  splitter.setAttribute("aria-valuenow", String(Math.round(height)));
  return height;
}

function clampTerminalDockHeight() {
  const dock = $("terminal-dock");
  if (dock.hidden) return;
  setTerminalDockHeight(dock.getBoundingClientRect().height);
}

function setupTerminalSplitter() {
  const splitter = $("terminal-splitter");
  const dock = $("terminal-dock");
  let resizeState = null;

  splitter.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    resizeState = {
      pointerId: event.pointerId,
      startY: event.clientY,
      startHeight: dock.getBoundingClientRect().height,
    };
    splitter.setPointerCapture(event.pointerId);
    document.body.classList.add("terminal-resizing");
    event.preventDefault();
  });
  splitter.addEventListener("pointermove", (event) => {
    if (!resizeState || event.pointerId !== resizeState.pointerId) return;
    setTerminalDockHeight(
      resizeState.startHeight + resizeState.startY - event.clientY
    );
  });
  const finishResize = (event) => {
    if (!resizeState || event.pointerId !== resizeState.pointerId) return;
    if (splitter.hasPointerCapture(event.pointerId)) {
      splitter.releasePointerCapture(event.pointerId);
    }
    resizeState = null;
    document.body.classList.remove("terminal-resizing");
  };
  splitter.addEventListener("pointerup", finishResize);
  splitter.addEventListener("pointercancel", finishResize);
  splitter.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowUp" && event.key !== "ArrowDown") return;
    const direction = event.key === "ArrowUp" ? 1 : -1;
    setTerminalDockHeight(dock.getBoundingClientRect().height + direction * 24);
    event.preventDefault();
  });
  window.addEventListener("resize", clampTerminalDockHeight);
}

function activatePocTerminal(sessionKey) {
  for (const [key, session] of terminalSessions) {
    const active = key === sessionKey;
    session.tab.classList.toggle("terminal-tab-active", active);
    session.tabButton.setAttribute("aria-selected", String(active));
    session.tabButton.tabIndex = active ? 0 : -1;
    session.panel.hidden = !active;
  }
  const session = terminalSessions.get(sessionKey);
  if (session) {
    requestAnimationFrame(() => {
      session.fit();
      session.term.focus();
    });
  }
}

function openPocTerminal(runId, vulnId, title, project = "", dedupeKey = "") {
  if (!terminalEnabled || !terminalToken) {
    window.alert("The server did not enable PoC terminals for this session.");
    return;
  }
  if (typeof window.Terminal !== "function") {
    window.alert("The terminal renderer could not be loaded.");
    return;
  }

  const isDisclosure = project !== "" && dedupeKey !== "";
  const sessionKey = isDisclosure
    ? `disclosure:${dedupeKey}`
    : `${runId}:${vulnId}`;
  if (terminalSessions.has(sessionKey)) {
    showTerminalDock();
    activatePocTerminal(sessionKey);
    return;
  }

  terminalSequence += 1;
  const dock = $("terminal-dock");
  const tabs = $("terminal-tabs");
  const panels = $("terminal-panels");
  const tabId = `terminal-tab-${terminalSequence}`;
  const panelId = `terminal-panel-${terminalSequence}`;
  const tab = document.createElement("div");
  tab.className = "terminal-tab";
  tab.innerHTML =
    `<button type="button" class="terminal-tab-button" id="${tabId}" role="tab" ` +
    `aria-controls="${panelId}" aria-selected="false">` +
    `<strong>${escapeHtml(vulnId)}</strong><span>${isDisclosure ? "Disclosure" : `Run #${escapeHtml(runId)}`}</span></button>` +
    `<button type="button" class="terminal-tab-close" ` +
    `aria-label="Close ${escapeHtml(vulnId)} terminal">×</button>`;
  const panel = document.createElement("article");
  panel.className = "terminal-panel";
  panel.id = panelId;
  panel.setAttribute("role", "tabpanel");
  panel.setAttribute("aria-labelledby", tabId);
  panel.hidden = true;
  panel.innerHTML =
    `<header class="terminal-session-header"><strong>${escapeHtml(title || vulnId)}</strong>` +
    `<span class="terminal-cwd">Connecting…</span></header>` +
    `<div class="terminal-host" id="terminal-${terminalSequence}"></div>`;
  tabs.appendChild(tab);
  panels.appendChild(panel);
  showTerminalDock();

  const tabButton = tab.querySelector(".terminal-tab-button");
  const host = panel.querySelector(".terminal-host");
  const cwd = panel.querySelector(".terminal-cwd");
  const term = new window.Terminal({
    cursorBlink: true,
    convertEol: false,
    scrollback: 5000,
    fontFamily: getComputedStyle(host).fontFamily,
    fontSize: 13,
    theme: {
      background: "#0d1117",
      foreground: "#e6edf3",
      cursor: "#58d6eb",
      selectionBackground: "#264f78",
    },
  });
  const fit = () => {
    if (!host.isConnected || panel.hidden) return;
    const cols = Math.max(40, Math.floor((host.clientWidth - 18) / 8));
    const rows = Math.max(5, Math.floor((host.clientHeight - 14) / 17));
    if (cols !== term.cols || rows !== term.rows) term.resize(cols, rows);
  };
  const session = { tab, tabButton, panel, term, fit, close: null };
  terminalSessions.set(sessionKey, session);
  activatePocTerminal(sessionKey);
  term.open(host);
  fit();
  const observer = new ResizeObserver(fit);
  observer.observe(host);

  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const socketUrl = isDisclosure
    ? `${scheme}://${location.host}/ws/disclosure-terminal?${new URLSearchParams({
        project,
        dedupe_key: dedupeKey,
        token: terminalToken,
      })}`
    : `${scheme}://${location.host}/ws/terminal/${encodeURIComponent(runId)}/` +
      `${encodeURIComponent(vulnId)}?token=${encodeURIComponent(terminalToken)}`;
  const socket = new WebSocket(socketUrl);
  socket.binaryType = "arraybuffer";
  socket.addEventListener("open", () => {
    socket.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
  });
  socket.addEventListener("message", (event) => {
    if (typeof event.data === "string") {
      try {
        const message = JSON.parse(event.data);
        if (message.type === "ready") {
          cwd.textContent = message.cwd;
          tab.title = message.cwd;
          if (!panel.hidden) term.focus();
        } else if (message.type === "error") {
          term.writeln(`\r\n[terminal error: ${message.detail}]`);
        }
      } catch {
        term.write(event.data);
      }
      return;
    }
    term.write(new Uint8Array(event.data));
  });
  socket.addEventListener("close", (event) => {
    cwd.textContent = event.code === 1000 ? "Session closed" : `Session closed (${event.code})`;
    term.options.cursorBlink = false;
  });
  socket.addEventListener("error", () => {
    term.writeln("\r\n[terminal connection failed]");
  });

  term.onData((data) => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "input", data }));
    }
  });
  term.onResize(({ cols, rows }) => {
    if (socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "resize", cols, rows }));
    }
  });

  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    const order = [...terminalSessions.keys()];
    const index = order.indexOf(sessionKey);
    const nextKey = order[index + 1] || order[index - 1] || "";
    observer.disconnect();
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) {
      socket.close(1000, "Closed by user");
    }
    term.dispose();
    terminalSessions.delete(sessionKey);
    tab.remove();
    panel.remove();
    if (terminalSessions.size === 0) {
      hideTerminalDock();
    } else if (nextKey) {
      activatePocTerminal(nextKey);
    }
  };
  tabButton.addEventListener("click", () => activatePocTerminal(sessionKey));
  tab.querySelector(".terminal-tab-close").addEventListener("click", close);
  session.close = close;
}

$("btn-terminal-dock-close").addEventListener("click", () => {
  [...terminalSessions.values()].forEach((session) => session.close());
});
setupTerminalSplitter();

// ── Hash routing ────────────────────────────────────────────────────────────
function route() {
  const hash = location.hash || "#/";
  const runMatch = hash.match(/^#\/run\/(\d+)$/);
  const targetMatch = hash.match(/^#\/target\/(.+)$/);
  const views = {
    new: $("view-new"),
    history: $("view-history"),
    reproduction: $("view-reproduction"),
    detail: $("view-run-detail"),
    disclosures: $("view-disclosures"),
    trash: $("view-trash"),
    cves: $("view-cves"),
    target: $("view-target"),
  };
  const tabs = document.querySelectorAll("#tabs .tab");

  for (const v of Object.values(views)) v.hidden = true;
  tabs.forEach((t) => t.classList.remove("tab-active"));

  if (runMatch) {
    views.detail.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "history") t.classList.add("tab-active");
    });
    loadRunDetail(runMatch[1]);
  } else if (targetMatch) {
    views.target.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "history") t.classList.add("tab-active");
    });
    loadTargetView(decodeURIComponent(targetMatch[1]));
  } else if (hash.startsWith("#/reproduction")) {
    views.reproduction.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "reproduction") t.classList.add("tab-active");
    });
    loadReproductionCandidates();
  } else if (hash.startsWith("#/disclosures")) {
    views.disclosures.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "disclosures") t.classList.add("tab-active");
    });
    loadDisclosures();
  } else if (hash.startsWith("#/trash")) {
    views.trash.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "trash") t.classList.add("tab-active");
    });
    loadTrash();
  } else if (hash.startsWith("#/cves")) {
    views.cves.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "cves") t.classList.add("tab-active");
    });
    loadCves();
  } else if (hash.startsWith("#/history")) {
    views.history.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "history") t.classList.add("tab-active");
    });
    loadHistory();
  } else {
    views.new.hidden = false;
    tabs.forEach((t) => {
      if (t.dataset.route === "new") t.classList.add("tab-active");
    });
  }
}

window.addEventListener("hashchange", route);

// ── Boot ────────────────────────────────────────────────────────────────────
async function boot() {
  resetStages();
  resetReproductionStage();
  route();
  await loadConfig();
  await Promise.all([loadRepos(), loadWikis(), refreshTrashCount()]);
  try {
    const res = await fetch("/api/audit/status");
    const status = await res.json();
    if (status.state && status.state !== "idle") {
      setJobState(status.state, status.error, status.kind || "audit");
      for (const s of status.stages || []) {
        if (s.status === "done") {
          rememberCompletedStage(status.kind || "audit", s.stage);
        }
        if (status.kind === "reproduction" && s.stage === 5) {
          updateReproductionStage(s.status, s.detail);
          updateReproductionProgress(s.items_done, s.items_total);
        } else {
          updateStage(s.stage, s.status, s.detail);
          updateProgress(s.stage, s.items_done, s.items_total);
        }
      }
    }
  } catch {
    // server not reachable yet; SSE connect will retry
  }
  connectEvents();
  window.setInterval(pollAuditHeartbeat, 10000);
}

boot();
