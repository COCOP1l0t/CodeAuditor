import fs from "node:fs/promises";
import path from "node:path";

import { runAgent } from "../agents/index.js";
import { CheckpointManager } from "../checkpoint.js";
import type { AuditConfig } from "../config.js";
import { getLogger } from "../logger.js";
import { loadPrompt } from "../prompts.js";
import {
  coerceError,
  compareSeverityThenId,
  formatValidationIssues,
  listMarkdownFiles,
  pathExists,
  runParallelLimited,
} from "../utils.js";
import { stripCodeFence, stripJsonComments } from "../validation/common.js";
import { validateStage4File } from "../validation/stage4.js";

const logger = getLogger("stage4");

type Severity = "Critical" | "High" | "Medium" | "Low";

const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];
const SEVERITY_PREFIX: Record<Severity, string> = {
  Critical: "C",
  High: "H",
  Medium: "M",
  Low: "L",
};
const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);

function taskKey(stage3Filename: string): string {
  return `stage4:${stage3Filename}`;
}

async function readSeverityFromPending(filePath: string): Promise<string | null> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const match = /###\s*Summary JSON Line\s*\n([\s\S]*?)(?=###\s*Detail|$)/.exec(content);
    if (!match) {
      return null;
    }
    const summary = JSON.parse(stripJsonComments(stripCodeFence((match[1] ?? "").trim()))) as {
      severity?: string;
    };
    return summary.severity ?? null;
  } catch (error) {
    logger.warning("Failed to read severity from %s: %s", filePath, coerceError(error).message);
    return null;
  }
}

async function readExistingId(filePath: string): Promise<string | null> {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const match = /"id"\s*:\s*"([A-Z]-\d+)"/.exec(content);
    return match?.[1] ?? null;
  } catch {
    return null;
  }
}

function normalizeSeverity(value: string): Severity | null {
  switch (value.toLowerCase()) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return null;
  }
}

async function injectIdIntoFile(filePath: string, realId: string): Promise<void> {
  const content = await fs.readFile(filePath, "utf8");
  const updated = content
    .replace(/"id"\s*:\s*"TBD"/, `"id": "${realId}"`)
    .replace(/\*\*ID\*\*\s*:\s*TBD/, `**ID**: ${realId}`);
  await fs.writeFile(filePath, updated);
}

async function listExistingFinalFiles(stage4Dir: string): Promise<string[]> {
  const files = await listMarkdownFiles(stage4Dir);
  return files.filter((filePath) => path.basename(filePath) !== "_pending");
}

async function runFinding(
  stage3FilePath: string,
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<string | null> {
  const stage3Filename = path.basename(stage3FilePath);
  const key = taskKey(stage3Filename);
  const pendingDir = path.join(config.outputDir, "stage-4-details", "_pending");
  const pendingPath = path.join(pendingDir, stage3Filename);

  if (checkpoint.isComplete(key)) {
    logger.info("Stage 4: %s already complete, skipping.", stage3Filename);
    return (await pathExists(pendingPath)) ? pendingPath : null;
  }

  const prompt = await loadPrompt("stage4.md", {
    finding_file_path: stage3FilePath,
    output_path: pendingPath,
  });

  await runAgent({
    prompt,
    config,
    cwd: config.target,
  });

  const confirmed = await pathExists(pendingPath);
  if (confirmed) {
    let issues = validateStage4File(pendingPath);
    if (issues.length > 0) {
      logger.warning("Stage 4: Validation failed for %s\n%s", pendingPath, formatValidationIssues(issues));
      const repairPrompt =
        `The evaluation file at \`${pendingPath}\` failed validation. ` +
        `Please fix all issues below:\n\n\`\`\`\n${formatValidationIssues(issues)}\n\`\`\``;
      await runAgent({
        prompt: repairPrompt,
        config,
        cwd: config.target,
        maxTurns: 10,
      });
      issues = validateStage4File(pendingPath);
      if (issues.length > 0) {
        logger.warning("Stage 4: Repair failed for %s\n%s", pendingPath, formatValidationIssues(issues));
      }
    }
  }

  checkpoint.markComplete(key);
  logger.info("Stage 4: %s complete (confirmed=%s)", stage3Filename, confirmed);
  return confirmed ? pendingPath : null;
}

async function assignIdsAndFinalize(pendingPaths: string[], config: AuditConfig): Promise<string[]> {
  const stage4Dir = path.join(config.outputDir, "stage-4-details");
  const existingFinalFiles = await listExistingFinalFiles(stage4Dir);

  const counters: Record<string, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  for (const filePath of existingFinalFiles) {
    const existingId = await readExistingId(filePath);
    if (!existingId) {
      continue;
    }
    const [prefix, numberText] = existingId.split("-");
    const severity = Object.entries(SEVERITY_PREFIX).find(([, value]) => value === prefix)?.[0];
    if (!severity) {
      continue;
    }
    const severityKey = severity as Severity;
    const currentCount = counters[severityKey] ?? 0;
    counters[severityKey] = Math.max(currentCount, Number(numberText ?? "0"));
  }

  const findings: Array<{ pendingPath: string; severity: Severity }> = [];
  for (const pendingPath of pendingPaths) {
    const severity = await readSeverityFromPending(pendingPath);
    if (severity && VALID_SEVERITIES.has(severity.toLowerCase())) {
      const normalizedSeverity = normalizeSeverity(severity);
      if (normalizedSeverity) {
        findings.push({ pendingPath, severity: normalizedSeverity });
      }
    } else {
      logger.warning("Stage 4: Skipping %s because severity could not be read.", path.basename(pendingPath));
    }
  }

  findings.sort((left, right) => {
    return SEVERITY_ORDER.indexOf(left.severity) - SEVERITY_ORDER.indexOf(right.severity);
  });

  const finalized: string[] = [...existingFinalFiles];
  for (const finding of findings) {
    const nextCount = (counters[finding.severity] ?? 0) + 1;
    counters[finding.severity] = nextCount;
    const realId = `${SEVERITY_PREFIX[finding.severity]}-${String(nextCount).padStart(2, "0")}`;
    const finalPath = path.join(stage4Dir, `${realId}.md`);
    await fs.rename(finding.pendingPath, finalPath);
    await injectIdIntoFile(finalPath, realId);
    finalized.push(finalPath);
    logger.info("Stage 4: Assigned %s to %s", realId, path.basename(finding.pendingPath));
  }

  return finalized.sort(compareSeverityThenId);
}

export async function runStage4(
  findingFiles: string[],
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<string[]> {
  if (findingFiles.length === 0) {
    logger.info("Stage 4: No findings to evaluate.");
    return await listExistingFinalFiles(path.join(config.outputDir, "stage-4-details"));
  }

  const results = await runParallelLimited(findingFiles, config.maxParallel, async (findingFile) => {
    return await runFinding(findingFile, config, checkpoint);
  });

  const confirmedPending: string[] = [];
  results.forEach((result, index) => {
    const findingFile = findingFiles[index];
    if (!findingFile) {
      return;
    }
    if (result.status === "rejected") {
      logger.error("Stage 4: %s failed: %s", path.basename(findingFile), coerceError(result.reason).message);
      return;
    }
    if (result.value) {
      confirmedPending.push(result.value);
    }
  });

  logger.info(
    "Stage 4: %s confirmed findings (from %s candidates).",
    confirmedPending.length,
    findingFiles.length,
  );

  const finalPaths = await assignIdsAndFinalize(confirmedPending, config);
  logger.info("Stage 4 complete. Final findings: %s", finalPaths.length);
  return finalPaths;
}
