import fs from "node:fs/promises";
import path from "node:path";

import { runAgent } from "../agents/index.js";
import { CheckpointManager } from "../checkpoint.js";
import type { AuditConfig, EntryPoint } from "../config.js";
import { getLogger } from "../logger.js";
import { loadPrompt } from "../prompts.js";
import { REFERENCE_DIR } from "../runtime.js";
import { coerceError, formatValidationIssues, listMatchingFiles, pathExists, runParallelLimited } from "../utils.js";
import { validateStage3File } from "../validation/stage3.js";

const logger = getLogger("stage3");

function taskKey(entryPoint: EntryPoint): string {
  return `stage3:${entryPoint.moduleId}:${entryPoint.id}`;
}

async function walkSourceTree(rootDir: string): Promise<Record<string, number>> {
  const counts = { c_cpp: 0, go: 0, rust: 0, managed: 0 };

  async function walk(currentDir: string): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (
          entry.name.startsWith(".") ||
          ["vendor", "node_modules", "target", "__pycache__"].includes(entry.name)
        ) {
          continue;
        }
        await walk(fullPath);
        continue;
      }

      const extension = path.extname(entry.name).toLowerCase();
      if ([".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"].includes(extension)) {
        counts.c_cpp += 1;
      } else if (extension === ".go") {
        counts.go += 1;
      } else if (extension === ".rs") {
        counts.rust += 1;
      } else if ([".py", ".java", ".cs", ".rb", ".php"].includes(extension)) {
        counts.managed += 1;
      }
    }
  }

  await walk(rootDir);
  return counts;
}

async function detectChecklist(config: AuditConfig): Promise<string> {
  const counts = await walkSourceTree(config.target);
  const dominant = Object.entries(counts).sort((left, right) => right[1] - left[1])[0]?.[0] ?? "c_cpp";
  const checklistMap: Record<string, string> = {
    c_cpp: "checklist-c-cpp.md",
    go: "checklist-go.md",
    rust: "checklist-rust.md",
    managed: "checklist-managed.md",
  };

  const preferred = path.join(REFERENCE_DIR, checklistMap[dominant] ?? "checklist-c-cpp.md");
  if (await pathExists(preferred)) {
    return preferred;
  }

  for (const name of [
    "checklist-c-cpp.md",
    "checklist-go.md",
    "checklist-rust.md",
    "checklist-managed.md",
  ]) {
    const candidate = path.join(REFERENCE_DIR, name);
    if (await pathExists(candidate)) {
      return candidate;
    }
  }

  return "";
}

async function runEntryPoint(
  entryPoint: EntryPoint,
  config: AuditConfig,
  checkpoint: CheckpointManager,
  stage1Output: string,
  checklistPath: string,
): Promise<string[]> {
  const key = taskKey(entryPoint);
  const resultDir = path.join(config.outputDir, "stage-3-details");
  const findingPrefix = `${entryPoint.moduleId}-${entryPoint.id}`;
  const findingPattern = new RegExp(`^${findingPrefix}-F-\\d+\\.md$`);

  if (checkpoint.isComplete(key)) {
    logger.info("Stage 3: %s/%s already complete, skipping.", entryPoint.moduleId, entryPoint.id);
    return await listMatchingFiles(resultDir, findingPattern);
  }

  const prompt = await loadPrompt("stage3.md", {
    stage1_output_path: stage1Output,
    ep_block: entryPoint.rawBlock,
    module_id: entryPoint.moduleId,
    ep_id: entryPoint.id,
    ep_type: entryPoint.type,
    location: entryPoint.location,
    attacker_controlled_data: entryPoint.attackerControlledData,
    initial_validation: entryPoint.initialValidation || "None observed",
    analysis_hints: entryPoint.analysisHints,
    result_dir: resultDir,
    finding_prefix: findingPrefix,
    checklist_path: checklistPath,
    target_path: config.target,
  });

  await runAgent({
    prompt,
    config,
    cwd: config.target,
  });

  const findingFiles = await listMatchingFiles(resultDir, findingPattern);
  for (const findingFile of findingFiles) {
    let issues = validateStage3File(findingFile);
    if (issues.length === 0) {
      continue;
    }

    logger.warning("Stage 3: Validation failed for %s\n%s", findingFile, formatValidationIssues(issues));
    const repairPrompt =
      `The finding file at \`${findingFile}\` failed validation. ` +
      `Please fix all issues listed below:\n\n\`\`\`\n${formatValidationIssues(issues)}\n\`\`\``;

    await runAgent({
      prompt: repairPrompt,
      config,
      cwd: config.target,
      maxTurns: 10,
    });

    issues = validateStage3File(findingFile);
    if (issues.length > 0) {
      logger.warning("Stage 3: Repair failed for %s\n%s", findingFile, formatValidationIssues(issues));
    }
  }

  checkpoint.markComplete(key);
  logger.info("Stage 3: %s/%s complete. Findings: %s", entryPoint.moduleId, entryPoint.id, findingFiles.length);
  return findingFiles;
}

export async function runStage3(
  entryPointMap: Record<string, EntryPoint[]>,
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<string[]> {
  const stage1Output = path.join(config.outputDir, "stage-1-scope.md");
  const checklistPath = await detectChecklist(config);
  if (checklistPath) {
    logger.info("Stage 3: Using checklist: %s", checklistPath);
  } else {
    logger.warning("Stage 3: No checklist found, agents will proceed without one.");
  }

  const allEntryPoints = Object.values(entryPointMap).flat();
  if (allEntryPoints.length === 0) {
    logger.warning("Stage 3: No entry points to analyze.");
    return [];
  }

  const results = await runParallelLimited(allEntryPoints, config.maxParallel, async (entryPoint) => {
    return await runEntryPoint(entryPoint, config, checkpoint, stage1Output, checklistPath);
  });

  const allFindingFiles: string[] = [];
  results.forEach((result, index) => {
    const entryPoint = allEntryPoints[index];
    if (!entryPoint) {
      return;
    }
    if (result.status === "rejected") {
      logger.error(
        "Stage 3: %s/%s failed with exception: %s",
        entryPoint.moduleId,
        entryPoint.id,
        coerceError(result.reason).message,
      );
      return;
    }
    allFindingFiles.push(...result.value);
  });

  logger.info("Stage 3 complete. Total finding files: %s", allFindingFiles.length);
  return allFindingFiles;
}
