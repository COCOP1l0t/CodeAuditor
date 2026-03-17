import fs from "node:fs/promises";
import path from "node:path";

import { CheckpointManager } from "../checkpoint.js";
import type { AuditConfig } from "../config.js";
import { getLogger } from "../logger.js";
import { generateReport } from "../report/generate.js";

const logger = getLogger("stage5");
const TASK_KEY = "stage5";

export async function runStage5(
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<string> {
  const reportPath = path.join(config.outputDir, "report.md");

  if (checkpoint.isComplete(TASK_KEY)) {
    logger.info("Stage 5 already complete.");
    return reportPath;
  }

  const stage1Scope = path.join(config.outputDir, "stage-1-scope.md");
  const stage4Dir = path.join(config.outputDir, "stage-4-details");
  const summary = generateReport(stage1Scope, stage4Dir, reportPath);
  const stat = await fs.stat(reportPath);
  if (stat.size === 0) {
    throw new Error(`Report file missing or empty: ${reportPath}`);
  }

  checkpoint.markComplete(TASK_KEY);
  logger.info("Stage 5 complete. Report: %s", reportPath);
  logger.info("Report summary: total=%s severities=%j", summary.totalFindings, summary.severityCounts);
  return reportPath;
}
