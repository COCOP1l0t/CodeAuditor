import path from "node:path";

import { runWithValidation } from "../agents/index.js";
import { CheckpointManager } from "../checkpoint.js";
import type { AuditConfig, Module } from "../config.js";
import { getLogger } from "../logger.js";
import { getInScopeModules } from "../parsing/stage1.js";
import { loadPrompt } from "../prompts.js";
import { validateStage1File } from "../validation/stage1.js";

const logger = getLogger("stage1");
const TASK_KEY = "stage1";

export async function runStage1(
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<Module[]> {
  const outputPath = path.join(config.outputDir, "stage-1-scope.md");

  if (checkpoint.isComplete(TASK_KEY)) {
    logger.info("Stage 1 already complete, loading existing output.");
    return getInScopeModules(outputPath);
  }

  const prompt = await loadPrompt("stage1.md", {
    target_path: config.target,
    output_path: outputPath,
    threat_model: config.threatModel,
    user_instructions: config.scope || "No additional scope constraints.",
  });

  const { passed } = await runWithValidation({
    config,
    prompt,
    cwd: config.target,
    outputPath,
    validator: validateStage1File,
  });

  if (!passed) {
    logger.warning("Stage 1 validation did not fully pass, continuing with best-effort output.");
  }

  checkpoint.markComplete(TASK_KEY);
  const modules = getInScopeModules(outputPath);
  logger.info("Stage 1 complete. In-scope modules: %s", modules.map((module) => module.id).join(", "));
  return modules;
}
