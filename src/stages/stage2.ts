import path from "node:path";

import { runParallelLimited, coerceError } from "../utils.js";
import { runWithValidation } from "../agents/index.js";
import { CheckpointManager } from "../checkpoint.js";
import type { AuditConfig, EntryPoint, Module } from "../config.js";
import { getLogger } from "../logger.js";
import { parseEntryPoints } from "../parsing/stage2.js";
import { loadPrompt } from "../prompts.js";
import { validateStage2File } from "../validation/stage2.js";

const logger = getLogger("stage2");

function taskKey(module: Module): string {
  return `stage2:${module.id}`;
}

async function runModule(
  module: Module,
  config: AuditConfig,
  checkpoint: CheckpointManager,
  stage1Output: string,
): Promise<EntryPoint[]> {
  const key = taskKey(module);
  const resultDir = path.join(config.outputDir, "stage-2-details");
  const outputPath = path.join(resultDir, `${module.id}.md`);

  if (checkpoint.isComplete(key)) {
    logger.info("Stage 2: %s already complete, loading existing output.", module.id);
    return parseEntryPoints(outputPath, module.id);
  }

  const prompt = await loadPrompt("stage2.md", {
    stage1_output_path: stage1Output,
    result_dir: resultDir,
    module_id: module.id,
  });

  const { passed } = await runWithValidation({
    config,
    prompt,
    cwd: config.target,
    outputPath,
    validator: validateStage2File,
  });

  if (!passed) {
    logger.warning("Stage 2: %s validation did not fully pass.", module.id);
  }

  checkpoint.markComplete(key);
  const entryPoints = parseEntryPoints(outputPath, module.id);
  logger.info(
    "Stage 2: %s complete. Entry points: %s",
    module.id,
    entryPoints.map((entryPoint) => entryPoint.id).join(", "),
  );
  return entryPoints;
}

export async function runStage2(
  modules: Module[],
  config: AuditConfig,
  checkpoint: CheckpointManager,
): Promise<Record<string, EntryPoint[]>> {
  const stage1Output = path.join(config.outputDir, "stage-1-scope.md");
  const results = await runParallelLimited(modules, config.maxParallel, async (module) => {
    return await runModule(module, config, checkpoint, stage1Output);
  });

  const entryPointMap: Record<string, EntryPoint[]> = {};
  results.forEach((result, index) => {
    const module = modules[index];
    if (!module) {
      return;
    }
    if (result.status === "rejected") {
      logger.error("Stage 2: %s failed with exception: %s", module.id, coerceError(result.reason).message);
      entryPointMap[module.id] = [];
      return;
    }
    entryPointMap[module.id] = result.value;
  });

  return entryPointMap;
}
