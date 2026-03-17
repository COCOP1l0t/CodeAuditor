import path from "node:path";

import { CheckpointManager } from "./checkpoint.js";
import type { AuditConfig, EntryPoint, Module } from "./config.js";
import { getLogger } from "./logger.js";
import { getInScopeModules } from "./parsing/stage1.js";
import { parseEntryPoints } from "./parsing/stage2.js";
import { listMarkdownFiles } from "./utils.js";
import { runSetup } from "./stages/stage0.js";
import { runStage1 } from "./stages/stage1.js";
import { runStage2 } from "./stages/stage2.js";
import { runStage3 } from "./stages/stage3.js";
import { runStage4 } from "./stages/stage4.js";
import { runStage5 } from "./stages/stage5.js";

const logger = getLogger("orchestrator");

export async function runAudit(config: AuditConfig): Promise<string> {
  const checkpoint = new CheckpointManager(config.outputDir, config.resume);

  if (config.resume) {
    logger.info("Resume mode enabled. Existing output files and markers will be reused.");
  }

  if (!config.skipStages.includes(0)) {
    await runSetup(config);
  }

  let modules: Module[] = [];
  if (!config.skipStages.includes(1)) {
    modules = await runStage1(config, checkpoint);
  } else {
    logger.info("Stage 1 skipped.");
    modules = getInScopeModules(path.join(config.outputDir, "stage-1-scope.md"));
  }

  if (modules.length === 0) {
    throw new Error("Stage 1 produced no in-scope modules.");
  }

  let entryPointMap: Record<string, EntryPoint[]> = {};
  if (!config.skipStages.includes(2)) {
    entryPointMap = await runStage2(modules, config, checkpoint);
  } else {
    logger.info("Stage 2 skipped.");
    const stage2Dir = path.join(config.outputDir, "stage-2-details");
    for (const module of modules) {
      const filePath = path.join(stage2Dir, `${module.id}.md`);
      entryPointMap[module.id] = parseEntryPoints(filePath, module.id);
    }
  }

  let findingFiles: string[] = [];
  if (!config.skipStages.includes(3)) {
    findingFiles = await runStage3(entryPointMap, config, checkpoint);
  } else {
    logger.info("Stage 3 skipped.");
    findingFiles = await listMarkdownFiles(path.join(config.outputDir, "stage-3-details"));
  }

  if (!config.skipStages.includes(4)) {
    await runStage4(findingFiles, config, checkpoint);
  } else {
    logger.info("Stage 4 skipped.");
  }

  let reportPath = "";
  if (!config.skipStages.includes(5)) {
    reportPath = await runStage5(config, checkpoint);
  } else {
    logger.info("Stage 5 skipped.");
  }

  logger.info("Audit complete. Report: %s", reportPath);
  return reportPath;
}
