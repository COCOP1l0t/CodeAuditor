import fs from "node:fs/promises";
import path from "node:path";

import type { AuditConfig } from "../config.js";
import { getLogger } from "../logger.js";

const logger = getLogger("stage0");

export async function runSetup(config: AuditConfig): Promise<void> {
  const directories = [
    config.outputDir,
    path.join(config.outputDir, ".markers"),
    path.join(config.outputDir, "stage-2-details"),
    path.join(config.outputDir, "stage-3-details"),
    path.join(config.outputDir, "stage-4-details"),
    path.join(config.outputDir, "stage-4-details", "_pending"),
  ];

  for (const directory of directories) {
    await fs.mkdir(directory, { recursive: true });
    logger.debug("Directory ready: %s", directory);
  }

  logger.info("Stage 0 complete. Output dir: %s", config.outputDir);
}
