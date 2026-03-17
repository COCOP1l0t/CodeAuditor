import fs from "node:fs";
import path from "node:path";

import { getLogger } from "./logger.js";

const logger = getLogger("checkpoint");

export class CheckpointManager {
  private readonly markersDir: string;

  constructor(
    private readonly outputDir: string,
    private readonly resume: boolean,
  ) {
    this.markersDir = path.join(outputDir, ".markers");
  }

  isComplete(taskKey: string): boolean {
    if (!this.resume) {
      return false;
    }

    const resolved = this.resolve(taskKey);
    if (!resolved) {
      return false;
    }

    const exists = fs.existsSync(resolved);
    if (exists) {
      logger.debug("Checkpoint hit: %s -> %s", taskKey, resolved);
    }
    return exists;
  }

  markComplete(taskKey: string): void {
    if (!this.needsMarker(taskKey)) {
      logger.debug("Checkpoint tracked by output file: %s", taskKey);
      return;
    }

    fs.mkdirSync(this.markersDir, { recursive: true });
    fs.writeFileSync(this.markerPath(taskKey), "");
  }

  private resolve(taskKey: string): string | null {
    if (taskKey === "stage1") {
      return path.join(this.outputDir, "stage-1-scope.md");
    }

    if (taskKey.startsWith("stage2:")) {
      const moduleId = taskKey.split(":", 2)[1];
      return path.join(this.outputDir, "stage-2-details", `${moduleId}.md`);
    }

    if (taskKey.startsWith("stage3:")) {
      return this.markerPath(taskKey);
    }

    if (taskKey.startsWith("stage4:")) {
      const marker = this.markerPath(taskKey);
      if (fs.existsSync(marker)) {
        return marker;
      }

      const stage3Filename = taskKey.split(":", 2)[1] ?? "";
      return path.join(this.outputDir, "stage-4-details", "_pending", stage3Filename);
    }

    if (taskKey === "stage5") {
      return path.join(this.outputDir, "report.md");
    }

    logger.warning("Unknown checkpoint task key: %s", taskKey);
    return null;
  }

  private needsMarker(taskKey: string): boolean {
    return taskKey.startsWith("stage3:") || taskKey.startsWith("stage4:");
  }

  private markerPath(taskKey: string): string {
    return path.join(this.markersDir, taskKey.replaceAll(":", "-"));
  }
}
