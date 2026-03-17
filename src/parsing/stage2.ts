import fs from "node:fs";

import type { EntryPoint } from "../config.js";

function getField(block: string, fieldName: string): string {
  const pattern = new RegExp(`\\*\\*${fieldName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\*\\*\\s*:\\s*(.+)`);
  const match = pattern.exec(block);
  return match?.[1]?.trim() ?? "";
}

function extractEntryPoints(content: string, moduleId: string): EntryPoint[] {
  const splits = content.split(/###\s+EP-(\d+)\s*:/);
  const entryPoints: EntryPoint[] = [];

  for (let index = 1; index < splits.length - 1; index += 2) {
    const epNumber = splits[index];
    const block = splits[index + 1];
    if (!epNumber || block === undefined) {
      continue;
    }

    const typeRaw = getField(block, "Type");
    const typeLetter = typeRaw.split(/\s+/, 1)[0]?.replace(/[()]/g, "").toUpperCase() || "P";
    const epId = `EP-${epNumber}`;

    entryPoints.push({
      id: epId,
      moduleId,
      type: typeLetter,
      moduleName: getField(block, "Module Name"),
      location: getField(block, "Location"),
      attackerControlledData: getField(block, "Attacker-controlled data"),
      initialValidation: getField(block, "Initial validation observed"),
      analysisHints: getField(block, "Analysis hints"),
      rawBlock: `### ${epId}:\n${block}`,
    });
  }

  return entryPoints;
}

export function parseEntryPoints(filePath: string, moduleId: string): EntryPoint[] {
  return extractEntryPoints(fs.readFileSync(filePath, "utf8"), moduleId);
}
