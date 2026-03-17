import fs from "node:fs";

import type { Module } from "../config.js";

function extractModules(content: string): Module[] {
  const sectionMatch = /##\s+Module Structure\s*\n([\s\S]*?)(?=\n## |$)/.exec(content);
  if (!sectionMatch) {
    return [];
  }

  const section = sectionMatch[1] ?? "";
  const modules: Module[] = [];

  for (const rawLine of section.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line.startsWith("|")) {
      continue;
    }

    const cells = line
      .replace(/^\|/, "")
      .replace(/\|$/, "")
      .split("|")
      .map((cell) => cell.trim());

    if (cells.length < 5) {
      continue;
    }

    const [moduleId = "", name = "", description = "", filesDir = "", verdict = ""] = cells;
    if (!/^M-\d+$/.test(moduleId)) {
      continue;
    }

    modules.push({
      id: moduleId,
      name,
      description,
      filesDir,
      analyze: verdict.toLowerCase().includes("yes"),
    });
  }

  return modules;
}

export function parseModules(filePath: string): Module[] {
  return extractModules(fs.readFileSync(filePath, "utf8"));
}

export function getInScopeModules(filePath: string): Module[] {
  return parseModules(filePath).filter((module) => module.analyze);
}
