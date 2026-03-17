import fs from "node:fs";

import type { ValidationIssue } from "../config.js";

export function fileMissingIssue(filePath: string): ValidationIssue {
  return {
    description: `Output file not found: "${filePath}"`,
    expected: "The file should exist at the specified path.",
    fix: "Ensure the output file was written to the correct path.",
  };
}

export function readFileOrIssues(filePath: string): { content: string; issues: ValidationIssue[] } {
  try {
    return { content: fs.readFileSync(filePath, "utf8"), issues: [] };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { content: "", issues: [fileMissingIssue(filePath)] };
    }
    throw error;
  }
}

export function findSection(content: string, heading: string): string | null {
  const escaped = heading.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`(?:^|\\n)##\\s+${escaped.replace(/^##\s+/, "")}\\s*\\n([\\s\\S]*?)(?=\\n## |$)`);
  const match = pattern.exec(content);
  return match?.[1]?.trim() ?? null;
}

export function parseMarkdownTableRows(sectionText: string): string[][] {
  const tableLines = sectionText
    .split(/\r?\n/)
    .filter((line) => line.trim().startsWith("|"));

  if (tableLines.length < 2) {
    return [];
  }

  return tableLines.slice(2).map((line) =>
    line
      .trim()
      .replace(/^\|/, "")
      .replace(/\|$/, "")
      .split("|")
      .map((cell) => cell.trim()),
  );
}

export function checkField(blockText: string, fieldName: string): string | null {
  const escaped = fieldName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`\\*\\*${escaped}\\*\\*\\s*:\\s*(.+)`);
  const match = pattern.exec(blockText);
  return match?.[1]?.trim() ?? null;
}

export function stripJsonComments(jsonText: string): string {
  return jsonText
    .split("\n")
    .map((line) => {
      let inString = false;
      let result = "";

      for (let index = 0; index < line.length; index += 1) {
        const char = line[index];
        if (char === '"' && (index === 0 || line[index - 1] !== "\\")) {
          inString = !inString;
          result += char;
          continue;
        }

        if (!inString && char === "/" && line[index + 1] === "/") {
          break;
        }

        result += char;
      }

      return result;
    })
    .join("\n");
}

export function stripCodeFence(text: string): string {
  return text
    .replace(/^```(?:json|JSON)?\s*\n?/, "")
    .replace(/\n?```\s*$/, "")
    .trim();
}
