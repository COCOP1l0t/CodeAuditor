import type { ValidationIssue } from "../config.js";

import { checkField, readFileOrIssues } from "./common.js";

const REQUIRED_FIELDS = [
  "Type",
  "Location",
  "Attacker-controlled data",
  "Analysis hints",
];
const VALID_TYPES = new Set(["p", "h", "s", "parser", "handler", "session"]);

function splitEntryPoints(content: string): Array<{ epId: string; block: string }> {
  const splits = content.split(/###\s+EP-(\d+)\s*:/);
  const results: Array<{ epId: string; block: string }> = [];

  for (let index = 1; index < splits.length - 1; index += 2) {
    const number = splits[index];
    const block = splits[index + 1];
    if (!number || block === undefined) {
      continue;
    }
    results.push({ epId: `EP-${number}`, block });
  }

  return results;
}

export function validateStage2File(filePath: string): ValidationIssue[] {
  const { content, issues } = readFileOrIssues(filePath);
  if (issues.length > 0) {
    return issues;
  }

  if (!content.trim()) {
    return [
      {
        description: "Output file is empty.",
        expected: "At least one entry point block (### EP-{N}:) with required fields.",
        fix: "Write the identified entry points to this file.",
      },
    ];
  }

  const entryPoints = splitEntryPoints(content);
  if (entryPoints.length === 0) {
    return [
      {
        description: "No entry point blocks found.",
        expected: 'At least one "### EP-{N}:" block (e.g., "### EP-1:").',
        fix: 'Add entry point blocks using the format "### EP-1:" followed by the required fields.',
      },
    ];
  }

  const validationIssues: ValidationIssue[] = [];
  for (const { epId, block } of entryPoints) {
    for (const field of REQUIRED_FIELDS) {
      const value = checkField(block, field);
      if (value === null) {
        validationIssues.push({
          description: `${epId}: Missing required field "**${field}**".`,
          expected: `Each entry point must have a "- **${field}**: ..." line.`,
          fix: `Add "- **${field}**: <value>" to the ${epId} block.`,
        });
      } else if (!value || ["none", "n/a", "..."].includes(value.toLowerCase())) {
        if (field === "Type" || field === "Location") {
          validationIssues.push({
            description: `${epId}: Field "**${field}**" has placeholder or empty value: "${value}".`,
            expected: `A concrete value for ${field}.`,
            fix: `Fill in the actual ${field} for ${epId}.`,
          });
        }
      }
    }

    const typeValue = checkField(block, "Type");
    if (typeValue) {
      const typeToken = typeValue.split(/\s+/, 1)[0]?.replace(/[()]/g, "").toLowerCase() ?? "";
      if (!VALID_TYPES.has(typeToken)) {
        validationIssues.push({
          description: `${epId}: Invalid Type value "${typeValue}".`,
          expected: 'Type must be one of: P (Parser), H (Handler), S (Session).',
          fix: `Change the Type of ${epId} to "P (Parser)", "H (Handler)", or "S (Session)".`,
        });
      }
    }
  }

  return validationIssues;
}
