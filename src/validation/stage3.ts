import type { ValidationIssue } from "../config.js";

import { checkField, readFileOrIssues } from "./common.js";

const REQUIRED_FIELDS = [
  "Location",
  "Vulnerability class",
  "Root cause",
  "Preliminary severity",
];

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);

function splitFindings(content: string): Array<{ findingId: string; block: string }> {
  const splits = content.split(/###\s+(F-\d+)\s*:/);
  const findings: Array<{ findingId: string; block: string }> = [];

  for (let index = 1; index < splits.length - 1; index += 2) {
    const findingId = splits[index];
    const block = splits[index + 1];
    if (!findingId || block === undefined) {
      continue;
    }
    findings.push({ findingId, block });
  }

  return findings;
}

export function validateStage3File(filePath: string): ValidationIssue[] {
  const { content, issues } = readFileOrIssues(filePath);
  if (issues.length > 0) {
    return issues;
  }

  if (!content.trim()) {
    return [
      {
        description: "Finding file is empty.",
        expected: "A single finding block (### F-{NN}: title) with required fields.",
        fix: "Write the finding block, or delete the file if there are no findings for this entry point.",
      },
    ];
  }

  const findings = splitFindings(content);
  if (findings.length === 0) {
    return [
      {
        description: "No finding block found.",
        expected: '"### F-{NN}: [Short Title]" block (e.g., "### F-01: Buffer Overflow in parse_options").',
        fix: 'Add a finding block using the format "### F-01: [Short Title]".',
      },
    ];
  }

  const validationIssues: ValidationIssue[] = [];
  if (findings.length > 1) {
    validationIssues.push({
      description: `File contains ${findings.length} finding blocks; expected exactly 1.`,
      expected: "Each finding file must contain exactly one finding block.",
      fix: "Split multiple findings into separate files, one finding per file.",
    });
  }

  for (const { findingId, block } of findings) {
    for (const field of REQUIRED_FIELDS) {
      if (checkField(block, field) === null) {
        validationIssues.push({
          description: `${findingId}: Missing required field "**${field}**".`,
          expected: `Each finding must have a "- **${field}**: ..." line.`,
          fix: `Add "- **${field}**: <value>" to the ${findingId} block.`,
        });
      }
    }

    const severity = checkField(block, "Preliminary severity");
    if (severity && !VALID_SEVERITIES.has(severity.toLowerCase())) {
      validationIssues.push({
        description: `${findingId}: Invalid Preliminary severity value "${severity}".`,
        expected: "Severity must be one of: Critical, High, Medium, Low.",
        fix: `Change the Preliminary severity of ${findingId} to one of: Critical, High, Medium, Low.`,
      });
    }
  }

  return validationIssues;
}
