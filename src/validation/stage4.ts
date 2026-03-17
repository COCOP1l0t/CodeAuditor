import type { ValidationIssue } from "../config.js";

import {
  checkField,
  readFileOrIssues,
  stripCodeFence,
  stripJsonComments,
} from "./common.js";

const REQUIRED_JSON_KEYS = [
  "id",
  "title",
  "location",
  "cwe_id",
  "vulnerability_class",
  "cvss_score",
  "severity",
];

const REQUIRED_DETAIL_FIELDS = [
  "ID",
  "Title",
  "Location",
  "Vulnerability class",
  "CWE ID",
  "Impact",
  "Severity",
  "Code snippet",
];

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low"]);

export function validateStage4File(filePath: string): ValidationIssue[] {
  const { content, issues } = readFileOrIssues(filePath);
  if (issues.length > 0) {
    return issues;
  }

  if (!content.trim()) {
    return [
      {
        description: "Output file is empty.",
        expected: "A finding file with Summary JSON Line and Detail sections.",
        fix: "Write the finding with both '### Summary JSON Line' and '### Detail' sections.",
      },
    ];
  }

  const validationIssues: ValidationIssue[] = [];
  const jsonMatch = /###\s*Summary JSON Line\s*\n([\s\S]*?)(?=###\s*Detail|$)/.exec(content);
  if (!jsonMatch) {
    validationIssues.push({
      description: 'Missing "### Summary JSON Line" section.',
      expected: 'A "### Summary JSON Line" heading followed by a JSON block.',
      fix: 'Add a "### Summary JSON Line" section before "### Detail" containing the finding\'s JSON summary.',
    });
  } else {
    const jsonText = stripJsonComments(stripCodeFence((jsonMatch[1] ?? "").trim()));
    if (!jsonText) {
      validationIssues.push({
        description: "Summary JSON Line section is empty.",
        expected: "A valid JSON object with finding metadata.",
        fix: `Add the JSON summary object with required keys: ${REQUIRED_JSON_KEYS.join(", ")}`,
      });
    } else {
      let summary: Record<string, unknown> | null = null;
      try {
        summary = JSON.parse(jsonText) as Record<string, unknown>;
      } catch (error) {
        validationIssues.push({
          description: `Summary JSON is not valid JSON: ${String(error)}`,
          expected: "A valid JSON object.",
          fix: "Fix the JSON syntax error. Common issues: trailing commas, missing quotes, unescaped characters.",
        });
      }

      if (summary) {
        for (const key of REQUIRED_JSON_KEYS) {
          if (!(key in summary)) {
            validationIssues.push({
              description: `JSON missing required key: "${key}".`,
              expected: `The JSON object must contain "${key}".`,
              fix: `Add "${key}": "<value>" to the JSON object.`,
            });
          }
        }

        const severity = typeof summary.severity === "string" ? summary.severity : "";
        if (severity && !VALID_SEVERITIES.has(severity.toLowerCase())) {
          validationIssues.push({
            description: `Invalid severity in JSON: "${severity}".`,
            expected: "Severity must be one of: Critical, High, Medium, Low.",
            fix: 'Change "severity" to one of: "Critical", "High", "Medium", "Low".',
          });
        }
      }
    }
  }

  const detailMatch = /###\s*Detail\s*\n([\s\S]*)/.exec(content);
  if (!detailMatch) {
    validationIssues.push({
      description: 'Missing "### Detail" section.',
      expected: 'A "### Detail" heading followed by finding details.',
      fix: `Add a "### Detail" section with the required fields: ${REQUIRED_DETAIL_FIELDS.join(", ")}`,
    });
  } else {
    const detailText = (detailMatch[1] ?? "").trim();
    if (!detailText) {
      validationIssues.push({
        description: "Detail section is empty.",
        expected: "Finding details with required fields.",
        fix: `Fill in the Detail section with: ${REQUIRED_DETAIL_FIELDS.join(", ")}`,
      });
    } else {
      for (const field of REQUIRED_DETAIL_FIELDS) {
        if (checkField(detailText, field) === null) {
          validationIssues.push({
            description: `Detail section missing required field "**${field}**".`,
            expected: `A "- **${field}**: ..." line in the Detail section.`,
            fix: `Add "- **${field}**: <value>" to the Detail section.`,
          });
        }
      }
    }
  }

  return validationIssues;
}
