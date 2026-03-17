import type { ValidationIssue } from "../config.js";

import { findSection, parseMarkdownTableRows, readFileOrIssues } from "./common.js";

export function validateStage1File(filePath: string): ValidationIssue[] {
  const { content, issues } = readFileOrIssues(filePath);
  if (issues.length > 0) {
    return issues;
  }

  if (!content.trim()) {
    return [
      {
        description: "Output file is empty.",
        expected: "A markdown file with Project Summary, Threat Model, and Module Structure sections.",
        fix: "Write the full Stage 1 output to this file.",
      },
    ];
  }

  const validationIssues: ValidationIssue[] = [];

  for (const sectionName of ["Project Summary", "Threat Model", "Module Structure"]) {
    const section = findSection(content, sectionName);
    if (section === null) {
      validationIssues.push({
        description: `Missing required section: "## ${sectionName}"`,
        expected: `A "## ${sectionName}" heading must be present.`,
        fix: `Add a "## ${sectionName}" section with appropriate content.`,
      });
      continue;
    }

    if (!section.trim()) {
      validationIssues.push({
        description: `Section "## ${sectionName}" is empty.`,
        expected: "This section must contain content.",
        fix: `Fill in the ${sectionName} section with the relevant information.`,
      });
    }
  }

  const moduleSection = findSection(content, "Module Structure");
  if (moduleSection !== null) {
    const rows = parseMarkdownTableRows(moduleSection);
    if (rows.length === 0) {
      validationIssues.push({
        description: "No data rows found in the Module Structure table.",
        expected: "A markdown table with at least one module row.",
        fix: "Add module rows to the table. Each row needs: ID, Module, Description, Files/Directory, Analyze verdict.",
      });
    } else {
      let hasYes = false;
      rows.forEach((cells, index) => {
        if (cells.length < 5) {
          validationIssues.push({
            description: `Module table row ${index + 1} has ${cells.length} columns (expected at least 5).`,
            expected: "Columns: ID | Module | Description | Files / Directory | Analyze in Stage 2",
            fix: `Ensure row ${index + 1} has all 5 columns separated by '|'.`,
          });
          return;
        }

        const moduleId = cells[0] ?? "";
        if (!/^M-\d+$/.test(moduleId)) {
          validationIssues.push({
            description: `Module ID "${moduleId}" in row ${index + 1} does not match expected format.`,
            expected: 'Module IDs must match pattern "M-{N}" (e.g., "M-1", "M-2").',
            fix: `Change "${moduleId}" to "M-{N}" format (e.g., "M-${index + 1}").`,
          });
        }

        if ((cells[4] ?? "").toLowerCase().includes("yes")) {
          hasYes = true;
        }
      });

      if (!hasYes) {
        validationIssues.push({
          description: "No module is marked for analysis (no 'Yes' in 'Analyze in Stage 2' column).",
          expected: "At least one module should be marked 'Yes' for Stage 2 analysis.",
          fix: "Mark at least one relevant module with 'Yes' in the last column.",
        });
      }
    }
  }

  return validationIssues;
}
