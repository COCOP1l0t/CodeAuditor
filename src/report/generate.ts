import fs from "node:fs";

import { compareSeverityThenId } from "../utils.js";
import { listMarkdownFilesSync } from "./helpers.js";

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

export interface GeneratedReportSummary {
  totalFindings: number;
  severityCounts: Record<string, number>;
}

function extractSection(content: string, header: string): string {
  const escaped = header.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`${escaped}\\n([\\s\\S]*?)(?=\\n## |$)`).exec(content);
  return match?.[1]?.trim() ?? "";
}

function stripJsonComments(jsonText: string): string {
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

function parseStage1Scope(filePath: string): { projectSummary: string; threatModel: string } {
  const content = fs.readFileSync(filePath, "utf8");
  return {
    projectSummary: extractSection(content, "## Project Summary"),
    threatModel: extractSection(content, "## Threat Model"),
  };
}

function parseFindingFile(filePath: string): {
  summary: Record<string, unknown> | null;
  detail: string;
} {
  const content = fs.readFileSync(filePath, "utf8");
  const jsonMatch = /###\s*Summary JSON Line\s*\n([\s\S]*?)(?=###\s*Detail)/.exec(content);
  const detailMatch = /(###\s*Detail[\s\S]*)/.exec(content);

  let summary: Record<string, unknown> | null = null;
  if (jsonMatch) {
    const jsonText = stripJsonComments(
      (jsonMatch[1] ?? "")
        .trim()
        .replace(/^```(?:json|JSON)?\s*\n?/, "")
        .replace(/\n?```\s*$/, ""),
    );
    try {
      summary = JSON.parse(jsonText) as Record<string, unknown>;
    } catch {
      summary = null;
    }
  }

  let detail = "";
  if (detailMatch) {
    detail = (detailMatch[1] ?? "").replace(/^###\s*Detail\s*\n?/, "").trim();
  }

  return { summary, detail };
}

function severitySortKey(finding: { summary: Record<string, unknown> }): [number, number] {
  const severity = String(finding.summary.severity ?? "Low");
  const severityRank = SEVERITY_ORDER[severity] ?? 3;
  const idText = String(finding.summary.id ?? "Z-99");
  const numberMatch = /(\d+)$/.exec(idText);
  return [severityRank, numberMatch ? Number(numberMatch[1]) : 99];
}

function formatArrayField(value: unknown): string {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(", ");
  }
  return value ? String(value) : "–";
}

function generateSummaryTable(findings: Array<{ summary: Record<string, unknown> }>): string {
  if (findings.length === 0) {
    return "No vulnerabilities found.\n";
  }

  const lines = [
    "| ID | Title | Vulnerability Class | Location | CVSS | Severity | CWE |",
    "|----|-------|---------------------|----------|------|----------|-----|",
  ];

  for (const finding of findings) {
    const summary = finding.summary;
    lines.push(
      `| ${String(summary.id ?? "N/A")} | ${String(summary.title ?? "N/A")} | ${formatArrayField(summary.vulnerability_class)} | ${String(summary.location ?? "N/A")} | ${String(summary.cvss_score ?? "N/A")} | ${String(summary.severity ?? "N/A")} | ${formatArrayField(summary.cwe_id)} |`,
    );
  }

  return `${lines.join("\n")}\n`;
}

export function generateReport(
  stage1Path: string,
  stage4Dir: string,
  outputPath: string,
): GeneratedReportSummary {
  const { projectSummary, threatModel } = parseStage1Scope(stage1Path);

  const findings = listMarkdownFilesSync(stage4Dir)
    .map((filePath) => ({ ...parseFindingFile(filePath), filePath }))
    .filter((finding) => finding.summary !== null)
    .map((finding) => ({
      ...finding,
      summary: finding.summary as Record<string, unknown>,
    }))
    .sort((left, right) => {
      const [leftSeverity, leftNumber] = severitySortKey(left);
      const [rightSeverity, rightNumber] = severitySortKey(right);
      if (leftSeverity !== rightSeverity) {
        return leftSeverity - rightSeverity;
      }
      if (leftNumber !== rightNumber) {
        return leftNumber - rightNumber;
      }
      return compareSeverityThenId(left.filePath, right.filePath);
    });

  const severityCounts: Record<string, number> = {};
  for (const finding of findings) {
    const severity = String(finding.summary.severity ?? "Low");
    severityCounts[severity] = (severityCounts[severity] ?? 0) + 1;
  }

  const report: string[] = [];
  report.push("# Security Audit Report", "");
  report.push("## Project Summary", "");
  report.push(projectSummary || "*(Project summary not available.)*", "");
  report.push("## Threat Model", "");
  report.push(threatModel || "*(Threat model not available.)*", "");
  report.push("## Findings Overview", "");
  report.push(`**Total findings**: ${findings.length}`, "");
  for (const severity of ["Critical", "High", "Medium", "Low"]) {
    const count = severityCounts[severity] ?? 0;
    if (count > 0) {
      report.push(`- **${severity}**: ${count}`);
    }
  }
  report.push("");
  report.push("## Findings Summary", "");
  report.push(generateSummaryTable(findings));
  report.push("## Detailed Findings", "");

  if (findings.length === 0) {
    report.push("No vulnerabilities were identified during this audit.", "");
  } else {
    for (const finding of findings) {
      report.push("---", "");
      report.push(`### ${String(finding.summary.id ?? "N/A")}: ${String(finding.summary.title ?? "N/A")}`, "");
      if (finding.detail) {
        report.push(finding.detail, "");
      }
    }
  }

  fs.writeFileSync(outputPath, report.join("\n"));
  return {
    totalFindings: findings.length,
    severityCounts,
  };
}
