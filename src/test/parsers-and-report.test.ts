import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { getInScopeModules } from "../parsing/stage1.js";
import { parseEntryPoints } from "../parsing/stage2.js";
import { generateReport } from "../report/generate.js";
import { validateStage4File } from "../validation/stage4.js";

test("stage1 parser returns only in-scope modules", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "protocol-auditor-stage1-"));
  const stage1Path = path.join(tempDir, "stage-1-scope.md");
  await fs.writeFile(
    stage1Path,
    `# Orient and Scope

## Project Summary
Example.

## Threat Model
Example threat model.

## Module Structure

| ID | Module | Description | Files / Directory | Analyze in Stage 2 |
|----|--------|-------------|-------------------|-------------------|
| M-1 | Parser | Core parser | src/parser | Yes |
| M-2 | Utils | Utility helpers | src/utils | No |
`,
  );

  const modules = getInScopeModules(stage1Path);
  assert.equal(modules.length, 1);
  assert.equal(modules[0]?.id, "M-1");
});

test("stage2 parser extracts entry points", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "protocol-auditor-stage2-"));
  const stage2Path = path.join(tempDir, "M-1.md");
  await fs.writeFile(
    stage2Path,
    `### EP-1:
- **Type**: P (Parser)
- **Module Name**: DHCP parser
- **Location**: \`parse_options\` at \`src/parser.c:12\`
- **Attacker-controlled data**: packet bytes
- **Initial validation observed**: Length field checks
- **Analysis hints**: Review offset arithmetic
`,
  );

  const entryPoints = parseEntryPoints(stage2Path, "M-1");
  assert.equal(entryPoints.length, 1);
  assert.equal(entryPoints[0]?.type, "P");
  assert.equal(entryPoints[0]?.moduleId, "M-1");
});

test("stage4 validator and report generator accept fenced JSON", async () => {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "protocol-auditor-report-"));
  const stage1Path = path.join(tempDir, "stage-1-scope.md");
  const stage4Dir = path.join(tempDir, "stage-4-details");
  const reportPath = path.join(tempDir, "report.md");
  const findingPath = path.join(stage4Dir, "H-01.md");

  await fs.mkdir(stage4Dir, { recursive: true });
  await fs.writeFile(
    stage1Path,
    `# Orient and Scope

## Project Summary
Example protocol implementation.

## Threat Model
Network attacker.
`,
  );
  await fs.writeFile(
    findingPath,
    `### Summary JSON Line

\`\`\`json
{
  "id": "H-01",
  "title": "Length underflow reaches memcpy",
  "location": "src/parser.c:parse_packet (lines 10-24)",
  "cwe_id": ["CWE-191"],
  "vulnerability_class": ["integer underflow"],
  "cvss_score": "8.1",
  "severity": "High"
}
\`\`\`

### Detail

- **ID**: H-01
- **Title**: Length underflow reaches memcpy
- **Location**: src/parser.c:parse_packet (lines 10-24)
- **Vulnerability class**: integer underflow
- **CWE ID**: CWE-191
- **Impact**: DoS
- **Severity**: High
- **Code snippet**: memcpy(...)
`,
  );

  assert.deepEqual(validateStage4File(findingPath), []);

  const summary = generateReport(stage1Path, stage4Dir, reportPath);
  const reportContent = await fs.readFile(reportPath, "utf8");

  assert.equal(summary.totalFindings, 1);
  assert.match(reportContent, /H-01: Length underflow reaches memcpy/);
});
