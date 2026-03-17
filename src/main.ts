#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import { ensureAgentRuntime } from "./agents/index.js";
import {
  AGENT_CHOICES,
  DEFAULT_THREAT_MODEL,
  type AgentType,
  type AuditConfig,
  type LogLevel,
} from "./config.js";
import { configureLogging, getLogger } from "./logger.js";
import { runAudit } from "./orchestrator.js";
import { REPO_ROOT } from "./runtime.js";

const logger = getLogger("main");

function printHelp(): void {
  const examples = [
    "protocol-auditor --agent claude-code --target /path/to/project",
    "protocol-auditor --agent codex --target /path/to/project --max-parallel 2 --resume",
    "protocol-auditor --agent claude-code --target /path/to/project --skip-stages 1,2 --output-dir /tmp/audit",
  ];

  process.stdout.write(
    [
      "Usage: protocol-auditor --agent {claude-code|codex} --target PATH [options]",
      "",
      "Options:",
      "  --agent {claude-code|codex}   Agent backend for stages 1-4",
      "  --target PATH                 Root directory of the project to audit",
      "  --output-dir PATH             Output directory (default: {target}/audit-output)",
      "  --max-parallel N              Maximum concurrent agents (default: 4)",
      "  --resume                      Resume from previous output files and markers",
      "  --threat-model TEXT           Override the default threat model",
      "  --scope TEXT                  Additional scope instructions for stage 1",
      "  --skip-stages LIST            Comma-separated list of stages to skip",
      "  --log-level LEVEL             DEBUG | INFO | WARNING | ERROR (default: INFO)",
      "  --help                        Show this help message",
      "",
      "Examples:",
      ...examples.map((example) => `  ${example}`),
      "",
      `Repository root: ${REPO_ROOT}`,
    ].join("\n"),
  );
}

function parseSkipStages(rawValue: string | undefined): number[] {
  if (!rawValue) {
    return [];
  }

  const values = rawValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => Number(value));

  if (values.some((value) => Number.isNaN(value))) {
    throw new Error("--skip-stages must be a comma-separated list of integers.");
  }

  return values;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      agent: { type: "string" },
      target: { type: "string" },
      "output-dir": { type: "string" },
      "max-parallel": { type: "string" },
      resume: { type: "boolean" },
      "threat-model": { type: "string" },
      scope: { type: "string" },
      "skip-stages": { type: "string" },
      "log-level": { type: "string" },
      help: { type: "boolean" },
    },
    allowPositionals: false,
  });

  if (values.help) {
    printHelp();
    return;
  }

  const agent = values.agent as AgentType | undefined;
  if (!agent || !AGENT_CHOICES.includes(agent)) {
    throw new Error(`--agent is required and must be one of: ${AGENT_CHOICES.join(", ")}`);
  }

  if (!values.target) {
    throw new Error("--target is required.");
  }

  const target = path.resolve(values.target);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
    throw new Error(`Target directory not found: ${target}`);
  }

  const outputDir = path.resolve(values["output-dir"] ?? path.join(target, "audit-output"));

  const logLevel = (values["log-level"] ?? "INFO").toUpperCase() as LogLevel;
  if (!["DEBUG", "INFO", "WARNING", "ERROR"].includes(logLevel)) {
    throw new Error("--log-level must be one of: DEBUG, INFO, WARNING, ERROR.");
  }

  const maxParallel = Number(values["max-parallel"] ?? "4");
  if (!Number.isInteger(maxParallel) || maxParallel <= 0) {
    throw new Error("--max-parallel must be a positive integer.");
  }

  const config: AuditConfig = {
    agent,
    target,
    outputDir,
    maxParallel,
    threatModel: values["threat-model"] ?? DEFAULT_THREAT_MODEL,
    scope: values.scope ?? "",
    skipStages: parseSkipStages(values["skip-stages"]),
    resume: values.resume ?? false,
    logLevel,
  };

  configureLogging(config.logLevel);
  ensureAgentRuntime(config);
  logger.info("Using agent backend: %s", config.agent);

  const reportPath = await runAudit(config);
  process.stdout.write(`\nAudit complete. Report: ${reportPath}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`\nError: ${message}\n`);
  process.exit(1);
});
