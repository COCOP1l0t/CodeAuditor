import fs from "node:fs";
import path from "node:path";

import { Codex } from "@openai/codex-sdk";

import type { AuditConfig, ValidationIssue } from "../config.js";
import { getLogger } from "../logger.js";
import { REFERENCE_DIR } from "../runtime.js";
import { runCommand } from "../utils.js";

const logger = getLogger("agents");

export const DEFAULT_TOOLS = ["Read", "Glob", "Grep", "Write", "Edit", "Bash"];

type Validator = (filePath: string) => ValidationIssue[] | Promise<ValidationIssue[]>;

function findExecutable(name: string): string | null {
  const pathEntries = (process.env.PATH ?? "").split(path.delimiter);
  for (const entry of pathEntries) {
    const candidate = path.join(entry, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  return null;
}

function additionalDirectories(config: AuditConfig, cwd: string): string[] {
  const resolvedCwd = path.resolve(cwd);
  return [config.outputDir, REFERENCE_DIR]
    .map((candidate) => path.resolve(candidate))
    .filter((candidate, index, values) => {
      return (
        candidate !== resolvedCwd &&
        fs.existsSync(candidate) &&
        values.indexOf(candidate) === index
      );
    });
}

export function ensureAgentRuntime(config: AuditConfig): void {
  if (config.agent === "claude-code") {
    if (!findExecutable("claude")) {
      throw new Error("Claude Code agent requested but `claude` was not found in PATH.");
    }
    return;
  }

  if (!findExecutable("codex")) {
    throw new Error("Codex agent requested but `codex` was not found in PATH.");
  }
}

export async function runAgent(options: {
  prompt: string;
  config: AuditConfig;
  cwd: string;
  allowedTools?: string[];
  maxTurns?: number;
}): Promise<string> {
  const allowedTools = options.allowedTools ?? DEFAULT_TOOLS;
  const maxTurns = options.maxTurns ?? 30;

  if (options.config.agent === "codex") {
    return await runCodexAgent(options.prompt, options.config, options.cwd, maxTurns);
  }
  return await runClaudeAgent(options.prompt, options.config, options.cwd, allowedTools, maxTurns);
}

async function runCodexAgent(
  prompt: string,
  config: AuditConfig,
  cwd: string,
  maxTurns: number,
): Promise<string> {
  if (maxTurns !== 30) {
    logger.debug(
      "Codex SDK backend ignores maxTurns=%s because the SDK does not expose a turn cap.",
      maxTurns,
    );
  }

  const codex = new Codex();
  const thread = codex.startThread({
    approvalPolicy: "never",
    sandboxMode: "danger-full-access",
    workingDirectory: path.resolve(cwd),
    skipGitRepoCheck: true,
    webSearchEnabled: false,
    additionalDirectories: additionalDirectories(config, cwd),
  });
  const turn = await thread.run(prompt);
  return turn.finalResponse ?? "";
}

async function runClaudeAgent(
  prompt: string,
  config: AuditConfig,
  cwd: string,
  allowedTools: string[],
  maxTurns: number,
): Promise<string> {
  if (maxTurns !== 30) {
    logger.debug("Claude Code backend ignores maxTurns=%s because the CLI does not expose a turn cap.", maxTurns);
  }

  const args = [
    "--print",
    "--output-format",
    "text",
    "--permission-mode",
    "bypassPermissions",
    "--no-session-persistence",
    "--tools",
    allowedTools.join(","),
  ];

  const extraDirs = additionalDirectories(config, cwd);
  if (extraDirs.length > 0) {
    args.push("--add-dir", ...extraDirs);
  }

  args.push(prompt);

  const result = await runCommand("claude", args, {
    cwd,
    env: process.env as Record<string, string>,
  });
  if (result.exitCode !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || "Claude Code CLI failed.");
  }
  return result.stdout.trim();
}

export async function runWithValidation(options: {
  config: AuditConfig;
  prompt: string;
  cwd: string;
  outputPath: string;
  validator: Validator;
  maxRetries?: number;
  allowedTools?: string[];
  maxTurns?: number;
  skipIfMissing?: boolean;
}): Promise<{ passed: boolean; result: string }> {
  const maxRetries = options.maxRetries ?? 2;
  const allowedTools = options.allowedTools ?? DEFAULT_TOOLS;
  const maxTurns = options.maxTurns ?? 30;
  const skipIfMissing = options.skipIfMissing ?? false;

  let result = await runAgent({
    prompt: options.prompt,
    config: options.config,
    cwd: options.cwd,
    allowedTools,
    maxTurns,
  });

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    if (skipIfMissing && !fs.existsSync(options.outputPath)) {
      logger.info("No output file at %s (filtered or no findings).", options.outputPath);
      return { passed: true, result };
    }

    const issues = await options.validator(options.outputPath);
    if (issues.length === 0) {
      logger.info("Validation passed for %s", options.outputPath);
      return { passed: true, result };
    }

    if (attempt === maxRetries) {
      return { passed: false, result };
    }

    const repairPrompt =
      `The output file at \`${options.outputPath}\` failed validation. ` +
      "Please fix all issues listed below, then save the corrected file.\n\n" +
      `Validation output:\n\`\`\`\n${formatValidationIssues(issues)}\n\`\`\``;

    result = await runAgent({
      prompt: repairPrompt,
      config: options.config,
      cwd: options.cwd,
      allowedTools,
      maxTurns: 10,
    });
  }

  return { passed: false, result };
}

export function formatValidationIssues(issues: ValidationIssue[]): string {
  const lines = [`FAIL: ${issues.length} issue(s) found`, ""];
  issues.forEach((issue, index) => {
    lines.push(`[Issue ${index + 1}] ${issue.description}`);
    lines.push(`  Expected: ${issue.expected}`);
    lines.push(`  Fix: ${issue.fix}`);
    lines.push("");
  });
  return lines.join("\n").trimEnd();
}
