import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

import type { ValidationIssue } from "./config.js";

export function coerceError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export async function pathExists(candidate: string): Promise<boolean> {
  try {
    await fsp.access(candidate);
    return true;
  } catch {
    return false;
  }
}

export function pathExistsSync(candidate: string): boolean {
  return fs.existsSync(candidate);
}

export async function listMarkdownFiles(dirPath: string): Promise<string[]> {
  if (!(await pathExists(dirPath))) {
    return [];
  }

  const entries = await fsp.readdir(dirPath, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => path.join(dirPath, entry.name))
    .sort();
}

export async function listMatchingFiles(
  dirPath: string,
  pattern: RegExp,
): Promise<string[]> {
  if (!(await pathExists(dirPath))) {
    return [];
  }

  const entries = await fsp.readdir(dirPath, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && pattern.test(entry.name))
    .map((entry) => path.join(dirPath, entry.name))
    .sort();
}

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export async function runCommand(
  command: string,
  args: string[],
  options: {
    cwd: string;
    input?: string;
    env?: Record<string, string>;
  },
): Promise<CommandResult> {
  return await new Promise<CommandResult>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      resolve({
        exitCode: code ?? 1,
        stdout,
        stderr,
      });
    });

    child.stdin.end(options.input ?? "");
  });
}

export async function runParallelLimited<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  if (items.length === 0) {
    return [];
  }

  const safeConcurrency = Math.max(1, concurrency);
  const results: PromiseSettledResult<R>[] = new Array(items.length);
  let nextIndex = 0;

  async function runOne(): Promise<void> {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) {
        return;
      }

      const item = items[index];
      if (item === undefined) {
        return;
      }

      try {
        const value = await worker(item, index);
        results[index] = { status: "fulfilled", value };
      } catch (error) {
        results[index] = { status: "rejected", reason: error };
      }
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(safeConcurrency, items.length) }, () => runOne()),
  );

  return results;
}

export function formatValidationIssues(issues: ValidationIssue[]): string {
  if (issues.length === 0) {
    return "PASS: All checks passed.";
  }

  const lines = [`FAIL: ${issues.length} issue(s) found`, ""];
  issues.forEach((issue, index) => {
    lines.push(`[Issue ${index + 1}] ${issue.description}`);
    lines.push(`  Expected: ${issue.expected}`);
    lines.push(`  Fix: ${issue.fix}`);
    lines.push("");
  });
  return lines.join("\n").trimEnd();
}

export function compareSeverityThenId(a: string, b: string): number {
  const severityRank = (id: string): number => {
    const prefix = id.split("-", 1)[0];
    switch (prefix) {
      case "C":
        return 0;
      case "H":
        return 1;
      case "M":
        return 2;
      case "L":
        return 3;
      default:
        return 99;
    }
  };

  const rankDiff = severityRank(path.basename(a, ".md")) - severityRank(path.basename(b, ".md"));
  if (rankDiff !== 0) {
    return rankDiff;
  }

  return a.localeCompare(b);
}
