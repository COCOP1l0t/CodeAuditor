import util from "node:util";

import type { LogLevel } from "./config.js";

const LEVEL_ORDER: Record<LogLevel, number> = {
  DEBUG: 10,
  INFO: 20,
  WARNING: 30,
  ERROR: 40,
};

let currentLevel: LogLevel = "INFO";

export function configureLogging(level: LogLevel): void {
  currentLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LEVEL_ORDER[level] >= LEVEL_ORDER[currentLevel];
}

function write(level: LogLevel, name: string, message: string, args: unknown[]): void {
  if (!shouldLog(level)) {
    return;
  }

  const timestamp = new Date().toISOString();
  const renderedMessage = util.format(message, ...args);
  process.stderr.write(`${timestamp} [${level}] ${name}: ${renderedMessage}\n`);
}

export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warning(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

export function getLogger(name: string): Logger {
  return {
    debug(message, ...args) {
      write("DEBUG", name, message, args);
    },
    info(message, ...args) {
      write("INFO", name, message, args);
    },
    warning(message, ...args) {
      write("WARNING", name, message, args);
    },
    error(message, ...args) {
      write("ERROR", name, message, args);
    },
  };
}
