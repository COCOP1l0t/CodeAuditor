export type AgentType = "claude-code" | "codex";
export type LogLevel = "DEBUG" | "INFO" | "WARNING" | "ERROR";

export const AGENT_CHOICES = ["claude-code", "codex"] as const;
export const DEFAULT_THREAT_MODEL =
  "Network attacker with full control over protocol messages. " +
  "The attacker can send arbitrary bytes, malformed messages, " +
  "and exploit any parsing or handling vulnerability.";

export interface AuditConfig {
  agent: AgentType;
  target: string;
  outputDir: string;
  maxParallel: number;
  threatModel: string;
  scope: string;
  skipStages: number[];
  resume: boolean;
  logLevel: LogLevel;
}

export interface Module {
  id: string;
  name: string;
  description: string;
  filesDir: string;
  analyze: boolean;
}

export interface EntryPoint {
  id: string;
  moduleId: string;
  type: string;
  moduleName: string;
  location: string;
  attackerControlledData: string;
  initialValidation: string;
  analysisHints: string;
  rawBlock: string;
}

export interface ValidationIssue {
  description: string;
  expected: string;
  fix: string;
}
