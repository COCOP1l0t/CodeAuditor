import path from "node:path";
import { fileURLToPath } from "node:url";

const CURRENT_DIR = path.dirname(fileURLToPath(import.meta.url));

export const REPO_ROOT = path.resolve(CURRENT_DIR, "..");
export const PROMPTS_DIR = path.join(REPO_ROOT, "prompts");
export const REFERENCE_DIR = path.join(REPO_ROOT, "reference");
