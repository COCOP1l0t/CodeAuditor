import fs from "node:fs/promises";
import path from "node:path";

import { PROMPTS_DIR } from "./runtime.js";

export async function loadPrompt(
  promptName: string,
  substitutions: Record<string, string>,
): Promise<string> {
  const promptPath = path.join(PROMPTS_DIR, promptName);
  let text = await fs.readFile(promptPath, "utf8");

  for (const [key, value] of Object.entries(substitutions)) {
    text = text.replaceAll(`__${key.toUpperCase()}__`, value);
  }

  return text;
}
