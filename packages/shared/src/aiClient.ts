import axios from "axios";

const ENGINE_URL = process.env.AI_SYNTHETIC_ENGINE_URL || process.env.AI_ENGINE_URL || "http://localhost:8080";
const ENGINE_API_KEY = process.env.AI_SYNTHETIC_API_KEY || "";
const COMMAND_PATH = process.env.AI_ENGINE_COMMAND_PATH || "/command";

export interface AIContext {
  userId: string;
  mode: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

export async function sendAICommand(command: string, payload: Record<string, unknown> = {}, context: AIContext) {
  const url = new URL(COMMAND_PATH, ENGINE_URL).toString();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (ENGINE_API_KEY) headers["X-API-Key"] = ENGINE_API_KEY;

  // Align with engines expecting `cmd` instead of `command` in the payload
  const body = { cmd: command, payload, context } as const;
  const res = await axios.post(url, body, { headers, timeout: 30_000 });
  return res.data;
}
