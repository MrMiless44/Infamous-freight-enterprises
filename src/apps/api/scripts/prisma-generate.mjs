import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const fallbackUrl = "postgresql://postgres:postgres@localhost:5432/postgres";
const databaseUrl =
  process.env.DATABASE_URL ?? process.env.NETLIFY_DATABASE_URL ?? fallbackUrl;

// Ensure Prisma always receives a database URL, even in build environments that only expose
// NETLIFY_DATABASE_URL (or provide nothing at all).
process.env.DATABASE_URL = databaseUrl;

const apiRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

execFileSync("pnpm", ["prisma", "generate"], {
  stdio: "inherit",
  cwd: apiRoot,
});
