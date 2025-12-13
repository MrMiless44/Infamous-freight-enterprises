// Environment variable validation utilities
export const requiredEnvVars = {
  api: ["DATABASE_URL", "JWT_SECRET", "NODE_ENV", "PORT"],
  web: ["NEXT_PUBLIC_API_URL", "NODE_ENV"],
} as const;

export function validateEnvVars(vars: string[]): {
  valid: boolean;
  missing: string[];
} {
  const missing = vars.filter((v) => !process.env[v]);
  return {
    valid: missing.length === 0,
    missing,
  };
}

export function getRequiredEnv(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

export function getOptionalEnv(key: string, defaultValue: string = ""): string {
  return process.env[key] || defaultValue;
}
