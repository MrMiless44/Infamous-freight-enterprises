// Environment variable validation utilities
export const requiredEnvVars = {
  api: ["DATABASE_URL", "JWT_SECRET", "NODE_ENV", "PORT"],
  web: ["NEXT_PUBLIC_API_URL", "NODE_ENV"],
} as const;

const isValueMissing = (value: string | undefined | null): boolean =>
  value === undefined || value === null || value === "";

export function validateEnvVars(vars: string[]): {
  valid: boolean;
  missing: string[];
} {
  const missing = vars.filter((v) => isValueMissing(process.env[v]));

  if (missing.length > 0) {
    const base = "Missing required environment variables";
    if (missing.length === 1) {
      throw new Error(`${base}: ${missing[0]}`);
    }
    throw new Error(base);
  }

  return {
    valid: true,
    missing: [],
  };
}

export function getRequiredEnv(key: string): string {
  const value = process.env[key];
  if (isValueMissing(value)) {
    throw new Error(`Required environment variable ${key} is not set`);
  }
  return value as string;
}

export function getOptionalEnv(
  key: string,
  defaultValue?: string,
): string | undefined {
  const value = process.env[key];
  if (isValueMissing(value)) {
    return defaultValue;
  }
  return value as string;
}
