import { validateEnvVars, getRequiredEnv, getOptionalEnv } from "../env";

describe("getRequiredEnv", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should return environment variable value if it exists", () => {
    process.env.TEST_VAR = "test-value";
    expect(getRequiredEnv("TEST_VAR")).toBe("test-value");
  });

  it("should throw error if environment variable is missing", () => {
    delete process.env.TEST_VAR;
    expect(() => getRequiredEnv("TEST_VAR")).toThrow(
      "Required environment variable TEST_VAR is not set",
    );
  });

  it("should throw error if environment variable is empty", () => {
    process.env.TEST_VAR = "";
    expect(() => getRequiredEnv("TEST_VAR")).toThrow(
      "Required environment variable TEST_VAR is not set",
    );
  });
});

describe("getOptionalEnv", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should return environment variable value if it exists", () => {
    process.env.OPTIONAL_VAR = "optional-value";
    expect(getOptionalEnv("OPTIONAL_VAR", "default")).toBe("optional-value");
  });

  it("should return default value if variable is missing", () => {
    delete process.env.OPTIONAL_VAR;
    expect(getOptionalEnv("OPTIONAL_VAR", "default-value")).toBe(
      "default-value",
    );
  });

  it("should return default value if variable is empty", () => {
    process.env.OPTIONAL_VAR = "";
    expect(getOptionalEnv("OPTIONAL_VAR", "default-value")).toBe(
      "default-value",
    );
  });

  it("should return undefined if no default provided and variable missing", () => {
    delete process.env.OPTIONAL_VAR;
    expect(getOptionalEnv("OPTIONAL_VAR")).toBeUndefined();
  });
});

describe("validateEnvVars", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterAll(() => {
    process.env = originalEnv;
  });

  it("should not throw if all required variables are set", () => {
    process.env.VAR1 = "value1";
    process.env.VAR2 = "value2";
    expect(() => validateEnvVars(["VAR1", "VAR2"])).not.toThrow();
  });

  it("should throw if any required variable is missing", () => {
    process.env.VAR1 = "value1";
    delete process.env.VAR2;
    expect(() => validateEnvVars(["VAR1", "VAR2"])).toThrow(
      "Missing required environment variables: VAR2",
    );
  });

  it("should throw with multiple missing variables", () => {
    delete process.env.VAR1;
    delete process.env.VAR2;
    expect(() => validateEnvVars(["VAR1", "VAR2", "VAR3"])).toThrow(
      "Missing required environment variables",
    );
  });
});
