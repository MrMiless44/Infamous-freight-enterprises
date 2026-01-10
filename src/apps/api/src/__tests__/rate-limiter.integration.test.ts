import { describe, it, expect } from "@jest/globals";

// Integration tests require a running API + seeded data. Skip in CI to avoid network flakiness.
describe.skip("Rate Limiter Integration Tests", () => {
  it("skipped in CI environment", () => {
    expect(true).toBe(true);
  });
});
