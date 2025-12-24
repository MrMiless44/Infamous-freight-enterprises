const { auditInvoice, generateSyntheticResponse } = require("../syntheticFallback");

describe("syntheticFallback", () => {
  describe("auditInvoice", () => {
    test("returns approval when invoice passes checks", () => {
      const result = auditInvoice({
        invoice: {
          carrier: "ACME Logistics",
          reference: "INV-123",
          totalAmount: 12500,
          currency: "USD",
        },
        ruleset: "standard_freight",
      });

      expect(result.status).toBe("approved");
      expect(result.issues).toHaveLength(0);
      expect(result.summary).toContain("passes");
      expect(result.confidence).toBeGreaterThan(0.8);
    });

    test("flags missing fields and unsupported currency", () => {
      const result = auditInvoice({
        invoice: {
          totalAmount: -50,
          currency: "ZAR",
        },
      });

      const issueCodes = result.issues.map((issue) => issue.code);
      expect(result.status).toBe("rejected");
      expect(issueCodes).toEqual(
        expect.arrayContaining([
          "invalid_total",
          "missing_reference",
          "missing_carrier",
          "unsupported_currency",
        ]),
      );
      expect(result.confidence).toBeLessThan(0.7);
    });
  });

  test("generateSyntheticResponse falls back to default for unknown commands", () => {
    const result = generateSyntheticResponse("unknown.action", { foo: "bar" });
    expect(result.command).toBe("unknown.action");
    expect(result.provider).toBe("synthetic");
    expect(result.source).toBe("offline-fallback");
    expect(result.echo.payload).toEqual({ foo: "bar" });
  });
});
