import {
  formatCurrency,
  formatDate,
  formatPhoneNumber,
  parseCSV,
  stringToSlug,
} from "../../utils/formatters";

describe("Formatter Utilities", () => {
  describe("formatCurrency", () => {
    it("should format USD currency", () => {
      const formatted = formatCurrency(1234.56, "USD");

      expect(formatted).toContain("$");
      expect(formatted).toContain("1,234.56");
    });

    it("should format EUR currency", () => {
      const formatted = formatCurrency(1234.56, "EUR");

      expect(formatted).toContain("€");
    });

    it("should handle zero amount", () => {
      const formatted = formatCurrency(0, "USD");

      expect(formatted).toContain("$");
      expect(formatted).toContain("0");
    });

    it("should handle large amounts", () => {
      const formatted = formatCurrency(1000000.99, "USD");

      expect(formatted).toContain("1,000,000.99");
    });
  });

  describe("formatDate", () => {
    it("should format date correctly", () => {
      const date = new Date("2026-01-15");

      const formatted = formatDate(date);

      expect(formatted).toContain("01");
      expect(formatted).toContain("15");
      expect(formatted).toContain("2026");
    });

    it("should support different formats", () => {
      const date = new Date("2026-01-15T14:30:00");

      const shortFormat = formatDate(date, "short");
      const longFormat = formatDate(date, "long");

      expect(shortFormat.length).toBeLessThan(longFormat.length);
    });

    it("should handle ISO format", () => {
      const date = new Date("2026-01-15");

      const formatted = formatDate(date, "iso");

      expect(formatted).toMatch(/2026-01-15/);
    });
  });

  describe("formatPhoneNumber", () => {
    it("should format US phone number", () => {
      const formatted = formatPhoneNumber("5551234567");

      expect(formatted).toBe("(555) 123-4567");
    });

    it("should handle phone with country code", () => {
      const formatted = formatPhoneNumber("+15551234567");

      expect(formatted).toContain("(555)");
      expect(formatted).toContain("123-4567");
    });

    it("should handle already formatted numbers", () => {
      const formatted = formatPhoneNumber("(555) 123-4567");

      expect(formatted).toBe("(555) 123-4567");
    });

    it("should handle short numbers", () => {
      const formatted = formatPhoneNumber("5551234");

      expect(formatted).toBeDefined();
    });
  });

  describe("parseCSV", () => {
    it("should parse simple CSV", () => {
      const csv = "name,email,phone\nJohn,john@example.com,5551234567";

      const parsed = parseCSV(csv);

      expect(parsed.length).toBe(1);
      expect(parsed[0].name).toBe("John");
      expect(parsed[0].email).toBe("john@example.com");
    });

    it("should handle quoted fields", () => {
      const csv = '"Last, First",email\n"Smith, John",john@example.com';

      const parsed = parseCSV(csv);

      expect(parsed[0]["Last, First"]).toContain("Smith");
    });

    it("should handle empty lines", () => {
      const csv = "name,email\nJohn,john@example.com\n\nJane,jane@example.com";

      const parsed = parseCSV(csv);

      expect(parsed.length).toBe(2);
    });
  });

  describe("stringToSlug", () => {
    it("should convert to lowercase slug", () => {
      const slug = stringToSlug("Hello World");

      expect(slug).toBe("hello-world");
    });

    it("should remove special characters", () => {
      const slug = stringToSlug("Hello & World!");

      expect(slug).toBe("hello-world");
    });

    it("should replace spaces with hyphens", () => {
      const slug = stringToSlug("New York City");

      expect(slug).toBe("new-york-city");
    });

    it("should handle multiple spaces", () => {
      const slug = stringToSlug("Hello    World");

      expect(slug).toBe("hello-world");
    });

    it("should handle hyphens", () => {
      const slug = stringToSlug("Hello-World");

      expect(slug).toBe("hello-world");
    });
  });
});
