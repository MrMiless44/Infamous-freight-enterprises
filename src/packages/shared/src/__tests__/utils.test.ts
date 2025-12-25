import {
  formatDate,
  formatCurrency,
  generateTrackingNumber,
  debounce,
} from "../utils";

describe("formatDate", () => {
  it("should format date to YYYY-MM-DD", () => {
    const date = new Date("2024-12-13T10:30:00Z");
    expect(formatDate(date)).toBe("2024-12-13");
  });

  it("should handle date strings", () => {
    expect(formatDate("2024-12-13")).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("should handle invalid dates gracefully", () => {
    expect(formatDate("invalid")).toBe("Invalid Date");
  });
});

describe("formatCurrency", () => {
  it("should format numbers as USD currency", () => {
    expect(formatCurrency(1234.56)).toBe("$1,234.56");
  });

  it("should handle zero", () => {
    expect(formatCurrency(0)).toBe("$0.00");
  });

  it("should handle negative numbers", () => {
    expect(formatCurrency(-100.5)).toBe("-$100.50");
  });

  it("should round to 2 decimal places", () => {
    expect(formatCurrency(10.999)).toBe("$11.00");
  });
});

describe("generateTrackingNumber", () => {
  it("should generate tracking number with IFE prefix", () => {
    const tracking = generateTrackingNumber();
    expect(tracking).toMatch(/^IFE-[A-Z0-9]{12}$/);
  });

  it("should generate unique tracking numbers", () => {
    const tracking1 = generateTrackingNumber();
    const tracking2 = generateTrackingNumber();
    expect(tracking1).not.toBe(tracking2);
  });

  it("should be 16 characters long", () => {
    const tracking = generateTrackingNumber();
    expect(tracking).toHaveLength(16); // IFE- + 12 chars
  });
});

describe("debounce", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  it("should delay function execution", () => {
    const mockFn = jest.fn();
    const debouncedFn = debounce(mockFn, 500);

    debouncedFn();
    expect(mockFn).not.toHaveBeenCalled();

    jest.advanceTimersByTime(500);
    expect(mockFn).toHaveBeenCalledTimes(1);
  });

  it("should only execute once for multiple rapid calls", () => {
    const mockFn = jest.fn();
    const debouncedFn = debounce(mockFn, 500);

    debouncedFn();
    debouncedFn();
    debouncedFn();

    jest.advanceTimersByTime(500);
    expect(mockFn).toHaveBeenCalledTimes(1);
  });

  it("should pass arguments to the debounced function", () => {
    const mockFn = jest.fn();
    const debouncedFn = debounce(mockFn, 500);

    debouncedFn("test", 123);
    jest.advanceTimersByTime(500);

    expect(mockFn).toHaveBeenCalledWith("test", 123);
  });
});
