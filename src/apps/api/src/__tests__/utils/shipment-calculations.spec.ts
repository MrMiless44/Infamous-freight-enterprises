import {
  calculateShippingPrice,
  calculateDistance,
  calculateDeliveryTime,
  formatAddress,
  validateEmail,
  validatePhone,
} from "../../utils/shipmentCalculations";

describe("Shipment Calculation Utils", () => {
  describe("calculateShippingPrice", () => {
    it("should calculate local delivery price", () => {
      const price = calculateShippingPrice({
        serviceType: "local",
        distance: 25,
        weight: 2000,
      });

      expect(price).toBeGreaterThan(0);
      expect(price).toBeLessThan(500); // Local should be cheap
    });

    it("should calculate regional delivery price", () => {
      const price = calculateShippingPrice({
        serviceType: "regional",
        distance: 300,
        weight: 5000,
      });

      expect(price).toBeGreaterThan(0);
      expect(price).toBeGreaterThan(100); // Regional more expensive
    });

    it("should calculate national delivery price", () => {
      const price = calculateShippingPrice({
        serviceType: "national",
        distance: 2000,
        weight: 10000,
      });

      expect(price).toBeGreaterThan(0);
      expect(price).toBeGreaterThan(500); // National most expensive
    });

    it("should apply weight surcharge", () => {
      const lightPrice = calculateShippingPrice({
        serviceType: "regional",
        distance: 300,
        weight: 1000,
      });

      const heavyPrice = calculateShippingPrice({
        serviceType: "regional",
        distance: 300,
        weight: 20000,
      });

      expect(heavyPrice).toBeGreaterThan(lightPrice);
    });

    it("should apply distance surcharge", () => {
      const closePrice = calculateShippingPrice({
        serviceType: "regional",
        distance: 100,
        weight: 5000,
      });

      const farPrice = calculateShippingPrice({
        serviceType: "regional",
        distance: 500,
        weight: 5000,
      });

      expect(farPrice).toBeGreaterThan(closePrice);
    });
  });

  describe("calculateDistance", () => {
    it("should calculate distance between two points", () => {
      const distance = calculateDistance(
        { lat: 40.7128, lng: -74.006 }, // New York
        { lat: 40.758, lng: -73.9855 }, // Midtown
      );

      expect(distance).toBeGreaterThan(0);
      expect(distance).toBeLessThan(1); // Less than 1 mile
    });

    it("should handle same location", () => {
      const distance = calculateDistance(
        { lat: 40.7128, lng: -74.006 },
        { lat: 40.7128, lng: -74.006 },
      );

      expect(distance).toBe(0);
    });

    it("should calculate long distances", () => {
      const distance = calculateDistance(
        { lat: 40.7128, lng: -74.006 }, // New York
        { lat: 41.8781, lng: -87.6298 }, // Chicago
      );

      expect(distance).toBeGreaterThan(700); // ~790 miles
      expect(distance).toBeLessThan(900);
    });
  });

  describe("calculateDeliveryTime", () => {
    it("should estimate delivery time for local", () => {
      const time = calculateDeliveryTime({
        distance: 25,
        serviceType: "local",
      });

      expect(time).toBeGreaterThan(30);
      expect(time).toBeLessThan(120); // 30min - 2 hours
    });

    it("should estimate delivery time for regional", () => {
      const time = calculateDeliveryTime({
        distance: 300,
        serviceType: "regional",
      });

      expect(time).toBeGreaterThan(120); // At least 2 hours
      expect(time).toBeLessThan(1440); // Less than 24 hours
    });

    it("should account for service type", () => {
      const standardTime = calculateDeliveryTime({
        distance: 300,
        serviceType: "standard",
      });

      const expressTime = calculateDeliveryTime({
        distance: 300,
        serviceType: "express",
      });

      expect(standardTime).toBeGreaterThan(expressTime);
    });
  });

  describe("formatAddress", () => {
    it("should format address correctly", () => {
      const address = formatAddress({
        street: "123 Main St",
        city: "New York",
        state: "NY",
        zip: "10001",
      });

      expect(address).toContain("123 Main St");
      expect(address).toContain("New York");
      expect(address).toContain("NY");
      expect(address).toContain("10001");
    });

    it("should handle missing fields", () => {
      const address = formatAddress({
        street: "123 Main St",
        city: "New York",
        state: "NY",
      });

      expect(address).toBeDefined();
      expect(address).not.toContain("undefined");
    });
  });

  describe("validateEmail", () => {
    it("should validate correct email", () => {
      expect(validateEmail("user@example.com")).toBe(true);
    });

    it("should reject invalid emails", () => {
      expect(validateEmail("invalid")).toBe(false);
      expect(validateEmail("user@")).toBe(false);
      expect(validateEmail("@example.com")).toBe(false);
    });
  });

  describe("validatePhone", () => {
    it("should validate US phone numbers", () => {
      expect(validatePhone("+15551234567")).toBe(true);
      expect(validatePhone("5551234567")).toBe(true);
    });

    it("should reject invalid phone numbers", () => {
      expect(validatePhone("123")).toBe(false);
      expect(validatePhone("abc")).toBe(false);
    });
  });
});
