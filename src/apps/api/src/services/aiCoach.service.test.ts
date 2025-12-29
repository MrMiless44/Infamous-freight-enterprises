import { generateCoaching } from "./aiCoach.service";

describe("aiCoach.service", () => {
  describe("generateCoaching", () => {
    it("should handle driver with no loads", async () => {
      const driver = {
        id: "driver-1",
        loads: [],
      };

      const result = await generateCoaching(driver);

      expect(result.metrics.totalLoads).toBe(0);
      expect(result.metrics.onTimePerformance).toBe(0);
      expect(result.metrics.averageRating).toBe(0);
    });

    it("should calculate metrics for delivered loads only", async () => {
      const driver = {
        id: "driver-1",
        loads: [
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-01"),
            deliveryTime: new Date("2024-01-02"),
            rating: 4.5,
          },
          {
            status: "PENDING",
            pickupTime: new Date("2024-01-03"),
            deliveryTime: new Date("2024-01-04"),
            rating: 5.0,
          },
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-05"),
            deliveryTime: new Date("2024-01-06"),
            rating: 3.5,
          },
        ],
      };

      const result = await generateCoaching(driver);

      expect(result.metrics.totalLoads).toBe(2);
      expect(result.metrics.averageRating).toBe(4.0);
      expect(result.metrics.onTimePerformance).toBe(100); // Simplified: all delivered = on-time
    });

    it("should handle loads without ratings", async () => {
      const driver = {
        id: "driver-1",
        loads: [
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-01"),
            deliveryTime: new Date("2024-01-02"),
            rating: null,
          },
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-03"),
            deliveryTime: new Date("2024-01-04"),
          },
        ],
      };

      const result = await generateCoaching(driver);

      expect(result.metrics.totalLoads).toBe(2);
      expect(result.metrics.averageRating).toBe(0);
    });

    it("should provide appropriate feedback for low rating", async () => {
      const driver = {
        id: "driver-1",
        loads: [
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-01"),
            deliveryTime: new Date("2024-01-02"),
            rating: 3.0,
          },
        ],
      };

      const result = await generateCoaching(driver);

      expect(result.suggestions.priority).toBe("high");
      expect(result.metrics.improvementAreas).toContain(
        "Customer satisfaction",
      );
      expect(result.suggestions.actions).toContain(
        "Focus on communication with customers",
      );
    });

    it("should provide excellent feedback for high performance", async () => {
      const driver = {
        id: "driver-1",
        loads: [
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-01"),
            deliveryTime: new Date("2024-01-02"),
            rating: 5.0,
          },
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-03"),
            deliveryTime: new Date("2024-01-04"),
            rating: 4.8,
          },
        ],
      };

      const result = await generateCoaching(driver);

      expect(result.feedback).toContain("Excellent on-time performance");
      expect(result.suggestions.priority).toBe("medium");
      expect(result.metrics.onTimePerformance).toBe(100);
    });

    it("should calculate correct average rating", async () => {
      const driver = {
        id: "driver-1",
        loads: [
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-01"),
            deliveryTime: new Date("2024-01-02"),
            rating: 5.0,
          },
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-03"),
            deliveryTime: new Date("2024-01-04"),
            rating: 3.0,
          },
          {
            status: "DELIVERED",
            pickupTime: new Date("2024-01-05"),
            deliveryTime: new Date("2024-01-06"),
            rating: 4.0,
          },
        ],
      };

      const result = await generateCoaching(driver);

      expect(result.metrics.averageRating).toBe(4.0);
      expect(result.metrics.totalLoads).toBe(3);
    });
  });
});
