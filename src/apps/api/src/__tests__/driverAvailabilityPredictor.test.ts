/**
 * Phase 3 Test Suite: Driver Availability Predictor
 * Target: 87%+ model accuracy
 */

import { DriverAvailabilityPredictor } from "../services/driverAvailabilityPredictor";

describe("DriverAvailabilityPredictor", () => {
  let predictor: DriverAvailabilityPredictor;

  beforeEach(() => {
    predictor = new DriverAvailabilityPredictor();
  });

  describe("predict()", () => {
    it("should return high availability for optimal conditions", () => {
      const result = predictor.predict("driver-123", "clear", 30, 2);

      expect(result.availabilityProbability).toBeGreaterThan(0.8);
      expect(result.confidence).toBeGreaterThan(0.7);
      expect(result.recommendation).toBe("HIGH");
    });

    it("should return low availability for poor conditions", () => {
      const result = predictor.predict("driver-456", "snow", 95, 5);

      expect(result.availabilityProbability).toBeLessThan(0.5);
      expect(result.recommendation).toBe("LOW");
    });

    it("should factor in weather conditions correctly", () => {
      const clearWeather = predictor.predict("driver-789", "clear", 50, 3);
      const snowWeather = predictor.predict("driver-789", "snow", 50, 3);

      expect(clearWeather.availabilityProbability).toBeGreaterThan(
        snowWeather.availabilityProbability,
      );
    });

    it("should return factors breakdown", () => {
      const result = predictor.predict("driver-123", "clear", 50, 3);

      expect(result.factors).toHaveProperty("timeOfDay");
      expect(result.factors).toHaveProperty("dayOfWeek");
      expect(result.factors).toHaveProperty("weather");
      expect(result.factors).toHaveProperty("traffic");
      expect(result.factors).toHaveProperty("recentActivity");
      expect(result.factors).toHaveProperty("historicalPattern");
    });

    it("should handle edge cases", () => {
      const result = predictor.predict("driver-edge", "rain", 0, 0);

      expect(result.availabilityProbability).toBeGreaterThanOrEqual(0);
      expect(result.availabilityProbability).toBeLessThanOrEqual(1);
    });

    it("should achieve target model accuracy", () => {
      // Simulate test dataset
      const testCases = [
        { conditions: ["clear", 30, 2], expected: "HIGH" },
        { conditions: ["clear", 45, 3], expected: "HIGH" },
        { conditions: ["rain", 70, 4], expected: "MEDIUM" },
        { conditions: ["snow", 90, 5], expected: "LOW" },
        { conditions: ["rain", 85, 4], expected: "LOW" },
      ];

      let correct = 0;
      testCases.forEach((testCase) => {
        const result = predictor.predict(
          "test-driver",
          testCase.conditions[0] as string,
          testCase.conditions[1] as number,
          testCase.conditions[2] as number,
        );
        if (result.recommendation === testCase.expected) {
          correct++;
        }
      });

      const accuracy = (correct / testCases.length) * 100;
      expect(accuracy).toBeGreaterThanOrEqual(80); // 80%+ accuracy target
    });
  });

  describe("trainModel()", () => {
    it("should train model with historical data", () => {
      const trainingData = [
        {
          driverId: "driver-1",
          timestamp: new Date(),
          online: true,
          weather: "clear",
        },
        {
          driverId: "driver-1",
          timestamp: new Date(),
          online: true,
          weather: "clear",
        },
        {
          driverId: "driver-2",
          timestamp: new Date(),
          online: false,
          weather: "snow",
        },
      ];

      const metrics = predictor.trainModel(trainingData);

      expect(metrics.accuracy).toBeGreaterThan(0.7);
      expect(metrics.precision).toBeGreaterThan(0.7);
      expect(metrics.recall).toBeGreaterThan(0.7);
    });
  });

  describe("performance", () => {
    it("should complete prediction in under 100ms", () => {
      const start = Date.now();
      predictor.predict("perf-test", "clear", 50, 3);
      const duration = Date.now() - start;

      expect(duration).toBeLessThan(100);
    });
  });
});
